//! Directory enumeration without administrator privileges or NTFS access.

use super::*;
use crate::paths;
use std::collections::BTreeMap;
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use windows_sys::Win32::Storage::FileSystem::*;

pub(crate) fn metadata_kind(m: &std::fs::Metadata) -> u8 {
    let attrs = m.file_attributes();
    let kind = if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        KIND_LINK
    } else if m.is_dir() {
        KIND_DIR
    } else if m.is_file() {
        KIND_FILE
    } else {
        KIND_OTHER
    };
    kind | if attrs & FILE_ATTRIBUTE_HIDDEN != 0 { FLAG_HIDDEN } else { 0 }
}

pub(crate) fn metadata_mtime(m: &std::fs::Metadata) -> u32 {
    m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |t| t.as_secs().min(u32::MAX as u64) as u32)
}

fn empty(id: u32) -> Listing {
    Listing { id, names: Vec::new(), ents: Vec::new() }
}

fn push(l: &mut Listing, name: &[u8], kind: u8, size: u64, mtime: u32, child: u32) {
    l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, size, mtime, child });
    l.names.extend_from_slice(name);
}

fn drives() -> io::Result<Vec<PathBuf>> {
    let mask = unsafe { GetLogicalDrives() };
    if mask == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((0..26).filter(|i| mask & (1 << i) != 0).map(|i| PathBuf::from(format!("{}:\\", (b'A' + i) as char))).collect())
}

pub fn list_one(path: &[u8]) -> Option<Listing> {
    if blocked(path) {
        return None;
    }
    let mut l = empty(0);
    if path == b"/" {
        for drive in drives().ok()? {
            let name = paths::encode(&drive);
            push(&mut l, &name[1..], KIND_DIR, 0, 0, NONE);
        }
        return Some(l);
    }
    let native = paths::decode(path);
    let m = std::fs::symlink_metadata(&native).ok()?;
    // Includes junctions and cloud placeholders: never traverse a reparse
    // point or hydrate offline directories while indexing.
    if metadata_kind(&m) & 3 != KIND_DIR
        || m.file_attributes() & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) != 0
    {
        return None;
    }
    let entries = match std::fs::read_dir(native) {
        Ok(entries) => entries,
        Err(e) => {
            if e.kind() == io::ErrorKind::PermissionDenied {
                DENIED.lock().unwrap().push(path.to_vec());
            }
            return None;
        }
    };
    for entry in entries.flatten() {
        let Ok(m) = entry.metadata() else { continue };
        let name = paths::name(&entry.file_name());
        if !name.is_empty() && name.len() <= u16::MAX as usize {
            push(&mut l, &name, metadata_kind(&m), m.len(), metadata_mtime(&m), NONE);
        }
    }
    Some(l)
}

struct Context {
    next: AtomicU32,
    listings: Mutex<Vec<Listing>>,
}

fn scan_dir<'a>(scope: &rayon::Scope<'a>, path: Vec<u8>, id: u32, ctx: &'a Context) {
    let mut listing = list_one(&path).unwrap_or_else(|| empty(id));
    listing.id = id;
    for entry in &mut listing.ents {
        if entry.kind & 3 != KIND_DIR {
            continue;
        }
        let child = crate::live::join(&path, &listing.names[entry.name_off as usize..][..entry.name_len as usize]);
        if blocked(&child) {
            continue;
        }
        let id = ctx.next.fetch_add(1, Ordering::Relaxed);
        entry.child = id;
        scope.spawn(move |s| scan_dir(s, child, id, ctx));
    }
    LISTED.fetch_add(listing.ents.len(), Ordering::Relaxed);
    ctx.listings.lock().unwrap().push(listing);
}

/// Scan a single directory. As on macOS, listing 0 represents `root`.
pub fn scan(root: &[u8], threads: usize) -> Vec<Listing> {
    let ctx = Context { next: AtomicU32::new(1), listings: Mutex::new(Vec::new()) };
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads.max(1)).build().unwrap();
    pool.scope(|s| scan_dir(s, root.to_vec(), 0, &ctx));
    ctx.listings.into_inner().unwrap()
}

/// Build the virtual drive/UNC hierarchy for selected absolute roots.
/// An empty root list enumerates the available drive letters.
pub fn scan_roots(roots: &[PathBuf], threads: usize) -> io::Result<Vec<Listing>> {
    if roots.is_empty() {
        // Failure to enumerate drives must not publish an empty snapshot.
        drives()?;
        return Ok(scan(b"/", threads));
    }
    let mut roots: Vec<Vec<u8>> = roots.iter().map(|p| absolute_root(p)).collect::<io::Result<_>>()?;
    roots.sort();
    roots.dedup();
    // Don't scan overlapping roots twice.
    let mut selected: Vec<Vec<u8>> = Vec::new();
    for root in roots {
        if !selected.iter().any(|p| root.starts_with(p) && root.get(p.len()) == Some(&b'/')) {
            selected.push(root);
        }
    }
    let mut skeleton = BTreeMap::from([(b"/".to_vec(), empty(0))]);
    let mut next = 1;
    for root in &selected {
        let mut parent = b"/".to_vec();
        for name in root.split(|&b| b == b'/').filter(|p| !p.is_empty()) {
            let child = crate::live::join(&parent, name);
            if !skeleton.contains_key(&child) {
                // UNC namespace/server nodes are synthetic; real ancestors
                // and selected roots carry the same metadata as scanned entries.
                let namespace = child == b"/UNC" || child.strip_prefix(b"/UNC/").is_some_and(|p| !p.contains(&b'/'));
                let metadata = if child == *root {
                    Some(std::fs::symlink_metadata(paths::decode(&child))?)
                } else if namespace {
                    None
                } else {
                    std::fs::symlink_metadata(paths::decode(&child)).ok()
                };
                let (kind, size, mtime) = metadata.as_ref().map_or((KIND_DIR, 0, 0), |m| (metadata_kind(m), m.len(), metadata_mtime(m)));
                push(skeleton.get_mut(&parent).unwrap(), name, kind, size, mtime, next);
                skeleton.insert(child.clone(), empty(next));
                next += 1;
            }
            parent = child;
        }
    }
    let work: Vec<_> = selected
        .into_iter()
        .map(|p| {
            let id = skeleton.remove(&p).unwrap().id;
            (p, id)
        })
        .collect();
    let ctx = Context { next: AtomicU32::new(next), listings: Mutex::new(skeleton.into_values().collect()) };
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads.max(1)).build().unwrap();
    pool.scope(|s| {
        for (path, id) in work {
            let ctx = &ctx;
            s.spawn(move |s| scan_dir(s, path, id, ctx));
        }
    });
    Ok(ctx.listings.into_inner().unwrap())
}

fn absolute_root(path: &Path) -> io::Result<Vec<u8>> {
    let m = std::fs::symlink_metadata(path)?;
    if metadata_kind(&m) & 3 != KIND_DIR {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not a directory, or is a reparse point", path.display())));
    }
    if m.file_attributes() & (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is an offline directory", path.display())));
    }
    let path = std::fs::canonicalize(path)?;
    let key = paths::encode(&path);
    if !(key.starts_with(b"/UNC/") || key.len() >= 3 && key[0] == b'/' && key[2] == b':') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "root must be a drive or UNC path"));
    }
    // Surface a root access error; individual inaccessible descendants are skipped.
    std::fs::read_dir(path)?;
    Ok(key)
}
