//! Filesystem-wide Linux notifications, translated to directory relists.
//! Requires Linux 5.17's named/target FIDs and CAP_SYS_ADMIN plus
//! CAP_DAC_READ_SEARCH. There is no event replay; the engine reconciles on
//! restart and on root MUST_SCAN_SUBDIRS events.

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MUST_SCAN_SUBDIRS: u32 = 0x1;
pub const USER_DROPPED: u32 = 0x2;
pub const KERNEL_DROPPED: u32 = 0x4;
pub const HISTORY_DONE: u32 = 0x10;

pub struct Event {
    pub path: Vec<u8>,
    pub flags: u32,
    pub id: u64,
}

const ENTRY_EVENTS: u64 = libc::FAN_CREATE | libc::FAN_DELETE | libc::FAN_MOVED_FROM | libc::FAN_MOVED_TO | libc::FAN_RENAME;
const EVENT_MASK: u64 = ENTRY_EVENTS | libc::FAN_MODIFY | libc::FAN_CLOSE_WRITE | libc::FAN_ATTRIB | libc::FAN_ONDIR;
const METADATA_LEN: usize = 24;
const MAX_HANDLE: usize = libc::MAX_HANDLE_SZ as usize;
const MAX_BATCH: usize = 4096;
static LAST_ID: AtomicU64 = AtomicU64::new(0);

/// An epoch-nanosecond checkpoint, monotonically increasing within the process.
pub fn current_id() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos().min(u64::MAX as u128) as u64;
    let last = LAST_ID.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| Some(now.max(last.saturating_add(1)))).unwrap();
    now.max(last.saturating_add(1))
}

/// Dropping the stream wakes and joins its worker before closing all fds.
pub struct Stream {
    stop: OwnedFd,
    worker: Option<JoinHandle<()>>,
}

impl Stream {
    /// Runtime watcher failures are also logged and signal root reconciliation.
    pub fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        let value = 1u64;
        loop {
            let n = unsafe { libc::write(self.stop.as_raw_fd(), (&value as *const u64).cast(), 8) };
            if n >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                break;
            }
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Establish all filesystem marks before returning, so crawling cannot race
/// watcher startup. `since` is intentionally unused: Linux has no replay.
pub fn watch(_since: u64, latency: f64, tx: Sender<Vec<Event>>) -> io::Result<Stream> {
    if !latency.is_finite() || latency < 0.0 || latency > 60.0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "fanotify latency must be between 0 and 60 seconds"));
    }
    let mut topology = File::open("/proc/self/mountinfo")?;
    let mut mountinfo = Vec::new();
    read_topology(&mut topology, &mut mountinfo)?;
    let fan = owned(unsafe {
        libc::fanotify_init(libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_REPORT_DFID_NAME_TARGET, 0)
    }).map_err(|e| context("fanotify_init (requires CAP_SYS_ADMIN and named FID support)", e))?;
    let mounts = refresh_mounts(fan.as_raw_fd(), &[])?;
    let stop = owned(unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) })?;
    let wake = stop.try_clone()?;
    let delay = Duration::from_secs_f64(latency);
    let worker = thread::Builder::new().name("fsearch-fanotify".into()).spawn(move || {
        // Marks are already active. HISTORY_DONE only releases the engine's
        // replay gate; it does not claim that historical events were replayed.
        if tx.send(vec![Event { path: b"/".to_vec(), flags: HISTORY_DONE, id: current_id() }]).is_err() {
            return;
        }
        if let Err(error) = run(fan, wake, topology, mountinfo, mounts, delay, &tx) {
            eprintln!("fsearch: Linux watcher stopped: {error}");
            let _ = tx.send(vec![Event { path: b"/".to_vec(), flags: MUST_SCAN_SUBDIRS | USER_DROPPED, id: current_id() }]);
        }
    })?;
    Ok(Stream { stop, worker: Some(worker) })
}

fn owned(fd: i32) -> io::Result<OwnedFd> {
    if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { OwnedFd::from_raw_fd(fd) }) }
}

fn context(operation: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{operation}: {error}"))
}

struct Mount {
    fsid: [i32; 2],
    fd: OwnedFd,
}

fn mark(fan: i32, mount: &Mount, action: u32) -> io::Result<()> {
    let result = unsafe { libc::fanotify_mark(fan, action | libc::FAN_MARK_FILESYSTEM, EVENT_MASK, mount.fd.as_raw_fd(), std::ptr::null()) };
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn refresh_mounts(fan: i32, old: &[Mount]) -> io::Result<Vec<Mount>> {
    let roots = crate::walk::mounts()?;
    if roots.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no supported local filesystems to watch"));
    }
    let mut mounts: Vec<Mount> = Vec::with_capacity(roots.len());
    for root in roots {
        let path = CString::new(root.as_slice()).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUL in mount path"))?;
        let fd = owned(unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })
            .map_err(|e| context(&format!("open mount {}", OsStr::from_bytes(&root).to_string_lossy()), e))?;
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut stat) } < 0 {
            return Err(context("fstatfs mount", io::Error::last_os_error()));
        }
        // fsid_t is the Linux ABI's pair of 32-bit integers, with private
        // fields in libc. Kernel FID records contain the same eight bytes.
        let fsid = unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(stat.f_fsid) };
        if fsid == [0, 0] {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "filesystem has no resolvable fanotify fsid"));
        }
        let mount = Mount { fsid, fd };
        if !mounts.iter().any(|m| m.fsid == fsid) {
            mark(fan, &mount, libc::FAN_MARK_ADD)
                .map_err(|e| context(&format!("fanotify filesystem mark {}", OsStr::from_bytes(&root).to_string_lossy()), e))?;
        }
        // Keep each mount fd: handles on bind mounts/subvolumes may only
        // resolve through one of the mounts of the same filesystem.
        mounts.push(mount);
    }
    for mount in old {
        if !mounts.iter().any(|m| m.fsid == mount.fsid) {
            if let Err(error) = mark(fan, mount, libc::FAN_MARK_REMOVE) {
                if error.raw_os_error() != Some(libc::ENOENT) {
                    return Err(context("remove fanotify filesystem mark", error));
                }
            }
        }
    }
    Ok(mounts)
}

fn read_topology(file: &mut File, buffer: &mut Vec<u8>) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    buffer.clear();
    file.read_to_end(buffer)?;
    Ok(())
}

fn run(
    fan: OwnedFd,
    stop: OwnedFd,
    mut topology: File,
    mut mountinfo: Vec<u8>,
    mut mounts: Vec<Mount>,
    delay: Duration,
    tx: &Sender<Vec<Event>>,
) -> io::Result<()> {
    let mut buffer = vec![0u8; 256 * 1024];
    let mut batch = Vec::new();
    let mut deadline: Option<Instant> = None;
    loop {
        let timeout = deadline.map_or(-1, |d| d.saturating_duration_since(Instant::now()).as_millis().min(i32::MAX as u128) as i32);
        let mut polls = [
            libc::pollfd { fd: fan.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: stop.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            // proc mountinfo's POLLPRI/POLLERR reports mount namespace
            // changes, not file polling or a substitute for fanotify.
            libc::pollfd { fd: topology.as_raw_fd(), events: libc::POLLPRI, revents: 0 },
        ];
        if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, timeout) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(context("fanotify poll", error));
        }
        if polls[1].revents != 0 { return Ok(()); }
        if polls[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("fanotify descriptor stopped reporting events"));
        }
        if polls[2].revents & (libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("mount topology descriptor closed"));
        }
        if polls[2].revents & (libc::POLLPRI | libc::POLLERR) != 0 {
            read_topology(&mut topology, &mut mountinfo)?;
            mounts = refresh_mounts(fan.as_raw_fd(), &mounts)?;
            reconcile(&mut batch, 0);
        }
        if polls[0].revents & libc::POLLIN != 0 {
            // Bound each drain so shutdown/topology/latency remain responsive
            // even when writers keep the notification queue continuously busy.
            for _ in 0..8 {
                let n = unsafe { libc::read(fan.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
                if n < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::WouldBlock { break; }
                    if error.kind() == io::ErrorKind::Interrupted { continue; }
                    return Err(context("fanotify read", error));
                }
                if n == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "fanotify EOF")); }
                translate_buffer(&buffer[..n as usize], &mut batch, |fid| resolve(fid, &mounts), push)?;
                if batch.len() >= MAX_BATCH { break; }
                if deadline.is_some_and(|d| Instant::now() >= d) { break; }
            }
        }
        if !batch.is_empty() && deadline.is_none() { deadline = Some(Instant::now() + delay); }
        if batch.len() >= MAX_BATCH || deadline.is_some_and(|d| Instant::now() >= d) {
            if tx.send(std::mem::take(&mut batch)).is_err() { return Ok(()); }
            deadline = None;
        }
    }
}

#[derive(Clone, Copy)]
struct Fid<'a> {
    fsid: [i32; 2],
    handle_type: i32,
    handle: &'a [u8],
    name: Option<&'a [u8]>,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed or incompatible fanotify record")
}

fn u16_at(bytes: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(bytes.get(at..at + 2).ok_or_else(invalid)?.try_into().unwrap()))
}

fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(bytes.get(at..at + 4).ok_or_else(invalid)?.try_into().unwrap()))
}

fn decode_fid(bytes: &[u8]) -> io::Result<Fid<'_>> {
    if bytes.len() < 20 { return Err(invalid()); }
    let size = u32_at(bytes, 12)? as usize;
    if size == 0 || size > MAX_HANDLE { return Err(invalid()); }
    let handle = bytes.get(20..20 + size).ok_or_else(invalid)?;
    let kind = bytes[0];
    let name = if matches!(kind, 2 | 10 | 12) {
        let rest = bytes.get(20 + size..).ok_or_else(invalid)?;
        let end = rest.iter().position(|b| *b == 0).ok_or_else(invalid)?;
        let name = &rest[..end];
        if name.is_empty() || name == b".." || name.contains(&b'/') { return Err(invalid()); }
        Some(name)
    } else { None };
    Ok(Fid {
        fsid: [u32_at(bytes, 4)? as i32, u32_at(bytes, 8)? as i32],
        handle_type: u32_at(bytes, 16)? as i32,
        handle,
        name,
    })
}

fn decode_records(bytes: &[u8], offset: usize) -> io::Result<[Option<Fid<'_>>; 5]> {
    let mut records = [None; 5];
    let mut offset = offset;
    while offset < bytes.len() {
        let rest = bytes.get(offset..).ok_or_else(invalid)?;
        if rest.len() < 4 { return Err(invalid()); }
        let len = u16_at(rest, 2)? as usize;
        if len < 4 || len > rest.len() { return Err(invalid()); }
        let slot = match rest[0] { 1 => Some(0), 2 => Some(1), 3 => Some(2), 10 => Some(3), 12 => Some(4), _ => None };
        if let Some(slot) = slot {
            if records[slot].is_some() { return Err(invalid()); }
            records[slot] = Some(decode_fid(&rest[..len])?);
        }
        offset += len;
    }
    Ok(records)
}

fn translate_buffer(
    mut bytes: &[u8],
    batch: &mut Vec<Event>,
    mut resolve: impl FnMut(&Fid<'_>) -> io::Result<Vec<u8>>,
    mut emit: impl FnMut(&mut Vec<Event>, Vec<u8>, u32, bool),
) -> io::Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < METADATA_LEN { return Err(invalid()); }
        let len = u32_at(bytes, 0)? as usize;
        let metadata = u16_at(bytes, 6)? as usize;
        if bytes[4] != libc::FANOTIFY_METADATA_VERSION || metadata < METADATA_LEN || len < metadata || len > bytes.len() {
            return Err(invalid());
        }
        let event = &bytes[..len];
        let mask = u64::from_ne_bytes(event[8..16].try_into().unwrap());
        // FID mode never supplies event fds. Still close a valid fd if the
        // kernel supplies one, rather than leaking it on an ABI transition.
        let fd = u32_at(event, 16)? as i32;
        if fd >= 0 { drop(unsafe { OwnedFd::from_raw_fd(fd) }); }
        let records = decode_records(event, metadata)?;
        if mask & libc::FAN_Q_OVERFLOW != 0 {
            reconcile(batch, KERNEL_DROPPED);
        } else {
            translate_event(mask, &records, batch, &mut resolve, &mut emit)?;
        }
        bytes = &bytes[len..];
    }
    Ok(())
}

fn translate_event(
    mask: u64,
    records: &[Option<Fid<'_>>; 5],
    batch: &mut Vec<Event>,
    resolve: &mut impl FnMut(&Fid<'_>) -> io::Result<Vec<u8>>,
    emit: &mut impl FnMut(&mut Vec<Event>, Vec<u8>, u32, bool),
) -> io::Result<()> {
    let is_dir = mask & libc::FAN_ONDIR != 0;
    let entry = mask & ENTRY_EVENTS != 0;
    if entry && !records.iter().skip(1).any(Option::is_some) {
        // Unlike unlink's later ATTRIB/CLOSE, a dirent event must identify
        // its parent(s); a target alone cannot remove an old indexed path.
        reconcile(batch, USER_DROPPED);
        return Ok(());
    }
    // fsnotify_link_count() sends inode-only ATTRIB, including for the victim
    // of overwrite rename. Link counts are not indexed; mandatory named
    // create/delete/rename events relist the affected parents. Do not ask
    // exportfs to resurrect that potentially dead inode just to find a path.
    // chmod/chown/utime use dentry notifications with parent/name instead;
    // directory ATTRIB carries FAN_ONDIR and must still invalidate children.
    if mask == libc::FAN_ATTRIB && records[0].is_some() && !records.iter().skip(1).any(Option::is_some) {
        return Ok(());
    }
    let mut has_parent = false;
    for fid in records.iter().skip(1).flatten() {
        has_parent = true;
        match resolve(fid) {
            Ok(dir) => {
                let child = if is_dir {
                    fid.name.map(|name| if name == b"." { dir.clone() } else { crate::live::join(&dir, name) })
                } else { None };
                if is_dir && !entry {
                    emit(batch, child.unwrap_or(dir), MUST_SCAN_SUBDIRS, true);
                } else {
                    emit(batch, dir, if is_dir && fid.name.is_none() { MUST_SCAN_SUBDIRS } else { 0 }, false);
                    if is_dir {
                        if let Some(child) = child {
                            emit(batch, child, MUST_SCAN_SUBDIRS, false);
                        }
                    }
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::ESTALE) => reconcile(batch, USER_DROPPED),
            Err(error) => return Err(context("resolve fanotify directory", error)),
        }
    }
    // Parent/name records are sufficient even when the target has already
    // been deleted. Do not open that stale target and trigger a full rebuild.
    if has_parent { return Ok(()); }
    if let Some(fid) = &records[0] {
        match resolve(fid) {
            Ok(path) => {
                let parent = parent(&path).to_vec();
                if is_dir {
                    emit(batch, path, MUST_SCAN_SUBDIRS, !entry);
                }
                emit(batch, parent, 0, false);
            }
            // A detached file can still be written/closed after unlink or
            // overwrite. It no longer names an indexed entry; its namespace
            // mutation is handled by the named event (or overflow recovery).
            Err(error) if error.raw_os_error() == Some(libc::ESTALE) && !is_dir && !entry => {}
            Err(error) if error.raw_os_error() == Some(libc::ESTALE) => reconcile(batch, USER_DROPPED),
            Err(error) => return Err(context("resolve fanotify target", error)),
        }
    } else {
        reconcile(batch, USER_DROPPED);
    }
    Ok(())
}

fn parent(path: &[u8]) -> &[u8] {
    path.iter().rposition(|b| *b == b'/').map_or(b"/".as_slice(), |n| if n == 0 { b"/" } else { &path[..n] })
}

fn readable_directory(path: &mut Vec<u8>) -> bool {
    path.push(0);
    // access(), unlike faccessat with AT_EACCESS, checks real UID/GID and
    // ignores this non-root daemon's DAC-bypass capabilities.
    let allowed = unsafe { libc::access(path.as_ptr().cast(), libc::R_OK | libc::X_OK) } == 0;
    path.pop();
    allowed
}

fn push(batch: &mut Vec<Event>, mut path: Vec<u8>, flags: u32, invalidate_denied: bool) {
    if crate::walk::blocked(&path) { return; }
    while !readable_directory(&mut path) {
        if !invalidate_denied || path == b"/" { return; }
        // A directory chmod can revoke access to previously indexed children.
        // Reconcile its nearest readable ancestor instead of exposing a
        // privileged directory listing or retaining the now-private subtree.
        let len = parent(&path).len();
        path.truncate(len);
        if crate::walk::blocked(&path) { return; }
    }
    batch.push(Event { path, flags, id: current_id() });
}

fn reconcile(batch: &mut Vec<Event>, flags: u32) {
    if let Some(event) = batch.iter_mut().find(|e| e.path == b"/" && e.flags & MUST_SCAN_SUBDIRS != 0) {
        event.flags |= flags;
        event.id = current_id();
    } else {
        batch.push(Event { path: b"/".to_vec(), flags: MUST_SCAN_SUBDIRS | flags, id: current_id() });
    }
}

#[repr(C)]
struct Handle {
    bytes: u32,
    kind: i32,
    data: [u8; MAX_HANDLE],
}

fn resolution_error(stage: &str, error: io::Error) -> io::Error {
    if error.raw_os_error() != Some(libc::ESTALE) {
        eprintln!("fsearch: resolving fanotify FID ({stage}): {error}");
    }
    error
}

fn resolve(fid: &Fid<'_>, mounts: &[Mount]) -> io::Result<Vec<u8>> {
    let mut handle = Handle { bytes: fid.handle.len() as u32, kind: fid.handle_type, data: [0; MAX_HANDLE] };
    handle.data[..fid.handle.len()].copy_from_slice(fid.handle);
    let mut error = io::Error::new(io::ErrorKind::NotFound, "no mount matching FID fsid");
    let mut excluded = None;
    for mount in mounts.iter().filter(|mount| mount.fsid == fid.fsid) {
        let result = (|| {
            let fd = owned(unsafe {
                libc::open_by_handle_at(mount.fd.as_raw_fd(), (&mut handle as *mut Handle).cast(), libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            }).map_err(|e| resolution_error("open_by_handle_at", e))?;
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } < 0 {
                return Err(resolution_error("fstat", io::Error::last_os_error()));
            }
            if stat.st_nlink == 0 { return Err(io::Error::from_raw_os_error(libc::ESTALE)); }
            let path = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                .map_err(|e| resolution_error("read_link", e))?.into_os_string().into_vec();
            if !path.starts_with(b"/") { return Err(resolution_error("nonabsolute-path", invalid())); }
            // A literal filename ending in this suffix is legal. Only reject
            // it when the path no longer identifies the opened inode.
            if path.ends_with(b" (deleted)") && !std::fs::symlink_metadata(OsStr::from_bytes(&path))
                .is_ok_and(|m| m.ino() == stat.st_ino && m.dev() == stat.st_dev)
            {
                return Err(io::Error::from_raw_os_error(libc::ESTALE));
            }
            Ok(path)
        })();
        match result {
            Ok(path) if !crate::walk::blocked(&path) => return Ok(path),
            Ok(path) => excluded = Some(path),
            Err(e) => error = e,
        }
    }
    excluded.map_or(Err(error), Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: u8, handle: u8, name: Option<&[u8]>) -> Vec<u8> {
        let mut bytes = vec![0; 21];
        bytes[0] = kind;
        bytes[4..8].copy_from_slice(&7u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&1u32.to_ne_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_ne_bytes());
        bytes[20] = handle;
        if let Some(name) = name { bytes.extend_from_slice(name); bytes.push(0); }
        let len = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&len.to_ne_bytes());
        bytes
    }

    fn event(mask: u64, records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0; METADATA_LEN];
        bytes[4] = libc::FANOTIFY_METADATA_VERSION;
        bytes[6..8].copy_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
        bytes[8..16].copy_from_slice(&mask.to_ne_bytes());
        bytes[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        for record in records { bytes.extend_from_slice(record); }
        let len = bytes.len() as u32;
        bytes[..4].copy_from_slice(&len.to_ne_bytes());
        bytes
    }

    #[test]
    fn named_rename_and_delete_survive_stale_targets_and_bad_lengths() {
        let rename = event(libc::FAN_RENAME | libc::FAN_ONDIR, &[
            record(1, 99, None), // Deliberately first; target is already stale.
            record(12, 2, Some(b"new\xff")),
            record(10, 1, Some(b"old")),
        ]);
        let delete = event(libc::FAN_DELETE, &[record(1, 99, None), record(2, 1, Some(b"gone"))]);
        let mut bytes = rename.clone();
        bytes.extend_from_slice(&delete);
        let mut batch = Vec::new();
        translate_buffer(&bytes, &mut batch, |fid| match fid.handle[0] {
            1 => Ok(b"/home/fsearch-parser-old".to_vec()),
            2 => Ok(b"/home/fsearch-parser-new".to_vec()),
            _ => panic!("a sufficient parent record must avoid opening a stale target"),
        }, |batch, path, flags, _| batch.push(Event { path, flags, id: current_id() })).unwrap();
        assert!(batch.iter().any(|e| e.path == b"/home/fsearch-parser-old/old" && e.flags == MUST_SCAN_SUBDIRS));
        assert!(batch.iter().any(|e| e.path == b"/home/fsearch-parser-new/new\xff" && e.flags == MUST_SCAN_SUBDIRS));
        assert!(batch.iter().any(|e| e.path == b"/home/fsearch-parser-old" && e.flags == 0));
        assert!(!batch.iter().any(|e| e.path == b"/"));
        let attrs = event(libc::FAN_ATTRIB | libc::FAN_ONDIR, &[record(2, 1, Some(b"."))]);
        let mut attrs_batch = Vec::new();
        translate_buffer(&attrs, &mut attrs_batch, |_| Ok(b"/home/fsearch-parser-old".to_vec()),
            |batch, path, flags, invalidate| {
                assert!(invalidate);
                batch.push(Event { path, flags, id: current_id() });
            }).unwrap();
        assert_eq!(attrs_batch.len(), 1);
        assert_eq!(attrs_batch[0].flags, MUST_SCAN_SUBDIRS);
        let unresolved = event(libc::FAN_MODIFY, &[record(2, 99, Some(b"unknown-parent"))]);
        let mut recovery = Vec::new();
        translate_buffer(&unresolved, &mut recovery, |_| Err(io::Error::from_raw_os_error(libc::ESTALE)),
            |_, _, _, _| unreachable!()).unwrap();
        translate_buffer(&event(libc::FAN_Q_OVERFLOW, &[]), &mut recovery, |_| unreachable!(),
            |_, _, _, _| unreachable!()).unwrap();
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].path, b"/");
        assert_eq!(recovery[0].flags, MUST_SCAN_SUBDIRS | USER_DROPPED | KERNEL_DROPPED);
        for length in 1..rename.len() {
            assert!(translate_buffer(&rename[..length], &mut Vec::new(), |_| unreachable!(), |_, _, _, _| unreachable!()).is_err());
        }
        let mut malformed = rename;
        malformed[METADATA_LEN + 12..METADATA_LEN + 16].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(translate_buffer(&malformed, &mut Vec::new(), |_| unreachable!(), |_, _, _, _| unreachable!()).is_err());
        let malformed = event(libc::FAN_DELETE, &[record(2, 1, Some(b"unterminated"))]);
        let mut malformed = malformed;
        *malformed.last_mut().unwrap() = b'x';
        assert!(translate_buffer(&malformed, &mut Vec::new(), |_| unreachable!(), |_, _, _, _| unreachable!()).is_err());
        let mut malformed = event(libc::FAN_DELETE, &[record(2, 1, Some(b"bad-size"))]);
        malformed[METADATA_LEN + 2..METADATA_LEN + 4].copy_from_slice(&3u16.to_ne_bytes());
        assert!(translate_buffer(&malformed, &mut Vec::new(), |_| unreachable!(), |_, _, _, _| unreachable!()).is_err());
    }

    #[test]
    fn overwrite_link_count_notices_preserve_named_updates_and_real_loss_recovery() {
        let emit = |batch: &mut Vec<Event>, path, flags, _| batch.push(Event { path, flags, id: current_id() });
        let mut batch = Vec::new();
        let mut bytes = event(libc::FAN_RENAME, &[
            record(1, 3, None), record(10, 1, Some(b"temporary")), record(12, 2, Some(b"victim")),
        ]);
        // The observed overwrite victim notice has no FAN_DELETE counterpart.
        bytes.extend(event(libc::FAN_ATTRIB, &[record(1, 7, None)]));
        translate_buffer(&bytes, &mut batch, |fid| match fid.handle[0] {
            1 => Ok(b"/home/fsearch-replace-old".to_vec()),
            2 => Ok(b"/home/fsearch-replace-new".to_vec()),
            _ => panic!("source and dead replacement victim do not need handle decoding"),
        }, emit).unwrap();
        assert_eq!(batch.len(), 2);
        assert!(batch.iter().any(|e| e.path == b"/home/fsearch-replace-old" && e.flags == 0));
        assert!(batch.iter().any(|e| e.path == b"/home/fsearch-replace-new" && e.flags == 0));

        // Actual file mtime/chmod and directory permissions still invalidate
        // their named context; the link-count fast path cannot swallow them.
        batch.clear();
        translate_buffer(&event(libc::FAN_ATTRIB, &[record(1, 7, None), record(2, 2, Some(b"victim"))]),
            &mut batch, |_| Ok(b"/home/fsearch-replace-new".to_vec()), emit).unwrap();
        assert_eq!(batch[0].path, b"/home/fsearch-replace-new");
        translate_buffer(&event(libc::FAN_ATTRIB | libc::FAN_ONDIR, &[record(2, 2, Some(b"private"))]),
            &mut batch, |_| Ok(b"/home/fsearch-replace-new".to_vec()),
            |batch, path, flags, invalidate| {
                assert!(invalidate);
                batch.push(Event { path, flags, id: current_id() });
            }).unwrap();
        assert_eq!(batch[1].path, b"/home/fsearch-replace-new/private");
        assert_eq!(batch[1].flags, MUST_SCAN_SUBDIRS);

        // Writes and the final close of an open, replaced inode have no
        // remaining namespace entry. Other lookup errors remain failures.
        batch.clear();
        for mask in [libc::FAN_MODIFY, libc::FAN_CLOSE_WRITE] {
            let detached = event(mask, &[record(1, 7, None)]);
            translate_buffer(&detached, &mut batch,
                |_| Err(io::Error::from_raw_os_error(libc::ESTALE)), emit).unwrap();
            assert!(batch.is_empty());
            assert!(translate_buffer(&detached, &mut batch,
                |_| Err(io::Error::from_raw_os_error(libc::ENOMEM)), emit).is_err());
        }
        // A live detached target still resolves and updates its remaining
        // path (for example, a file with another surviving hard link).
        translate_buffer(&event(libc::FAN_MODIFY, &[record(1, 7, None)]), &mut batch,
            |_| Ok(b"/home/fsearch-replace-new/surviving-link".to_vec()), emit).unwrap();
        assert_eq!(batch[0].path, b"/home/fsearch-replace-new");

        // Missing directory identity/context is not ordinary inode churn.
        for broken in [
            event(libc::FAN_ATTRIB | libc::FAN_ONDIR, &[record(2, 9, Some(b"."))]),
            event(libc::FAN_DELETE, &[record(1, 7, None)]),
            event(libc::FAN_MODIFY, &[]),
        ] {
            batch.clear();
            translate_buffer(&broken, &mut batch,
                |_| Err(io::Error::from_raw_os_error(libc::ESTALE)), emit).unwrap();
            assert_eq!(batch[0].path, b"/");
            assert_eq!(batch[0].flags, MUST_SCAN_SUBDIRS | USER_DROPPED);
        }
        batch.clear();
        translate_buffer(&event(libc::FAN_Q_OVERFLOW, &[]), &mut batch,
            |_| unreachable!(), emit).unwrap();
        assert_eq!(batch[0].flags, MUST_SCAN_SUBDIRS | KERNEL_DROPPED);
    }
}
