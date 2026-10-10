//! Parallel whole-disk enumeration with getattrlistbulk(2).
//!
//! One syscall returns hundreds of entries with name, type, size, mtime and
//! flags already attached, so there is no per-file stat. Directories fan out
//! over a rayon pool; mount points are not crossed, firmlinks are (that is
//! how /Users etc. on the data volume appear under / exactly once).

use rayon::Scope;
use std::cell::RefCell;
use std::ffi::CString;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

pub const NONE: u32 = u32::MAX;

/// Folders never to open: set when the daemon runs without Full Disk
/// Access, where opening a consent-gated folder (Downloads, Desktop, ...)
/// pops a privacy prompt and blocks the call until someone answers it.
pub static SKIP: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();

/// Folders a scan was refused (EPERM): without Full Disk Access macOS also
/// silently denies some, like ~/Library/Mail. Recorded only while paths are
/// tracked, i.e. while SKIP is set.
pub static DENIED: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

pub fn blocked(path: &[u8]) -> bool {
    SKIP.get().is_some_and(|v| v.iter().any(|s| path.starts_with(s) && (path.len() == s.len() || path[s.len()] == b'/')))
}

const ATTR_CMN_ERROR: u32 = 0x2000_0000;
const DIR_MNTSTATUS_TRIGGER: u32 = 0x2;
const SF_FIRMLINK: u32 = 0x0080_0000;

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_LINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;

/// Entry flag bit: UF_HIDDEN set by the Finder.
pub const FLAG_HIDDEN: u8 = 1 << 2;
/// Directory that is a mount point we did not descend into.
pub const FLAG_MOUNT: u8 = 1 << 3;
/// Only while a listing is parsed: a directory its parent reports empty.
/// Firmlinks report 0 too (their entries live on the data volume), so they
/// never get it; grafts (MobileAsset images) do, so `finish_dir` checks.
const MAYBE_EMPTY: u8 = 1 << 7;

#[derive(Clone, Copy)]
pub struct RawEnt {
    pub name_off: u32,
    pub name_len: u16,
    /// kind in the low 2 bits, FLAG_* above.
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
    /// Temp id of the listing for this directory, or NONE.
    pub child: u32,
}

pub struct Listing {
    pub id: u32,
    pub names: Vec<u8>,
    pub ents: Vec<RawEnt>,
}

struct Ctx {
    next_id: AtomicU32,
    out: Vec<Mutex<Vec<Listing>>>,
}

thread_local! {
    static BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 256 * 1024]);
}

/// Scan `root` recursively. Listing id 0 is `root` itself.
pub fn scan(root: &[u8], threads: usize) -> Vec<Listing> {
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).start_handler(|_| crate::no_materialize()).build().unwrap();
    let ctx = Ctx { next_id: AtomicU32::new(1), out: (0..threads + 1).map(|_| Mutex::new(Vec::new())).collect() };
    raise_fd_limit();
    let fd = if blocked(root) { -1 } else { CString::new(root).map_or(-1, |c| unsafe { libc::open(c.as_ptr(), OPEN_DIR) }) };
    // Paths are only tracked when there is something to skip.
    let path = SKIP.get().is_some_and(|v| !v.is_empty()).then(|| root.to_vec());
    pool.scope(|s| finish_dir(s, fd, path, 0, &ctx));
    let parts: Vec<Vec<Listing>> = ctx.out.into_iter().map(|m| m.into_inner().unwrap()).collect();
    let mut out = Vec::with_capacity(parts.iter().map(Vec::len).sum());
    for p in parts {
        out.extend(p);
    }
    out
}

fn raise_fd_limit() {
    let mut r: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) };
    r.rlim_cur = r.rlim_max.min(65536);
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) };
}

/// List a single directory (no recursion). Subdirectories come back with
/// `child == NONE`. Used by the live updater.
pub fn list_one(path: &[u8]) -> Option<Listing> {
    if blocked(path) {
        return None;
    }
    let mut l = Listing { id: 0, names: Vec::new(), ents: Vec::new() };
    if !list_into(path, &mut l) {
        return None;
    }
    for e in &mut l.ents {
        e.kind &= !MAYBE_EMPTY;
    }
    Some(l)
}

const OPEN_DIR: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Directory fd shared by the tasks that still need to openat() a child.
struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

// Children are opened with openat() relative to the parent's fd, so paths
// never get rebuilt and PATH_MAX never bites. Measured on this Mac: open() +
// close() is ~19us per directory (two Endpoint Security clients tax every
// open), getattrlistbulk ~14us; past ~8 threads the kernel side stops scaling.
// 18% of directories are empty: those the parent's listing already says
// so (rechecked with one lookup) are never opened.
fn finish_dir<'s>(s: &Scope<'s>, fd: i32, path: Option<Vec<u8>>, id: u32, ctx: &'s Ctx) {
    let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
    if fd < 0 {
        push(l, ctx);
        return;
    }
    list_fd(fd, &mut l);
    let me = std::sync::Arc::new(Fd(fd));
    let mut kids = Vec::new();
    let mut empty = Vec::new();
    for e in l.ents.iter_mut() {
        let maybe_empty = e.kind & MAYBE_EMPTY != 0;
        e.kind &= !MAYBE_EMPTY;
        if e.kind & 3 == KIND_DIR && e.kind & FLAG_MOUNT == 0 {
            let name = &l.names[e.name_off as usize..e.name_off as usize + e.name_len as usize];
            let child_path = path.as_ref().map(|p| crate::live::join(p, name));
            if child_path.as_deref().is_some_and(blocked) {
                continue;
            }
            e.child = ctx.next_id.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(name).unwrap_or_default();
            // (With paths tracked, opening is how refusals get recorded.)
            if maybe_empty && child_path.is_none() && entry_count(fd, &name) == Some(0) {
                empty.push(e.child);
            } else {
                kids.push((name, e.child, child_path));
            }
        }
    }
    push(l, ctx);
    for id in empty {
        push(Listing { id, names: Vec::new(), ents: Vec::new() }, ctx);
    }
    for (name, cid, child_path) in kids {
        let parent = me.clone();
        s.spawn(move |s| {
            let fd = unsafe { libc::openat(parent.0, name.as_ptr(), OPEN_DIR) };
            drop(parent);
            if fd < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
                && let Some(p) = &child_path
            {
                DENIED.lock().unwrap().push(p.clone());
            }
            finish_dir(s, fd, child_path, cid, ctx);
        });
    }
}

/// Entries in the directory `name` (in `dir`) resolves to.
fn entry_count(dir: i32, name: &CString) -> Option<u32> {
    let mut al: libc::attrlist = unsafe { std::mem::zeroed() };
    al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    al.dirattr = libc::ATTR_DIR_ENTRYCOUNT;
    let mut b = [0u32; 2];
    let r = unsafe { libc::getattrlistat(dir, name.as_ptr(), (&raw mut al).cast(), b.as_mut_ptr().cast(), 8, libc::FSOPT_NOFOLLOW as _) };
    (r == 0).then_some(b[1])
}

fn push(l: Listing, ctx: &Ctx) {
    let slot = rayon::current_thread_index().unwrap_or(ctx.out.len() - 1);
    ctx.out[slot].lock().unwrap().push(l);
}

fn rd32(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

fn rd64(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

/// Returns false if the directory could not be opened.
fn list_into(path: &[u8], l: &mut Listing) -> bool {
    let Ok(cpath) = CString::new(path) else { return false };
    let fd = unsafe { libc::open(cpath.as_ptr(), OPEN_DIR) };
    if fd < 0 {
        return false;
    }
    list_fd(fd, l);
    unsafe { libc::close(fd) };
    true
}

fn list_fd(fd: i32, l: &mut Listing) {
    let mut al: libc::attrlist = unsafe { std::mem::zeroed() };
    al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    al.commonattr =
        libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_NAME | ATTR_CMN_ERROR | libc::ATTR_CMN_OBJTYPE | libc::ATTR_CMN_MODTIME | libc::ATTR_CMN_FLAGS;
    al.dirattr = libc::ATTR_DIR_ENTRYCOUNT | libc::ATTR_DIR_MOUNTSTATUS;
    al.fileattr = libc::ATTR_FILE_DATALENGTH;
    BUF.with_borrow_mut(|buf| {
        loop {
            let n = unsafe { libc::getattrlistbulk(fd, &mut al as *mut _ as *mut libc::c_void, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                break;
            }
            // Size the listing exactly: 8M entries' worth of growth slack
            // would be ~150 MB at the scan's peak.
            let (mut p, mut bytes) = (0usize, 0usize);
            for _ in 0..n {
                let (b, common) = (&buf[p..], rd32(buf, p + 4));
                if common & libc::ATTR_CMN_NAME != 0 {
                    let f = if common & ATTR_CMN_ERROR != 0 { 28 } else { 24 };
                    bytes += (rd32(b, f + 4) as usize).saturating_sub(1);
                }
                p += rd32(b, 0) as usize;
            }
            l.ents.reserve_exact(n as usize);
            l.names.reserve_exact(bytes);
            let mut p = 0usize;
            for _ in 0..n {
                let len = rd32(buf, p) as usize;
                parse_entry(&buf[p..p + len], l);
                p += len;
            }
        }
    });
}

fn parse_entry(b: &[u8], l: &mut Listing) {
    let common = rd32(b, 4);
    let dirattr = rd32(b, 12);
    let fileattr = rd32(b, 16);
    let mut f = 24;
    if common & ATTR_CMN_ERROR != 0 {
        f += 4;
    }
    if common & libc::ATTR_CMN_NAME == 0 {
        return;
    }
    let off = rd32(b, f) as i32 as isize;
    let nlen = rd32(b, f + 4) as usize;
    let start = (f as isize + off) as usize;
    let name = &b[start..start + nlen.saturating_sub(1)];
    f += 8;
    let mut kind = KIND_OTHER;
    if common & libc::ATTR_CMN_OBJTYPE != 0 {
        kind = match rd32(b, f) {
            1 => KIND_FILE,
            2 => KIND_DIR,
            5 => KIND_LINK,
            _ => KIND_OTHER,
        };
        f += 4;
    }
    let mut mtime = 0u32;
    if common & libc::ATTR_CMN_MODTIME != 0 {
        mtime = (rd64(b, f) as i64).clamp(0, u32::MAX as i64) as u32;
        f += 16;
    }
    let mut flags = 0;
    if common & libc::ATTR_CMN_FLAGS != 0 {
        flags = rd32(b, f);
        if flags & libc::UF_HIDDEN != 0 {
            kind |= FLAG_HIDDEN;
        }
        f += 4;
    }
    if dirattr & libc::ATTR_DIR_ENTRYCOUNT != 0 {
        if rd32(b, f) == 0 && flags & SF_FIRMLINK == 0 {
            kind |= MAYBE_EMPTY;
        }
        f += 4;
    }
    if dirattr & libc::ATTR_DIR_MOUNTSTATUS != 0 {
        if rd32(b, f) & (libc::DIR_MNTSTATUS_MNTPOINT | DIR_MNTSTATUS_TRIGGER) != 0 {
            kind |= FLAG_MOUNT;
        }
        f += 4;
    }
    let mut size = 0u64;
    if fileattr & libc::ATTR_FILE_DATALENGTH != 0 {
        size = rd64(b, f);
    }
    if name.is_empty() || name.len() > u16::MAX as usize {
        return;
    }
    l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, size, mtime, child: NONE });
    l.names.extend_from_slice(name);
}
