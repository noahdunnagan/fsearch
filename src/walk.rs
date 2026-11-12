//! Parallel whole-disk enumeration with getattrlistbulk(2).
//!
//! One syscall returns hundreds of entries with name, type, size, mtime and
//! flags already attached, so there is no per-file stat. Directories fan out
//! over a rayon pool; mount points are not crossed, firmlinks are (that is
//! how /Users etc. on the data volume appear under / exactly once).

use rayon::Scope;
use std::cell::RefCell;
use std::collections::HashSet;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};

pub const NONE: u32 = u32::MAX;

/// Folders never to open: consent-gated ones when the daemon runs without
/// Full Disk Access (opening one pops a privacy prompt and blocks the call
/// until someone answers it). `LAZY` folders are indexed but their
/// changes applied in batches; `SKIP` ones are never opened.
pub static SKIP: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();

/// Churn folders whose contents are indexed like everything else, but
/// whose changes batch until quiet (see `LazyDirs` and engine's `Lazy`).
/// `~` is the user's home.
#[rustfmt::skip]
const LAZY_PREFIXES: &[&str] = &[
    "~/.cache", "~/Library/Caches", "~/Library/Logs", "~/.Trash", "~/.npm",
    "~/.cargo/registry", "~/.gradle/caches",
    "~/Library/Developer/Xcode/DerivedData", "~/Library/Developer/CoreSimulator",
    "/private/var", "/private/tmp", "/Library/Caches",
];

/// Folder names lazy wherever they appear. (.git is deliberately not one:
/// its contents feed git status refreshes and info/exclude lookups.)
const LAZY_NAMES: &[&str] = &["node_modules", "__pycache__"];

/// A folder holding a regular file with this name declares itself a cache
/// (cargo writes one into target/): lazy wherever it is.
const CACHE_TAG: &[u8] = b"CACHEDIR.TAG";

/// The folders whose changes are applied lazily, learned from the
/// defaults and from CACHEDIR.TAG files found while crawling.
/// FSEARCH_NO_LAZY turns the defaults off.
pub static LAZY: std::sync::OnceLock<LazyDirs> = std::sync::OnceLock::new();

pub struct LazyDirs {
    /// Absolute paths (normalized, no trailing '/').
    prefixes: Vec<Vec<u8>>,
    /// Basenames lazy wherever they appear ("node_modules").
    names: Vec<Vec<u8>>,
    /// Folders found holding a CACHEDIR.TAG, in crawl or live listings.
    pub cachedir: RwLock<HashSet<Vec<u8>>>,
    /// CACHEDIR.TAG marking is on (off with the defaults).
    cache_dirs: bool,
}

/// `p` as an absolute normalized path: `~` and bare names are home-relative.
pub(crate) fn expand(p: &[u8], home: &[u8]) -> Vec<u8> {
    let p = match p.strip_prefix(b"~") {
        Some(rest) => [home, rest].concat(),
        None if p.starts_with(b"/") => p.to_vec(),
        None => crate::live::join(home, p),
    };
    crate::live::normalize(&p)
}

impl LazyDirs {
    /// The lazy set: the defaults above, unless `no_lazy` (FSEARCH_NO_LAZY).
    pub fn build(home: &[u8], no_lazy: bool) -> LazyDirs {
        LazyDirs {
            prefixes: if no_lazy { Vec::new() } else { LAZY_PREFIXES.iter().map(|p| expand(p.as_bytes(), home)).collect() },
            names: if no_lazy { Vec::new() } else { LAZY_NAMES.iter().map(|n| n.as_bytes().to_vec()).collect() },
            cachedir: RwLock::new(HashSet::new()),
            cache_dirs: !no_lazy,
        }
    }

    /// Anything lazy at all: if not, LAZY stays unset.
    pub fn used(&self) -> bool {
        !self.prefixes.is_empty() || !self.names.is_empty() || self.cache_dirs
    }

    /// Forget CACHEDIR dirs whose tag file is gone: a folder that lost its
    /// tag (or was deleted) stops being a lazy unit. Costly — compaction
    /// calls this, nothing else.
    pub fn prune(&self) {
        let mut set = self.cachedir.write().unwrap();
        set.retain(|p| {
            let tag = [p.as_slice(), b"/", CACHE_TAG].concat();
            std::fs::symlink_metadata(std::ffi::OsStr::from_bytes(&tag)).is_ok_and(|m| m.is_file())
        });
    }

    /// The unit a lazy path's changes batch under, as its length within
    /// `path`: a lazy prefix plus one more component (the prefix itself
    /// when the event is on it), else the topmost lazy-name or CACHEDIR
    /// dir on the path.
    pub fn unit(&self, path: &[u8]) -> Option<usize> {
        for p in &self.prefixes {
            if path.starts_with(p.as_slice()) && (path.len() == p.len() || path[p.len()] == b'/') {
                if path.len() == p.len() {
                    return Some(p.len());
                }
                let r = &path[p.len() + 1..];
                return Some(match r.iter().position(|&b| b == b'/') {
                    Some(i) => p.len() + 1 + i,
                    None => path.len(),
                });
            }
        }
        let set = self.cachedir.read().unwrap();
        let mut i = 0usize;
        while i < path.len() {
            let start = if path[i] == b'/' { i + 1 } else { i };
            if start >= path.len() {
                break;
            }
            let end = path[start..].iter().position(|&b| b == b'/').map_or(path.len(), |p| start + p);
            if self.names.iter().any(|n| &path[start..end] == n.as_slice()) || (!set.is_empty() && set.contains(&path[..end])) {
                return Some(end);
            }
            i = end;
        }
        None
    }
}

/// Folders a scan was refused (EPERM): without Full Disk Access macOS also
/// silently denies some, like ~/Library/Mail. Recorded only while paths are
/// tracked, i.e. while SKIP is set.
pub static DENIED: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// Entries the first run's whole-disk crawl has listed so far.
pub static LISTED: AtomicUsize = AtomicUsize::new(0);

/// Work a search is waiting on (listing or reading one folder): while any
/// runs, background work (the whole-disk crawl, content builds) waits in
/// `yield_to_searches`, so the search gets the cores and the kernel to
/// itself (they are bound by the same per-file kernel costs).
static HOLD: AtomicUsize = AtomicUsize::new(0);

/// Holds background work off while it lives (see `HOLD`).
pub struct Hold(());

impl Hold {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Hold {
        HOLD.fetch_add(1, Ordering::Relaxed);
        Hold(())
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        HOLD.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Background work's turn: wait while a `Hold` lives, but at most 2 s, so
/// searches back to back never stall it for good.
pub fn yield_to_searches() {
    let t = std::time::Instant::now();
    while HOLD.load(Ordering::Relaxed) > 0 && t.elapsed() < std::time::Duration::from_secs(2) {
        std::thread::sleep(std::time::Duration::from_micros(500));
    }
}

pub fn blocked(path: &[u8]) -> bool {
    SKIP.get().is_some_and(|s| s.iter().any(|s| path.starts_with(s.as_slice()) && (path.len() == s.len() || path[s.len()] == b'/')))
}

/// A folder holding a regular file named CACHEDIR.TAG is a cache wherever
/// it sits: remember it so its changes are applied lazily — and forget it
/// the day a listing of it no longer holds the tag.
fn learn_cachedir(path: Option<&[u8]>, l: &Listing) {
    if !LAZY.get().is_some_and(|s| s.cache_dirs) {
        return;
    }
    let tagged =
        l.ents.iter().any(|e| e.kind & 3 == KIND_FILE && &l.names[e.name_off as usize..e.name_off as usize + e.name_len as usize] == CACHE_TAG);
    let Some(p) = path else { return };
    let set = &LAZY.get().unwrap().cachedir;
    if tagged {
        set.write().unwrap().insert(p.to_vec());
    } else if set.read().unwrap().contains(p) {
        set.write().unwrap().remove(p);
    }
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

#[derive(Default)]
pub struct Listing {
    pub id: u32,
    pub names: Vec<u8>,
    pub ents: Vec<RawEnt>,
}

struct Ctx {
    next_id: AtomicU32,
    out: Vec<Mutex<Vec<Listing>>>,
    /// The whole-disk crawl: counts LISTED, yields to searches.
    disk: bool,
}

thread_local! {
    static BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 256 * 1024]);
}

/// Scan `root` recursively. Listing id 0 is `root` itself.
pub fn scan(root: &[u8], threads: usize) -> Vec<Listing> {
    scan_with(root, threads, false)
}

/// The first run's crawl of the whole disk (see `LISTED`, `HOLD`).
pub fn scan_disk(threads: usize) -> Vec<Listing> {
    scan_with(b"/", threads, true)
}

fn scan_with(root: &[u8], threads: usize, disk: bool) -> Vec<Listing> {
    raise_fd_limit();
    let fd = if blocked(root) { -1 } else { CString::new(root).map_or(-1, |c| unsafe { libc::open(c.as_ptr(), OPEN_DIR) }) };
    // Paths are only tracked when there is something to skip or to learn
    // (a CACHEDIR.TAG needs its folder's path).
    let path = (SKIP.get().is_some() || LAZY.get().is_some()).then(|| root.to_vec());
    let mut l = Listing { id: 0, names: Vec::new(), ents: Vec::new() };
    if fd >= 0 {
        if disk {
            yield_to_searches();
        }
        list_fd(fd, &mut l);
        learn_cachedir(path.as_deref(), &l);
    }
    // A folder holding no folder (most new ones) needs no pool: its threads
    // cost ~120 us of CPU a scan, most of what a burst of new folders costs.
    if !l.ents.iter().any(|e| e.kind & 3 == KIND_DIR && e.kind & FLAG_MOUNT == 0) {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        for e in &mut l.ents {
            e.kind &= !MAYBE_EMPTY;
        }
        if disk {
            LISTED.fetch_add(l.ents.len(), Ordering::Relaxed);
        }
        return vec![l];
    }
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).start_handler(|_| crate::no_materialize()).build().unwrap();
    let ctx = Ctx { next_id: AtomicU32::new(1), out: (0..threads + 1).map(|_| Mutex::new(Vec::new())).collect(), disk };
    pool.scope(|s| descend(s, fd, path, l, &ctx));
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
    learn_cachedir(Some(path), &l);
    for e in &mut l.ents {
        e.kind &= !MAYBE_EMPTY;
    }
    Some(l)
}

// O_NOFOLLOW only checks the last component of a full path; O_NOFOLLOW_ANY
// refuses a link anywhere in it. It needs macOS 11, so Apple Silicon only.
#[cfg(target_arch = "aarch64")]
pub(crate) const NOFOLLOW: i32 = libc::O_NOFOLLOW_ANY;
#[cfg(not(target_arch = "aarch64"))]
pub(crate) const NOFOLLOW: i32 = libc::O_NOFOLLOW;

const OPEN_DIR: i32 = libc::O_RDONLY | libc::O_DIRECTORY | NOFOLLOW | libc::O_CLOEXEC;

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
    if ctx.disk {
        yield_to_searches();
    }
    list_fd(fd, &mut l);
    learn_cachedir(path.as_deref(), &l);
    descend(s, fd, path, l, ctx);
}

/// Push `l`, the listing of `fd`, and scan its folders.
fn descend<'s>(s: &Scope<'s>, fd: i32, path: Option<Vec<u8>>, mut l: Listing, ctx: &'s Ctx) {
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

/// Is the folder at `path` a mount point, as a listing of its parent flags
/// one (FLAG_MOUNT)?
pub fn is_mount(path: &[u8]) -> bool {
    let Ok(c) = CString::new(path) else { return false };
    let mut al: libc::attrlist = unsafe { std::mem::zeroed() };
    al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    al.dirattr = libc::ATTR_DIR_MOUNTSTATUS;
    let mut b = [0u32; 2];
    let r = unsafe { libc::getattrlist(c.as_ptr(), (&raw mut al).cast(), b.as_mut_ptr().cast(), 8, libc::FSOPT_NOFOLLOW as _) };
    r == 0 && b[1] & (libc::DIR_MNTSTATUS_MNTPOINT | DIR_MNTSTATUS_TRIGGER) != 0
}

fn push(l: Listing, ctx: &Ctx) {
    if ctx.disk {
        LISTED.fetch_add(l.ents.len(), Ordering::Relaxed);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Lazy units: a lazy prefix plus one component (the prefix itself
    /// when the event is on it), the topmost lazy-name or CACHEDIR dir,
    /// and nothing at all for ordinary paths.
    #[test]
    fn lazy_units() {
        let s = LazyDirs::build(b"/home/u", false);
        fn unit<'a>(s: &LazyDirs, p: &'a [u8]) -> Option<&'a [u8]> {
            s.unit(p).map(|n| &p[..n])
        }
        assert_eq!(unit(&s, b"/private/var/folders/zz/x"), Some(&b"/private/var/folders"[..]));
        assert_eq!(unit(&s, b"/private/var"), Some(&b"/private/var"[..]));
        assert_eq!(unit(&s, b"/home/u/.cache/foo/deep"), Some(&b"/home/u/.cache/foo"[..]));
        assert_eq!(unit(&s, b"/a/b/node_modules/c/d"), Some(&b"/a/b/node_modules"[..]));
        assert_eq!(unit(&s, b"/a/b/node_modules"), Some(&b"/a/b/node_modules"[..]));
        assert_eq!(unit(&s, b"/x/__pycache__/m"), Some(&b"/x/__pycache__"[..]));
        // .git is not lazy: git status refreshes read its entries.
        assert_eq!(unit(&s, b"/a/b/.git/x"), None);
        assert!(unit(&s, b"/usr/lib").is_none() && unit(&s, b"/home/u/Documents/x").is_none());
        // A name inside a lazy prefix: the prefix unit (topmost) wins.
        assert_eq!(unit(&s, b"/private/var/x/node_modules/y"), Some(&b"/private/var/x"[..]));
        // A name nested in a name: the outer one is the unit.
        assert_eq!(unit(&s, b"/a/node_modules/x/node_modules/y"), Some(&b"/a/node_modules"[..]));
        // A learned CACHEDIR dir, and the topmost one of two.
        s.cachedir.write().unwrap().insert(b"/cc/target".to_vec());
        s.cachedir.write().unwrap().insert(b"/cc/target/inner".to_vec());
        assert_eq!(unit(&s, b"/cc/target/deep/d"), Some(&b"/cc/target"[..]));
        assert_eq!(unit(&s, b"/cc/target"), Some(&b"/cc/target"[..]));
        assert_eq!(unit(&s, b"/cc/other"), None);
        // FSEARCH_NO_LAZY: nothing is lazy.
        let s = LazyDirs::build(b"/home/u", true);
        assert!(!s.used() && s.unit(b"/home/u/.cache/x").is_none() && s.unit(b"/a/node_modules/x").is_none());
    }

    /// A scan over a temp tree: CACHEDIR.TAG and node_modules children
    /// are indexed (nothing is skipped), and the tagged folder is learned.
    #[test]
    fn lazy_dirs_index_their_children() {
        // Under the ignored target/, not the temp dir: /var is a symlink
        // (O_NOFOLLOW_ANY refuses it) and /private/var a lazy prefix.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(format!("fsearch-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("cache/deep")).unwrap();
        std::fs::write(root.join("cache/CACHEDIR.TAG"), b"tag").unwrap();
        std::fs::write(root.join("cache/deep/f.rs"), b"x").unwrap();
        std::fs::create_dir_all(root.join("proj/node_modules/pkg")).unwrap();
        std::fs::write(root.join("proj/node_modules/pkg/index.js"), b"x").unwrap();
        std::fs::write(root.join("proj/app.rs"), b"x").unwrap();
        // SKIP/LAZY are per-process OnceLocks; this config also carries
        // the engine tests' prefix so whichever set wins keeps theirs.
        let _ = SKIP.set(vec![b"/nonexistent-fsearch-skip".to_vec()]);
        let _ = LAZY.set(LazyDirs::build(b"/h", false));
        let r = root.to_str().unwrap().as_bytes();
        let ls = scan(r, 2);
        let mut paths = Vec::new();
        crate::live::for_each_path(&ls, r, |p, _| paths.push(p));
        let has = |suffix: &[u8]| paths.iter().any(|p| p.ends_with(suffix));
        assert!(has(b"/CACHEDIR.TAG") && has(b"/deep") && has(b"/index.js") && has(b"/app.rs"));
        // The tagged folder was learned: paths beneath it are lazy.
        let tagged = [r, b"/cache"].concat();
        assert!(LAZY.get().unwrap().cachedir.read().unwrap().contains(&tagged.to_vec()));
        assert_eq!(LAZY.get().unwrap().unit(&[tagged.as_slice(), b"/x"].concat()), Some(tagged.len()));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A folder whose listing loses its CACHEDIR.TAG is forgotten (and one
    /// that gains it is learned); `prune` drops tags gone from disk.
    #[test]
    fn cachedir_is_forgotten() {
        let s = LazyDirs::build(b"/h", false);
        let mut l = Listing {
            id: 0,
            names: b"CACHEDIR.TAG".to_vec(),
            ents: vec![RawEnt { name_off: 0, name_len: 12, kind: KIND_FILE, size: 0, mtime: 0, child: NONE }],
        };
        // Learned when the tag is listed, forgotten when it isn't.
        let _ = LAZY.set(LazyDirs::build(b"/h", false));
        learn_cachedir(Some(b"/x"), &l);
        assert!(LAZY.get().unwrap().cachedir.read().unwrap().contains(b"/x".as_slice()));
        l.ents.clear();
        learn_cachedir(Some(b"/x"), &l);
        assert!(!LAZY.get().unwrap().cachedir.read().unwrap().contains(b"/x".as_slice()));
        // prune() keeps a tag that exists and drops one that is gone.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(format!("fsearch-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("CACHEDIR.TAG"), b"tag").unwrap();
        let p = root.to_str().unwrap().as_bytes().to_vec();
        s.cachedir.write().unwrap().insert(p.clone());
        s.cachedir.write().unwrap().insert(b"/gone".to_vec());
        s.prune();
        {
            let set = s.cachedir.read().unwrap();
            assert!(set.contains(&p) && !set.contains(b"/gone".as_slice()));
        }
        std::fs::remove_file(root.join("CACHEDIR.TAG")).unwrap();
        s.prune();
        assert!(s.cachedir.read().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}
