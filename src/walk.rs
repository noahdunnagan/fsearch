//! Parallel whole-disk enumeration with getattrlistbulk(2) on macOS,
//! getdents64 + fstatat on Linux.
//!
//! One syscall returns hundreds of entries with name, type, size, mtime and
//! flags already attached, so there is no per-file stat. Directories fan out
//! over a rayon pool; mount points are not crossed, firmlinks are (that is
//! how /Users etc. on the data volume appear under / exactly once).
//! On Linux, getdents64 plus fstatat build the same listings. The walker
//! skips mount points by comparing each device id against the scan root.

use rayon::Scope;
use std::cell::RefCell;
use std::ffi::CString;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

pub const NONE: u32 = u32::MAX;

/// Folders never to open: set when the daemon runs without Full Disk
/// Access, where opening a consent-gated folder (Downloads, Desktop, ...)
/// pops a privacy prompt and blocks the call until someone answers it.
/// On Linux it holds pseudo-filesystems like `/proc` and `/sys`. The walker
/// never opens them.
pub static SKIP: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();

pub fn blocked(path: &[u8]) -> bool {
    SKIP.get().is_some_and(|v| v.iter().any(|s| path.starts_with(s) && (path.len() == s.len() || path[s.len()] == b'/')))
}

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_LINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;

/// Entry flag bit: UF_HIDDEN set by the Finder.
pub const FLAG_HIDDEN: u8 = 1 << 2;
/// Directory that is a mount point we did not descend into.
pub const FLAG_MOUNT: u8 = 1 << 3;
/// Graft prefix above the scan root (Linux home-only index). Never set on
/// macOS: only `graft_home_prefix` sets it, which is Linux-only.
pub const FLAG_SYNTH: u8 = 1 << 4;

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
    #[cfg(target_os = "linux")]
    root_dev: u64,
}

thread_local! {
    static BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 256 * 1024]);
}

/// Scan `root` recursively. Listing id 0 is `root` itself.
pub fn scan(root: &[u8], threads: usize) -> Vec<Listing> {
    raise_fd_limit();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).start_handler(|_| crate::no_materialize()).build().unwrap();
    let fd = if blocked(root) { -1 } else { CString::new(root).map_or(-1, |c| unsafe { libc::open(c.as_ptr(), OPEN_DIR) }) };
    #[cfg(target_os = "linux")]
    let (fd, root_dev) = if fd >= 0 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // A failed fstat would zero the dev and disable mount-skip; drop
        // the fd instead of crossing mounts blind.
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            unsafe { libc::close(fd) };
            (-1, 0)
        } else {
            (fd, st.st_dev)
        }
    } else {
        (fd, 0)
    };
    let ctx = Ctx {
        next_id: AtomicU32::new(1),
        out: (0..threads + 1).map(|_| Mutex::new(Vec::new())).collect(),
        #[cfg(target_os = "linux")]
        root_dev,
    };
    // Paths are only tracked when there is something to skip.
    let path = SKIP.get().is_some_and(|v| !v.is_empty()).then(|| root.to_vec());
    pool.scope(|s| finish_dir(s, fd, path, 0, &ctx));
    ctx.out.into_iter().flat_map(|m| m.into_inner().unwrap()).collect()
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
    list_into(path, &mut l).then_some(l)
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
fn finish_dir<'s>(s: &Scope<'s>, fd: i32, path: Option<Vec<u8>>, id: u32, ctx: &'s Ctx) {
    let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
    if fd < 0 {
        push(l, ctx);
        return;
    }
    #[cfg(target_os = "linux")]
    list_fd(fd, &mut l, ctx.root_dev);
    #[cfg(not(target_os = "linux"))]
    list_fd(fd, &mut l);
    let me = std::sync::Arc::new(Fd(fd));

    let mut kids = Vec::new();
    for e in l.ents.iter_mut() {
        if e.kind & 3 == KIND_DIR && e.kind & FLAG_MOUNT == 0 {
            let name = &l.names[e.name_off as usize..e.name_off as usize + e.name_len as usize];
            let child_path = path.as_ref().map(|p| crate::live::join(p, name));
            if child_path.as_deref().is_some_and(blocked) {
                continue;
            }
            let cname = CString::new(name).unwrap_or_default();
            e.child = ctx.next_id.fetch_add(1, Ordering::Relaxed);
            kids.push((cname, e.child, child_path));
        }
    }
    push(l, ctx);
    for (name, cid, child_path) in kids {
        let parent = me.clone();
        s.spawn(move |s| {
            let fd = unsafe { libc::openat(parent.0, name.as_ptr(), OPEN_DIR) };
            drop(parent);
            finish_dir(s, fd, child_path, cid, ctx);
        });
    }
}

fn push(l: Listing, ctx: &Ctx) {
    let slot = rayon::current_thread_index().unwrap_or(ctx.out.len() - 1);
    ctx.out[slot].lock().unwrap().push(l);
}

/// Returns false if the directory could not be opened.
fn list_into(path: &[u8], l: &mut Listing) -> bool {
    let Ok(cpath) = CString::new(path) else { return false };
    let fd = unsafe { libc::open(cpath.as_ptr(), OPEN_DIR) };
    if fd < 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    list_fd(fd, l, 0);
    #[cfg(not(target_os = "linux"))]
    list_fd(fd, l);
    #[cfg(target_os = "linux")]
    {
        // Mount-skip agreement with full scans: a child on another device
        // is a mount point the scan would never descend into.
        let mut pst: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut pst) } == 0 && pst.st_dev != 0 {
            for e in l.ents.iter_mut() {
                if e.kind & 3 != KIND_DIR {
                    continue;
                }
                let name = &l.names[e.name_off as usize..e.name_off as usize + e.name_len as usize];
                let cname = CString::new(name).unwrap_or_default();
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstatat(fd, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0 && st.st_dev != pst.st_dev {
                    e.kind |= FLAG_MOUNT;
                }
            }
        }
    }
    unsafe { libc::close(fd) };
    true
}

#[cfg(target_os = "linux")]
/// Re-root a home scan at `/`. The index builds paths from listing 0 as `/`,
/// so a scan rooted at `$HOME` would index `/proj/...` instead of
/// `$HOME/proj/...` and break lookup, content scope and compact. Synthetic
/// parents hold the home components. The real scan shifts its ids above them.
pub fn graft_home_prefix(mut ls: Vec<Listing>, root: &[u8]) -> Vec<Listing> {
    let comps: Vec<&[u8]> = root.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() {
        return ls;
    }
    let k = comps.len() as u32;
    for l in ls.iter_mut() {
        l.id += k;
        for e in l.ents.iter_mut() {
            if e.child != NONE {
                e.child += k;
            }
        }
    }
    let mut out = Vec::with_capacity(ls.len() + comps.len());
    for (i, comp) in comps.iter().enumerate() {
        let child = if i + 1 < comps.len() { i as u32 + 1 } else { k };
        // Ancestors above home were never listed; flag them so searches skip
        // them. Home itself stays plain: it is the real scan root.
        let kind = if i + 1 < comps.len() { KIND_DIR | FLAG_SYNTH } else { KIND_DIR };
        out.push(Listing {
            id: i as u32,
            names: comp.to_vec(),
            ents: vec![RawEnt { name_off: 0, name_len: comp.len() as u16, kind, size: 0, mtime: 0, child }],
        });
    }
    out.extend(ls);
    out
}

#[cfg(target_os = "linux")]
fn list_fd(fd: i32, l: &mut Listing, root_dev: u64) {
    // Raw getdents64: libc has no wrapper. The reclen field is read in native
    // byte order, matching every architecture Linux runs on.
    BUF.with_borrow_mut(|buf| {
        loop {
            let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            let mut offset = 0;
            let bytes = n as usize;
            while offset < bytes {
                let reclen = u16::from_ne_bytes([buf[offset + 16], buf[offset + 17]]) as usize;
                if reclen == 0 {
                    break;
                }
                let d_type = buf[offset + 18];
                let name_start = offset + 19;
                let mut name_end = name_start;
                while name_end < offset + reclen && buf[name_end] != 0 {
                    name_end += 1;
                }
                let name = &buf[name_start..name_end];
                if !(name == b"." || name == b"..") {
                    parse_entry_linux(fd, name, d_type, l, root_dev);
                }
                offset += reclen;
            }
        }
    });
}

#[cfg(target_os = "linux")]
fn parse_entry_linux(fd: i32, name: &[u8], d_type: u8, l: &mut Listing, root_dev: u64) {
    let mut kind = match d_type {
        libc::DT_REG => KIND_FILE,
        libc::DT_DIR => KIND_DIR,
        libc::DT_LNK => KIND_LINK,
        _ => KIND_OTHER,
    };

    let cname = CString::new(name).unwrap_or_default();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatat(fd, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
    if ret == 0 && d_type == libc::DT_UNKNOWN {
        kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => KIND_FILE,
            libc::S_IFDIR => KIND_DIR,
            libc::S_IFLNK => KIND_LINK,
            _ => KIND_OTHER,
        };
    }
    // Mount points never descend: the fstatat above already statted the
    // child, so compare its device against the scan root here instead of
    // statting twice. Live updates agree through list_into's post-pass.
    if ret == 0 && root_dev != 0 && kind == KIND_DIR && st.st_dev != root_dev {
        kind |= FLAG_MOUNT;
    }

    let mut mtime = 0u32;
    let mut size = 0u64;
    if ret == 0 {
        mtime = (st.st_mtime as i64).clamp(0, u32::MAX as i64) as u32;
        size = st.st_size as u64;
    }

    if name.is_empty() || name.len() > u16::MAX as usize {
        return;
    }
    l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, size, mtime, child: NONE });
    l.names.extend_from_slice(name);
}

#[cfg(target_os = "macos")]
const ATTR_CMN_ERROR: u32 = 0x2000_0000;
#[cfg(target_os = "macos")]
const DIR_MNTSTATUS_TRIGGER: u32 = 0x2;

#[cfg(target_os = "macos")]
fn rd32(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

#[cfg(target_os = "macos")]
fn rd64(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(b[at..at + 8].try_into().unwrap())
}

#[cfg(target_os = "macos")]
fn list_fd(fd: i32, l: &mut Listing) {
    let mut al: libc::attrlist = unsafe { std::mem::zeroed() };
    al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    al.commonattr =
        libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_NAME | ATTR_CMN_ERROR | libc::ATTR_CMN_OBJTYPE | libc::ATTR_CMN_MODTIME | libc::ATTR_CMN_FLAGS;
    al.dirattr = libc::ATTR_DIR_MOUNTSTATUS;
    al.fileattr = libc::ATTR_FILE_DATALENGTH;
    BUF.with_borrow_mut(|buf| {
        loop {
            let n = unsafe { libc::getattrlistbulk(fd, &mut al as *mut _ as *mut libc::c_void, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                break;
            }
            let mut p = 0usize;
            for _ in 0..n {
                let len = rd32(buf, p) as usize;
                parse_entry(&buf[p..p + len], l);
                p += len;
            }
        }
    });
}

#[cfg(target_os = "macos")]
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
    if common & libc::ATTR_CMN_FLAGS != 0 {
        if rd32(b, f) & libc::UF_HIDDEN != 0 {
            kind |= FLAG_HIDDEN;
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn listing(id: u32, entries: &[(&[u8], u8, u32)]) -> Listing {
        let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
        for (name, kind, child) in entries {
            l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind: *kind, size: 0, mtime: 0, child: *child });
            l.names.extend_from_slice(name);
        }
        l
    }

    #[test]
    fn graft_roots_home_at_slash() {
        let scan = vec![listing(0, &[(b"proj", KIND_DIR, 1)]), listing(1, &[(b"main.rs", KIND_FILE, NONE)])];
        let out = graft_home_prefix(scan, b"/home/alice");
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].id, 0);
        assert_eq!(out[1].id, 1);
        assert_eq!(out[2].id, 2);
        let by_id: std::collections::HashMap<u32, &Listing> = out.iter().map(|l| (l.id, l)).collect();
        for l in &out {
            for e in &l.ents {
                if e.child != NONE {
                    assert!(by_id.contains_key(&e.child), "dangling child id");
                }
            }
        }
        assert_eq!(&by_id[&2].names[by_id[&2].ents[0].name_off as usize..][..by_id[&2].ents[0].name_len as usize], b"proj");
    }

    #[test]
    fn graft_root_slash_is_identity() {
        let scan = vec![listing(0, &[(b"etc", KIND_DIR, NONE)])];
        let out = graft_home_prefix(scan, b"/");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, 0);
    }

    #[test]
    fn graft_flags_prefix_not_home() {
        let scan = vec![listing(0, &[(b"proj", KIND_DIR, NONE)])];
        let out = graft_home_prefix(scan, b"/tmp/h/h1");
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].ents[0].kind & FLAG_SYNTH, FLAG_SYNTH);
        assert_eq!(out[1].ents[0].kind & FLAG_SYNTH, FLAG_SYNTH);
        assert_eq!(out[2].ents[0].kind & FLAG_SYNTH, 0);
    }
}
