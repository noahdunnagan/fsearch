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
/// tracked, i.e. while SKIP is set. A set: rescans refuse the same folders
/// again.
pub static DENIED: Mutex<std::collections::BTreeSet<Vec<u8>>> = Mutex::new(std::collections::BTreeSet::new());

pub fn blocked(path: &[u8]) -> bool {
    SKIP.get().is_some_and(|v| v.iter().any(|s| path.starts_with(s) && (path.len() == s.len() || path[s.len()] == b'/')))
}

const ATTR_CMN_ERROR: u32 = 0x2000_0000;
const DIR_MNTSTATUS_TRIGGER: u32 = 0x2;

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_LINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;

/// Entry flag bit: UF_HIDDEN set by the Finder.
pub const FLAG_HIDDEN: u8 = 1 << 2;
/// Directory that is a mount point we did not descend into.
pub const FLAG_MOUNT: u8 = 1 << 3;

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
            e.child = ctx.next_id.fetch_add(1, Ordering::Relaxed);
            kids.push((CString::new(name).unwrap_or_default(), e.child, child_path));
        }
    }
    push(l, ctx);
    for (name, cid, child_path) in kids {
        let parent = me.clone();
        s.spawn(move |s| {
            let fd = unsafe { libc::openat(parent.0, name.as_ptr(), OPEN_DIR) };
            // Read errno before the drop: closing the parent may reset it.
            let refused = fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
            drop(parent);
            if refused && let Some(p) = &child_path {
                DENIED.lock().unwrap().insert(p.clone());
            }
            finish_dir(s, fd, child_path, cid, ctx);
        });
    }
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::AtomicUsize;

    /// A fresh directory under the temp dir, removed on drop. Canonical
    /// (/private/var/..., not /var/...) since the live code compares paths.
    pub(crate) struct Tmp(pub PathBuf);
    impl Tmp {
        pub(crate) fn new(tag: &str) -> Tmp {
            static N: AtomicUsize = AtomicUsize::new(0);
            let base = std::env::temp_dir().canonicalize().unwrap();
            let p = base.join(format!("fsearch-test-{}-{}-{tag}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        pub(crate) fn bytes(&self) -> &[u8] {
            self.0.as_os_str().as_bytes()
        }
        pub(crate) fn p(&self, rel: &str) -> PathBuf {
            assert!(!rel.starts_with('/'), "stay inside the temp dir");
            self.0.join(rel)
        }
        pub(crate) fn b(&self, rel: &str) -> Vec<u8> {
            self.p(rel).as_os_str().as_bytes().to_vec()
        }
        pub(crate) fn file(&self, rel: &str, len: usize) -> PathBuf {
            let p = self.p(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, vec![b'x'; len]).unwrap();
            p
        }
        pub(crate) fn dir(&self, rel: &str) -> PathBuf {
            let p = self.p(rel);
            std::fs::create_dir_all(&p).unwrap();
            p
        }
        pub(crate) fn link(&self, target: &str, rel: &str) -> PathBuf {
            let p = self.p(rel);
            std::os::unix::fs::symlink(target, &p).unwrap();
            p
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            fix_perms(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fix_perms(p: &Path) {
        use std::os::unix::fs::PermissionsExt;
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                let _ = std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(0o755));
                fix_perms(&e.path());
            }
        }
    }

    pub(crate) fn set_hidden(p: &Path) {
        let c = CString::new(p.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chflags(c.as_ptr(), libc::UF_HIDDEN) }, 0);
    }

    fn name<'a>(l: &'a Listing, e: &RawEnt) -> &'a [u8] {
        &l.names[e.name_off as usize..][..e.name_len as usize]
    }

    /// Every scanned entry by path relative to the root.
    fn flatten(ls: &[Listing]) -> BTreeMap<Vec<u8>, RawEnt> {
        let by_id: std::collections::HashMap<u32, &Listing> = ls.iter().map(|l| (l.id, l)).collect();
        let mut out = BTreeMap::new();
        let mut stack = vec![(0u32, Vec::new())];
        while let Some((id, path)) = stack.pop() {
            let l = by_id[&id];
            for e in &l.ents {
                let mut p = path.clone();
                if !p.is_empty() {
                    p.push(b'/');
                }
                p.extend_from_slice(name(l, e));
                if e.child != NONE {
                    stack.push((e.child, p.clone()));
                }
                assert!(out.insert(p, *e).is_none());
            }
        }
        out
    }

    #[test]
    fn scan_tree() {
        let t = Tmp::new("scan");
        t.file("a.txt", 5);
        t.file("sub/b.bin", 3000);
        t.file("sub/deep/c", 0);
        t.dir("empty");
        t.link("sub", "dirlink");
        t.link("loop", "loop");
        t.link("missing-target", "dangling");
        t.file("hid", 1);
        set_hidden(&t.p("hid"));
        t.file("caf\u{e9} \u{1f600}.txt", 2);
        let fifo = CString::new(t.b("fifo")).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);

        let ls = scan(t.bytes(), 3);
        let ids: std::collections::HashSet<u32> = ls.iter().map(|l| l.id).collect();
        assert_eq!(ids.len(), ls.len(), "listing ids unique");
        assert!(ids.contains(&0));
        let all = flatten(&ls);
        let keys: Vec<&[u8]> = all.keys().map(|k| k.as_slice()).collect();
        assert_eq!(
            keys,
            [
                &b"a.txt"[..],
                "caf\u{e9} \u{1f600}.txt".as_bytes(),
                b"dangling",
                b"dirlink",
                b"empty",
                b"fifo",
                b"hid",
                b"loop",
                b"sub",
                b"sub/b.bin",
                b"sub/deep",
                b"sub/deep/c",
            ]
        );
        assert_eq!((all[&b"a.txt"[..]].kind, all[&b"a.txt"[..]].size), (KIND_FILE, 5));
        assert_eq!(all[&b"sub/b.bin"[..]].size, 3000);
        assert_eq!((all[&b"sub"[..]].kind, all[&b"sub"[..]].size), (KIND_DIR, 0));
        assert_eq!(all[&b"empty"[..]].kind, KIND_DIR);
        // Symlinks are entries, never followed (no listing under them).
        for l in [&b"dirlink"[..], b"loop", b"dangling"] {
            assert_eq!((all[l].kind, all[l].child), (KIND_LINK, NONE));
        }
        assert_eq!(all[&b"fifo"[..]].kind, KIND_OTHER);
        assert_eq!(all[&b"hid"[..]].kind, KIND_FILE | FLAG_HIDDEN);
        let empty = ls.iter().find(|l| l.id == all[&b"empty"[..]].child).unwrap();
        assert!(empty.ents.is_empty());
        use std::os::unix::fs::MetadataExt;
        assert_eq!(all[&b"a.txt"[..]].mtime as i64, std::fs::metadata(t.p("a.txt")).unwrap().mtime());
    }

    #[test]
    fn scan_root_not_a_dir() {
        let t = Tmp::new("notdir");
        t.file("f", 1);
        t.dir("real");
        t.link("real", "lnk");
        for root in ["f", "nope", "lnk"] {
            // O_NOFOLLOW: a symlinked root is not followed either.
            let ls = scan(&t.b(root), 1);
            assert_eq!(ls.len(), 1);
            assert_eq!(ls[0].id, 0);
            assert!(ls[0].ents.is_empty());
            assert!(list_one(&t.b(root)).is_none());
        }
        assert!(list_one(b"/no\0nul").is_none());
        assert_eq!(scan(b"/no\0nul", 1).len(), 1);
    }

    #[test]
    fn unreadable_dir_is_listed_empty() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tmp::new("perm");
        t.file("locked/inner", 1);
        // Mode 000 gives EACCES on open (not the TCC EPERM): still an entry,
        // with an empty listing.
        std::fs::set_permissions(t.p("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let ls = scan(t.bytes(), 2);
        let all = flatten(&ls);
        assert_eq!(all.keys().cloned().collect::<Vec<_>>(), [b"locked".to_vec()]);
        let child = all[&b"locked"[..]].child;
        assert!(ls.iter().any(|l| l.id == child && l.ents.is_empty()));
        assert!(list_one(&t.b("locked")).is_none());
    }

    #[test]
    fn list_one_and_big_dirs() {
        let t = Tmp::new("big");
        // Long names so the entries overflow one 256 KiB getattrlistbulk buffer.
        let long = "n".repeat(200);
        for i in 0..2000 {
            std::fs::write(t.p(&format!("{long}{i:05}")), b"").unwrap();
        }
        t.file("sub/x", 1);
        let l = list_one(t.bytes()).unwrap();
        assert_eq!(l.id, 0);
        assert_eq!(l.ents.len(), 2001);
        let sub = l.ents.iter().find(|e| name(&l, e) == b"sub").unwrap();
        assert_eq!((sub.kind, sub.child), (KIND_DIR, NONE));
        assert_eq!(flatten(&scan(t.bytes(), 2)).len(), 2002);
    }

    #[test]
    fn mount_points_flagged_not_crossed() {
        // /System/Volumes holds the APFS volume mounts (Data, VM, ...): one
        // listing of it, no recursion.
        let Some(l) = list_one(b"/System/Volumes") else { return };
        let data = l.ents.iter().find(|e| name(&l, e) == b"Data").expect("Data volume");
        assert_eq!(data.kind & 3, KIND_DIR);
        assert_ne!(data.kind & FLAG_MOUNT, 0);
    }

    #[test]
    fn nothing_blocked_without_skip() {
        assert!(SKIP.get().is_none(), "SKIP is set only in tests/walk_skip.rs");
        assert!(!blocked(b"/Users"));
    }
}
