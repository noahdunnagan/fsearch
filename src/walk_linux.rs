//! Native parallel Linux enumeration. Only local filesystems with live FID
//! support are traversed; permissions are checked using the ordinary user's
//! real credentials even when the service has DAC capabilities.

use rayon::Scope;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, OnceLock};
use parking_lot::Mutex;

pub const NONE: u32 = u32::MAX;
pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_LINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;
pub const FLAG_HIDDEN: u8 = 1 << 2;
pub const FLAG_MOUNT: u8 = 1 << 3;
pub static SKIP: OnceLock<Vec<Vec<u8>>> = OnceLock::new();

#[derive(Clone, Copy)]
pub struct RawEnt {
    pub name_off: u32,
    pub name_len: u16,
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
    pub child: u32,
}

pub struct Listing {
    pub id: u32,
    pub names: Vec<u8>,
    pub ents: Vec<RawEnt>,
}

const EXCLUDED: &[&[u8]] = &[
    b"/proc", b"/sys", b"/dev", b"/run", b"/tmp", b"/boot",
    b"/var/cache", b"/var/tmp", b"/var/log", b"/var/spool", b"/lost+found",
];

fn beneath(path: &[u8], root: &[u8]) -> bool {
    path.starts_with(root) && (root == b"/" || path.len() == root.len() || path.get(root.len()) == Some(&b'/'))
}

fn explicitly_blocked(path: &[u8]) -> bool {
    EXCLUDED.iter().any(|p| beneath(path, p))
        || SKIP.get().is_some_and(|v| v.iter().any(|p| beneath(path, p)))
}

/// Defaults, explicit exclusions, unsupported mounts and duplicate bind trees.
/// Mount notifications invalidate the cache synchronously, including for Live.
pub fn blocked(path: &[u8]) -> bool {
    explicitly_blocked(path)
        || mount_table().map_or(true, |t| t.excluded.iter().any(|p| beneath(path, p)))
}

struct MountTable {
    roots: Vec<Vec<u8>>,
    excluded: Vec<Vec<u8>>,
}

struct MountCache {
    file: Option<File>,
    table: Option<Arc<MountTable>>,
}

static MOUNTS: LazyLock<Mutex<MountCache>> = LazyLock::new(|| Mutex::new(MountCache { file: None, table: None }));

/// Distinct local mounted directory roots supporting fanotify file handles.
pub fn mounts() -> io::Result<Vec<Vec<u8>>> {
    let table = mount_table()?;
    let mut roots = Vec::new();
    for root in &table.roots {
        if !explicitly_blocked(root) && std::fs::metadata(std::ffi::OsStr::from_bytes(root))?.is_dir() {
            roots.push(root.clone());
        }
    }
    Ok(roots)
}

fn mount_table() -> io::Result<Arc<MountTable>> {
    let mut cache = MOUNTS.lock();
    if cache.file.is_none() {
        cache.file = Some(File::open("/proc/self/mountinfo")?);
    }
    let file = cache.file.as_mut().unwrap();
    let mut poll = libc::pollfd { fd: file.as_raw_fd(), events: libc::POLLPRI | libc::POLLERR, revents: 0 };
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if poll.revents != 0 || cache.table.is_none() {
        // A failed refresh must fail closed, not resurrect stale exclusions.
        cache.table = None;
        let file = cache.file.as_mut().unwrap();
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        cache.table = Some(Arc::new(parse_mounts(&bytes)?));
    }
    Ok(cache.table.as_ref().unwrap().clone())
}

fn unescape(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' {
            let digits = bytes.get(at + 1..at + 4).ok_or_else(|| io::Error::other("truncated mount escape"))?;
            if !digits.iter().all(|b| (b'0'..=b'7').contains(b)) || digits[0] > b'3' {
                return Err(io::Error::other("invalid mount escape"));
            }
            out.push((digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + digits[2] - b'0');
            at += 4;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    Ok(out)
}

fn parse_mounts(bytes: &[u8]) -> io::Result<MountTable> {
    struct Mount { dev: Vec<u8>, root: Vec<u8>, path: Vec<u8>, supported: bool }
    let mut entries = Vec::new();
    for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let fields: Vec<_> = line.split(|&b| b == b' ').collect();
        let separator = fields.iter().position(|f| *f == b"-")
            .ok_or_else(|| io::Error::other("invalid mountinfo separator"))?;
        if separator < 6 || fields.len() < separator + 4 {
            return Err(io::Error::other("invalid mountinfo record"));
        }
        entries.push(Mount {
            dev: fields[2].to_vec(), root: unescape(fields[3])?, path: unescape(fields[4])?,
            supported: matches!(fields[separator + 1], b"ext4" | b"btrfs" | b"xfs" | b"f2fs"),
        });
    }
    if entries.is_empty() {
        return Err(io::Error::other("empty mountinfo"));
    }
    // Prefer the broadest filesystem tree, then its shortest visible path.
    // A bind of an already covered subtree must not expose a second copy or
    // create a recursion cycle. Distinct btrfs subvolumes remain independent.
    entries.sort_by(|a, b| a.root.len().cmp(&b.root.len()).then(a.path.len().cmp(&b.path.len())).then(a.path.cmp(&b.path)));
    let mut table = MountTable { roots: Vec::new(), excluded: Vec::new() };
    let mut selected: Vec<Mount> = Vec::new();
    for entry in entries {
        if !entry.supported {
            table.excluded.push(entry.path);
        } else if explicitly_blocked(&entry.path) {
            continue;
        } else if selected.iter().any(|m| m.dev == entry.dev && beneath(&entry.root, &m.root)) {
            table.excluded.push(entry.path);
        } else {
            table.roots.push(entry.path.clone());
            selected.push(entry);
        }
    }
    table.roots.retain(|p| !table.excluded.iter().any(|e| beneath(p, e)));
    Ok(table)
}

const OPEN_DIR: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

struct Fd(i32);
impl Drop for Fd {
    fn drop(&mut self) { unsafe { libc::close(self.0) }; }
}

struct Dir(*mut libc::DIR);
impl Drop for Dir {
    fn drop(&mut self) { unsafe { libc::closedir(self.0) }; }
}

fn open_dir(path: &CStr, parent: Option<(&Fd, &CStr)>) -> Option<Fd> {
    if blocked(path.to_bytes()) || unsafe { libc::access(path.as_ptr(), libc::R_OK | libc::X_OK) } != 0 {
        return None;
    }
    let fd = match parent {
        Some((fd, name)) => unsafe { libc::openat(fd.0, name.as_ptr(), OPEN_DIR) },
        None => unsafe { libc::open(path.as_ptr(), OPEN_DIR) },
    };
    if fd < 0 { return None; }
    let fd = Fd(fd);
    // Check the opened inode too: a rename between access() and openat() must
    // not let service capabilities bypass the real user's directory ACL.
    if unsafe { libc::syscall(libc::SYS_faccessat2, fd.0, c"".as_ptr(), libc::R_OK | libc::X_OK, libc::AT_EMPTY_PATH) } != 0 {
        return None;
    }
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(fd.0, &mut fs) } != 0
        // ext4, btrfs, xfs, f2fs; reject newly mounted virtual filesystems too.
        || !matches!(fs.f_type as u64, 0xef53 | 0x9123683e | 0x58465342 | 0xf2f52010) {
        return None;
    }
    Some(fd)
}

struct Ctx {
    next_id: AtomicU32,
    out: Vec<Mutex<Vec<Listing>>>,
    visited: Mutex<HashSet<(libc::dev_t, libc::ino_t)>>,
}

/// Recursive scan with listing zero always present, even for unreadable roots.
pub fn scan(root: &[u8], threads: usize) -> Vec<Listing> {
    let threads = threads.max(1);
    let pool = rayon::ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
    let ctx = Ctx {
        next_id: AtomicU32::new(1),
        out: (0..threads + 1).map(|_| Mutex::new(Vec::new())).collect(),
        visited: Mutex::new(HashSet::new()),
    };
    // Parent descriptors are shared by queued child tasks, just as on macOS.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
        limit.rlim_cur = limit.rlim_max.min(65536);
        unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    }
    let path = CString::new(root).ok();
    let fd = path.as_deref().and_then(|p| open_dir(p, None));
    pool.scope(|s| finish_dir(s, fd, path, 0, &ctx));
    ctx.out.into_iter().flat_map(Mutex::into_inner).collect()
}

/// Nonrecursive listing; every entry has `child == NONE`.
pub fn list_one(path: &[u8]) -> Option<Listing> {
    let path = CString::new(path).ok()?;
    let fd = open_dir(&path, None)?;
    let mut listing = Listing { id: 0, names: Vec::new(), ents: Vec::new() };
    list_fd(&fd, &path, &mut listing).then_some(listing)
}

fn finish_dir<'s>(scope: &Scope<'s>, fd: Option<Fd>, path: Option<CString>, id: u32, ctx: &'s Ctx) {
    let mut listing = Listing { id, names: Vec::new(), ents: Vec::new() };
    let opened = fd.zip(path).filter(|(fd, _)| {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        (unsafe { libc::fstat(fd.0, &mut st) }) == 0 && ctx.visited.lock().insert((st.st_dev, st.st_ino))
    });
    let mut children = Vec::new();
    let mut parent = None;
    if let Some((fd, path)) = opened {
        if list_fd(&fd, &path, &mut listing) {
            for entry in &mut listing.ents {
                if entry.kind & 3 != KIND_DIR || entry.kind & FLAG_MOUNT != 0 { continue; }
                let name = &listing.names[entry.name_off as usize..][..entry.name_len as usize];
                let child = crate::live::join(path.to_bytes(), name);
                if explicitly_blocked(&child) { continue; }
                let name_at = child.len() - name.len();
                let child = CString::new(child).unwrap();
                entry.child = ctx.next_id.fetch_add(1, Ordering::Relaxed);
                children.push((child, name_at, entry.child));
            }
        }
        parent = Some(Arc::new(fd));
    }
    let slot = rayon::current_thread_index().unwrap_or(ctx.out.len() - 1);
    ctx.out[slot].lock().push(listing);
    if let Some(parent) = parent {
        for (path, name_at, child_id) in children {
            let parent = parent.clone();
            scope.spawn(move |scope| {
                let name = CStr::from_bytes_with_nul(&path.as_bytes_with_nul()[name_at..]).unwrap();
                let fd = open_dir(&path, Some((&parent, name)));
                drop(parent);
                finish_dir(scope, fd, Some(path), child_id, ctx);
            });
        }
    }
}

fn list_fd(fd: &Fd, path: &CStr, listing: &mut Listing) -> bool {
    let Ok(table) = mount_table() else { return false; };
    let duplicate = unsafe { libc::fcntl(fd.0, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 { return false; }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return false;
    }
    let stream = Dir(stream);
    // Only directories need paths, reused in-place; ordinary files never do.
    let mut child_path = path.to_bytes().to_vec();
    if child_path.last() != Some(&b'/') { child_path.push(b'/'); }
    let prefix_len = child_path.len();
    loop {
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() { break; }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." || bytes.len() > u16::MAX as usize { continue; }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(fd.0, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 { continue; }
        let mut kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => KIND_FILE,
            libc::S_IFDIR => KIND_DIR,
            libc::S_IFLNK => KIND_LINK,
            _ => KIND_OTHER,
        };
        if bytes.first() == Some(&b'.') { kind |= FLAG_HIDDEN; }
        if kind & 3 == KIND_DIR {
            child_path.extend_from_slice(bytes);
            if table.excluded.iter().any(|p| beneath(&child_path, p)) { kind |= FLAG_MOUNT; }
            child_path.truncate(prefix_len);
        }
        listing.ents.push(RawEnt {
            name_off: listing.names.len() as u32, name_len: bytes.len() as u16,
            kind, size: if matches!(kind & 3, KIND_FILE | KIND_LINK) { st.st_size.max(0) as u64 } else { 0 },
            mtime: st.st_mtime.clamp(0, u32::MAX as i64) as u32, child: NONE,
        });
        listing.names.extend_from_slice(bytes);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn traversal_preserves_bytes_and_does_not_follow_links() {
        let home = std::env::var_os("HOME").unwrap();
        let root = std::path::PathBuf::from(home).join(format!(".fsearch-walk-test-{}-{}", std::process::id(), crate::query::now_secs()));
        std::fs::create_dir(&root).unwrap();
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
        let _scratch = Scratch(root.clone());
        std::fs::create_dir(root.join("child")).unwrap();
        let special = std::ffi::OsString::from_vec(b".space\n\\\xff".to_vec());
        std::fs::write(root.join("child").join(&special), b"abc").unwrap();
        symlink(&root, root.join("loop")).unwrap();
        std::fs::create_dir(root.join("private")).unwrap();
        std::fs::write(root.join("private/secret"), b"hidden").unwrap();
        std::fs::set_permissions(root.join("private"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let listings = scan(root.as_os_str().as_bytes(), 2);
        std::fs::set_permissions(root.join("private"), std::fs::Permissions::from_mode(0o700)).unwrap();
        let zero = listings.iter().find(|l| l.id == 0).unwrap();
        let link = zero.ents.iter().find(|e| &zero.names[e.name_off as usize..][..e.name_len as usize] == b"loop").unwrap();
        assert_eq!(link.kind & 3, KIND_LINK);
        assert_eq!(link.child, NONE);
        let mut seen = Vec::new();
        crate::live::for_each_path(&listings, root.as_os_str().as_bytes(), |path, e| seen.push((path, *e)));
        let file = seen.iter().find(|(p, _)| p.ends_with(special.as_bytes())).unwrap();
        assert_eq!(file.1.kind, KIND_FILE | FLAG_HIDDEN);
        assert_eq!(file.1.size, 3);
        if unsafe { libc::getuid() } != 0 { assert!(!seen.iter().any(|(p, _)| p.ends_with(b"/secret"))); }
        assert!(list_one(root.as_os_str().as_bytes()).unwrap().ents.iter().all(|e| e.child == NONE));
        let missing = scan(root.join("missing").as_os_str().as_bytes(), 1);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].id, 0);
        assert!(missing[0].ents.is_empty());
        let table = parse_mounts(b"1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 8:1 /home /alias rw - ext4 /dev/a rw\n3 1 8:2 / /mnt/a\\040b rw - xfs /dev/b rw\n4 1 0:2 / /virtual rw - tmpfs tmpfs rw\n").unwrap();
        assert_eq!(table.roots, vec![b"/".to_vec(), b"/mnt/a b".to_vec()]);
        assert!(table.excluded.contains(&b"/alias".to_vec()));
        assert!(table.excluded.contains(&b"/virtual".to_vec()));
    }
}
