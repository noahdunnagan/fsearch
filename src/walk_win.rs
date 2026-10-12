//! Parallel directory walk. Prefers `NtQueryDirectoryFile` (one syscall per
//! buffer, not per entry). A fixed worker pool + deque replaces one rayon
//! task per folder (hundreds of thousands of spawns on a whole disk).

use crate::pathwin::{self, SEP};
use parking_lot::{Condvar, Mutex};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FIND_FIRST_EX_LARGE_FETCH,
    FindClose, FindExInfoBasic, FindExSearchNameMatch, FindFirstFileExW, FindNextFileW, OPEN_EXISTING, WIN32_FIND_DATAW,
};

pub const NONE: u32 = u32::MAX;
pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_LINK: u8 = 2;
pub const KIND_OTHER: u8 = 3;
pub const FLAG_HIDDEN: u8 = 1 << 2;
pub const FLAG_MOUNT: u8 = 1 << 3;

pub static SKIP: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
pub static DENIED: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());
pub static LISTED: AtomicUsize = AtomicUsize::new(0);

pub struct Hold(());
impl Hold {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Hold {
        Hold(())
    }
}
impl Drop for Hold {
    fn drop(&mut self) {}
}
pub fn yield_to_searches() {}

pub fn blocked(path: &[u8]) -> bool {
    SKIP.get().is_some_and(|v| {
        v.iter().any(|s| path.len() >= s.len() && path[..s.len()].eq_ignore_ascii_case(s) && (path.len() == s.len() || pathwin::is_sep(path[s.len()])))
    })
}

pub fn scan_disk(threads: usize) -> Vec<Listing> {
    crate::nt::enable_privileges();
    let mut mft = Vec::new();
    let mut walked = Vec::new();
    for letter in crate::nt::drive_letters() {
        let root = [letter, b':', b'\\'];
        if crate::nt::is_ntfs(letter) {
            if let Some(vol) = crate::nt::crawl_volume(letter) {
                mft.push(vol);
                continue;
            }
        }
        walked.extend(scan(&root, threads.max(1)));
    }
    let mut ls = if mft.is_empty() { Vec::new() } else { crate::nt::listings_from_mft(&mft) };
    ls.extend(walked);
    LISTED.store(ls.iter().map(|l| l.ents.len()).sum(), Ordering::Relaxed);
    ls
}


#[derive(Clone, Copy)]
pub struct RawEnt {
    pub name_off: u32,
    pub name_len: u16,
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
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
}

const WALK_SKIP: &[&[u8]] = &[
    b"System Volume Information",
    b"$Recycle.Bin",
    b"WinSxS",
    b"Windows.old",
    b"CSC",
    b"Temp",
    b"tmp",
];

const FILE_LIST_DIRECTORY: u32 = 1;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
const FILE_DIRECTORY_INFORMATION: u32 = 1;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryDirectoryFile(
        file_handle: HANDLE,
        event: HANDLE,
        apc_routine: *const core::ffi::c_void,
        apc_context: *const core::ffi::c_void,
        io_status_block: *mut IoStatusBlock,
        file_information: *mut u8,
        length: u32,
        file_information_class: u32,
        return_single_entry: u8,
        file_name: *const core::ffi::c_void,
        restart_scan: u8,
    ) -> i32;
}

thread_local! {
    static DIR_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; 256 * 1024]);
}

pub fn scan(root: &[u8], threads: usize) -> Vec<Listing> {
    let threads = threads.max(1);
    let jobs = Mutex::new(VecDeque::from([(root.to_vec(), 0u32)]));
    let cv = Condvar::new();
    let pending = AtomicUsize::new(1);
    let ctx = Ctx { next_id: AtomicU32::new(1), out: (0..threads).map(|_| Mutex::new(Vec::new())).collect() };
    std::thread::scope(|s| {
        for slot in 0..threads {
            let jobs = &jobs;
            let cv = &cv;
            let pending = &pending;
            let ctx = &ctx;
            s.spawn(move || worker(slot, jobs, cv, pending, ctx));
        }
    });
    ctx.out.into_iter().flat_map(|m| m.into_inner()).collect()
}

fn worker(slot: usize, jobs: &Mutex<VecDeque<(Vec<u8>, u32)>>, cv: &Condvar, pending: &AtomicUsize, ctx: &Ctx) {
    loop {
        let job = {
            let mut g = jobs.lock();
            loop {
                if let Some(j) = g.pop_front() {
                    break Some(j);
                }
                if pending.load(Ordering::SeqCst) == 0 {
                    cv.notify_all();
                    return;
                }
                cv.wait(&mut g);
            }
        };
        let Some((path, id)) = job else { return };
        let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
        if blocked(&path) || !list_into(&path, &mut l) {
            ctx.out[slot].lock().push(l);
            if pending.fetch_sub(1, Ordering::SeqCst) == 1 {
                cv.notify_all();
            }
            continue;
        }
        let mut extra = 0usize;
        for e in l.ents.iter_mut() {
            if e.kind & 3 != KIND_DIR || e.kind & FLAG_MOUNT != 0 {
                continue;
            }
            let name = &l.names[e.name_off as usize..e.name_off as usize + e.name_len as usize];
            if WALK_SKIP.iter().any(|n| name.eq_ignore_ascii_case(n)) {
                continue;
            }
            let child = pathwin::join(&path, name);
            if blocked(&child) {
                continue;
            }
            e.child = ctx.next_id.fetch_add(1, Ordering::Relaxed);
            jobs.lock().push_back((child, e.child));
            extra += 1;
        }
        ctx.out[slot].lock().push(l);
        if extra > 0 {
            pending.fetch_add(extra, Ordering::SeqCst);
            cv.notify_all();
        }
        if pending.fetch_sub(1, Ordering::SeqCst) == 1 {
            cv.notify_all();
        }
    }
}

pub fn list_one(path: &[u8]) -> Option<Listing> {
    if blocked(path) {
        return None;
    }
    let mut l = Listing { id: 0, names: Vec::new(), ents: Vec::new() };
    list_into(path, &mut l).then_some(l)
}

fn list_into(path: &[u8], l: &mut Listing) -> bool {
    if list_nt(path, l) {
        return true;
    }
    list_find(path, l)
}

fn list_nt(path: &[u8], l: &mut Listing) -> bool {
    let w = pathwin::long_wide(path);
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return false;
    }
    let ok = DIR_BUF.with(|b| {
        let mut buf = b.borrow_mut();
        let mut restart = 1u8;
        loop {
            let mut iosb = IoStatusBlock { status: 0, information: 0 };
            let st = unsafe {
                NtQueryDirectoryFile(
                    h,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    &mut iosb,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    FILE_DIRECTORY_INFORMATION,
                    0,
                    std::ptr::null(),
                    restart,
                )
            } as u32;
            restart = 0;
            if st == STATUS_NO_MORE_FILES || st == STATUS_NO_SUCH_FILE {
                return true;
            }
            if st != 0 {
                return false;
            }
            let used = iosb.information.min(buf.len());
            if used < 64 {
                return true;
            }
            parse_dir_info(&buf[..used], l);
        }
    });
    unsafe { CloseHandle(h) };
    ok
}

fn parse_dir_info(buf: &[u8], l: &mut Listing) {
    let mut off = 0usize;
    loop {
        if off + 64 > buf.len() {
            break;
        }
        let next = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let write_lo = u32::from_le_bytes(buf[off + 0x18..off + 0x1C].try_into().unwrap());
        let write_hi = u32::from_le_bytes(buf[off + 0x1C..off + 0x20].try_into().unwrap());
        let size = u64::from_le_bytes(buf[off + 0x28..off + 0x30].try_into().unwrap());
        let attr = u32::from_le_bytes(buf[off + 0x38..off + 0x3C].try_into().unwrap());
        let nlen = u32::from_le_bytes(buf[off + 0x3C..off + 0x40].try_into().unwrap()) as usize;
        let ns = off + 0x40;
        let ne = (ns + nlen).min(buf.len());
        if ne > ns {
            let mut wname = Vec::with_capacity(nlen / 2);
            for c in buf[ns..ne].chunks_exact(2) {
                wname.push(u16::from_le_bytes(c.try_into().unwrap()));
            }
            push_ent(&wname, attr, size, filetime_unix(write_lo, write_hi), l);
        }
        if next == 0 {
            break;
        }
        off = off.saturating_add(next);
        if off >= buf.len() {
            break;
        }
    }
}

fn list_find(path: &[u8], l: &mut Listing) -> bool {
    let mut glob = pathwin::normalize(path);
    if glob.last() != Some(&SEP) {
        glob.push(SEP);
    }
    glob.push(b'*');
    let w = pathwin::long_wide(&glob);
    let mut data: WIN32_FIND_DATAW = unsafe { std::mem::zeroed() };
    let h = unsafe { FindFirstFileExW(w.as_ptr(), FindExInfoBasic, &mut data as *mut _ as *mut _, FindExSearchNameMatch, std::ptr::null(), FIND_FIRST_EX_LARGE_FETCH) };
    if h == INVALID_HANDLE_VALUE {
        return false;
    }
    loop {
        push_ent(&wide_c_name(&data.cFileName), data.dwFileAttributes, ((data.nFileSizeHigh as u64) << 32) | data.nFileSizeLow as u64, filetime_unix(data.ftLastWriteTime.dwLowDateTime, data.ftLastWriteTime.dwHighDateTime), l);
        if unsafe { FindNextFileW(h, &mut data) } == 0 {
            break;
        }
    }
    unsafe { FindClose(h) };
    true
}

fn wide_c_name(w: &[u16]) -> Vec<u16> {
    let n = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    w[..n].to_vec()
}

fn push_ent(wname: &[u16], attr: u32, size: u64, mtime: u32, l: &mut Listing) {
    if wname.is_empty() || wname == [b'.' as u16] || wname == [b'.' as u16, b'.' as u16] {
        return;
    }
    let start = l.names.len();
    utf16_extend(&mut l.names, wname);
    let nlen = l.names.len() - start;
    if nlen == 0 || nlen > u16::MAX as usize {
        l.names.truncate(start);
        return;
    }
    let mut kind = if attr & FILE_ATTRIBUTE_DIRECTORY != 0 { KIND_DIR } else { KIND_FILE };
    if attr & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        kind = if attr & FILE_ATTRIBUTE_DIRECTORY != 0 { KIND_DIR | FLAG_MOUNT } else { KIND_LINK };
    }
    if attr & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0 {
        kind |= FLAG_HIDDEN;
    }
    l.ents.push(RawEnt { name_off: start as u32, name_len: nlen as u16, kind, size, mtime, child: NONE });
}

fn utf16_extend(out: &mut Vec<u8>, w: &[u16]) {
    for r in char::decode_utf16(w.iter().copied()) {
        match r {
            Ok(c) => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
            Err(_) => out.push(b'?'),
        }
    }
}

pub fn filetime_unix(lo: u32, hi: u32) -> u32 {
    let t = ((hi as u64) << 32) | lo as u64;
    if t == 0 {
        return 0;
    }
    (t / 10_000_000).saturating_sub(11_644_473_600).min(u32::MAX as u64) as u32
}

/// Prefix a scan of `path` with ancestor listings so reconstructed paths are absolute.
pub fn wrap_path(path: &[u8], mut ls: Vec<Listing>) -> Vec<Listing> {
    let norm = crate::pathwin::normalize(path);
    let comps = crate::pathwin::split(&norm);
    if comps.is_empty() {
        return ls;
    }
    let base = comps.len() as u32;
    remap_listings(&mut ls, base);
    let mut all = Vec::with_capacity(comps.len() + ls.len());
    for (i, name) in comps.iter().enumerate() {
        let mut l = Listing { id: i as u32, names: Vec::new(), ents: Vec::new() };
        l.ents.push(RawEnt {
            name_off: 0,
            name_len: name.len() as u16,
            kind: KIND_DIR,
            size: 0,
            mtime: 0,
            child: i as u32 + 1,
        });
        l.names.extend_from_slice(name);
        all.push(l);
    }
    all.append(&mut ls);
    all
}

fn remap_listings(ls: &mut [Listing], base: u32) {
    for l in ls.iter_mut() {
        l.id += base;
        for e in &mut l.ents {
            if e.child != NONE {
                e.child += base;
            }
        }
    }
}
