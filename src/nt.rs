//! NTFS MFT sequential crawl and USN change journal.
//!
//! Opening `\\.\X:` needs admin. That path is sequential I/O against $MFT —
//! typically several times faster than walking directories, which is what
//! macOS fsearch has to do with `getattrlistbulk`.

use crate::pathwin;
use crate::walk::{self, KIND_DIR, KIND_FILE, KIND_LINK, Listing, NONE, RawEnt, FLAG_HIDDEN, FLAG_MOUNT};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::io::FromRawHandle;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFinalPathNameByHandleW,
    GetVolumeInformationW, GetLogicalDrives, OPEN_EXISTING, OpenFileById,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::FSCTL_GET_NTFS_VOLUME_DATA;

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x000900F4;
const FSCTL_READ_USN_JOURNAL: u32 = 0x000900BB;

const AT_STANDARD: u32 = 0x10;
const AT_FILE_NAME: u32 = 0x30;
const AT_DATA: u32 = 0x80;
const AT_END: u32 = 0xFFFF_FFFF;

#[repr(C)]
struct NtfsVolumeData {
    serial: u64,
    number_sectors: i64,
    total_clusters: i64,
    free_clusters: i64,
    total_reserved: i64,
    bytes_per_sector: u32,
    bytes_per_cluster: u32,
    bytes_per_file_record: u32,
    clusters_per_file_record: u32,
    mft_valid_data_length: i64,
    mft_start_lcn: i64,
    mft2_start_lcn: i64,
    mft_zone_start: i64,
    mft_zone_end: i64,
}

#[repr(C)]
struct UsnJournalData {
    usn_journal_id: u64,
    first_usn: i64,
    next_usn: i64,
    lowest_valid_usn: i64,
    max_usn: i64,
    maximum_size: u64,
    allocation_delta: u64,
}

#[repr(C)]
struct ReadUsnJournalData {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: u64,
    bytes_to_wait_for: u64,
    usn_journal_id: u64,
}

#[repr(C)]
struct FileIdDescriptor {
    dw_size: u32,
    type_: u32,
    file_id: u64,
}

pub struct MftEnt {
    pub rec: u64,
    pub parent: u64,
    pub name: Vec<u8>,
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
}

pub struct VolumeCrawl {
    pub letter: u8,
    pub journal_id: u64,
    pub next_usn: i64,
    pub ents: Vec<MftEnt>,
}

pub struct UsnEvent {
    pub parent_frn: u64,
    pub rec: u64,
    pub name: Vec<u8>,
    pub reason: u32,
}

pub fn enable_privileges() {
    crate::winpriv::enable(&["SeBackupPrivilege", "SeRestorePrivilege"]);
}

pub fn drive_letters() -> Vec<u8> {
    let mask = unsafe { GetLogicalDrives() };
    (0..26).filter(|i| mask & (1 << i) != 0).map(|i| b'A' + i as u8).collect()
}

pub fn is_ntfs(letter: u8) -> bool {
    let root = pathwin::to_wide(&[letter, b':', b'\\']);
    let mut fs = [0u16; 32];
    let ok = unsafe {
        GetVolumeInformationW(root.as_ptr(), std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), fs.as_mut_ptr(), fs.len() as u32)
    };
    ok != 0 && pathwin::from_wide(&fs).eq_ignore_ascii_case(b"NTFS")
}

pub fn open_volume(letter: u8) -> Option<Handle> {
    let p = pathwin::to_wide(&[b'\\', b'\\', b'.', b'\\', letter, b':']);
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    let access = [GENERIC_READ | GENERIC_WRITE, GENERIC_READ, MAXIMUM_ALLOWED];
    for acc in access {
        let h = unsafe {
            CreateFileW(
                p.as_ptr(),
                acc,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | 0x0800_0000,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            return Some(Handle(h));
        }
    }
    None
}

pub struct Handle(pub HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

pub fn crawl_volume(letter: u8) -> Option<VolumeCrawl> {
    let h = open_volume(letter)?;
    let mut vol: NtfsVolumeData = unsafe { std::mem::zeroed() };
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(h.0, FSCTL_GET_NTFS_VOLUME_DATA, std::ptr::null(), 0, &mut vol as *mut _ as *mut _, std::mem::size_of::<NtfsVolumeData>() as u32, &mut ret, std::ptr::null_mut())
    };
    if ok == 0 || vol.bytes_per_cluster == 0 {
        return None;
    }
    let rec_size = if vol.bytes_per_file_record == 0 { 1024 } else { vol.bytes_per_file_record as usize };
    let bps = vol.bytes_per_sector.max(512) as usize;
    let mut file = unsafe { std::fs::File::from_raw_handle(dup(h.0)?) };
    let mft0_off = vol.mft_start_lcn as u64 * vol.bytes_per_cluster as u64;
    let mut rec0 = vec![0u8; rec_size.max(1024)];
    file.seek(SeekFrom::Start(mft0_off)).ok()?;
    file.read_exact(&mut rec0).ok()?;
    apply_fixup(&mut rec0, bps);
    let runs = mft_data_runs(&rec0)?;
    let mut ents = Vec::with_capacity(1_000_000);
    let mut buf = vec![0u8; 16 << 20];
    let mut rec_no = 0u64;
    for (lcn, clusters) in runs {
        if lcn == 0 {
            rec_no += clusters * vol.bytes_per_cluster as u64 / rec_size as u64;
            continue;
        }
        let mut remain = clusters * vol.bytes_per_cluster as u64;
        let mut off = lcn * vol.bytes_per_cluster as u64;
        while remain > 0 {
            let n = remain.min(buf.len() as u64) as usize;
            let n = n / rec_size * rec_size;
            if n == 0 {
                break;
            }
            if file.seek(SeekFrom::Start(off)).is_err() || file.read_exact(&mut buf[..n]).is_err() {
                break;
            }
            for chunk in buf[..n].chunks_exact_mut(rec_size) {
                apply_fixup(chunk, bps);
                parse_record(chunk, rec_no, &mut ents);
                rec_no += 1;
            }
            off += n as u64;
            remain -= n as u64;
        }
    }
    let (journal_id, next_usn) = query_usn(&h).unwrap_or((0, 0));
    Some(VolumeCrawl { letter, journal_id, next_usn, ents })
}

fn dup(h: HANDLE) -> Option<std::os::windows::io::RawHandle> {
    use windows_sys::Win32::Foundation::DuplicateHandle;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    const DUPLICATE_SAME_ACCESS: u32 = 2;
    let mut out: HANDLE = std::ptr::null_mut();
    let ok = unsafe { DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &mut out, 0, 0, DUPLICATE_SAME_ACCESS) };
    if ok == 0 { None } else { Some(out as _) }
}

fn apply_fixup(rec: &mut [u8], sector: usize) {
    if rec.len() < 8 || &rec[..4] != b"FILE" {
        return;
    }
    let usa_off = u16::from_le_bytes(rec[4..6].try_into().unwrap()) as usize;
    let usa_count = u16::from_le_bytes(rec[6..8].try_into().unwrap()) as usize;
    if usa_off == 0 || usa_count < 2 || usa_off + usa_count * 2 > rec.len() {
        return;
    }
    for i in 1..usa_count {
        let pos = i * sector - 2;
        if pos + 2 > rec.len() {
            break;
        }
        rec[pos] = rec[usa_off + i * 2];
        rec[pos + 1] = rec[usa_off + i * 2 + 1];
    }
}

fn mft_data_runs(rec0: &[u8]) -> Option<Vec<(u64, u64)>> {
    let mut at = u16::from_le_bytes(rec0.get(0x14..0x16)?.try_into().ok()?) as usize;
    while at + 16 < rec0.len() {
        let ty = u32::from_le_bytes(rec0[at..at + 4].try_into().ok()?);
        if ty == AT_END {
            break;
        }
        let len = u32::from_le_bytes(rec0[at + 4..at + 8].try_into().ok()?) as usize;
        if len < 16 || at + len > rec0.len() {
            break;
        }
        if ty == AT_DATA {
            let name_len = rec0[at + 9] as usize;
            if name_len == 0 && rec0[at + 8] != 0 {
                let run_off = u16::from_le_bytes(rec0[at + 0x20..at + 0x22].try_into().ok()?) as usize;
                return parse_runs(&rec0[at + run_off..at + len]);
            }
        }
        at += len;
    }
    None
}

fn parse_runs(mut data: &[u8]) -> Option<Vec<(u64, u64)>> {
    let mut lcn: i64 = 0;
    let mut out = Vec::new();
    while !data.is_empty() {
        let h = data[0];
        if h == 0 {
            break;
        }
        data = &data[1..];
        let len_sz = (h & 0x0f) as usize;
        let off_sz = (h >> 4) as usize;
        let (length, n) = read_le(data, len_sz, false)?;
        data = &data[n..];
        if off_sz == 0 {
            out.push((0, length as u64));
            continue;
        }
        let (off, n) = read_le(data, off_sz, true)?;
        data = &data[n..];
        lcn += off;
        if lcn < 0 {
            return None;
        }
        out.push((lcn as u64, length as u64));
    }
    Some(out)
}

fn read_le(data: &[u8], n: usize, signed: bool) -> Option<(i64, usize)> {
    if n == 0 || n > 8 || data.len() < n {
        return None;
    }
    let mut tmp = [0u8; 8];
    tmp[..n].copy_from_slice(&data[..n]);
    if signed && data[n - 1] & 0x80 != 0 {
        for b in tmp.iter_mut().skip(n) {
            *b = 0xff;
        }
    }
    Some((i64::from_le_bytes(tmp), n))
}

fn parse_record(rec: &[u8], rec_no: u64, out: &mut Vec<MftEnt>) {
    if rec.len() < 0x30 || &rec[..4] != b"FILE" {
        return;
    }
    let flags = u16::from_le_bytes(rec[0x16..0x18].try_into().unwrap());
    if flags & 1 == 0 {
        return;
    }
    let base = u64::from_le_bytes(rec[0x20..0x28].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
    if base != 0 {
        return;
    }
    let mut mtime = 0u32;
    let mut attrs = 0u32;
    let mut data_size = 0u64;
    let mut names: Vec<(u64, Vec<u8>, u8)> = Vec::new();
    let mut at = u16::from_le_bytes(rec[0x14..0x16].try_into().unwrap()) as usize;
    while at + 16 < rec.len() {
        let ty = u32::from_le_bytes(rec[at..at + 4].try_into().unwrap());
        if ty == AT_END {
            break;
        }
        let len = u32::from_le_bytes(rec[at + 4..at + 8].try_into().unwrap()) as usize;
        if len < 16 || at + len > rec.len() {
            break;
        }
        let resident = rec[at + 8] == 0;
        match ty {
            AT_STANDARD if resident => {
                let (v, vl) = resident_val(rec, at);
                if vl >= 0x24 {
                    mtime = walk::filetime_unix(u32::from_le_bytes(v[8..12].try_into().unwrap()), u32::from_le_bytes(v[12..16].try_into().unwrap()));
                    attrs = u32::from_le_bytes(v[0x20..0x24].try_into().unwrap());
                }
            }
            AT_FILE_NAME if resident => {
                let (v, vl) = resident_val(rec, at);
                if vl >= 0x42 {
                    let ntype = v[0x41];
                    if ntype != 2 {
                        let nlen = v[0x40] as usize;
                        let parent = u64::from_le_bytes(v[0..8].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
                        let mut w = Vec::with_capacity(nlen);
                        let bytes = &v[0x42..];
                        for i in 0..nlen {
                            if i * 2 + 1 >= bytes.len() {
                                break;
                            }
                            w.push(u16::from_le_bytes(bytes[i * 2..i * 2 + 2].try_into().unwrap()));
                        }
                        let name = pathwin::from_wide(&w);
                        if !name.is_empty() && name != b"." && name != b".." {
                            names.push((parent, name, ntype));
                        }
                    }
                }
            }
            AT_DATA => {
                let name_len = rec[at + 9] as usize;
                if name_len == 0 {
                    if resident {
                        data_size = u32::from_le_bytes(rec[at + 0x10..at + 0x14].try_into().unwrap()) as u64;
                    } else if at + 0x38 <= rec.len() {
                        data_size = u64::from_le_bytes(rec[at + 0x30..at + 0x38].try_into().unwrap());
                    }
                }
            }
            _ => {}
        }
        at += len;
    }
    let mut kind = if flags & 2 != 0 { KIND_DIR } else { KIND_FILE };
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        kind = if flags & 2 != 0 { KIND_DIR | FLAG_MOUNT } else { KIND_LINK };
    }
    if attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0 {
        kind |= FLAG_HIDDEN;
    }
    if names.is_empty() {
        return;
    }
    names.sort_by_key(|n| n.2);
    names.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    for (parent, name, _) in names {
        out.push(MftEnt { rec: rec_no, parent, name, kind, size: data_size, mtime });
    }
}

fn resident_val(rec: &[u8], at: usize) -> (&[u8], usize) {
    let vl = u32::from_le_bytes(rec[at + 0x10..at + 0x14].try_into().unwrap()) as usize;
    let vo = u16::from_le_bytes(rec[at + 0x14..at + 0x16].try_into().unwrap()) as usize;
    let s = at + vo;
    let e = (s + vl).min(rec.len());
    if s >= rec.len() { (&[], 0) } else { (&rec[s..e], e - s) }
}

pub fn listings_from_mft(vols: &[VolumeCrawl]) -> Vec<Listing> {
    let mut root = Listing { id: 0, names: Vec::new(), ents: Vec::new() };
    let mut out = Vec::new();
    let mut next = 1u32;
    for vol in vols {
        let (mut ls, used) = volume_listings(vol, next);
        if ls.is_empty() {
            continue;
        }
        let vol_name = [vol.letter, b':'];
        root.ents.push(RawEnt {
            name_off: root.names.len() as u32,
            name_len: 2,
            kind: KIND_DIR,
            size: 0,
            mtime: 0,
            child: next,
        });
        root.names.extend_from_slice(&vol_name);
        next += used;
        out.append(&mut ls);
    }
    let mut all = vec![root];
    all.append(&mut out);
    all
}

fn volume_listings(vol: &VolumeCrawl, base: u32) -> (Vec<Listing>, u32) {
    let mut by_rec: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, e) in vol.ents.iter().enumerate() {
        by_rec.entry(e.parent).or_default().push(i);
    }
    let mut dir_id: HashMap<u64, u32> = HashMap::new();
    dir_id.insert(5, base);
    let mut next = 1u32;
    for e in &vol.ents {
        if e.kind & 3 == KIND_DIR && e.rec != 5 {
            dir_id.entry(e.rec).or_insert_with(|| {
                let id = next;
                next += 1;
                id
            });
        }
    }
    let mut listings: Vec<Listing> = (0..next).map(|i| Listing { id: base + i, names: Vec::new(), ents: Vec::new() }).collect();
    for e in &vol.ents {
        if e.rec == 5 {
            continue;
        }
        let Some(&lid) = dir_id.get(&e.parent) else { continue };
        let local = lid - base;
        let child = if e.kind & 3 == KIND_DIR { dir_id.get(&e.rec).copied().unwrap_or(NONE) } else { NONE };
        let l = &mut listings[local as usize];
        if e.name.len() > u16::MAX as usize {
            continue;
        }
        l.ents.push(RawEnt {
            name_off: l.names.len() as u32,
            name_len: e.name.len() as u16,
            kind: e.kind,
            size: e.size,
            mtime: e.mtime,
            child,
        });
        l.names.extend_from_slice(&e.name);
    }
    (listings, next)
}

pub fn query_usn(h: &Handle) -> Option<(u64, i64)> {
    let mut j: UsnJournalData = unsafe { std::mem::zeroed() };
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(h.0, FSCTL_QUERY_USN_JOURNAL, std::ptr::null(), 0, &mut j as *mut _ as *mut _, std::mem::size_of::<UsnJournalData>() as u32, &mut ret, std::ptr::null_mut())
    };
    if ok == 0 { None } else { Some((j.usn_journal_id, j.next_usn)) }
}

pub fn read_usn(h: &Handle, journal_id: u64, start: i64) -> Result<(i64, Vec<UsnEvent>), UsnErr> {
    let mut q = ReadUsnJournalData {
        start_usn: start,
        reason_mask: 0xFFFF_FFFF,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_wait_for: 0,
        usn_journal_id: journal_id,
    };
    let mut buf = vec![0u8; 1 << 20];
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(h.0, FSCTL_READ_USN_JOURNAL, &mut q as *mut _ as *mut _, std::mem::size_of::<ReadUsnJournalData>() as u32, buf.as_mut_ptr() as *mut _, buf.len() as u32, &mut ret, std::ptr::null_mut())
    };
    if ok == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(if err == 1179 || err == 1181 { UsnErr::Wrap } else { UsnErr::Io });
    }
    if ret < 8 {
        return Ok((start, Vec::new()));
    }
    let next = i64::from_le_bytes(buf[..8].try_into().unwrap());
    let mut events = Vec::new();
    let mut p = 8usize;
    while p + 60 <= ret as usize {
        let len = u32::from_le_bytes(buf[p..p + 4].try_into().unwrap()) as usize;
        if len < 60 || p + len > ret as usize {
            break;
        }
        let rec = u64::from_le_bytes(buf[p + 8..p + 16].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
        let parent = u64::from_le_bytes(buf[p + 16..p + 24].try_into().unwrap()) & 0x0000_FFFF_FFFF_FFFF;
        let reason = u32::from_le_bytes(buf[p + 40..p + 44].try_into().unwrap());
        let nlen = u16::from_le_bytes(buf[p + 56..p + 58].try_into().unwrap()) as usize;
        let noff = u16::from_le_bytes(buf[p + 58..p + 60].try_into().unwrap()) as usize;
        let mut wname = Vec::new();
        if noff + nlen <= len {
            let bytes = &buf[p + noff..p + noff + nlen];
            for c in bytes.chunks_exact(2) {
                wname.push(u16::from_le_bytes(c.try_into().unwrap()));
            }
        }
        events.push(UsnEvent { parent_frn: parent, rec, name: pathwin::from_wide(&wname), reason });
        p += len;
    }
    Ok((next, events))
}

pub enum UsnErr {
    Wrap,
    Io,
}

pub fn path_from_frn(h: &Handle, frn: u64) -> Option<Vec<u8>> {
    let mut desc = FileIdDescriptor { dw_size: std::mem::size_of::<FileIdDescriptor>() as u32, type_: 0, file_id: frn };
    let fh = unsafe {
        OpenFileById(h.0, &mut desc as *mut _ as *mut _, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), FILE_FLAG_BACKUP_SEMANTICS)
    };
    if fh == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut buf = [0u16; 1024];
    let n = unsafe { GetFinalPathNameByHandleW(fh, buf.as_mut_ptr(), buf.len() as u32, 0) };
    unsafe { CloseHandle(fh) };
    if n == 0 || n as usize >= buf.len() {
        return None;
    }
    Some(pathwin::strip_nt_prefix(pathwin::from_wide(&buf[..n as usize])))
}
