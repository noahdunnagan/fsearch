//! The name index: every entry on disk in one flat blob, mmap-able as is.
//!
//! Layout trick: entries are emitted one directory *block* at a time, blocks
//! in depth-first order. So every directory's children are contiguous (and
//! sorted, for path lookup), and every directory's whole subtree is the single
//! range `dir_start..dir_end`. Scoping a search to a folder is a range bound,
//! not a filter.
//!
//! Names are interned: 7.5M entries share ~2M distinct names, so each name
//! is stored once with its char mask, and queries score unique names, not
//! entries.

use crate::walk::{KIND_DIR, Listing, NONE};
use memmap2::{Mmap, MmapMut};
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const MAGIC: &[u8; 8] = b"FSIDX007";
// This FSEvents value starts a watch without replaying saved history.
const EVENT_SINCE_NOW: u64 = u64::MAX;

#[derive(Clone, Copy)]
enum Sec {
    NameMask,
    NameOff,
    Names,
    EntName,
    Kind,
    Parent,
    Size,
    Mtime,
    DirEntry,
    DirStart,
    DirLen,
    DirEnd,
    DirPrior,
    DirParent,
    NameEntsOff,
    NameEnts,
}
const NSEC: usize = 16;

pub struct Index {
    map: Mmap,
    pub n: usize,
    pub d: usize,
    /// Distinct names.
    pub u: usize,
    names_len: usize,
    u1: usize,
    /// FSEvents id the index is current as of; replay starts here.
    pub event_id: u64,
    /// Wall-clock second the index is known complete as of (0: unknown).
    /// If FSEvents history from `event_id` is gone, folders changed since
    /// then are what needs relisting.
    pub synced_at: u32,
    off: [usize; NSEC],
    plan: std::sync::OnceLock<MemoPlan>,
}

/// How to fold per-dir data down the tree in parallel (see `memo_plan`).
pub struct MemoPlan {
    /// Dirs to do one by one, parents first.
    pub upper: Vec<u32>,
    /// (dir, its descendants' id range): the range's parents are the dir or
    /// inside the range, so each runs on its own once `upper` is done.
    pub chunks: Vec<(u32, std::ops::Range<u32>)>,
}

/// A typed view of one section of `self.map`, `self.$len` long. Shared with
/// content segments, which use the same file layout (see `layout`).
macro_rules! sec {
    ($name:ident, $s:expr, $t:ty, $len:ident) => {
        pub fn $name(&self) -> &[$t] {
            let length = self.$len.checked_mul(std::mem::size_of::<$t>()).expect("section byte length overflow");
            let bytes = &self.map[self.off[$s as usize]..][..length];
            // Section offsets are privately owned and 64-byte aligned.
            unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const $t, self.$len) }
        }
    };
}
pub(crate) use sec;

impl Index {
    // Per distinct name: char mask, offset into `names` (u + 1 entries).
    sec!(name_mask, Sec::NameMask, u64, u);
    sec!(name_off, Sec::NameOff, u32, u1);
    sec!(names, Sec::Names, u8, names_len);
    // Per entry: its name id, kind (walk::KIND_* | walk::FLAG_*), dir id of
    // its parent, size (see size_of), mtime.
    sec!(ent_name, Sec::EntName, u32, n);
    sec!(kind, Sec::Kind, u8, n);
    sec!(parent, Sec::Parent, u32, n);
    sec!(size_raw, Sec::Size, u32, n);
    sec!(mtime, Sec::Mtime, u32, n);
    // Per dir: entry index (ascending, so parents precede children), block
    // of children, end of the whole subtree range, location prior.
    sec!(dir_entry, Sec::DirEntry, u32, d);
    sec!(dir_start, Sec::DirStart, u32, d);
    sec!(dir_len, Sec::DirLen, u32, d);
    sec!(dir_end, Sec::DirEnd, u32, d);
    sec!(dir_prior, Sec::DirPrior, i8, d);
    sec!(dir_parent, Sec::DirParent, u32, d);
    // Per distinct name, the entries carrying it (ascending): a selective
    // query visits only these instead of every entry on disk.
    sec!(name_ents_off, Sec::NameEntsOff, u32, u1);
    sec!(name_ents, Sec::NameEnts, u32, n);

    pub fn uname(&self, id: u32) -> &[u8] {
        let o = self.name_off();
        &self.names()[o[id as usize] as usize..o[id as usize + 1] as usize]
    }

    pub fn name(&self, i: usize) -> &[u8] {
        self.uname(self.ent_name()[i])
    }

    pub fn size_of(&self, i: usize) -> u64 {
        dec_size(self.size_raw()[i])
    }

    pub fn dir_of(&self, entry: u32) -> Option<u32> {
        self.dir_entry().binary_search(&entry).ok().map(|d| d as u32)
    }

    pub fn children(&self, d: u32) -> std::ops::Range<usize> {
        let s = self.dir_start()[d as usize] as usize;
        s..s + self.dir_len()[d as usize] as usize
    }

    /// Dir ids of `k`'s strict descendants: one contiguous range, since dir
    /// ids follow entry order and a subtree's entries are contiguous.
    pub fn descendants(&self, k: u32) -> std::ops::Range<u32> {
        let de = self.dir_entry();
        let (s, e) = (self.dir_start()[k as usize], self.dir_end()[k as usize]);
        de.partition_point(|&x| x < s) as u32..de.partition_point(|&x| x < e) as u32
    }

    /// Split the dir tree for parallel top-down folding: subtrees of at most
    /// ~4k dirs become chunks; the children of bigger dirs go in `upper`.
    pub fn memo_plan(&self) -> &MemoPlan {
        self.plan.get_or_init(|| {
            const CHUNK: u32 = 4096;
            let de = self.dir_entry();
            let mut p = MemoPlan { upper: Vec::new(), chunks: Vec::new() };
            let mut big = vec![0u32];
            while let Some(k) = big.pop() {
                // k's child dirs: the dirs whose entry is in k's children block.
                let (s, l) = (self.dir_start()[k as usize], self.dir_len()[k as usize]);
                let kids = de.partition_point(|&x| x < s) as u32..de.partition_point(|&x| x < s + l) as u32;
                for c in kids {
                    p.upper.push(c);
                    let r = self.descendants(c);
                    if r.end - r.start > CHUNK {
                        big.push(c)
                    } else if r.start < r.end {
                        p.chunks.push((c, r))
                    }
                }
            }
            p.chunks.sort_by_key(|c| c.1.start);
            p
        })
    }

    pub fn path(&self, i: usize, out: &mut Vec<u8>) {
        out.clear();
        let mut chain = Vec::new();
        let mut e = i as u32;
        while e != 0 {
            chain.push(e);
            e = self.dir_entry()[self.parent()[e as usize] as usize];
        }
        if chain.is_empty() {
            out.push(b'/');
        }
        for e in chain.into_iter().rev() {
            out.push(b'/');
            out.extend_from_slice(self.name(e as usize));
        }
    }

    /// Resolve an absolute path to its entry.
    pub fn lookup(&self, path: &[u8]) -> Option<u32> {
        let mut e = 0u32;
        for comp in path.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            let r = self.children(self.dir_of(e)?);
            let (mut lo, mut hi) = (r.start, r.end);
            while lo < hi {
                let mid = (lo + hi) / 2;
                if self.name(mid) < comp { lo = mid + 1 } else { hi = mid }
            }
            e = if lo < r.end && self.name(lo) == comp {
                lo as u32
            } else {
                // APFS is case-insensitive by default; callers may not be.
                r.clone().find(|&c| self.name(c).eq_ignore_ascii_case(comp))? as u32
            };
        }
        Some(e)
    }

    /// Lay listings out as blocks in DFS order and compute everything derived.
    /// Listing id 0 is the root ("/").
    pub fn build(mut ls: Vec<Listing>, event_id: u64, synced_at: u32, home: &[u8]) -> Index {
        ls.par_iter_mut().for_each(|l| {
            let names = &l.names;
            l.ents.sort_unstable_by(|a, b| {
                names[a.name_off as usize..][..a.name_len as usize].cmp(&names[b.name_off as usize..][..b.name_len as usize])
            })
        });
        let max_id = ls.iter().map(|l| l.id).max().unwrap_or(0) as usize;
        let mut by_id = vec![NONE; max_id + 1];
        for (i, l) in ls.iter().enumerate() {
            by_id[l.id as usize] = i as u32;
        }
        let n_max = 1 + ls.iter().map(|l| l.ents.len()).sum::<usize>();
        let names_max: usize = ls.iter().map(|l| l.names.len()).sum();

        // Pass 1: DFS layout into plain vectors (sizes are only upper bounds
        // until unreachable listings are known).
        let mut name_off = vec![0u32; n_max];
        let mut name_len = vec![0u16; n_max];
        let mut kind = vec![0u8; n_max];
        let mut parent = vec![0u32; n_max];
        let mut size = vec![0u64; n_max];
        let mut mtime = vec![0u32; n_max];
        let mut names = Vec::with_capacity(names_max);
        kind[0] = KIND_DIR;
        let mut pos = 1usize;
        let mut blocks: Vec<(u32, u32, u32)> = Vec::with_capacity(ls.len()); // (dir entry, start, len)
        let mut stack: Vec<(u32, u32)> = vec![(0, by_id[0])];
        let mut kids: Vec<(u32, u32)> = Vec::new();
        while let Some((e, li)) = stack.pop() {
            let l = &ls[li as usize];
            let start = pos;
            kids.clear();
            for r in &l.ents {
                name_off[pos] = names.len() as u32;
                name_len[pos] = r.name_len;
                names.extend_from_slice(&l.names[r.name_off as usize..][..r.name_len as usize]);
                kind[pos] = r.kind;
                size[pos] = r.size;
                mtime[pos] = r.mtime;
                parent[pos] = e; // entry index for now, converted below
                if let Some(&li) = by_id.get(r.child as usize).filter(|&&li| li != NONE) {
                    kids.push((pos as u32, li));
                }
                pos += 1;
            }
            blocks.push((e, start as u32, (pos - start) as u32));
            stack.extend(kids.iter().rev());
        }
        drop(ls);
        let n = pos;
        blocks.sort_unstable();
        let d = blocks.len();
        let mut dir_of = vec![NONE; n];
        for (k, b) in blocks.iter().enumerate() {
            dir_of[b.0 as usize] = k as u32;
        }
        parent[..n].par_iter_mut().for_each(|p| *p = dir_of[*p as usize]);
        parent[0] = 0;
        drop(dir_of);

        // Intern names in entry order.
        let mut ids: HashMap<&[u8], u32, Fx> = HashMap::with_capacity_and_hasher(n / 3, Fx);
        let mut ent_name = vec![0u32; n];
        let mut uoff = vec![0u32];
        let mut unames: Vec<u8> = Vec::with_capacity(names.len() / 2);
        for i in 0..n {
            let nm = &names[name_off[i] as usize..][..name_len[i] as usize];
            let next = ids.len() as u32;
            let id = *ids.entry(nm).or_insert_with(|| {
                unames.extend_from_slice(nm);
                uoff.push(unames.len() as u32);
                next
            });
            ent_name[i] = id;
        }
        let u = ids.len();
        drop(ids);
        let mut umask = vec![0u64; u];
        umask.par_iter_mut().enumerate().for_each(|(k, m)| *m = name_mask(&unames[uoff[k] as usize..uoff[k + 1] as usize]));
        let enc: Vec<u32> = size[..n].iter().map(|&s| enc_size(s)).collect();
        // Entries grouped by name (counting sort keeps them ascending).
        let mut ne_off = vec![0u32; u + 1];
        for &id in &ent_name {
            ne_off[id as usize + 1] += 1;
        }
        for k in 0..u {
            ne_off[k + 1] += ne_off[k];
        }
        let mut fill = ne_off[..u].to_vec();
        let mut ne = vec![0u32; n];
        for (i, &id) in ent_name.iter().enumerate() {
            ne[fill[id as usize] as usize] = i as u32;
            fill[id as usize] += 1;
        }
        drop(fill);

        // Subtree end: own block end, folded upward (children have larger ids).
        let dir_entry: Vec<u32> = blocks.iter().map(|b| b.0).collect();
        let mut end: Vec<u32> = blocks.iter().map(|b| b.1 + b.2).collect();
        for k in (1..d).rev() {
            let p = parent[dir_entry[k] as usize] as usize;
            end[p] = end[p].max(end[k]);
        }
        let comps: Vec<&[u8]> = home.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
        let mut prior = vec![0i8; d];
        let mut depth = vec![0u8; d];
        // How many leading components of `home` this dir's path matches;
        // u8::MAX once it diverges.
        let mut hm = vec![0u8; d];
        for k in 1..d {
            let e = dir_entry[k] as usize;
            let p = parent[e] as usize;
            let nm = &names[name_off[e] as usize..][..name_len[e] as usize];
            depth[k] = depth[p].saturating_add(1);
            hm[k] = match hm[p] {
                u8::MAX => u8::MAX,
                h if h as usize >= comps.len() => h,
                h if comps[h as usize] == nm => h + 1,
                _ => u8::MAX,
            };
            let entered_home = hm[k] as usize == comps.len() && (hm[p] as usize) < comps.len();
            let adj = prior_adjust(nm, depth[k]) + if entered_home { 15 } else { 0 };
            prior[k] = (prior[p] as i32 + adj).clamp(-100, 60) as i8;
        }

        // Write the blob.
        let (off, total) = layout(&section_lens(n, d, u, unames.len()).expect("index lengths")).expect("index layout");
        let mut m = MmapMut::map_anon(total).expect("anon map");
        let mut put = |s: Sec, v: &[u8]| m[off[s as usize]..][..v.len()].copy_from_slice(v);
        put(Sec::NameMask, as_bytes(&umask));
        put(Sec::NameOff, as_bytes(&uoff));
        put(Sec::Names, &unames);
        put(Sec::EntName, as_bytes(&ent_name));
        put(Sec::Kind, &kind[..n]);
        put(Sec::Parent, as_bytes(&parent[..n]));
        put(Sec::Size, as_bytes(&enc));
        put(Sec::Mtime, as_bytes(&mtime[..n]));
        put(Sec::DirEntry, as_bytes(&dir_entry));
        put(Sec::DirStart, as_bytes(&blocks.iter().map(|b| b.1).collect::<Vec<_>>()));
        put(Sec::DirLen, as_bytes(&blocks.iter().map(|b| b.2).collect::<Vec<_>>()));
        put(Sec::DirEnd, as_bytes(&end));
        put(Sec::DirPrior, as_bytes(&prior));
        put(Sec::DirParent, as_bytes(&dir_entry.iter().map(|&e| parent[e as usize]).collect::<Vec<_>>()));
        put(Sec::NameEntsOff, as_bytes(&ne_off));
        put(Sec::NameEnts, as_bytes(&ne));
        m[..HDR].copy_from_slice(&header(MAGIC, &[n as u64, d as u64, u as u64, unames.len() as u64, event_id, synced_at as u64]));
        Index::from_map(m.make_read_only().unwrap()).unwrap()
    }

    fn from_map(map: Mmap) -> Option<Index> {
        let [n, d, u, names_len, event_id, synced_at] = fields(&map, MAGIC)?;
        let (n, d, u, names_len) = (cache_count(n)?, cache_count(d)?, cache_count(u)?, cache_count(names_len)?);
        let synced_at = u32::try_from(synced_at).ok()?;
        let (off, total) = layout(&section_lens(n, d, u, names_len)?)?;
        if n == 0 || d == 0 || u == 0 || d > n || u > n || map.len() != total || event_id == EVENT_SINCE_NOW {
            return None;
        }
        let index = Index { n, d, u, u1: u + 1, names_len, event_id, synced_at, off, map, plan: std::sync::OnceLock::new() };
        index.valid_records().then_some(index)
    }

    /// The checked layout makes typed slices safe; these checks make their
    /// IDs, path components, and DFS ranges safe for all query consumers.
    fn valid_records(&self) -> bool {
        let (de, dp, parent, names) = (self.dir_entry(), self.dir_parent(), self.parent(), self.ent_name());
        if de[0] != 0 || dp[0] != 0 || parent[0] != 0 || names[0] != 0 || self.kind()[0] != KIND_DIR {
            return false;
        }
        if !valid_offsets(self.name_off(), self.names_len) || self.name_off()[1] != 0 {
            return false;
        }
        for k in 0..self.u {
            let name = self.uname(k as u32);
            if (k != 0 && !valid_component(name)) || self.name_mask()[k] != name_mask(name) {
                return false;
            }
        }
        for i in 0..self.n {
            let p = parent[i] as usize;
            if names[i] as usize >= self.u || p >= self.d || self.kind()[i] & !0x0f != 0 {
                return false;
            }
            if i != 0 {
                let start = self.dir_start()[p] as usize;
                let Some(end) = start.checked_add(self.dir_len()[p] as usize) else { return false };
                if names[i] == 0 || !(start..end).contains(&i) {
                    return false;
                }
            }
        }
        let mut ends = Vec::with_capacity(self.d);
        for k in 0..self.d {
            let e = de[k] as usize;
            let start = self.dir_start()[k] as usize;
            let Some(end) = start.checked_add(self.dir_len()[k] as usize) else { return false };
            if e >= self.n
                || self.kind()[e] & 3 != KIND_DIR
                || (k > 0 && (de[k - 1] >= de[k] || dp[k] as usize >= k))
                || dp[k] != parent[e]
                || start > end
                || end > self.n
            {
                return false;
            }
            let mut previous: Option<&[u8]> = None;
            for (i, &entry_parent) in parent.iter().enumerate().take(end).skip(start) {
                let name = self.name(i);
                if entry_parent != k as u32 || previous.is_some_and(|p| p >= name) {
                    return false;
                }
                previous = Some(name);
            }
            ends.push(end as u32);
        }
        let mut next = 1usize;
        let mut visited = 0usize;
        let mut stack = vec![0usize];
        while let Some(k) = stack.pop() {
            let range = self.children(k as u32);
            if range.start != next {
                return false;
            }
            next = range.end;
            visited += 1;
            let children = de.partition_point(|&e| (e as usize) < range.start)..de.partition_point(|&e| (e as usize) < range.end);
            stack.extend(children.rev());
        }
        if visited != self.d || next != self.n {
            return false;
        }
        for k in (1..self.d).rev() {
            let p = dp[k] as usize;
            ends[p] = ends[p].max(ends[k]);
        }
        if ends != self.dir_end() || !valid_offsets(self.name_ents_off(), self.n) {
            return false;
        }
        for k in 0..self.u {
            let off = self.name_ents_off();
            let group = &self.name_ents()[off[k] as usize..off[k + 1] as usize];
            if group.is_empty()
                || group.windows(2).any(|w| w[0] >= w[1])
                || group.iter().any(|&e| e as usize >= self.n || names[e as usize] != k as u32)
            {
                return false;
            }
        }
        true
    }

    /// Write atomically (tmp + rename), stamping the current event id.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        let mut f = crate::storage::open_private_file(&tmp)?;
        f.set_len(0)?;
        f.write_all(&header(MAGIC, &[self.n as u64, self.d as u64, self.u as u64, self.names_len as u64, self.event_id, self.synced_at as u64]))?;
        f.write_all(&self.map[HDR..])?;
        f.sync_data()?;
        std::fs::rename(tmp, path)
    }

    /// The event id a saved index is current as of, from its header alone.
    pub fn saved_event_id(path: &Path) -> Option<u64> {
        let mut h = [0u8; 56];
        open_cache(path, MAX_CACHE_BYTES).ok()?.file.read_exact(&mut h).ok()?;
        let event_id = fields::<6>(&h, MAGIC)?[4];
        (event_id != EVENT_SINCE_NOW).then_some(event_id)
    }

    pub fn load(path: &Path) -> Option<Index> {
        Index::from_map(read_cache(path).ok()?)
    }

    pub fn bytes(&self) -> usize {
        self.map.len()
    }

    /// Fault in the arrays every query scans so the first one is fast; the
    /// rest (sizes, mtimes, dir tables) page in on demand.
    pub fn prefault(&self) {
        let mut sum = 0u8;
        for s in [Sec::NameMask, Sec::NameOff, Sec::Names, Sec::EntName, Sec::Kind, Sec::Parent] {
            let start = self.off[s as usize];
            let end = self.off.get(s as usize + 1).copied().unwrap_or(self.map.len());
            for i in (start..end).step_by(16 * 1024) {
                sum = sum.wrapping_add(unsafe { std::ptr::read_volatile(self.map.as_ptr().add(i)) });
            }
        }
        std::hint::black_box(sum);
    }
}

/// Section files (this index, content segments): a 4 KiB header (magic,
/// then u64 fields), then the sections, each 64-byte aligned.
pub(crate) const HDR: usize = 4096;

pub(crate) fn header(magic: &[u8; 8], fields: &[u64]) -> Vec<u8> {
    let mut h = vec![0u8; HDR];
    h[..8].copy_from_slice(magic);
    for (k, v) in fields.iter().enumerate() {
        h[8 + k * 8..16 + k * 8].copy_from_slice(&v.to_le_bytes());
    }
    h
}

/// The header's fields, if `b` starts with `magic`.
pub(crate) fn fields<const N: usize>(b: &[u8], magic: &[u8; 8]) -> Option<[u64; N]> {
    (b.len() >= 8 + N * 8 && &b[..8] == magic).then(|| std::array::from_fn(|k| u64::from_le_bytes(b[8 + k * 8..16 + k * 8].try_into().unwrap())))
}

/// Section offsets for these lengths, and the file size.
pub(crate) fn layout<const N: usize>(lens: &[usize; N]) -> Option<([usize; N], usize)> {
    let mut off = [0usize; N];
    let mut at = HDR;
    for (k, &l) in lens.iter().enumerate() {
        off[k] = at;
        at = at.checked_add(l)?.checked_add(63)? & !63;
        if at > isize::MAX as usize {
            return None;
        }
    }
    Some((off, at))
}

/// A 1 GiB file limit bounds allocation before parsing. Larger cache files
/// are rejected, so raising this limit is an explicit memory-budget choice.
const MAX_CACHE_BYTES: u64 = 1 << 30;

struct CacheFile {
    file: std::fs::File,
    length: usize,
}

fn open_cache(path: &Path, limit: u64) -> std::io::Result<CacheFile> {
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid cache file type or size"));
    }
    let length = usize::try_from(metadata.len()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "cache file is too large"))?;
    Ok(CacheFile { file, length })
}

/// Cache writers rename complete files. Copy into an anonymous mapping so
/// later changes or truncation of the source cannot invalidate safe slices.
pub(crate) fn read_cache(path: &Path) -> std::io::Result<Mmap> {
    let CacheFile { mut file, length } = open_cache(path, MAX_CACHE_BYTES)?;
    let mut map = MmapMut::map_anon(length)?;
    file.read_exact(&mut map)?;
    map.make_read_only()
}

pub(crate) fn read_cache_text(path: &Path, limit: u64) -> std::io::Result<String> {
    let CacheFile { file, length } = open_cache(path, limit)?;
    let mut text = String::with_capacity(length);
    let read = file.take(length as u64).read_to_string(&mut text)?;
    if read != length {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "cache text changed while reading"));
    }
    Ok(text)
}

pub(crate) fn cache_count(value: u64) -> Option<usize> {
    usize::try_from(u32::try_from(value).ok()?).ok()
}

pub(crate) fn valid_offsets(offsets: &[u32], length: usize) -> bool {
    offsets.first() == Some(&0) && offsets.last().is_some_and(|&last| last as usize == length) && offsets.windows(2).all(|w| w[0] <= w[1])
}

fn valid_component(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.iter().any(|&b| b == 0 || b == b'/')
}

pub(crate) fn as_bytes<T: Copy>(v: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

fn section_lens(n: usize, d: usize, u: usize, names_len: usize) -> Option<[usize; NSEC]> {
    let u1 = u.checked_add(1)?;
    let sections =
        [(u, 8), (u1, 4), (names_len, 1), (n, 4), (n, 1), (n, 4), (n, 4), (n, 4), (d, 4), (d, 4), (d, 4), (d, 4), (d, 1), (d, 4), (u1, 4), (n, 4)];
    let mut lengths = [0usize; NSEC];
    for (k, (count, size)) in sections.into_iter().enumerate() {
        lengths[k] = count.checked_mul(size)?;
    }
    Some(lengths)
}

/// Sizes in 4 bytes: exact below 2 GiB, 2 MiB granularity above.
pub fn enc_size(s: u64) -> u32 {
    if s < 1 << 31 { s as u32 } else { (1 << 31) | (s >> 21).min((1 << 31) - 1) as u32 }
}

pub fn dec_size(v: u32) -> u64 {
    if v & (1 << 31) == 0 { v as u64 } else { ((v & !(1 << 31)) as u64) << 21 }
}

/// FxHash: interning 7.5M names wants a hasher cheaper than SipHash.
#[derive(Clone, Copy, Default)]
pub struct Fx;
pub struct FxH(u64);
impl std::hash::BuildHasher for Fx {
    type Hasher = FxH;
    fn build_hasher(&self) -> FxH {
        FxH(0)
    }
}
impl std::hash::Hasher for FxH {
    fn write(&mut self, bytes: &[u8]) {
        for c in bytes.chunks(8) {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            self.0 = (self.0.rotate_left(5) ^ u64::from_le_bytes(w)).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
        }
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

/// Which character classes a name contains. A query token can only match a
/// name whose mask is a superset of the token's mask, which rejects most of
/// the disk with one AND per entry.
pub fn char_mask(s: &[u8]) -> u64 {
    s.iter().fold(0, |m, &b| m | char_bit(b))
}

/// A name's mask: `char_mask`, plus in the spare high bits a hash of the
/// first byte of the name (past a leading dot) and of each space-separated
/// word: where a typo match may start (`query::typo_score`), so a search
/// rejects every other name without reading it.
pub fn name_mask(s: &[u8]) -> u64 {
    let off = (s.len() > 1 && s[0] == b'.') as usize;
    let starts = s.get(off).into_iter().chain(s.windows(2).filter(|w| w[0] == b' ').map(|w| &w[1]));
    starts.fold(char_mask(s), |m, &b| m | start_bit(b))
}

/// The `name_mask` bit for a word starting with `b` (bits 41..64).
#[inline]
pub fn start_bit(b: u8) -> u64 {
    1 << (41 + b.to_ascii_lowercase() % 23)
}

#[inline]
pub fn char_bit(b: u8) -> u64 {
    match b {
        b'a'..=b'z' => 1 << (b - b'a'),
        b'A'..=b'Z' => 1 << (b - b'A'),
        b'0'..=b'9' => 1 << (26 + b - b'0'),
        b'.' => 1 << 36,
        b'-' | b'_' => 1 << 37,
        b' ' => 1 << 38,
        0x80.. => 1 << 39,
        _ => 1 << 40,
    }
}

#[rustfmt::skip]
const BUNDLE_EXTS: &[&[u8]] = &[
    b".framework", b".bundle", b".plugin", b".appex", b".kext", b".xpc", b".lproj", b".xcassets", b".photoslibrary",
    b".musiclibrary", b".tvlibrary", b".imovielibrary", b".dSYM", b".xcarchive", b".sdk", b".platform",
];

/// How much a directory's name moves everything under it in ranking.
fn prior_adjust(name: &[u8], depth: u8) -> i32 {
    if depth == 1 {
        return match name {
            b"Users" => 0,
            b"Applications" => 10,
            b"Volumes" => -10,
            b"Library" => -25,
            b"System" => -40,
            b"opt" => -25,
            _ => -35,
        };
    }
    if name == b"Applications" {
        return 30;
    }
    if name.ends_with(b".app") {
        return -25;
    }
    if BUNDLE_EXTS.iter().any(|x| name.len() > x.len() && name[name.len() - x.len()..].eq_ignore_ascii_case(x)) {
        return -20;
    }
    if name.first() == Some(&b'.') {
        return -25;
    }
    match name {
        b"Library" => -20,
        b"Caches" | b"caches" | b"cache" | b"Cache" | b"Logs" | b"DerivedData" | b"CoreSimulator" => -20,
        b"node_modules" | b"__pycache__" | b"site-packages" | b"Pods" | b"venv" | b"bower_components" => -30,
        b"target" | b"build" | b"dist" | b"out" | b"vendor" | b"deps" | b"tmp" | b"temp" => -12,
        b"folders" | b"Containers" | b"Group Containers" => -10,
        b"Application Support" => -5,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walk::{KIND_FILE, RawEnt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fixture_path() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("fsearch-index-tests-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&dir).unwrap();
        dir.join("index.bin")
    }

    fn listing(id: u32, entries: &[(&[u8], u8, u32)]) -> Listing {
        let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
        for &(name, kind, child) in entries {
            l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, child, size: 12, mtime: 123 });
            l.names.extend_from_slice(name);
        }
        l
    }

    fn fixture() -> Index {
        Index::build(
            vec![
                listing(0, &[(b"folder", KIND_DIR, 1), (b"readme.txt", KIND_FILE, NONE)]),
                listing(1, &[(b"alpha.txt", KIND_FILE, NONE), (b"nested", KIND_DIR, 2)]),
                listing(2, &[(b"last.txt", KIND_FILE, NONE), (b"readme.txt", KIND_FILE, NONE)]),
            ],
            42,
            123,
            b"/folder",
        )
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn cache_roundtrip_preserves_lookup_and_tree_ranges() {
        // Given a saved index with a nested directory and distinct names.
        let path = fixture_path();
        let original = fixture();
        original.save(&path).unwrap();
        assert_eq!(original.lookup(b"/folder/nested/last.txt"), Some(5));
        // When the production loader reads the saved cache.
        let loaded = Index::load(&path).expect("valid cache must load");
        // Then paths, subtree bounds, and the source event remain correct.
        let mut out = Vec::new();
        loaded.path(5, &mut out);
        assert_eq!(out, b"/folder/nested/last.txt");
        assert_eq!(loaded.lookup(&out), Some(5));
        assert_eq!(loaded.children(0), 1..3);
        assert_eq!(loaded.descendants(0), 1..3);
        assert_eq!(loaded.event_id, 42);
        assert_eq!(loaded.memo_plan().upper, vec![1]);
        let name_id = loaded.ent_name()[2] as usize;
        assert_eq!(&loaded.name_ents()[loaded.name_ents_off()[name_id] as usize..loaded.name_ents_off()[name_id + 1] as usize], &[2, 6]);
    }

    #[test]
    fn cache_root_only_tree_loads_and_searches() {
        // Given a saved index with no files or child directories.
        let path = fixture_path();
        Index::build(vec![listing(0, &[])], 0, 0, b"/").save(&path).unwrap();
        // When the production loader reads the root-only cache.
        let loaded = Index::load(&path).expect("root-only cache must load");
        // Then the root is available and all child ranges are empty.
        assert_eq!((loaded.n, loaded.d, loaded.u), (1, 1, 1));
        assert_eq!(loaded.lookup(b"/"), Some(0));
        assert_eq!(loaded.lookup(b"/missing"), None);
        assert_eq!(loaded.children(0), 1..1);
        assert_eq!(loaded.descendants(0), 1..1);
        assert!(loaded.memo_plan().upper.is_empty());
    }

    #[test]
    fn cache_loader_rejects_truncated_and_invalid_header_counts() {
        let original = fixture();
        for (label, field, value) in [
            ("zero entries", 0, 0),
            ("zero directories", 1, 0),
            ("zero names", 2, 0),
            ("oversized count", 2, u64::MAX),
            ("timestamp overflow", 5, u32::MAX as u64 + 1),
        ] {
            // Given a valid saved cache with one invalid header count.
            let path = fixture_path();
            original.save(&path).unwrap();
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[8 + field * 8..16 + field * 8].copy_from_slice(&value.to_le_bytes());
            std::fs::write(&path, bytes).unwrap();
            // When the production loader reads that cache.
            let loaded = Index::load(&path);
            // Then it rejects the cache before any consumer can use it.
            assert!(loaded.is_none(), "accepted cache with {label}");
        }
        for length in [7, HDR - 1, original.bytes() - 1] {
            // Given a cache that ends before its full serialized layout.
            let path = fixture_path();
            original.save(&path).unwrap();
            std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(length as u64).unwrap();
            // When the production loader reads that cache.
            let loaded = Index::load(&path);
            // Then it rejects the incomplete cache.
            assert!(loaded.is_none(), "accepted cache truncated to {length} bytes");
        }
    }

    #[test]
    fn cache_loader_rejects_invalid_record_offsets_ids_and_order() {
        let original = fixture();
        let edits = [
            ("name offset", Sec::NameOff, 1, u32::MAX),
            ("entry name id", Sec::EntName, 1, original.u as u32),
            ("parent id", Sec::Parent, 1, original.d as u32),
            ("directory entry id", Sec::DirEntry, 1, original.n as u32),
            ("directory cycle", Sec::DirParent, 1, 1),
            ("child range", Sec::DirLen, 0, u32::MAX),
            ("subtree range", Sec::DirEnd, 0, 3),
            ("DFS block order", Sec::DirStart, 1, 1),
            ("name posting offset", Sec::NameEntsOff, 1, u32::MAX),
            ("name posting id", Sec::NameEnts, 1, original.n as u32),
            ("name posting order", Sec::NameEnts, original.name_ents_off()[original.ent_name()[2] as usize] as usize + 1, 2),
            ("sibling order", Sec::EntName, 1, original.ent_name()[2]),
        ];
        for (label, section, element, value) in edits {
            // Given a saved cache with one invalid record or range.
            let path = fixture_path();
            original.save(&path).unwrap();
            let mut bytes = std::fs::read(&path).unwrap();
            put_u32(&mut bytes, original.off[section as usize] + element * 4, value);
            std::fs::write(&path, bytes).unwrap();
            // When the production loader reads that cache.
            let loaded = Index::load(&path);
            // Then it rejects the invalid storage representation.
            assert!(loaded.is_none(), "accepted invalid {label}");
        }
    }

    #[test]
    fn cache_loader_rejects_invalid_name_components_and_masks() {
        let original = fixture();
        for (label, section, byte) in [("path separator", Sec::Names, b'/'), ("NUL", Sec::Names, 0), ("character mask", Sec::NameMask, 0)] {
            // Given a saved index with invalid name bytes or a mismatched mask.
            let path = fixture_path();
            original.save(&path).unwrap();
            let mut bytes = std::fs::read(&path).unwrap();
            let offset = original.off[section as usize] + if matches!(section, Sec::NameMask) { 8 } else { 0 };
            bytes[offset] = byte;
            std::fs::write(&path, bytes).unwrap();
            // When the production loader reads that cache.
            let loaded = Index::load(&path);
            // Then the invalid component cannot become a filesystem path.
            assert!(loaded.is_none(), "accepted invalid {label}");
        }
    }

    #[test]
    fn cache_loader_rejects_symlinks_and_oversized_files() {
        // Given a valid cache reached through a symbolic link.
        let path = fixture_path();
        fixture().save(&path).unwrap();
        let link = path.with_extension("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        // When the production loader opens that path.
        let loaded = Index::load(&link);
        // Then it rejects the indirect file.
        assert!(loaded.is_none(), "accepted a symbolic-link cache");
        assert_eq!(Index::saved_event_id(&link), None);

        // Given a cache with a declared file length above the 1 GiB bound.
        std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len((1 << 30) + 1).unwrap();
        // When the production loader reads that file.
        let loaded = Index::load(&path);
        // Then it rejects the file before allocating its cache buffer.
        assert!(loaded.is_none(), "accepted an oversized cache");
    }

    #[test]
    fn cache_loader_and_header_reader_reject_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        // Given a FIFO in place of a saved cache file.
        let path = fixture_path();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        // When both production read paths try to load it.
        let loaded = Index::load(&path);
        let event = Index::saved_event_id(&path);
        // Then both return immediately with an invalid-cache result.
        assert!(loaded.is_none());
        assert_eq!(event, None);
    }

    #[test]
    fn cache_loader_and_header_reader_reject_reserved_event_id() {
        // Given a valid saved cache whose event ID is changed to the reserved SinceNow value.
        let path = fixture_path();
        fixture().save(&path).unwrap();
        assert_eq!(Index::saved_event_id(&path), Some(42));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();
        // When the production full-cache and header-only readers load that file.
        let loaded_event = Index::load(&path).map(|index| index.event_id);
        let header_event = Index::saved_event_id(&path);
        // Then both reject the reserved value so startup can rebuild and replay history.
        assert_eq!((loaded_event, header_event), (None, None));
    }

    #[test]
    fn cache_save_rejects_a_planted_temporary_symlink() {
        // Given a generated target file and a temporary-cache symlink to that target.
        let path = fixture_path();
        let target = path.with_extension("target");
        std::fs::write(&target, b"keep these target bytes").unwrap();
        std::os::unix::fs::symlink(&target, path.with_extension("tmp")).unwrap();
        // When the production index writer saves through that temporary path.
        let result = fixture().save(&path);
        // Then it rejects the save and leaves the target bytes unchanged.
        assert!(result.is_err(), "accepted a symbolic-link temporary cache");
        assert_eq!(std::fs::read(target).unwrap(), b"keep these target bytes");
    }

    #[test]
    #[should_panic(expected = "section byte length overflow")]
    fn cache_sections_reject_an_invalid_public_entry_count() {
        // Given a valid index whose public count is changed after construction.
        let mut index = fixture();
        assert_eq!(index.size_raw().len(), 7);
        index.n = usize::MAX;
        // When a safe caller asks for the corresponding typed section.
        // Then the accessor fails with the stated bounds error before creating a raw slice.
        index.size_raw();
    }

    #[test]
    fn cache_loaded_index_survives_source_file_truncation() {
        // Given a valid cache that has been loaded into stable memory.
        let path = fixture_path();
        fixture().save(&path).unwrap();
        let loaded = Index::load(&path).unwrap();
        assert_eq!(loaded.lookup(b"/folder/nested/last.txt"), Some(5));
        // When another writer truncates the original file.
        std::fs::OpenOptions::new().write(true).open(&path).unwrap().set_len(0).unwrap();
        // Then the loaded index still returns its complete saved path.
        let mut out = Vec::new();
        loaded.path(5, &mut out);
        assert_eq!(out, b"/folder/nested/last.txt");
        assert_eq!(loaded.lookup(&out), Some(5));
    }

    #[test]
    fn cache_roundtrip_preserves_paths_deeper_than_256_directories() {
        // Given a saved valid tree with 300 ancestor directories.
        let path = fixture_path();
        let mut listings: Vec<Listing> = (0..300).map(|id| listing(id, &[(b"x", KIND_DIR, id + 1)])).collect();
        listings.push(listing(300, &[(b"leaf.txt", KIND_FILE, NONE)]));
        let expected = format!("{}/leaf.txt", "/x".repeat(300)).into_bytes();
        Index::build(listings, 0, 0, b"/").save(&path).unwrap();
        // When the production loader reconstructs the leaf path.
        let loaded = Index::load(&path).unwrap();
        let mut out = Vec::new();
        loaded.path(301, &mut out);
        // Then all ancestor components survive and lookup finds the same leaf.
        assert_eq!(out, expected);
        assert_eq!(loaded.lookup(&out), Some(301));
    }

    #[test]
    fn cache_large_tree_search_uses_valid_parallel_ancestor_ranges() {
        use crate::live::Live;
        use crate::query::{FULL_PASS, Query, Searcher};
        // Given more than 4,096 directories, nested branches, and an empty root sibling.
        let path = fixture_path();
        let mut listings = vec![listing(0, &[(b"selected", KIND_DIR, 1), (b"empty", KIND_DIR, 2)]), listing(2, &[])];
        let branches: Vec<Vec<u8>> = (0..4100).map(|i| format!("branch-{i:04}").into_bytes()).collect();
        let entries: Vec<(&[u8], u8, u32)> = branches.iter().enumerate().map(|(i, name)| (name.as_slice(), KIND_DIR, i as u32 + 3)).collect();
        listings.push(listing(1, &entries));
        for i in 0..4100 {
            let mut children: Vec<(&[u8], u8, u32)> = vec![(b"readme.txt", KIND_FILE, NONE)];
            if i % 10 == 0 {
                children.push((b"nested", KIND_DIR, 5000 + i));
                listings.push(listing(5000 + i, &[(b"leaf.txt", KIND_FILE, NONE)]));
            }
            listings.push(listing(3 + i, &children));
        }
        Index::build(listings, 0, 0, b"/").save(&path).unwrap();
        let live = Live::new(Index::load(&path).expect("valid large cache must load"));
        assert!(live.base.memo_plan().upper.len() > 4096);
        assert_eq!(live.base.memo_plan().chunks.len(), 410);
        let query = Query::parse("selected leaf limit:200", "/").unwrap();
        // When a full search folds directory tokens through the parallel memo ranges.
        FULL_PASS.store(true, Ordering::Relaxed);
        let hits = Searcher { live: &live }.search(&query);
        FULL_PASS.store(false, Ordering::Relaxed);
        // Then the ordered result paths exactly match the expected first 200 files.
        let actual: Vec<Vec<u8>> = hits
            .into_iter()
            .map(|hit| {
                let mut path = Vec::new();
                live.base.path(hit.idx as usize, &mut path);
                path
            })
            .collect();
        let expected: Vec<Vec<u8>> = (0..200).map(|i| format!("/selected/branch-{:04}/nested/leaf.txt", i * 10).into_bytes()).collect();
        assert_eq!(actual, expected);
    }
}
