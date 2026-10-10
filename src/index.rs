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
use std::io::Write;
use std::path::Path;

const MAGIC: &[u8; 8] = b"FSIDX007";

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
            unsafe { std::slice::from_raw_parts(self.map.as_ptr().add(self.off[$s as usize]) as *const $t, self.$len) }
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
        let mut chain = [0u32; 256];
        let mut deep = Vec::new();
        let mut k = 0;
        let mut e = i as u32;
        // No real chain is longer than the entry count: a corrupt index
        // whose parents loop is cut off there, not followed forever.
        while e != 0 && k + deep.len() < self.n {
            if k < chain.len() {
                chain[k] = e;
                k += 1;
            } else {
                deep.push(e);
            }
            e = self.dir_entry()[self.parent()[e as usize] as usize];
        }
        if k == 0 {
            out.push(b'/');
        }
        for &d in deep.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(self.name(d as usize));
        }
        for j in (0..k).rev() {
            out.push(b'/');
            out.extend_from_slice(self.name(chain[j] as usize));
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
        let (off, total) = layout(&section_lens(n, d, u, unames.len()));
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
        let [n, d, u, names_len, event_id, synced_at] = fields(&map, MAGIC)?.map(|v| v as usize);
        // Each count takes at least a byte per item, so a corrupt header
        // can't make the section sizes below overflow.
        if [n, d, u, names_len].iter().any(|&c| c > map.len()) {
            return None;
        }
        let (off, total) = layout(&section_lens(n, d, u, names_len));
        if map.len() < total {
            return None;
        }
        let idx = Index {
            n,
            d,
            u,
            u1: u + 1,
            names_len,
            event_id: event_id as u64,
            synced_at: synced_at as u32,
            off,
            map,
            plan: std::sync::OnceLock::new(),
        };
        idx.ids_in_range().then_some(idx)
    }

    /// Every id a section holds points inside the section it indexes, so a
    /// corrupt file is refused here rather than panicking at a lookup.
    fn ids_in_range(&self) -> bool {
        let (n, d, u) = (self.n as u32, self.d as u32, self.u as u32);
        let monotonic = |v: &[u32], max: usize| v.windows(2).all(|w| w[0] <= w[1]) && v.last().is_none_or(|&x| x as usize <= max);
        monotonic(self.name_off(), self.names_len)
            && monotonic(self.name_ents_off(), self.n)
            && self.ent_name().iter().all(|&x| x < u)
            && self.parent().iter().all(|&x| x < d.max(1))
            && self.dir_entry().iter().all(|&x| x < n)
            && self.dir_parent().iter().all(|&x| x < d)
            && self.dir_end().iter().all(|&x| x <= n)
            && self.dir_start().iter().zip(self.dir_len()).all(|(&s, &l)| s as u64 + l as u64 <= n as u64)
            && self.name_ents().iter().all(|&x| x < n)
    }

    /// Write atomically (tmp + rename), stamping the current event id.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&header(MAGIC, &[self.n as u64, self.d as u64, self.u as u64, self.names_len as u64, self.event_id, self.synced_at as u64]))?;
        f.write_all(&self.map[HDR..])?;
        f.sync_data()?;
        std::fs::rename(tmp, path)
    }

    /// The event id a saved index is current as of, from its header alone.
    pub fn saved_event_id(path: &Path) -> Option<u64> {
        use std::io::Read;
        let mut h = [0u8; 56];
        std::fs::File::open(path).ok()?.read_exact(&mut h).ok()?;
        fields::<6>(&h, MAGIC).map(|f| f[4])
    }

    pub fn load(path: &Path) -> Option<Index> {
        let f = std::fs::File::open(path).ok()?;
        Index::from_map(unsafe { Mmap::map(&f) }.ok()?)
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
pub(crate) fn layout<const N: usize>(lens: &[usize; N]) -> ([usize; N], usize) {
    let mut off = [0usize; N];
    let mut at = HDR;
    for (k, &l) in lens.iter().enumerate() {
        off[k] = at;
        at = (at + l + 63) & !63;
    }
    (off, at)
}

pub(crate) fn as_bytes<T: Copy>(v: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

fn section_lens(n: usize, d: usize, u: usize, names_len: usize) -> [usize; NSEC] {
    [u * 8, (u + 1) * 4, names_len, n * 4, n, n * 4, n * 4, n * 4, d * 4, d * 4, d * 4, d * 4, d, d * 4, (u + 1) * 4, n * 4]
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
pub(crate) mod tests {
    use super::*;
    use crate::walk::tests::Tmp;
    use crate::walk::{FLAG_HIDDEN, KIND_FILE, KIND_LINK, RawEnt};

    const F: u8 = KIND_FILE;
    const D: u8 = KIND_DIR;

    /// A listing from (name, kind, size, child listing id or NONE).
    pub(crate) fn lst(id: u32, ents: &[(&[u8], u8, u64, u32)]) -> Listing {
        let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
        for (k, &(name, kind, size, child)) in ents.iter().enumerate() {
            l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, size, mtime: 1000 + k as u32, child });
            l.names.extend_from_slice(name);
        }
        l
    }

    fn sample() -> Index {
        let ls = vec![
            lst(0, &[(b"b.txt", F, 10, NONE), (b"Users", D, 0, 1), (b"Applications", D, 0, 2), (b"a", F | FLAG_HIDDEN, 3 << 30, NONE)]),
            lst(1, &[(b"me", D, 0, 3)]),
            lst(3, &[(b"notes.txt", F, 7, NONE), (b"Library", D, 0, 4), (b"X.app", D, 0, NONE), (b"\xff\xfe", F, 1, NONE)]),
            lst(4, &[]),
            lst(2, &[(b"Foo.app", D, 0, 5), (b"ln", KIND_LINK, 4, NONE)]),
            lst(5, &[(b"notes.txt", F, 8, NONE)]),
            // Unreachable: nothing points at it.
            lst(9, &[(b"ghost", F, 1, NONE)]),
        ];
        Index::build(ls, 42, 77, b"/Users/me")
    }

    fn all_paths(idx: &Index) -> Vec<Vec<u8>> {
        let mut p = Vec::new();
        (0..idx.n)
            .map(|i| {
                idx.path(i, &mut p);
                p.clone()
            })
            .collect()
    }

    #[test]
    fn build_layout_and_lookup() {
        let idx = sample();
        assert_eq!((idx.n, idx.d, idx.event_id, idx.synced_at), (13, 6, 42, 77));
        let paths = all_paths(&idx);
        assert_eq!(paths[0], b"/");
        assert!(!paths.iter().any(|p| p.ends_with(b"ghost")));
        for (i, p) in paths.iter().enumerate() {
            assert_eq!(idx.lookup(p), Some(i as u32), "{}", String::from_utf8_lossy(p));
        }
        assert_eq!(idx.lookup(b""), Some(0));
        assert_eq!(idx.lookup(b"//Users//me/"), idx.lookup(b"/Users/me"));
        assert_eq!(idx.lookup(b"/users/ME/NOTES.txt"), idx.lookup(b"/Users/me/notes.txt"));
        assert_eq!(idx.lookup(b"/Users/me/notes"), None);
        assert_eq!(idx.lookup(b"/Users/mee"), None);
        assert_eq!(idx.lookup(b"/b.txt/x"), None, "a file has no children");
        assert_eq!(idx.lookup(b"/Users/me/X.app/y"), None, "a dir without a listing has none either");
        assert_eq!(idx.lookup(b"/Users/me/\xff\xfe").map(|e| idx.name(e as usize)), Some(&b"\xff\xfe"[..]));

        let a = idx.lookup(b"/a").unwrap() as usize;
        assert_eq!((idx.kind()[a], idx.size_of(a)), (F | FLAG_HIDDEN, 3 << 30));
        let n = idx.lookup(b"/Applications/Foo.app/notes.txt").unwrap() as usize;
        assert_eq!((idx.size_of(n), idx.mtime()[n]), (8, 1000));

        // Children blocks are sorted and contiguous; parent/dir tables agree.
        for d in 0..idx.d as u32 {
            let r = idx.children(d);
            assert!(r.clone().zip(r.clone().skip(1)).all(|(x, y)| idx.name(x) < idx.name(y)));
            for c in r {
                assert_eq!(idx.parent()[c], d);
            }
            assert_eq!(idx.dir_of(idx.dir_entry()[d as usize]), Some(d));
            if d > 0 {
                assert_eq!(idx.dir_parent()[d as usize], idx.parent()[idx.dir_entry()[d as usize] as usize]);
            }
        }
        assert_eq!(idx.dir_of(idx.lookup(b"/b.txt").unwrap()), None);
        assert_eq!(idx.dir_of(idx.lookup(b"/Users/me/X.app").unwrap()), None);

        // Subtree ranges: /Users/me's range is exactly the entries under it.
        let me = idx.dir_of(idx.lookup(b"/Users/me").unwrap()).unwrap();
        let (s, e) = (idx.dir_start()[me as usize] as usize, idx.dir_end()[me as usize] as usize);
        let under: Vec<usize> = (0..idx.n).filter(|&i| paths[i].starts_with(b"/Users/me/")).collect();
        assert_eq!(under, (s..e).collect::<Vec<_>>());
        let lib = idx.dir_of(idx.lookup(b"/Users/me/Library").unwrap()).unwrap();
        assert_eq!(idx.descendants(me), lib..lib + 1);
        assert_eq!(idx.descendants(0), 1..idx.d as u32);
        assert!(idx.children(lib).is_empty());

        // Interned names: both notes.txt share one id, entries listed ascending.
        let id = idx.ent_name()[n];
        let o = idx.name_ents_off();
        let ents = &idx.name_ents()[o[id as usize] as usize..o[id as usize + 1] as usize];
        assert_eq!(ents.len(), 2);
        assert!(ents[0] < ents[1]);
        assert_eq!(idx.uname(id), b"notes.txt");
        assert_eq!(idx.name_mask()[id as usize], name_mask(b"notes.txt"));
        assert_eq!(o[idx.u] as usize, idx.n);
        assert!(idx.bytes() >= HDR);
        idx.prefault();
    }

    #[test]
    fn priors() {
        let idx = sample();
        let prior = |p: &[u8]| idx.dir_prior()[idx.dir_of(idx.lookup(p).unwrap()).unwrap() as usize];
        assert_eq!(prior(b"/"), 0);
        assert_eq!(prior(b"/Users"), 0);
        assert_eq!(prior(b"/Users/me"), 15, "entering home");
        assert_eq!(prior(b"/Users/me/Library"), -5);
        assert_eq!(prior(b"/Applications"), 10);
        assert_eq!(prior(b"/Applications/Foo.app"), -15);
        // No home: nothing is boosted.
        let idx = Index::build(vec![lst(0, &[(b"Users", D, 0, 1)]), lst(1, &[(b"me", D, 0, 2)]), lst(2, &[])], 0, 0, b"");
        assert_eq!(idx.dir_prior(), [0, 0, 0]);

        assert_eq!(prior_adjust(b"System", 1), -40);
        assert_eq!(prior_adjust(b"anything", 1), -35);
        assert_eq!(prior_adjust(b"Volumes", 1), -10);
        assert_eq!(prior_adjust(b"Library", 1), -25);
        assert_eq!(prior_adjust(b"opt", 1), -25);
        assert_eq!(prior_adjust(b"Applications", 3), 30);
        assert_eq!(prior_adjust(b"Foo.FRAMEWORK", 3), -20);
        assert_eq!(prior_adjust(b".framework", 3), -25, "a bare extension is a dotfile, not a bundle");
        assert_eq!(prior_adjust(b".git", 3), -25);
        assert_eq!(prior_adjust(b"node_modules", 3), -30);
        assert_eq!(prior_adjust(b"Caches", 3), -20);
        assert_eq!(prior_adjust(b"Library", 3), -20);
        assert_eq!(prior_adjust(b"target", 3), -12);
        assert_eq!(prior_adjust(b"Containers", 3), -10);
        assert_eq!(prior_adjust(b"Application Support", 3), -5);
        assert_eq!(prior_adjust(b"src", 3), 0);
        // Clamped at -100 however deep the penalties stack.
        let mut ls: Vec<Listing> = (0..10u32).map(|k| lst(k, &[(b"node_modules", D, 0, k + 1)])).collect();
        ls.push(lst(10, &[]));
        let idx = Index::build(ls, 0, 0, b"");
        assert_eq!(*idx.dir_prior().iter().min().unwrap(), -100);
    }

    #[test]
    fn size_encoding() {
        for s in [0, 1, 4096, (1 << 31) - 1] {
            assert_eq!(dec_size(enc_size(s)), s);
        }
        assert_eq!(dec_size(enc_size(1 << 31)), 1 << 31);
        // 2 MiB granularity above 2 GiB, rounding down.
        let s = (5u64 << 30) + 12345;
        assert_eq!(dec_size(enc_size(s)), 5 << 30);
        // Saturates instead of wrapping; re-encoding is stable.
        assert_eq!(dec_size(enc_size(u64::MAX)), ((1u64 << 31) - 1) << 21);
        for s in [0, 77, 1 << 31, (9 << 30) + 1, u64::MAX] {
            assert_eq!(enc_size(dec_size(enc_size(s))), enc_size(s));
        }
        assert!(enc_size(3 << 31) > enc_size((1 << 31) - 1), "order preserved across the switch");
    }

    #[test]
    fn masks() {
        assert_eq!(char_mask(b"aZ9.-_ \xc3!"), 1 | 1 << 25 | 1 << 35 | 1 << 36 | 1 << 37 | 1 << 38 | 1 << 39 | 1 << 40);
        assert_eq!(char_bit(b'A'), char_bit(b'a'));
        assert_eq!(name_mask(b""), 0);
        assert_eq!(name_mask(b"."), char_bit(b'.') | start_bit(b'.'));
        assert_eq!(name_mask(b".bashrc"), char_mask(b".bashrc") | start_bit(b'b'));
        assert_eq!(name_mask(b"My file"), char_mask(b"My file") | start_bit(b'm') | start_bit(b'f'));
        assert_eq!(start_bit(b'M'), start_bit(b'm'));
        assert!((0..=255u8).all(|b| start_bit(b) >= 1 << 41));
    }

    #[test]
    fn fx_hasher() {
        use std::hash::{BuildHasher, Hasher};
        let h = |b: &[u8]| {
            let mut s = Fx.build_hasher();
            s.write(b);
            s.finish()
        };
        assert_ne!(h(b"abcdefghij"), h(b"abcdefghik"));
        assert_eq!(h(b"same"), h(b"same"));
    }

    #[test]
    fn memo_plan_covers_every_dir() {
        // Root -> big (5000 empty dirs) and small (a chain of three).
        let mut ls = vec![lst(0, &[(b"big", D, 0, 1), (b"small", D, 0, 2)]), lst(2, &[(b"s1", D, 0, 3)]), lst(3, &[(b"s2", D, 0, 4)]), lst(4, &[])];
        let names: Vec<Vec<u8>> = (0..5000).map(|k| format!("d{k:04}").into_bytes()).collect();
        let kids: Vec<(&[u8], u8, u64, u32)> = names.iter().enumerate().map(|(k, n)| (n.as_slice(), D, 0, 10 + k as u32)).collect();
        ls.push(lst(1, &kids));
        ls.extend((0..5000).map(|k| lst(10 + k, &[])));
        let idx = Index::build(ls, 0, 0, b"");
        assert_eq!(idx.d, 5005);
        let p = idx.memo_plan();
        let mut seen = vec![0u32; idx.d];
        for &c in &p.upper {
            seen[c as usize] += 1;
        }
        for (c, r) in &p.chunks {
            assert_eq!(idx.descendants(*c), r.clone());
            for k in r.clone() {
                seen[k as usize] += 1;
            }
        }
        assert_eq!(seen[0], 0);
        assert!(seen[1..].iter().all(|&s| s == 1));
        assert!(p.chunks.windows(2).all(|w| w[0].1.start < w[1].1.start));
        assert!(std::ptr::eq(p, idx.memo_plan()), "computed once");
    }

    #[test]
    fn deep_paths() {
        // Deeper than path()'s fixed ancestor buffer (256).
        let mut ls: Vec<Listing> = (0..300u32).map(|k| lst(k, &[(b"d", D, 0, k + 1)])).collect();
        ls.push(lst(300, &[(b"leaf", F, 1, NONE)]));
        let idx = Index::build(ls, 0, 0, b"");
        let mut want = b"/d".repeat(300);
        want.extend_from_slice(b"/leaf");
        let leaf = idx.lookup(&want).unwrap();
        let mut p = Vec::new();
        idx.path(leaf as usize, &mut p);
        assert_eq!(p, want);
    }

    /// Ids inside the sections are checked at load too: an out-of-range one
    /// is refused, not a panic at the first lookup that follows it.
    #[test]
    fn load_rejects_out_of_range_ids() {
        let t = Tmp::new("idx-ids");
        let idx = Index::build(vec![lst(0, &[(b"a", D, 0, 1)]), lst(1, &[(b"f", F, 1, NONE)])], 0, 0, b"");
        let path = t.p("index.bin");
        idx.save(&path).unwrap();
        let f = idx.lookup(b"/a/f").unwrap() as usize;
        let corrupt = |sec: &[u32], i: usize, v: u32| {
            let at = sec.as_ptr() as usize - idx.map.as_ptr() as usize + i * 4;
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[at..at + 4].copy_from_slice(&v.to_ne_bytes());
            let bad = t.p("bad.bin");
            std::fs::write(&bad, bytes).unwrap();
            Index::load(&bad).is_none()
        };
        assert!(corrupt(idx.parent(), f, idx.d as u32), "parent past the last dir");
        assert!(corrupt(idx.ent_name(), f, idx.u as u32), "name id past the last name");
        assert!(corrupt(idx.dir_entry(), 1, idx.n as u32), "dir entry past the last entry");
        assert!(corrupt(idx.dir_len(), 0, idx.n as u32), "children past the last entry");
        assert!(corrupt(idx.name_off(), 1, u32::MAX), "name offset past the names");
        assert!(corrupt(idx.name_ents(), 0, idx.n as u32), "name's entry past the last entry");
    }

    /// A corrupt index whose parent links loop must not recurse forever: a
    /// stack overflow would crash the daemon on every start.
    #[test]
    fn path_survives_a_parent_cycle() {
        let t = Tmp::new("idx-cycle");
        let idx = Index::build(vec![lst(0, &[(b"a", D, 0, 1)]), lst(1, &[(b"f", F, 1, NONE)])], 0, 0, b"");
        let path = t.p("index.bin");
        idx.save(&path).unwrap();
        let a = idx.lookup(b"/a").unwrap() as usize;
        let da = idx.dir_of(a as u32).unwrap();
        // Make /a's parent folder /a itself.
        let at = idx.parent().as_ptr() as usize - idx.map.as_ptr() as usize + a * 4;
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[at..at + 4].copy_from_slice(&da.to_ne_bytes());
        std::fs::write(&path, bytes).unwrap();
        let bad = Index::load(&path).unwrap();
        let mut p = Vec::new();
        bad.path(a, &mut p);
        assert!(p.len() <= (bad.n + 1) * 3, "a cycle is cut off, not followed");
    }

    #[test]
    fn save_load() {
        let t = Tmp::new("idx");
        let idx = sample();
        let path = t.p("index.bin");
        assert_eq!(Index::saved_event_id(&path), None);
        assert!(Index::load(&path).is_none());
        idx.save(&path).unwrap();
        assert!(!t.p("index.tmp").exists());
        assert_eq!(Index::saved_event_id(&path), Some(42));
        let back = Index::load(&path).unwrap();
        assert_eq!((back.n, back.d, back.u, back.event_id, back.synced_at), (idx.n, idx.d, idx.u, 42, 77));
        assert_eq!(all_paths(&back), all_paths(&idx));
        assert_eq!(back.size_raw(), idx.size_raw());
        assert_eq!(back.dir_prior(), idx.dir_prior());
        assert_eq!(back.name_ents(), idx.name_ents());
        assert_eq!(back.bytes(), idx.bytes());
        // A loaded index saves again byte for byte.
        back.save(&t.p("again.bin")).unwrap();
        assert_eq!(std::fs::read(t.p("again.bin")).unwrap(), std::fs::read(&path).unwrap());
    }

    #[test]
    fn load_rejects_bad_files() {
        let t = Tmp::new("bad");
        sample().save(&t.p("good")).unwrap();
        let good = std::fs::read(t.p("good")).unwrap();
        let try_load = |bytes: &[u8]| {
            std::fs::write(t.p("f"), bytes).unwrap();
            (Index::load(&t.p("f")).is_some(), Index::saved_event_id(&t.p("f")))
        };
        assert_eq!(try_load(&good), (true, Some(42)));
        assert_eq!(try_load(b""), (false, None));
        assert_eq!(try_load(&good[..40]), (false, None));
        assert_eq!(try_load(&good[..HDR]), (false, Some(42)), "header only");
        assert_eq!(try_load(&good[..good.len() - 1]), (false, Some(42)), "truncated");
        let mut wrong = good.clone();
        wrong[7] = b'6';
        assert_eq!(try_load(&wrong), (false, None), "old format version");
        // Counts so large the section sizes overflow must not wrap into a
        // layout that "fits" the file.
        for n in [u64::MAX, u64::MAX / 4 + 1, 1 << 62, 1 << 61] {
            for field in [8, 16, 24, 32] {
                let mut huge = good.clone();
                huge[field..field + 8].copy_from_slice(&n.to_le_bytes());
                assert!(!try_load(&huge).0, "field {field} = {n}");
            }
        }
    }

    #[test]
    fn build_from_scan() {
        let t = Tmp::new("bscan");
        t.file("x/y/z.txt", 3);
        t.file("x/w", 0);
        t.dir("e");
        let idx = Index::build(crate::walk::scan(t.bytes(), 2), 0, 0, b"");
        let mut got = all_paths(&idx);
        got.sort();
        let want: Vec<&[u8]> = vec![b"/", b"/e", b"/x", b"/x/w", b"/x/y", b"/x/y/z.txt"];
        assert_eq!(got, want);
        assert_eq!(idx.size_of(idx.lookup(b"/x/y/z.txt").unwrap() as usize), 3);
    }
}
