//! The name index: every entry on disk in one flat blob, mmap-able as is.
//!
//! Layout trick: entries are emitted one directory *block* at a time, blocks
//! in depth-first order. So every directory's children are contiguous (and
//! sorted, for path lookup), and every directory's whole subtree is the single
//! range `dir_start..dir_end`. Scoping a search to a folder is a range bound,
//! not a filter.
//!
//! Names are interned: 7.5M entries share ~2M distinct names, so each name
//! is stored once, and queries score unique names, not entries. Which names
//! can match a query is answered 64 names at a time from per-class bitmaps
//! (see `name_bits`) before any name is read.

use crate::walk::{KIND_DIR, Listing, NONE};
use memmap2::{Mmap, MmapMut};
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

const MAGIC: &[u8; 8] = b"FSIDX011";

#[derive(Clone, Copy)]
enum Sec {
    NameBits,
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
    NamePrior,
    NameInfo,
    NameExt,
    Exts,
    Zones,
}
const NSEC: usize = 21;

pub struct Index {
    map: Mmap,
    pub n: usize,
    pub d: usize,
    /// Distinct names.
    pub u: usize,
    names_len: usize,
    u1: usize,
    /// Words per name bitmap (64 names each), and all bitmaps' words.
    pub words: usize,
    bits_len: usize,
    zones_len: usize,
    ext_slots: usize,
    /// FSEvents id the index is current as of; replay starts here.
    pub event_id: u64,
    /// Wall-clock second the index is known complete as of (0: unknown).
    /// If FSEvents history from `event_id` is gone, folders changed since
    /// then are what needs relisting.
    pub synced_at: u32,
    off: [usize; NSEC],
    plan: std::sync::OnceLock<MemoPlan>,
    counts: std::sync::OnceLock<[[u32; CLASSES]; 2]>,
    top_prior: std::sync::OnceLock<i8>,
    by_key: std::sync::OnceLock<ByKey>,
}

/// Per distinct name, what bounds its score for one fuzzy token without
/// reading the name (see `query::Searcher::ranked`).
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct NameInfo {
    /// The best location prior among the name's folders, plus the best rank
    /// tweak its flags allow, less the length penalty.
    pub key: i8,
    /// Length past a leading dot (at most 255).
    pub len: u8,
    /// Stem length (up to the last dot) past a leading dot (at most 255).
    pub stem: u8,
    /// First byte past a leading dot, ASCII-folded.
    pub head: u8,
}

/// The names with the highest `NameInfo::key`, best first: every name whose
/// key is at least `cover`, and how many have each key from `cover` up.
pub struct ByKey {
    pub cover: i32,
    pub list: Vec<(i8, u32)>,
    pub counts: Vec<u32>,
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
    // Per distinct name: the name bitmaps (see `bitmap`), offset into
    // `names` (u + 1 entries).
    sec!(name_bits, Sec::NameBits, u64, bits_len);
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
    // Per distinct name, the entries carrying it (best location prior
    // first): a selective query visits only these instead of every entry.
    sec!(name_ents_off, Sec::NameEntsOff, u32, u1);
    sec!(name_ents, Sec::NameEnts, u32, n);
    // Per distinct name, the highest location prior among the folders
    // holding it: bounds what any entry with the name can score.
    sec!(name_prior, Sec::NamePrior, i8, u);
    // Per distinct name, what bounds its score without reading it.
    sec!(name_info, Sec::NameInfo, NameInfo, u);
    // Per distinct name, its extension as an `ext_table` slot: 0 none, 255
    // one not in the table.
    sec!(name_ext, Sec::NameExt, u8, u);
    // The EXT_SLOTS most common extensions among the names, lowercased: slot
    // i is `[len, bytes..]` (slot 0 and 255 unused).
    sec!(ext_table, Sec::Exts, [u8; 16], ext_slots);

    /// The `name_ext` slot of extension `e` (lowercase): 255 if it is not
    /// in the table (names with such an extension have to be read).
    pub fn ext_slot(&self, e: &[u8]) -> u8 {
        let t = self.ext_table();
        (1..255).find(|&i| t[i][0] as usize == e.len() && &t[i][1..1 + e.len()] == e).unwrap_or(255) as u8
    }
    // Per ZONE entries: what a filter on size, mtime or kind can skip.
    sec!(zones, Sec::Zones, Zone, zones_len);

    /// Name bitmap `b` (see `BM_FIRST` and on): bit `k % 64` of word `k / 64`
    /// is set when name `k` has the property.
    pub fn bitmap(&self, b: usize) -> &[u64] {
        &self.name_bits()[b * self.words..][..self.words]
    }

    /// How many names have each char class: a query checks rare ones first.
    pub fn class_counts(&self) -> &[u32; CLASSES] {
        &self.counts()[0]
    }

    /// How many names have each char class at least twice.
    pub fn double_counts(&self) -> &[u32; CLASSES] {
        &self.counts()[1]
    }

    fn counts(&self) -> &[[u32; CLASSES]; 2] {
        self.counts.get_or_init(|| {
            let count = |b: &[u64]| b.iter().map(|x| x.count_ones()).sum();
            [
                std::array::from_fn(|c| self.bitmap(BM_FIRST + c).iter().zip(self.bitmap(BM_SECOND + c)).map(|(a, b)| (a | b).count_ones()).sum()),
                std::array::from_fn(|c| count(self.bitmap(BM_DOUBLE + c))),
            ]
        })
    }

    /// The highest `name_prior`.
    pub fn top_prior(&self) -> i8 {
        *self.top_prior.get_or_init(|| self.name_prior().iter().copied().max().unwrap_or(0))
    }

    /// The names with the highest keys (see `ByKey`).
    pub fn by_key(&self) -> &ByKey {
        self.by_key.get_or_init(|| {
            const WANT: usize = 1 << 14;
            let info = self.name_info();
            let mut count = [0usize; 256];
            for x in info {
                count[(x.key as i32 + 128) as usize] += 1;
            }
            // The lowest key such that all names at or above it fit.
            let (mut cover, mut n) = (i8::MAX as i32 + 1, 0);
            while cover > i8::MIN as i32 && n + count[(cover - 1 + 128) as usize] <= WANT {
                cover -= 1;
                n += count[(cover + 128) as usize];
            }
            let mut list: Vec<(i8, u32)> = info.iter().enumerate().filter(|(_, x)| x.key as i32 >= cover).map(|(k, x)| (x.key, k as u32)).collect();
            list.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            let counts = (cover..=i8::MAX as i32).map(|k| count[(k + 128) as usize] as u32).collect();
            ByKey { cover, list, counts }
        })
    }

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
        if i == 0 {
            out.push(b'/');
            return;
        }
        // The entries from i up: the walk goes folder to parent folder (one
        // dependent load a level); their entries and names load alongside.
        let (de, dp) = (self.dir_entry(), self.dir_parent());
        let mut chain = [0u32; 256];
        chain[0] = i as u32;
        let (mut k, mut d) = (1, self.parent()[i]);
        while d != 0 && k < chain.len() {
            chain[k] = de[d as usize];
            k += 1;
            d = dp[d as usize];
        }
        for &e in chain[..k].iter().rev() {
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
        let words = u.div_ceil(64);
        // Each 64-name block's word of every bitmap, then transposed so each
        // bitmap is contiguous.
        let mut by_block = vec![0u64; words * NBITMAPS];
        by_block.par_chunks_mut(NBITMAPS).enumerate().for_each(|(w, out)| {
            for k in w * 64..(w * 64 + 64).min(u) {
                for b in name_bitmaps(&unames[uoff[k] as usize..uoff[k + 1] as usize]) {
                    out[b] |= 1 << (k % 64);
                }
            }
        });
        let mut ubits = vec![0u64; words * NBITMAPS];
        ubits.par_chunks_mut(words).enumerate().for_each(|(b, out)| {
            for (w, o) in out.iter_mut().enumerate() {
                *o = by_block[w * NBITMAPS + b];
            }
        });
        drop(by_block);
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
        put(Sec::NameBits, as_bytes(&ubits));
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
        // Each name's entries best location prior first (then ascending): a
        // search visiting them can stop at the first that cannot make it.
        ne.par_sort_unstable_by_key(|&e| (ent_name[e as usize], std::cmp::Reverse(prior[parent[e as usize] as usize]), e));
        put(Sec::NameEntsOff, as_bytes(&ne_off));
        put(Sec::NameEnts, as_bytes(&ne));
        let mut name_prior = vec![i8::MIN; u];
        for (i, &k) in ent_name.iter().enumerate().skip(1) {
            name_prior[k as usize] = name_prior[k as usize].max(prior[parent[i] as usize]);
        }
        put(Sec::NamePrior, as_bytes(&name_prior));
        let info: Vec<NameInfo> =
            (0..u).into_par_iter().map(|k| NameInfo::of(&unames[uoff[k] as usize..uoff[k + 1] as usize], name_prior[k])).collect();
        put(Sec::NameInfo, as_bytes(&info));
        let (table, slots) = ext_slots(&unames, &uoff);
        put(Sec::NameExt, &slots);
        put(Sec::Exts, as_bytes(&table));
        put(Sec::Zones, as_bytes(&zones(&kind[..n], &enc, &mtime[..n])));
        m[..HDR].copy_from_slice(&header(MAGIC, &[n as u64, d as u64, u as u64, unames.len() as u64, event_id, synced_at as u64]));
        Index::from_map(m.make_read_only().unwrap()).unwrap()
    }

    fn from_map(map: Mmap) -> Option<Index> {
        let [n, d, u, names_len, event_id, synced_at] = fields(&map, MAGIC)?.map(|v| v as usize);
        let (off, total) = layout(&section_lens(n, d, u, names_len));
        let words = u.div_ceil(64);
        if map.len() < total {
            return None;
        }
        Some(Index {
            n,
            d,
            u,
            u1: u + 1,
            names_len,
            words,
            bits_len: words * NBITMAPS,
            zones_len: n.div_ceil(ZONE),
            ext_slots: 256,
            event_id: event_id as u64,
            synced_at: synced_at as u32,
            off,
            map,
            plan: std::sync::OnceLock::new(),
            counts: std::sync::OnceLock::new(),
            top_prior: std::sync::OnceLock::new(),
            by_key: std::sync::OnceLock::new(),
        })
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
        for s in [Sec::NameBits, Sec::NameOff, Sec::Names, Sec::EntName, Sec::Kind, Sec::Parent] {
            let start = self.off[s as usize];
            let end = self.off.get(s as usize + 1).copied().unwrap_or(self.map.len());
            for i in (start..end).step_by(16 * 1024) {
                sum = sum.wrapping_add(unsafe { std::ptr::read_volatile(self.map.as_ptr().add(i)) });
            }
        }
        std::hint::black_box(sum);
        self.class_counts();
        self.top_prior();
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

/// A name's extension (the bytes after its last dot) as `[len, bytes..]`,
/// lowercased; None if it has no dot or a longer extension.
fn ext_key(name: &[u8]) -> Option<[u8; 16]> {
    let dot = name.iter().rposition(|&b| b == b'.')?;
    let e = &name[dot + 1..];
    if e.len() > 15 {
        return None;
    }
    let mut key = [0u8; 16];
    key[0] = e.len() as u8;
    for (k, &b) in key[1..].iter_mut().zip(e) {
        *k = crate::query::fold(b);
    }
    Some(key)
}

/// The table of the 254 most common extensions among `names` (each at
/// most 15 bytes) and each name's slot in it (see `Index::name_ext`).
pub(crate) fn ext_slots(names: &[u8], off: &[u32]) -> (Vec<[u8; 16]>, Vec<u8>) {
    let name = |k: usize| &names[off[k] as usize..off[k + 1] as usize];
    let count = (0..off.len() - 1)
        .into_par_iter()
        .with_min_len(1 << 16)
        .fold(HashMap::<[u8; 16], u32, Fx>::default, |mut m, k| {
            if let Some(e) = ext_key(name(k)) {
                *m.entry(e).or_default() += 1;
            }
            m
        })
        .reduce(HashMap::default, |mut a, b| {
            for (e, n) in b {
                *a.entry(e).or_default() += n;
            }
            a
        });
    let mut common: Vec<([u8; 16], u32)> = count.into_iter().collect();
    common.sort_by(|(a, m), (b, n)| n.cmp(m).then_with(|| a[1..=a[0] as usize].cmp(&b[1..=b[0] as usize])));
    let mut table = vec![[0u8; 16]; 256];
    let mut slot: HashMap<[u8; 16], u8, Fx> = HashMap::default();
    for (i, (e, _)) in common.into_iter().take(254).enumerate() {
        table[i + 1] = e;
        slot.insert(e, i as u8 + 1);
    }
    let slots = (0..off.len() - 1)
        .into_par_iter()
        .map(|k| {
            let n = name(k);
            match ext_key(n) {
                Some(e) => slot.get(&e).copied().unwrap_or(255),
                None => n.contains(&b'.') as u8 * 255,
            }
        })
        .collect();
    (table, slots)
}

impl NameInfo {
    /// The info of a name whose folders' best location prior is `prior`.
    pub fn of(name: &[u8], prior: i8) -> NameInfo {
        let off = (name.len() > 1 && name[0] == b'.') as usize;
        let stem = name.iter().rposition(|&b| b == b'.').filter(|&p| p > off).unwrap_or(name.len());
        let tweak = 10 + if name.ends_with(b".app") { 25 } else { 0 } - if name.first() == Some(&b'.') { 8 } else { 0 };
        NameInfo {
            key: (prior as i32 + tweak - (name.len() as i32).min(80) / 3).max(i8::MIN as i32) as i8,
            len: (name.len() - off).min(255) as u8,
            stem: (stem - off).min(255) as u8,
            head: name.get(off).map_or(0, |&b| crate::query::fold(b)),
        }
    }
}

fn section_lens(n: usize, d: usize, u: usize, names_len: usize) -> [usize; NSEC] {
    let (n4, d4, u4) = (n * 4, d * 4, (u + 1) * 4);
    let z = n.div_ceil(ZONE) * std::mem::size_of::<Zone>();
    [u.div_ceil(64) * NBITMAPS * 8, u4, names_len, n4, n, n4, n4, n4, d4, d4, d4, d4, d, d4, u4, n4, u, u * 4, u, 256 * 16, z]
}

/// Entries per `Zone`.
pub const ZONE: usize = 1024;

/// A run of ZONE entries at a glance: entries matching a size, mtime or
/// kind filter cluster (a folder's big files, the recently modified), so
/// a pass over every entry skips most runs whole.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Zone {
    /// Largest `size_raw` (its encoding keeps order).
    pub max_size: u32,
    pub min_mtime: u32,
    pub max_mtime: u32,
    /// Bit `kind & 3` for every kind present.
    pub kinds: u32,
}

pub(crate) fn zones(kind: &[u8], size: &[u32], mtime: &[u32]) -> Vec<Zone> {
    (0..kind.len().div_ceil(ZONE))
        .map(|z| {
            let r = z * ZONE..((z + 1) * ZONE).min(kind.len());
            Zone {
                max_size: size[r.clone()].iter().copied().max().unwrap_or(0),
                min_mtime: mtime[r.clone()].iter().copied().min().unwrap_or(0),
                max_mtime: mtime[r.clone()].iter().copied().max().unwrap_or(0),
                kinds: kind[r].iter().fold(0, |m, &k| m | 1 << (k & 3)),
            }
        })
        .collect()
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
    1 << (CLASSES + start_hash(b))
}

#[inline]
pub fn start_hash(b: u8) -> usize {
    (b.to_ascii_lowercase() % 23) as usize
}

/// Char classes (`char_bit`).
pub const CLASSES: usize = 41;
/// Name bitmaps, per char class: names with that class in their first half
/// (`BM_FIRST + class`), in their second half (`BM_SECOND + class`). A
/// query's chars must appear in order, so a name can only match if some
/// prefix of the query fits its first half and the rest its second half.
pub const BM_FIRST: usize = 0;
pub const BM_SECOND: usize = CLASSES;
/// Names with a word starting with a letter of this `start_bit` hash.
pub const BM_START: usize = 2 * CLASSES;
/// Names starting with a dot; names ending in ".app".
pub const BM_DOT: usize = BM_START + 23;
pub const BM_APP: usize = BM_DOT + 1;
/// Names with this char class at least twice: a token with a class twice
/// can only match those (with a typo, it may lose one).
pub const BM_DOUBLE: usize = BM_APP + 1;
pub const NBITMAPS: usize = BM_DOUBLE + CLASSES;

/// The bitmaps (see `BM_FIRST` and on) a name is in.
fn name_bitmaps(s: &[u8]) -> impl Iterator<Item = usize> {
    let (a, b) = s.split_at(s.len() / 2);
    let class = |m: u64, base: usize| (0..CLASSES).filter(move |c| m & (1 << c) != 0).map(move |c| base + c);
    let starts = name_mask(s) >> CLASSES;
    class(char_mask(a), BM_FIRST)
        .chain(class(char_mask(b), BM_SECOND))
        .chain((0..23).filter(move |h| starts & (1 << h) != 0).map(|h| BM_START + h))
        .chain(s.first().is_some_and(|&c| c == b'.').then_some(BM_DOT))
        .chain(s.ends_with(b".app").then_some(BM_APP))
        .chain(class(doubled(s), BM_DOUBLE))
}

/// The char classes `s` has at least twice.
pub fn doubled(s: &[u8]) -> u64 {
    let (mut once, mut twice) = (0, 0);
    for &b in s {
        twice |= once & char_bit(b);
        once |= char_bit(b);
    }
    twice
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
