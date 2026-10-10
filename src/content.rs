//! Content search: a trigram index over the user's text files.
//!
//! Segments are immutable, mmap'd files: a doc table, and the contents first
//! indexed there: per trigram, the ids of the contents holding it (delta
//! varints), and per content a bloom filter of its 6-byte substrings. Each
//! distinct file content is indexed once (most copies are git worktrees):
//! every doc names its content by a gid, and a copy indexed later, even in
//! another segment, just names the same gid. A query becomes an AND/OR of
//! trigrams, the posting lists pick candidate contents, those become the docs
//! holding them, the bloom filters drop most of those that only contain the
//! pattern's trigrams scattered about, and the rest are read fresh from disk
//! and matched for real. Results therefore never show stale content; only
//! candidate selection can trail a file written in the last couple of seconds.
//!
//! The index is kept in sync by diffing, exactly like the name index: for a
//! directory (or subtree), compare the eligible files the live name index
//! knows about with the docs we hold, reindex what changed, tombstone what
//! went away. The first build is just a sync of $HOME.

use crate::index::{HDR, as_bytes, fields, header, layout, sec};
use crate::live::{Live, join};
use crate::query::{GrepMode, Query, fold};
use crate::walk::KIND_FILE;
use memmap2::Mmap;
use rayon::prelude::*;
use regex::bytes::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, Hir, HirKind};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MAX_FILE: u64 = 1 << 20;
/// File bytes per segment build; bounds the build's transient memory.
const SEG_BYTES: u64 = 64 << 20;
/// Largest merge, in posting bytes; bounds the merge's transient memory.
const MERGE_CAP: usize = 96 << 20;
const MAGIC: &[u8; 8] = b"FSCSEG10";
/// tri_off high bit: this trigram's list is a bitset over the segment's
/// contents (cheaper than varints once more than 1 in 8 contain it).
const BITSET: u32 = 1 << 31;
/// tri_off next bit: this varint list starts with a skip table, one entry
/// per SKIP of its contents after the first SKIP: (the content before them,
/// where they start in the varints), so a search can jump ahead.
const SKIPS: u32 = 1 << 30;
const FLAGS: u32 = BITSET | SKIPS;
const SKIP: usize = 64;
/// The gid of a doc that is not text, or a doc no content holds.
const NONE: u32 = u32::MAX;

/// Directory names whose subtrees are generated, vendored, or caches.
#[rustfmt::skip]
const SKIP_DIRS: &[&[u8]] = &[
    b"node_modules", b".git", b"target", b"DerivedData", b"__pycache__", b".venv", b"venv", b"site-packages", b"Pods",
    b".next", b".turbo", b".cache", b"Library", b"dist", b"build", b".build", b".rustup", b".cargo", b".npm", b".bun",
    b".nvm", b"vendor", b".pnpm-store", b"coverage", b".Trash", b".svn", b".hg", b".gradle", b".m2", b".pyenv",
    b".rbenv", b".gem", b".conda", b"miniconda3", b"anaconda3", b".docker", b".orbstack", b".colima", b".lima",
    b".ollama", b".android", b".expo", b".terraform.d", b".wrangler", b".vscode-server", b"cache", b"Cache", b"caches",
    b"Caches",
];

/// Home-relative trees that are dependencies or app data, not your files.
#[rustfmt::skip]
const SKIP_UNDER_HOME: &[&[u8]] = &[
    b"go/pkg", b".cursor/extensions", b".vscode/extensions", b".local/share", b".local/state", b".config/gcloud", b".codex/.tmp",
];

/// Package/library bundles: their insides are app data.
#[rustfmt::skip]
const SKIP_SUFFIXES: &[&[u8]] = &[
    b".app", b".photoslibrary", b".library", b".lrlibrary", b".musiclibrary", b".tvlibrary", b".imovielibrary",
    b".xcassets", b".framework", b".bundle", b".xcarchive", b".xcresult", b".dSYM", b".salon", b".lrdata",
];

#[rustfmt::skip]
const TEXT_EXTS: &[&[u8]] = &[
    b"rs", b"c", b"h", b"cc", b"cpp", b"cxx", b"hpp", b"hh", b"m", b"mm", b"swift", b"go", b"py", b"pyi", b"js", b"mjs", b"cjs",
    b"ts", b"mts", b"cts", b"tsx", b"jsx", b"java", b"kt", b"kts", b"scala", b"rb", b"php", b"cs", b"fs", b"sh", b"zsh", b"bash",
    b"fish", b"lua", b"sql", b"html", b"htm", b"css", b"scss", b"sass", b"less", b"json", b"jsonc", b"json5", b"yaml", b"yml",
    b"toml", b"xml", b"vue", b"svelte", b"astro", b"zig", b"nim", b"hs", b"ml", b"mli", b"ex", b"exs", b"erl", b"clj", b"dart",
    b"r", b"jl", b"md", b"mdx", b"markdown", b"txt", b"text", b"rst", b"org", b"tex", b"csv", b"tsv", b"ini", b"cfg", b"conf",
    b"env", b"properties", b"plist", b"metal", b"glsl", b"wgsl", b"hlsl", b"proto", b"graphql", b"gql", b"nix", b"tf", b"hcl",
    b"gradle", b"cmake", b"mk", b"make", b"dockerfile", b"log", b"jsonl", b"ndjson", b"diff", b"patch", b"srt", b"vtt", b"rtf",
    b"svg", b"pl", b"pm", b"ps1", b"bat", b"vim", b"el", b"lisp", b"scm", b"rkt", b"elm", b"purs", b"sol", b"v", b"sv", b"vhd",
    b"asm", b"s", b"d", b"cr", b"pas", b"f90", b"cmd", b"service", b"desktop", b"gitignore", b"editorconfig", b"lock", b"sum",
];

pub struct Segment {
    map: std::sync::Arc<Mmap>,
    pub id: u64,
    pub ndocs: usize,
    ndocs1: usize,
    ntri: usize,
    ntri1: usize,
    plen: usize,
    paths_len: usize,
    nwords: usize,
    /// Contents first indexed here (its own).
    nown: usize,
    nown1: usize,
    nown2: usize,
    off: [usize; NS],
    dead: Vec<u64>,
    pub live_docs: usize,
    /// Per own content, the live docs (in any segment) holding it; kept by
    /// `Content` (see `link`).
    refs: Counts,
    /// Own contents as runs of consecutive gids: (first content, first gid, length).
    runs: Vec<(u32, u32, u32)>,
}

#[derive(Clone, Copy)]
enum S {
    TriKey,
    TriOff,
    Post,
    PathOff,
    Paths,
    Size,
    Mtime,
    ByPath,
    Rank,
    ByRank,
    DocGid,
    RankGid,
    GidSorted,
    ByGid,
    OwnGid,
    OwnDoc,
    Hash,
    ByHash,
    BloomOff,
    Bloom,
}
const NS: usize = 20;

#[rustfmt::skip]
fn lens(ndocs: usize, ntri: usize, plen: usize, paths_len: usize, nwords: usize, nown: usize) -> [usize; NS] {
    let (d, c) = (ndocs * 4, nown * 4);
    [ntri * 4, (ntri + 1) * 4, plen, d + 4, paths_len, ndocs * 8, d, d, ndocs, d, d, d, d, d, c, c, c * 4, c, c + 4, nwords * 8]
}

impl Segment {
    sec!(tri_key, S::TriKey, u32, ntri);
    sec!(tri_off, S::TriOff, u32, ntri1);
    sec!(post, S::Post, u8, plen);
    sec!(path_off, S::PathOff, u32, ndocs1);
    sec!(paths, S::Paths, u8, paths_len);
    sec!(size, S::Size, u64, ndocs);
    sec!(mtime, S::Mtime, u32, ndocs);
    sec!(by_path, S::ByPath, u32, ndocs);
    sec!(rank, S::Rank, i8, ndocs);
    // Doc ids, best-ranked first.
    sec!(by_rank, S::ByRank, u32, ndocs);
    // Per doc, its content's gid (NONE: not text); the same in by_rank order.
    sec!(doc_gid, S::DocGid, u32, ndocs);
    sec!(rank_gid, S::RankGid, u32, ndocs);
    // The docs by gid: the gids (ascending), and the doc ids.
    sec!(gid_sorted, S::GidSorted, u32, ndocs);
    sec!(by_gid, S::ByGid, u32, ndocs);
    // Per own content: its gid, the first doc here holding it (or NONE), a
    // hash of its bytes (two u64s), and a bloom filter of its GRAM-byte
    // substrings. And the contents in hash order.
    sec!(own_gid, S::OwnGid, u32, nown);
    sec!(own_doc, S::OwnDoc, u32, nown);
    sec!(hash, S::Hash, u64, nown2);
    sec!(by_hash, S::ByHash, u32, nown);
    sec!(bloom_off, S::BloomOff, u32, nown1);
    sec!(bloom, S::Bloom, u64, nwords);

    pub fn path(&self, d: u32) -> &[u8] {
        let o = self.path_off();
        &self.paths()[o[d as usize] as usize..o[d as usize + 1] as usize]
    }

    fn bloom_of(&self, c: u32) -> &[u64] {
        let o = self.bloom_off();
        &self.bloom()[o[c as usize] as usize..o[c as usize + 1] as usize]
    }

    fn hash_of(&self, c: u32) -> [u64; 2] {
        [self.hash()[2 * c as usize], self.hash()[2 * c as usize + 1]]
    }

    /// Can own content `c` hold every gram in `probes`, by its bloom filter?
    fn may_contain(&self, c: u32, probes: &[u32]) -> bool {
        let words = self.bloom_of(c);
        probes.iter().all(|&h| bloom_bits(h, words.len()).iter().all(|&b| words.get(b / 64).is_some_and(|w| w >> (b % 64) & 1 != 0)))
    }

    /// Own contents a live doc still holds.
    fn live_own(&self) -> usize {
        self.refs.live()
    }

    #[inline]
    pub fn is_dead(&self, d: u32) -> bool {
        self.dead[d as usize >> 6] & (1 << (d & 63)) != 0
    }

    fn kill(&mut self, d: u32) -> bool {
        let w = &mut self.dead[d as usize >> 6];
        if *w & (1 << (d & 63)) != 0 {
            return false;
        }
        *w |= 1 << (d & 63);
        self.live_docs -= 1;
        true
    }

    /// Live docs whose path starts with `prefix`, via the sorted permutation.
    fn with_prefix<'a>(&'a self, prefix: &'a [u8]) -> impl Iterator<Item = u32> + 'a {
        let bp = self.by_path();
        let start = bp.partition_point(|&d| self.path(d) < prefix);
        bp[start..].iter().copied().take_while(move |&d| self.path(d).starts_with(prefix)).filter(move |&d| !self.is_dead(d))
    }

    /// How many docs (live or not) have paths starting with `prefix`.
    fn count_prefix(&self, prefix: &[u8]) -> usize {
        let bp = self.by_path();
        let start = bp.partition_point(|&d| self.path(d) < prefix);
        bp[start..].partition_point(|&d| self.path(d).starts_with(prefix))
    }

    /// Live docs directly inside `prefix` (which ends in '/'), skipping each
    /// subdirectory's run of paths with one binary search.
    fn direct_children(&self, prefix: &[u8]) -> Vec<u32> {
        let bp = self.by_path();
        let mut out = Vec::new();
        let mut i = bp.partition_point(|&d| self.path(d) < prefix);
        while i < bp.len() {
            let p = self.path(bp[i]);
            if !p.starts_with(prefix) {
                break;
            }
            match p[prefix.len()..].iter().position(|&b| b == b'/') {
                None => {
                    if !self.is_dead(bp[i]) {
                        out.push(bp[i]);
                    }
                    i += 1;
                }
                Some(k) => {
                    // Jump past "prefix/sub/..." : first path >= "prefix/sub0".
                    let mut hi = p[..prefix.len() + k + 1].to_vec();
                    *hi.last_mut().unwrap() = b'/' + 1;
                    i += bp[i..].partition_point(|&d| self.path(d) < hi.as_slice());
                }
            }
        }
        out
    }

    fn list(&self, tri: u32) -> Option<List<'_>> {
        self.tri_key().binary_search(&tri).ok().map(|k| self.list_at(k))
    }

    fn list_at(&self, k: usize) -> List<'_> {
        let o = self.tri_off();
        let bytes = &self.post()[(o[k] & !FLAGS) as usize..(o[k + 1] & !FLAGS) as usize];
        if o[k] & BITSET != 0 { List::Bits(bytes) } else { List::Var(Var::new(bytes, o[k] & SKIPS != 0)) }
    }

    /// The live docs under `prefix` lie in this doc id range (exactly, for a
    /// segment built from sorted paths; a superset after a merge, or when
    /// most of the segment is under it). True if every doc is under it.
    fn doc_range(&self, prefix: &[u8]) -> (std::ops::Range<u32>, bool) {
        let bp = self.by_path();
        let (Some(&first), Some(&last)) = (bp.first(), bp.last()) else { return (0..0, false) };
        let (first, last) = (self.path(first), self.path(last));
        if last < prefix || (first > prefix && !first.starts_with(prefix)) {
            return (0..0, false);
        }
        // Paths under the prefix are one run in path order.
        if first.starts_with(prefix) && last.starts_with(prefix) {
            return (0..self.ndocs as u32, true);
        }
        let a = bp.partition_point(|&d| self.path(d) < prefix);
        let z = a + bp[a..].partition_point(|&d| self.path(d).starts_with(prefix));
        if (z - a) * 2 > bp.len() {
            return (0..self.ndocs as u32, false);
        }
        let (lo, hi) = bp[a..z].iter().fold((u32::MAX, 0), |(lo, hi), &d| (lo.min(d), hi.max(d + 1)));
        (lo.min(hi)..hi, false)
    }

    fn list_into(&self, k: usize, out: &mut Vec<u32>) {
        match self.list_at(k) {
            List::Bits(bytes) => {
                for (w, &b) in bytes.iter().enumerate() {
                    let mut b = b;
                    while b != 0 {
                        out.push(w as u32 * 8 + b.trailing_zeros());
                        b &= b - 1;
                    }
                }
            }
            List::Var(v) => out.extend(v.iter()),
        }
    }

    fn load(dir: &Path, id: u64) -> Option<Segment> {
        let f = std::fs::File::open(seg_path(dir, id)).ok()?;
        let map = std::sync::Arc::new(unsafe { Mmap::map(&f) }.ok()?);
        let [ndocs, ntri, plen, paths_len, nwords, nown] = fields(&map, MAGIC)?.map(|v| v as usize);
        let (off, total) = layout(&lens(ndocs, ntri, plen, paths_len, nwords, nown));
        if map.len() < total {
            return None;
        }
        let mut dead = vec![0u64; ndocs.div_ceil(64)];
        if let Ok(b) = std::fs::read(dead_path(dir, id)) {
            for (w, c) in dead.iter_mut().zip(b.chunks_exact(8)) {
                *w = u64::from_le_bytes(c.try_into().unwrap());
            }
        }
        let live_docs = ndocs - dead.iter().map(|w| w.count_ones() as usize).sum::<usize>();
        #[rustfmt::skip]
        let mut s = Segment {
            map, id, ndocs, ndocs1: ndocs + 1, ntri, ntri1: ntri + 1, plen, paths_len, nwords, nown, nown1: nown + 1, nown2: nown * 2,
            off, dead, live_docs, refs: Counts::new(nown), runs: Vec::new(),
        };
        let mut runs: Vec<(u32, u32, u32)> = Vec::new();
        for (c, &g) in s.own_gid().iter().enumerate() {
            match runs.last_mut() {
                Some((_, g0, n)) if *g0 + *n == g => *n += 1,
                _ => runs.push((c as u32, g, 1)),
            }
        }
        s.runs = runs;
        Some(s)
    }

    fn save_dead(&self, dir: &Path) {
        let bytes: Vec<u8> = self.dead.iter().flat_map(|w| w.to_le_bytes()).collect();
        let tmp = dead_path(dir, self.id).with_extension("tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(tmp, dead_path(dir, self.id));
        }
    }
}

fn seg_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("seg-{id:06}.fsc"))
}
fn dead_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("seg-{id:06}.dead"))
}

#[inline]
fn varint(b: &[u8]) -> (u32, usize) {
    let mut v = 0u32;
    for (i, &x) in b.iter().enumerate().take(5) {
        v |= ((x & 0x7f) as u32) << (7 * i);
        if x & 0x80 == 0 {
            return (v, i + 1);
        }
    }
    (v, b.len().min(5))
}

fn put_varint(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// A 128-bit hash of a file's bytes: files with the same hash are taken to
/// hold the same bytes. Four multiply-fold lanes, 32 bytes a step.
fn content_hash(b: &[u8]) -> [u64; 2] {
    #[inline]
    fn mix(x: u64, y: u64) -> u64 {
        let m = x as u128 * y as u128;
        m as u64 ^ (m >> 64) as u64
    }
    const K: [u64; 4] = [0x9E37_79B9_7F4A_7C15, 0xC2B2_AE3D_27D4_EB4F, 0x1656_67B1_9E37_79F9, 0x85EB_CA77_C2B2_AE63];
    let word = |w: &[u8], i: usize| u64::from_le_bytes(w[i * 8..i * 8 + 8].try_into().unwrap());
    let mut s = [K[0] ^ b.len() as u64, K[1], K[2], K[3] ^ (b.len() as u64).rotate_left(32)];
    let mut step = |w: &[u8]| {
        let x = [word(w, 0), word(w, 1), word(w, 2), word(w, 3)];
        s = [mix(x[0] ^ K[0], x[1] ^ s[0]), mix(x[1] ^ K[1], x[0] ^ s[1]), mix(x[2] ^ K[2], x[3] ^ s[2]), mix(x[3] ^ K[3], x[2] ^ s[3])];
    };
    let mut blocks = b.chunks_exact(32);
    for w in &mut blocks {
        step(w);
    }
    let mut last = [0u8; 32];
    last[..blocks.remainder().len()].copy_from_slice(blocks.remainder());
    step(&last);
    let h0 = mix(mix(s[0] ^ K[1], s[2] ^ K[2]) ^ s[1], s[3] ^ K[0]);
    let h1 = mix(mix(s[1] ^ K[3], s[3] ^ K[1]) ^ s[0], s[2] ^ K[2]);
    [h0, h1]
}

/// A file's distinct trigrams and its end-of-file key into `tri`, and the
/// distinct hashes of its GRAM-byte grams into `grams` (both cleared,
/// unordered). One pass, with no branch on whether a gram is new. `seen` is
/// two 2 MiB bitsets, all zero on entry and exit.
fn index_grams(buf: &[u8], seen: &mut [u64], tri: &mut Vec<u32>, grams: &mut Vec<u32>) {
    tri.clear();
    grams.clear();
    let n = buf.len();
    if n < 2 {
        return;
    }
    let (st, sg) = seen.split_at_mut(seen.len() / 2);
    // Its last two bytes and a 0: so a two-byte search finds them too.
    let eof = (fold(buf[n - 2]) as u32) << 16 | (fold(buf[n - 1]) as u32) << 8;
    st[(eof >> 6) as usize] |= 1 << (eof & 63);
    tri.resize(n, 0);
    tri[0] = eof;
    grams.resize(n, 0);
    let (mut nt, mut ng) = (1, 0);
    let mut g = (fold(buf[0]) as u64) << 8 | fold(buf[1]) as u64;
    for (i, &c) in buf.iter().enumerate().skip(2) {
        g = g << 8 | fold(c) as u64;
        let t = (g & 0xFF_FFFF) as u32;
        let (w, bit) = ((t >> 6) as usize, 1u64 << (t & 63));
        tri[nt] = t;
        nt += (st[w] & bit == 0) as usize;
        st[w] |= bit;
        let full = i + 1 >= GRAM;
        let h = gram_hash(g & ((1 << (8 * GRAM)) - 1));
        let (w, bit) = ((h >> 6) as usize, 1u64 << (h & 63));
        grams[ng] = h;
        ng += (full & (sg[w] & bit == 0)) as usize;
        sg[w] |= bit & 0u64.wrapping_sub(full as u64);
    }
    tri.truncate(nt);
    grams.truncate(ng);
    for &t in tri.iter() {
        st[(t >> 6) as usize] = 0;
    }
    for &h in grams.iter() {
        sg[(h >> 6) as usize] = 0;
    }
}

/// Trigrams of a short string (query side), no scratch needed.
fn trigrams_small(s: &[u8]) -> Vec<u32> {
    let mut t: Vec<u32> = s.windows(3).map(|w| (fold(w[0]) as u32) << 16 | (fold(w[1]) as u32) << 8 | fold(w[2]) as u32).collect();
    t.sort_unstable();
    t.dedup();
    t
}

/// Bloom filters hold a content's case-folded substrings of this many bytes:
/// a match holds all of its pattern's grams, so a content missing one of them
/// can't match even if it has every trigram.
const GRAM: usize = 6;

/// A gram's 24-bit hash (its folded bytes, big-endian in the low 40 bits).
#[inline]
fn gram_hash(g: u64) -> u32 {
    (g.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40) as u32
}

/// The two bits a gram hash sets in a bloom filter of `words` u64s.
#[inline]
fn bloom_bits(h: u32, words: usize) -> [usize; 2] {
    let at = |h: u32| ((h as u64 * words as u64 * 64) >> 24) as usize;
    [at(h), at(h.wrapping_mul(0x9E37_79B1) & 0xFF_FFFF)]
}

/// Append a bloom filter of these gram hashes to `out`: `bits` per gram, two
/// set per gram, in whole words. A gram the doc lacks still passes 24% of
/// the time at three bits, 40% at two.
fn bloom(hashes: &[u32], bits: usize, out: &mut Vec<u64>) {
    let words = (hashes.len() * bits).div_ceil(64);
    let at = out.len();
    out.resize(at + words, 0);
    for &h in hashes {
        for b in bloom_bits(h, words) {
            out[at + b / 64] |= 1 << (b % 64);
        }
    }
}

/// Keywords a definition starts with (`sym:` search).
const DEFINES: &str = "fn|func|function|def|class|struct|enum|trait|interface|type|typealias|impl|let|const|var|val|static|module|mod|protocol|extension|macro_rules!|define|typedef|union|object|record|namespace|actor";

/// The posting key for "this doc defines `name`": a hash above the 24-bit
/// trigram space, so definitions live in the same key table as trigrams.
fn symbol_key(name: &[u8]) -> u32 {
    let h = name.iter().fold(0x811c_9dc5u32, |h, &b| (h ^ b as u32).wrapping_mul(0x0100_0193));
    h | 0x8000_0000
}

/// Is `name` something the definition index records (a plain identifier)?
fn plain_identifier(name: &[u8]) -> bool {
    name.first().is_some_and(|&b| b.is_ascii_alphabetic() || b == b'_') && name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Append the sorted distinct definition keys of a buffer to `out`: every
/// identifier right after a declaring keyword, as `sym:` matches it.
fn symbols(buf: &[u8], out: &mut Vec<u32>) {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        RegexBuilder::new(&format!(r"(?-u:\b)(?:{DEFINES})(?:<[^>\n]*>)?[ \t*&]+(?:mut[ \t]+)?[A-Za-z_][A-Za-z0-9_]*"))
            .unicode(false)
            .build()
            .unwrap()
    });
    let mut keys = Vec::new();
    let mut at = 0;
    while let Some(m) = re.find_at(buf, at) {
        let end = m.end();
        let begin = buf[..end].iter().rposition(|&b| !(b.is_ascii_alphanumeric() || b == b'_')).map_or(0, |p| p + 1);
        keys.push(symbol_key(&buf[begin..end]));
        // The name may itself be a keyword ("static func main"): look again
        // from it, not past it.
        at = begin;
    }
    keys.sort_unstable();
    keys.dedup();
    out.extend(keys);
}

/// Paths with size and mtime, all in one buffer: a full sync holds ~500k
/// of them, and one allocation (mmap-backed, returned on drop) beats 500k.
#[derive(Default)]
pub struct Docs {
    buf: Vec<u8>,
    items: Vec<(u32, u32, u64, u32)>,
    /// What builds of these docs share: the contents already indexed (set
    /// by `diff`; docs from elsewhere are for a new, empty index).
    dedup: std::sync::OnceLock<Dedup>,
}

/// What one sync's segment builds share so each distinct content is indexed
/// once: the segments held before it, the contents built since (by hash),
/// and the gids free to hand out.
#[derive(Default)]
struct Dedup {
    held: Vec<Held>,
    built: std::sync::Mutex<HashMap<[u64; 2], u32>>,
    free: std::sync::Mutex<Gids>,
}

/// A segment's own contents, findable by hash while a sync builds.
struct Held {
    map: std::sync::Arc<Mmap>,
    nown: usize,
    off: [usize; NS],
}

impl Held {
    fn find(&self, h: [u64; 2]) -> Option<u32> {
        let at = |s: S, k: usize| unsafe { (self.map.as_ptr().add(self.off[s as usize]) as *const u32).add(k).read() };
        let hash = |c: u32| unsafe {
            let p = (self.map.as_ptr().add(self.off[S::Hash as usize]) as *const u64).add(2 * c as usize);
            [p.read(), p.add(1).read()]
        };
        let (mut lo, mut hi) = (0, self.nown);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if hash(at(S::ByHash, mid)) < h { lo = mid + 1 } else { hi = mid }
        }
        (lo < self.nown && hash(at(S::ByHash, lo)) == h).then(|| at(S::OwnGid, at(S::ByHash, lo) as usize))
    }
}

impl Dedup {
    /// The gid of a content with this hash, if one is indexed.
    fn find(&self, h: [u64; 2]) -> Option<u32> {
        self.held.iter().find_map(|s| s.find(h)).or_else(|| self.built.lock().unwrap().get(&h).copied())
    }
}

/// Gids not in use: ascending gaps, then everything from `next`.
#[derive(Default)]
struct Gids {
    gaps: Vec<(u32, u32)>,
    next: u32,
}

impl Gids {
    /// `n` gids, lowest first.
    fn take(&mut self, n: usize) -> Vec<u32> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            match self.gaps.first_mut() {
                Some((a, b)) => {
                    out.push(*a);
                    *a += 1;
                    if a == b {
                        self.gaps.remove(0);
                    }
                }
                None => {
                    out.push(self.next);
                    self.next += 1;
                }
            }
        }
        out
    }
}

impl Docs {
    fn push(&mut self, path: &[u8], size: u64, mtime: u32) {
        self.items.push((self.buf.len() as u32, path.len() as u32, size, mtime));
        self.buf.extend_from_slice(path);
    }
    fn path(&self, i: usize) -> &[u8] {
        let (o, l, _, _) = self.items[i];
        &self.buf[o as usize..(o + l) as usize]
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    fn sort(&mut self) {
        let buf = &self.buf;
        self.items.sort_by(|a, b| buf[a.0 as usize..(a.0 + a.1) as usize].cmp(&buf[b.0 as usize..(b.0 + b.1) as usize]));
        self.items.dedup_by(|a, b| buf[a.0 as usize..(a.0 + a.1) as usize] == buf[b.0 as usize..(b.0 + b.1) as usize]);
    }
    fn find(&self, path: &[u8]) -> Option<usize> {
        let i = self.items.partition_point(|&(o, l, _, _)| &self.buf[o as usize..(o + l) as usize] < path);
        (i < self.items.len() && self.path(i) == path).then_some(i)
    }

    /// Index ranges of about SEG_BYTES of file data each.
    pub fn batches(&self) -> Vec<std::ops::Range<usize>> {
        let (mut out, mut start, mut bytes) = (Vec::new(), 0, 0u64);
        for (i, it) in self.items.iter().enumerate() {
            if bytes >= SEG_BYTES {
                out.push(start..i);
                (start, bytes) = (i, 0);
            }
            bytes += it.2;
        }
        if start < self.items.len() {
            out.push(start..self.items.len());
        }
        out
    }
}

/// Contents smaller than this are shared only within a segment: their copies
/// cost next to nothing, and empty files are everywhere.
const SMALL: usize = 256;

/// Rank of a doc that turned out not to be text: kept so diffs know we
/// looked at it, never a candidate.
const NOT_TEXT: i8 = i8::MIN;

struct DocMeta<'a> {
    path: &'a [u8],
    size: u64,
    mtime: u32,
    rank: i8,
    gid: u32,
}

/// One of the contents a segment being written owns.
struct ContentMeta<'a> {
    gid: u32,
    hash: [u64; 2],
    bloom: &'a [u64],
    /// The first doc there holding it, or NONE.
    doc: u32,
}

/// What a doc holds, as a build finds it.
#[derive(Clone, Copy)]
enum Holds {
    /// Nothing: it is not text.
    Nothing,
    /// A content indexed before.
    Gid(u32),
    /// A content new in this build (numbered as first seen).
    New(u32),
}

/// One run of docs' output: what each doc holds, and for the contents new
/// in this build that it saw first, their (trigram, content) pairs in 256
/// buckets by the trigram's first byte, and their definition keys and bloom
/// filters, flat.
struct Split {
    pairs: Vec<Vec<u64>>,
    syms: Vec<u32>,
    blooms: Vec<u64>,
    docs: Vec<(usize, Holds)>,
    contents: Vec<SplitContent>,
}

/// Where a new content's data is in its split.
struct SplitContent {
    new: u32,
    hash: [u64; 2],
    small: bool,
    sym: std::ops::Range<usize>,
    bloom: std::ops::Range<usize>,
}

/// Build one segment file from docs (any order). Files that turn out not
/// to be text are recorded with no content; a file whose bytes are already
/// indexed (this sync, or before it: see `diff`) just names that content.
pub fn build_segment(dir: &Path, id: u64, docs: &Docs, range: std::ops::Range<usize>) -> Option<Segment> {
    use std::io::Read;
    // Docs in runs of 256, a run on one thread with its next 8 files open
    // and their reads started (`open_ahead`): on a cold cache those reads
    // overlap the work on earlier files. A read buffer and a 2 MiB seen-set
    // go back to a pool after each run, so a build holds one per thread.
    const RUN: usize = 256;
    const AHEAD: usize = 8;
    let dedup = docs.dedup.get_or_init(Dedup::default);
    // Contents new in this build, by hash, numbered as first seen.
    let new = std::sync::Mutex::new(HashMap::<[u64; 2], u32>::new());
    let scratch = std::sync::Mutex::new(Vec::new());
    let runs: Vec<std::ops::Range<usize>> = range.clone().step_by(RUN).map(|s| s..(s + RUN).min(range.end)).collect();
    let splits: Vec<Split> = (runs.into_par_iter())
        .map(|run| {
            let (mut seen, mut buf, mut hashes, mut tri) =
                scratch.lock().unwrap().pop().unwrap_or_else(|| (vec![0u64; 2 << 18], Vec::new(), Vec::new(), Vec::new()));
            let mut sp = Split { pairs: vec![Vec::new(); 256], syms: Vec::new(), blooms: Vec::new(), docs: Vec::new(), contents: Vec::new() };
            let mut ahead = std::collections::VecDeque::new();
            for i in run.clone() {
                while ahead.len() <= AHEAD && i + ahead.len() < run.end {
                    ahead.push_back(open_ahead(docs.path(i + ahead.len())));
                }
                buf.clear();
                let text = (ahead.pop_front().flatten())
                    .and_then(|f| f.take(MAX_FILE + 1).read_to_end(&mut buf).ok())
                    .is_some_and(|n| n as u64 <= MAX_FILE && memchr::memchr(0, &buf[..n.min(8192)]).is_none());
                let holds = if !text {
                    Holds::Nothing
                } else {
                    let h = content_hash(&buf);
                    match (buf.len() >= SMALL).then(|| dedup.find(h)).flatten() {
                        Some(g) => Holds::Gid(g),
                        None => {
                            let (k, first) = {
                                let mut m = new.lock().unwrap();
                                let n = m.len() as u32;
                                let k = *m.entry(h).or_insert(n);
                                (k, k == n)
                            };
                            if first {
                                let (sym, bl) = (sp.syms.len(), sp.blooms.len());
                                index_grams(&buf, &mut seen, &mut tri, &mut hashes);
                                for &t in &tri {
                                    sp.pairs[(t >> 16) as usize].push((t as u64) << 32 | k as u64);
                                }
                                symbols(&buf, &mut sp.syms);
                                // Big files are candidates far more often (per byte of
                                // filter too): three bits a gram for them, two for others.
                                bloom(&hashes, if buf.len() >= 4 << 10 { 3 } else { 2 }, &mut sp.blooms);
                                let bloom = bl..sp.blooms.len();
                                sp.contents.push(SplitContent { new: k, hash: h, small: buf.len() < SMALL, sym: sym..sp.syms.len(), bloom });
                            }
                            Holds::New(k)
                        }
                    }
                };
                sp.docs.push((i, holds));
            }
            scratch.lock().unwrap().push((seen, buf, hashes, tri));
            sp
        })
        .collect();
    // The new contents, numbered by their first doc (docs in path order:
    // splits cover contiguous runs, in order), with gids.
    let nnew = new.into_inner().unwrap().len();
    let (mut local, mut first) = (vec![NONE; nnew], Vec::with_capacity(nnew));
    for (d, &(_, holds)) in splits.iter().flat_map(|sp| &sp.docs).enumerate() {
        if let Holds::New(k) = holds
            && local[k as usize] == NONE
        {
            local[k as usize] = first.len() as u32;
            first.push(d as u32);
        }
    }
    let gids = dedup.free.lock().unwrap().take(nnew);
    let meta: Vec<DocMeta> = (splits.iter().flat_map(|sp| &sp.docs))
        .map(|&(i, holds)| {
            let (_, _, size, mtime) = docs.items[i];
            let gid = match holds {
                Holds::Nothing => NONE,
                Holds::Gid(g) => g,
                Holds::New(k) => gids[local[k as usize] as usize],
            };
            DocMeta { path: docs.path(i), size, mtime, rank: if gid == NONE { NOT_TEXT } else { doc_rank(docs.path(i)) }, gid }
        })
        .collect();
    let mut own: Vec<Option<ContentMeta>> = (0..nnew).map(|_| None).collect();
    for sp in &splits {
        for c in &sp.contents {
            let l = local[c.new as usize] as usize;
            own[l] = Some(ContentMeta { gid: gids[l], hash: c.hash, bloom: &sp.blooms[c.bloom.clone()], doc: first[l] });
        }
    }
    let own: Vec<ContentMeta> = own.into_iter().map(Option::unwrap).collect();
    let shared: Vec<([u64; 2], u32)> =
        splits.iter().flat_map(|sp| &sp.contents).filter(|c| !c.small).map(|c| (c.hash, gids[local[c.new as usize] as usize])).collect();
    // Postings, built in parallel over runs of keys: a run of trigrams takes
    // its bucket of every split, the definition keys every new content's.
    let parts = key_runs()
        .map(|keys| {
            let mut pairs: Vec<u64> = Vec::new();
            if keys.start < 1 << 24 {
                for sp in &splits {
                    pairs.extend(sp.pairs[(keys.start >> 16) as usize].iter().map(|&p| p >> 32 << 32 | local[p as u32 as usize] as u64));
                }
            } else {
                for sp in &splits {
                    for c in &sp.contents {
                        let l = local[c.new as usize] as u64;
                        pairs.extend(sp.syms[c.sym.clone()].iter().map(|&x| (x as u64) << 32 | l));
                    }
                }
            }
            pairs.sort_unstable();
            let (mut part, mut list) = (Postings::default(), Vec::new());
            for run in pairs.chunk_by(|a, b| a >> 32 == b >> 32) {
                list.clear();
                list.extend(run.iter().map(|&p| p as u32));
                part.push(nnew, (run[0] >> 32) as u32, &list);
            }
            part
        })
        .collect();
    let seg = write_segment(dir, id, &meta, &own, parts)?;
    // This sync's later builds find these contents.
    dedup.built.lock().unwrap().extend(shared);
    Some(seg)
}

/// Merge segments into one, dropping tombstoned docs and the contents no
/// live doc (anywhere) holds. Postings stay in order because contents are
/// renumbered segment by segment.
pub fn merge(dir: &Path, id: u64, segs: &[&Segment]) -> Option<Segment> {
    let mut meta = Vec::new();
    for s in segs {
        for d in (0..s.ndocs as u32).filter(|&d| !s.is_dead(d)) {
            let i = d as usize;
            meta.push(DocMeta { path: s.path(d), size: s.size()[i], mtime: s.mtime()[i], rank: s.rank()[i], gid: s.doc_gid()[i] });
        }
    }
    let (mut own, mut remap) = (Vec::new(), Vec::with_capacity(segs.len()));
    for s in segs {
        let mut r = vec![NONE; s.nown];
        for c in (0..s.nown).filter(|&c| s.refs.get(c) > 0) {
            r[c] = own.len() as u32;
            own.push(ContentMeta { gid: s.own_gid()[c], hash: s.hash_of(c as u32), bloom: s.bloom_of(c as u32), doc: NONE });
        }
        remap.push(r);
    }
    let at: HashMap<u32, u32> = own.iter().enumerate().map(|(c, m)| (m.gid, c as u32)).collect();
    for (d, m) in meta.iter().enumerate() {
        if let Some(&c) = at.get(&m.gid)
            && own[c as usize].doc == NONE
        {
            own[c as usize].doc = d as u32;
        }
    }
    // Postings, merged in parallel over runs of keys.
    let parts = key_runs()
        .map(|keys| {
            let k = |s: &Segment, x: u64| s.tri_key().partition_point(|&t| (t as u64) < x);
            let mut pos: Vec<std::ops::Range<usize>> = segs.iter().map(|s| k(s, keys.start)..k(s, keys.end)).collect();
            let (mut out, mut list, mut part) = (Postings::default(), Vec::new(), Vec::new());
            while let Some(t) = segs.iter().zip(&pos).filter(|(_, p)| !p.is_empty()).map(|(s, p)| s.tri_key()[p.start]).min() {
                list.clear();
                for (si, s) in segs.iter().enumerate() {
                    if !pos[si].is_empty() && s.tri_key()[pos[si].start] == t {
                        part.clear();
                        s.list_into(pos[si].start, &mut part);
                        list.extend(part.iter().map(|&c| remap[si][c as usize]).filter(|&c| c != NONE));
                        pos[si].start += 1;
                    }
                }
                if !list.is_empty() {
                    out.push(own.len(), t, &list);
                }
            }
            out
        })
        .collect();
    write_segment(dir, id, &meta, &own, parts)
}

/// The key space in runs that postings are built in, in parallel: the
/// trigrams 64k at a time, then the definition keys (above 2^24).
fn key_runs() -> impl IndexedParallelIterator<Item = std::ops::Range<u64>> {
    (0..257usize).into_par_iter().map(|r| if r < 256 { (r as u64) << 16..(r as u64 + 1) << 16 } else { 1 << 24..1 << 32 })
}

/// Posting lists for a run of keys, encoded: the keys (ascending), where
/// each list starts in `post` (with its flags), and the bytes.
#[derive(Default)]
struct Postings {
    keys: Vec<u32>,
    offs: Vec<u32>,
    post: Vec<u8>,
}

impl Postings {
    /// Add `key`'s contents (ascending) in a segment owning `n`: a bitset
    /// when dense, delta varints otherwise.
    fn push(&mut self, n: usize, key: u32, list: &[u32]) {
        self.keys.push(key);
        if list.len() * 8 > n {
            self.offs.push(self.post.len() as u32 | BITSET);
            let at = self.post.len();
            self.post.resize(at + n.div_ceil(8), 0);
            for &d in list {
                self.post[at + d as usize / 8] |= 1 << (d % 8);
            }
        } else {
            let (at, skips) = (self.post.len(), list.len().saturating_sub(1) / SKIP);
            if skips > 0 {
                self.offs.push(at as u32 | SKIPS);
                self.post.extend_from_slice(&(skips as u32).to_le_bytes());
                self.post.resize(at + 4 + skips * 8, 0);
            } else {
                self.offs.push(at as u32);
            }
            let start = self.post.len();
            let mut last = 0u32;
            for (i, &d) in list.iter().enumerate() {
                if i > 0 && i % SKIP == 0 {
                    let e = at + 4 + (i / SKIP - 1) * 8;
                    let off = (self.post.len() - start) as u32;
                    self.post[e..e + 8].copy_from_slice(&((off as u64) << 32 | last as u64).to_le_bytes());
                }
                put_varint(&mut self.post, d - last);
                last = d;
            }
        }
    }
}

/// Write the segment file: docs, own contents, and their postings in runs
/// of keys (ascending).
fn write_segment(dir: &Path, id: u64, docs: &[DocMeta<'_>], own: &[ContentMeta<'_>], parts: Vec<Postings>) -> Option<Segment> {
    if docs.is_empty() && own.is_empty() {
        return None;
    }
    let (ndocs, nown) = (docs.len(), own.len());
    let (mut keys, mut tri_off, mut post) = (Vec::new(), Vec::new(), Vec::new());
    for p in &parts {
        let base = post.len() as u32;
        keys.extend_from_slice(&p.keys);
        tri_off.extend(p.offs.iter().map(|&o| ((o & !FLAGS) + base) | (o & FLAGS)));
        post.extend_from_slice(&p.post);
    }
    drop(parts);
    tri_off.push(post.len() as u32);
    let mut paths = Vec::new();
    let mut path_off = vec![0u32];
    for d in docs {
        paths.extend_from_slice(d.path);
        path_off.push(paths.len() as u32);
    }
    let size: Vec<u64> = docs.iter().map(|d| d.size).collect();
    let mtime: Vec<u32> = docs.iter().map(|d| d.mtime).collect();
    let rank: Vec<i8> = docs.iter().map(|d| d.rank).collect();
    let mut by_path: Vec<u32> = (0..ndocs as u32).collect();
    by_path.sort_by(|&a, &b| docs[a as usize].path.cmp(docs[b as usize].path));
    let mut by_rank: Vec<u32> = (0..ndocs as u32).collect();
    by_rank.sort_by_key(|&d| (rank_key(docs[d as usize].rank, docs[d as usize].mtime), d));
    let doc_gid: Vec<u32> = docs.iter().map(|d| d.gid).collect();
    let rank_gid: Vec<u32> = by_rank.iter().map(|&d| doc_gid[d as usize]).collect();
    let mut by_gid: Vec<u32> = (0..ndocs as u32).collect();
    by_gid.sort_by_key(|&d| doc_gid[d as usize]);
    let gid_sorted: Vec<u32> = by_gid.iter().map(|&d| doc_gid[d as usize]).collect();
    let own_gid: Vec<u32> = own.iter().map(|c| c.gid).collect();
    let own_doc: Vec<u32> = own.iter().map(|c| c.doc).collect();
    let hash: Vec<u64> = own.iter().flat_map(|c| c.hash).collect();
    let mut by_hash: Vec<u32> = (0..nown as u32).collect();
    by_hash.sort_by_key(|&c| own[c as usize].hash);
    let (mut bloom_off, mut blooms) = (vec![0u32], Vec::new());
    for c in own {
        blooms.extend_from_slice(c.bloom);
        bloom_off.push(blooms.len() as u32);
    }

    let (off, _) = layout(&lens(ndocs, keys.len(), post.len(), paths.len(), blooms.len(), nown));
    let fields = [ndocs, keys.len(), post.len(), paths.len(), blooms.len(), nown].map(|v| v as u64);
    let hdr = header(MAGIC, &fields);
    let sections: [&[u8]; NS] = [
        as_bytes(&keys),
        as_bytes(&tri_off),
        &post,
        as_bytes(&path_off),
        &paths,
        as_bytes(&size),
        as_bytes(&mtime),
        as_bytes(&by_path),
        as_bytes(&rank),
        as_bytes(&by_rank),
        as_bytes(&doc_gid),
        as_bytes(&rank_gid),
        as_bytes(&gid_sorted),
        as_bytes(&by_gid),
        as_bytes(&own_gid),
        as_bytes(&own_doc),
        as_bytes(&hash),
        as_bytes(&by_hash),
        as_bytes(&bloom_off),
        as_bytes(&blooms),
    ];
    let p = seg_path(dir, id);
    let tmp = p.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
        f.write_all(&hdr)?;
        let mut at = HDR;
        for (k, sec) in sections.iter().enumerate() {
            f.write_all(&vec![0u8; off[k] - at])?;
            f.write_all(sec)?;
            at = off[k] + sec.len();
        }
        f.write_all(&vec![0u8; ((at + 63) & !63) - at])?;
        f.flush()
    };
    write().ok()?;
    std::fs::rename(&tmp, &p).ok()?;
    Segment::load(dir, id)
}

/// Should this file be in the content index?
pub fn eligible(path: &[u8], size: u64, home: &[u8]) -> bool {
    let name = &path[path.iter().rposition(|&b| b == b'/').map_or(0, |p| p + 1)..];
    name_ok(name, size) && in_scope(path, home)
}

/// The name/size half of eligibility, checkable before building a path.
fn name_ok(name: &[u8], size: u64) -> bool {
    if size > MAX_FILE {
        return false;
    }
    match name.iter().rposition(|&b| b == b'.').filter(|&p| p > 0) {
        Some(dot) => {
            let ext = &name[dot + 1..];
            TEXT_EXTS.iter().any(|x| x.eq_ignore_ascii_case(ext)) && !name.ends_with(b".min.js") && name != b"package-lock.json"
        }
        None => size <= 256 << 10,
    }
}

/// Is this path (file or directory) inside the indexed area?
pub fn in_scope(path: &[u8], home: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(home) else { return false };
    if !rest.is_empty() && rest[0] != b'/' {
        return false;
    }
    let rel = rest.strip_prefix(b"/").unwrap_or(rest);
    if SKIP_UNDER_HOME.iter().any(|p| rel.starts_with(p) && rel.get(p.len()).is_none_or(|&b| b == b'/')) {
        return false;
    }
    !rel.split(|&b| b == b'/').any(|c| SKIP_DIRS.contains(&c) || SKIP_SUFFIXES.iter().any(|x| c.len() > x.len() && c.ends_with(x)))
}

/// Does the name query let every indexed doc under its scope (if any)
/// through: no words, extensions, ranges or patterns? Then a segment wholly
/// in scope needn't be checked doc by doc.
fn only_scope(q: &Query) -> bool {
    q.tokens.is_empty()
        && q.kind_ok(KIND_FILE)
        && q.exts.is_empty()
        && q.size == (0, u64::MAX)
        && q.mtime == (0, u32::MAX)
        && q.name_re.is_none()
        && q.path_re.is_none()
}

/// Candidate order tier: your files first, then dot-dirs, logs and transcripts.
fn doc_rank(path: &[u8]) -> i8 {
    let mut r = 0i8;
    if path.split(|&b| b == b'/').any(|c| c.first() == Some(&b'.')) {
        r -= 2;
    }
    let name = &path[path.iter().rposition(|&b| b == b'/').map_or(0, |p| p + 1)..];
    if [&b".jsonl"[..], b".ndjson", b".log", b".lock", b".sum"].iter().any(|x| name.ends_with(x)) {
        r -= 1;
    }
    r
}

pub struct Content {
    pub dir: PathBuf,
    pub segs: Vec<Segment>,
    next_id: u64,
    /// Every segment's own contents as runs of gids, by first gid: (first
    /// gid, length, segment, first content).
    gids: Vec<(u32, u32, u32, u32)>,
    /// Per segment, where its docs start in one numbering of all docs; and
    /// per 256 of those numbers, the segment where the first one is.
    base: Vec<u32>,
    blocks: Vec<u32>,
    /// Per segment, its own contents held by more docs than their first one.
    copies: Vec<Copies>,
    /// Per segment, the segments whose live docs hold its contents (itself
    /// too), each with how many of them.
    users: Vec<Vec<(u32, u32)>>,
    /// Per segment, the segments owning contents its live docs hold (itself
    /// too), each with how many of them.
    sources: Vec<Vec<(u32, u32)>>,
}

/// A segment's own contents held by more docs than their first one: those
/// contents (ascending), where each one's other docs start in `docs` (the
/// next start ends them), and those docs, numbered by `Content::base`.
#[derive(Default)]
struct Copies {
    contents: Vec<u32>,
    starts: Vec<u32>,
    docs: Vec<u32>,
}

/// How many live docs hold each of a segment's own contents, in bit planes
/// (bit c of plane k: bit k of content c's count), so that the docs holding
/// any of a set of contents add up a word at a time.
#[derive(Default)]
struct Counts {
    planes: Vec<Vec<u64>>,
    n: usize,
}

impl Counts {
    fn new(n: usize) -> Counts {
        Counts { planes: Vec::new(), n }
    }

    fn get(&self, c: usize) -> u32 {
        self.planes.iter().enumerate().map(|(k, p)| ((p[c / 64] >> (c % 64) & 1) as u32) << k).sum()
    }

    fn add(&mut self, c: usize) {
        for p in &mut self.planes {
            p[c / 64] ^= 1 << (c % 64);
            if p[c / 64] >> (c % 64) & 1 != 0 {
                return;
            }
        }
        let mut p = vec![0u64; self.n.div_ceil(64)];
        p[c / 64] = 1 << (c % 64);
        self.planes.push(p);
    }

    /// (The count is above zero.)
    fn sub(&mut self, c: usize) {
        for p in &mut self.planes {
            p[c / 64] ^= 1 << (c % 64);
            if p[c / 64] >> (c % 64) & 1 == 0 {
                return;
            }
        }
    }

    /// The counts of the contents set in `bits`, added up.
    fn sum(&self, bits: &[u64]) -> usize {
        (self.planes.iter().enumerate()).map(|(k, p)| p.iter().zip(bits).map(|(a, b)| (a & b).count_ones() as usize).sum::<usize>() << k).sum()
    }

    /// How many are held at all.
    fn live(&self) -> usize {
        (0..self.n.div_ceil(64)).map(|w| self.planes.iter().fold(0, |x, p| x | p[w]).count_ones() as usize).sum()
    }
}

/// The segment and own content of gid `g`, by the table in `Content::gids`.
fn content_of(gids: &[(u32, u32, u32, u32)], g: u32) -> Option<(usize, u32)> {
    let i = gids.partition_point(|r| r.0 <= g).checked_sub(1)?;
    let (g0, n, s, c0) = gids[i];
    (g - g0 < n).then_some((s as usize, c0 + (g - g0)))
}

impl Content {
    /// Open the segments the manifest lists, without touching anything: the
    /// view of an engine that follows another process's index.
    pub fn open_shared(dir: PathBuf) -> Content {
        let manifest: Vec<u64> =
            std::fs::read_to_string(dir.join("manifest")).unwrap_or_default().split_whitespace().filter_map(|s| s.parse().ok()).collect();
        let segs: Vec<Segment> = manifest.iter().filter_map(|&id| Segment::load(&dir, id)).collect();
        let next_id = segs.iter().map(|s| s.id + 1).max().unwrap_or(1);
        #[rustfmt::skip]
        let mut c = Content { dir, segs, next_id, gids: Vec::new(), base: Vec::new(), blocks: Vec::new(), copies: Vec::new(), users: Vec::new(), sources: Vec::new() };
        c.link();
        c
    }

    /// Open as the owner: also delete what the manifest doesn't list.
    pub fn open(dir: PathBuf) -> Content {
        std::fs::create_dir_all(&dir).ok();
        let c = Content::open_shared(dir);
        // Anything not loaded (old format, crashed build) is garbage.
        let keep: Vec<String> = c.segs.iter().flat_map(|s| [format!("seg-{:06}.fsc", s.id), format!("seg-{:06}.dead", s.id)]).collect();
        for e in std::fs::read_dir(&c.dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("seg-") && !keep.contains(&name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        c
    }

    /// Link the segments through the contents they share: the gid table,
    /// each content's live docs, and which segments use which.
    fn link(&mut self) {
        self.gids = (self.segs.iter().enumerate()).flat_map(|(si, s)| s.runs.iter().map(move |&(c, g, n)| (g, n, si as u32, c))).collect();
        self.gids.sort_unstable();
        self.base = Vec::new();
        self.copies = (0..self.segs.len()).map(|_| Copies::default()).collect();
        self.users = vec![Vec::new(); self.segs.len()];
        self.sources = vec![Vec::new(); self.segs.len()];
        for s in &mut self.segs {
            s.refs = Counts::new(s.nown);
        }
        self.link_docs(0);
    }

    /// Link the live docs of the segments from `from` on (all earlier ones
    /// linked) to the contents they hold.
    fn link_docs(&mut self, from: usize) {
        let n = self.segs.len();
        while self.base.len() < n {
            let at = self.base.len();
            self.base.push(if at == 0 { 0 } else { self.base[at - 1] + self.segs[at - 1].ndocs as u32 });
        }
        let all = self.base.last().map_or(0, |&b| b as usize + self.segs[n - 1].ndocs);
        self.blocks = (0..all.div_ceil(256)).map(|k| (self.base.partition_point(|&b| b as usize <= k * 256) - 1) as u32).collect();
        let mut refs: Vec<Counts> = self.segs.iter_mut().map(|s| std::mem::take(&mut s.refs)).collect();
        // Per owner, (content, doc) of the docs that are not its first.
        let mut more: Vec<Vec<(u32, u32)>> = vec![Vec::new(); n];
        for b in from..n {
            let s = &self.segs[b];
            let mut weight = vec![0u32; n];
            // The run the last doc's gid was in: copies come in runs too.
            let mut run = (0u32, 0u32, 0u32, 0u32);
            for (d, &g) in s.doc_gid().iter().enumerate() {
                if g == NONE || s.is_dead(d as u32) {
                    continue;
                }
                if g.wrapping_sub(run.0) >= run.1 {
                    let Some(i) = self.gids.partition_point(|r| r.0 <= g).checked_sub(1).filter(|&i| g - self.gids[i].0 < self.gids[i].1) else {
                        continue;
                    };
                    run = self.gids[i];
                }
                let (a, c) = (run.2 as usize, run.3 + g - run.0);
                refs[a].add(c as usize);
                weight[a] += 1;
                if !(a == b && self.segs[a].own_doc()[c as usize] == d as u32) {
                    more[a].push((c, self.base[b] + d as u32));
                }
            }
            for (a, &w) in weight.iter().enumerate().filter(|(_, w)| **w > 0) {
                self.users[a].push((b as u32, w));
                self.sources[b].push((a as u32, w));
            }
        }
        for (a, mut add) in more.into_iter().enumerate().filter(|(_, m)| !m.is_empty()) {
            let cp = &mut self.copies[a];
            for (k, &c) in cp.contents.iter().enumerate() {
                let end = cp.starts.get(k + 1).map_or(cp.docs.len(), |&e| e as usize);
                add.extend(cp.docs[cp.starts[k] as usize..end].iter().map(|&h| (c, h)));
            }
            add.sort_unstable();
            *cp = Copies { docs: Vec::with_capacity(add.len()), ..Default::default() };
            for (k, &(c, h)) in add.iter().enumerate() {
                if cp.contents.last() != Some(&c) {
                    cp.contents.push(c);
                    cp.starts.push(k as u32);
                }
                cp.docs.push(h);
            }
            cp.contents.shrink_to_fit();
            cp.starts.shrink_to_fit();
        }
        for (s, r) in self.segs.iter_mut().zip(refs) {
            s.refs = r;
        }
    }

    /// The segment and doc numbered `h` (see `base`).
    #[inline]
    fn doc_at(&self, h: u32) -> (usize, u32) {
        let mut b = self.blocks[h as usize / 256] as usize;
        while self.base.get(b + 1).is_some_and(|&x| x <= h) {
            b += 1;
        }
        (b, h - self.base[b])
    }

    /// The segment and own content of gid `g`.
    fn content_of(&self, g: u32) -> Option<(usize, u32)> {
        content_of(&self.gids, g)
    }

    /// Every live doc holding one of the own contents `sel` (ascending) of
    /// segment `a`, as (segment, doc).
    fn holders(&self, a: usize, sel: &[u32], mut f: impl FnMut(usize, u32)) {
        let (s, cp) = (&self.segs[a], &self.copies[a]);
        let mut k = 0;
        for &c in sel {
            let first = s.own_doc()[c as usize];
            if first != NONE && !s.is_dead(first) {
                f(a, first);
            }
            k = gallop(&cp.contents, k, c);
            if cp.contents.get(k) == Some(&c) {
                let end = cp.starts.get(k + 1).map_or(cp.docs.len(), |&e| e as usize);
                for &h in &cp.docs[cp.starts[k] as usize..end] {
                    let (b, d) = self.doc_at(h);
                    if !self.segs[b].is_dead(d) {
                        f(b, d);
                    }
                }
            }
        }
    }

    fn save_manifest(&self) {
        let s: String = self.segs.iter().map(|s| format!("{}\n", s.id)).collect();
        let tmp = self.dir.join("manifest.tmp");
        if std::fs::write(&tmp, s).is_ok() {
            let _ = std::fs::rename(tmp, self.dir.join("manifest"));
        }
    }

    pub fn docs(&self) -> usize {
        self.segs.iter().map(|s| s.live_docs).sum()
    }

    pub fn bytes(&self) -> usize {
        self.segs.iter().map(|s| s.map.len()).sum()
    }

    /// Diff what the name index wants (from `wanted`, per dir) against the
    /// docs we hold: tombstone what changed or went away, return what needs
    /// (re)indexing. Cheap; the caller builds segments off-lock.
    pub fn diff(&mut self, wants: Vec<(Vec<u8>, bool, Docs)>) -> Docs {
        let mut todo = Docs::default();
        let mut touched = vec![false; self.segs.len()];
        let mut killed = Vec::new();
        let gids = &self.gids;
        for (dir, recursive, want) in wants {
            let mut held = vec![false; want.len()];
            let lo = join(&dir, b"");
            for (si, s) in self.segs.iter_mut().enumerate() {
                let ids = if recursive { s.with_prefix(&lo).collect::<Vec<_>>() } else { s.direct_children(&lo) };
                for d in ids {
                    let (i, g) = (d as usize, s.doc_gid()[d as usize]);
                    match want.find(s.path(d)) {
                        // (A doc whose content is gone is indexed again.)
                        Some(k)
                            if want.items[k].2 == s.size()[i] && want.items[k].3 == s.mtime()[i] && (g == NONE || content_of(gids, g).is_some()) =>
                        {
                            held[k] = true
                        }
                        _ => {
                            if s.kill(d) {
                                touched[si] = true;
                                killed.push(g);
                            }
                        }
                    }
                }
            }
            for (i, h) in held.iter().enumerate() {
                if !h {
                    let (_, _, size, mtime) = want.items[i];
                    todo.push(want.path(i), size, mtime);
                }
            }
        }
        for g in killed {
            if let Some((a, c)) = self.content_of(g) {
                self.segs[a].refs.sub(c as usize);
            }
        }
        for (s, t) in self.segs.iter().zip(&touched) {
            if *t {
                s.save_dead(&self.dir);
            }
        }
        // A segment goes once no live doc is in it and none holds its contents.
        let empty: Vec<u64> = self.segs.iter().filter(|s| s.live_docs == 0 && s.live_own() == 0).map(|s| s.id).collect();
        if !empty.is_empty() {
            self.drop_segments(&empty);
            self.link();
            self.save_manifest();
        }
        todo.sort();
        if !todo.is_empty() {
            let _ = todo.dedup.set(self.dedup());
        }
        todo
    }

    /// What a sync's builds need to index each distinct content once: the
    /// segments' own contents, by hash, and the gids no segment owns.
    fn dedup(&self) -> Dedup {
        let held = self.segs.iter().filter(|s| s.nown > 0).map(|s| Held { map: s.map.clone(), nown: s.nown, off: s.off }).collect();
        let (mut gaps, mut next) = (Vec::new(), 0u32);
        for &(g, n, _, _) in &self.gids {
            if g > next {
                gaps.push((next, g));
            }
            next = next.max(g + n);
        }
        Dedup { held, built: Default::default(), free: std::sync::Mutex::new(Gids { gaps, next }) }
    }

    /// Folders holding an indexed file that changed (or went away) since
    /// `since`: an edit in place leaves its folder's mtime alone, so lost
    /// FSEvents history is recovered for the content index by an lstat per
    /// indexed file.
    pub fn changed_dirs(&self, since: u32) -> Vec<Vec<u8>> {
        let pool = crate::live::stat_pool();
        let mut out: Vec<Vec<u8>> = pool.install(|| {
            self.segs
                .par_iter()
                .flat_map_iter(|s| (0..s.ndocs as u32).filter(|&d| !s.is_dead(d)).map(move |d| (s, d)))
                .filter(|&(s, d)| crate::live::lstat(s.path(d)).is_none_or(|o| o.mtime >= since || o.size != s.size()[d as usize]))
                .map(|(s, d)| {
                    let p = s.path(d);
                    p[..p.iter().rposition(|&b| b == b'/').unwrap_or(0).max(1)].to_vec()
                })
                .collect()
        });
        out.sort();
        out.dedup();
        out
    }

    pub fn alloc_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id - 1
    }

    pub fn push(&mut self, seg: Segment) {
        let si = self.segs.len() as u32;
        self.gids.extend(seg.runs.iter().map(|&(c, g, n)| (g, n, si, c)));
        self.gids.sort_unstable();
        self.segs.push(seg);
        self.copies.push(Copies::default());
        self.users.push(Vec::new());
        self.sources.push(Vec::new());
        self.link_docs(self.segs.len() - 1);
        self.save_manifest();
    }

    /// Tiered merging: 8 segments of the same size tier become one, so
    /// incremental updates never pile up thousands of tiny segments. Returns
    /// the group to merge (ids), capped so a merge's postings stay small.
    /// First, a segment whose docs or contents were mostly replaced is
    /// rewritten alone: every query decodes the postings of its dead
    /// contents too.
    pub fn merge_plan(&self) -> Option<Vec<u64>> {
        let stale = |s: &&Segment| {
            let own = s.live_own();
            (s.live_docs > 0 || own > 0) && (s.live_docs * 2 < s.ndocs || own * 2 < s.nown)
        };
        if let Some(s) = self.segs.iter().find(stale) {
            return Some(vec![s.id]);
        }
        let tier = |s: &Segment| (s.plen.max(1) as f64).log(4.0) as u32;
        let mut by_tier: HashMap<u32, Vec<&Segment>> = HashMap::new();
        for s in &self.segs {
            by_tier.entry(tier(s)).or_default().push(s);
        }
        let mut tiers: Vec<_> = by_tier.into_iter().filter(|(_, v)| v.len() >= 8).collect();
        tiers.sort_by_key(|(t, _)| *t);
        for (_, v) in tiers {
            let group: Vec<u64> = v.iter().take(8).map(|s| s.id).collect();
            let bytes: usize = v.iter().take(8).map(|s| s.plen).sum();
            if bytes <= MERGE_CAP {
                return Some(group);
            }
        }
        None
    }

    pub fn segments(&self, ids: &[u64]) -> Vec<&Segment> {
        self.segs.iter().filter(|s| ids.contains(&s.id)).collect()
    }

    /// Swap merged segments for their replacement, where the first of them
    /// was (a rewritten segment keeps its place in the ranking's tie order).
    /// Only the content worker writes, so nothing was tombstoned while the
    /// merge ran.
    pub fn replace(&mut self, ids: &[u64], seg: Segment) {
        let at = self.segs.iter().position(|s| ids.contains(&s.id)).unwrap_or(self.segs.len());
        self.drop_segments(ids);
        self.segs.insert(at, seg);
        self.link();
        self.save_manifest();
    }

    fn drop_segments(&mut self, ids: &[u64]) {
        self.segs.retain(|s| !ids.contains(&s.id));
        for id in ids {
            let _ = std::fs::remove_file(seg_path(&self.dir, *id));
            let _ = std::fs::remove_file(dead_path(&self.dir, *id));
        }
    }

    /// Candidate docs for a pattern, filtered by the name query: in groups
    /// (each with its `FIRST` best in front), and how many in all.
    fn candidates(&self, plan: &TQ, filt: &Query) -> Found {
        // A scope narrows each segment to the doc range holding its paths;
        // None: no live doc there under it.
        let prefix = filt.scope.as_ref().map(|s| [s.as_slice(), b"/"].concat());
        let only_scope = only_scope(filt);
        let scope: Vec<Option<(std::ops::Range<u32>, bool)>> = (self.segs.iter())
            .map(|s| {
                let (docs, whole) = prefix.as_ref().map_or((0..s.ndocs as u32, true), |p| s.doc_range(p));
                (s.live_docs > 0 && !docs.is_empty()).then_some((docs, !(only_scope && whole)))
            })
            .collect();
        // About a lane per 25k docs to search, at most 8: helpers start
        // within ~10 us, but past 8 lanes they get in each other's way.
        let docs: usize = scope.iter().flatten().map(|(docs, _)| docs.len()).sum();
        let lanes = |n: usize| (docs / 25_000).clamp(1, n.max(1)).min(8);
        let ranked = |s: &Segment, si: usize, d: u32| (rank_key(s.rank()[d as usize], s.mtime()[d as usize]), si as u32, d);
        if matches!(plan, TQ::All) {
            let work: Vec<usize> = (0..self.segs.len()).filter(|&si| scope[si].is_some()).collect();
            let per = par_claim(&work, lanes(work.len()), |&si| {
                let s = &self.segs[si];
                let (docs, check) = scope[si].clone().unwrap();
                let ids = if !check && docs.len() == s.ndocs {
                    let (mut bits, total) = live_text(s);
                    // A pattern with nothing to look up: walk the docs
                    // best-ranked first, to the segment's FIRST best.
                    if total * 8 > s.ndocs {
                        let mut top = Vec::with_capacity(FIRST);
                        for &d in s.by_rank() {
                            if top.len() == FIRST {
                                break;
                            }
                            let w = &mut bits[d as usize / 64];
                            if *w >> (d % 64) & 1 != 0 {
                                *w &= !(1 << (d % 64));
                                top.push(ranked(s, si, d));
                            }
                        }
                        return (Cands::Walk { si, bits, top }, total);
                    }
                    set_bits(&bits, total)
                } else {
                    docs.collect()
                };
                let mut v: Vec<Ranked> = Vec::with_capacity(ids.len());
                v.extend(
                    ids.into_iter()
                        .filter(|&d| !s.is_dead(d) && s.rank()[d as usize] != NOT_TEXT)
                        .filter(|&d| !check || filt.match_path(s.path(d), KIND_FILE, s.size()[d as usize], s.mtime()[d as usize]).is_some())
                        .map(|d| ranked(s, si, d)),
                );
                let n = v.len();
                (Cands::list(v), n)
            });
            let total = per.iter().map(|p| p.1).sum();
            return Found { per: per.into_iter().map(|p| p.0).collect(), total, dense: Vec::new() };
        }
        // Every live doc counts, unchecked: then a content found in bulk
        // counts as its live docs.
        let global =
            scope.iter().zip(&self.segs).all(|(x, s)| s.live_docs == 0 || x.as_ref().is_some_and(|(docs, check)| !check && docs.len() == s.ndocs));
        // A candidate doc under the scope.
        let admit = |b: usize, d: u32| -> Option<Ranked> {
            let (docs, check) = scope[b].as_ref()?;
            let t = &self.segs[b];
            let ok = docs.contains(&d) && (!check || filt.match_path(t.path(d), KIND_FILE, t.size()[d as usize], t.mtime()[d as usize]).is_some());
            ok.then(|| ranked(t, b, d))
        };
        // A scope holding few of the docs (up to 1 in 16): the contents its
        // docs hold, per owner, then which of those the plan selects (in the
        // range they span).
        let few = self.segs.iter().map(|s| s.ndocs).sum::<usize>() / 16;
        let under: Option<Vec<(usize, Vec<u32>)>> = (prefix.as_ref())
            .filter(|p| {
                !global && (self.segs.iter().enumerate()).filter(|(b, _)| scope[*b].is_some()).map(|(_, t)| t.count_prefix(p)).sum::<usize>() <= few
            })
            .map(|p| (0..self.segs.len()).filter(|&b| scope[b].is_some()).map(|b| (b, self.segs[b].with_prefix(p).collect())).collect());
        if let Some(under) = under {
            let mut need: Vec<Vec<(u32, u32, u32)>> = vec![Vec::new(); self.segs.len()];
            for (b, docs) in under {
                let t = &self.segs[b];
                for d in docs {
                    if let Some((a, c)) = self.content_of(t.doc_gid()[d as usize]) {
                        need[a].push((c, b as u32, d));
                    }
                }
            }
            let owners: Vec<usize> = (0..self.segs.len()).filter(|&a| !need[a].is_empty()).collect();
            let per = par_claim(&owners, lanes(owners.len()), |&a| {
                let mut top = Top::new();
                let n = needed(&self.segs[a], plan, need[a].clone(), |b, d| admit(b, d).map(|r| top.push(r)).is_some());
                (top.done(), n)
            });
            let total = per.iter().map(|p| p.1).sum();
            return Found { per: per.into_iter().map(|p| p.0).collect(), total, dense: Vec::new() };
        }
        // Per segment owning contents docs under the scope hold, the ones
        // the plan selects. A few become their docs right away (many, in
        // chunks any lane takes). When every doc counts, a common pattern's
        // many in a segment (more than 1 in 8 of its contents, and FIRST or
        // more) are set in `dense` by gid instead; once every owner is done,
        // the segments holding them are walked best-ranked first, or find
        // their few by gid (see `decide`).
        use std::sync::atomic::{AtomicUsize, Ordering::*};
        let n = self.segs.len();
        let owners: Vec<usize> =
            (0..n).filter(|&a| self.segs[a].nown > 0 && self.users[a].iter().any(|&(b, _)| scope[b as usize].is_some())).collect();
        // (Made by the first owner that needs it.)
        let dense: std::sync::OnceLock<Vec<std::sync::atomic::AtomicU64>> = Default::default();
        let has_dense = |g: u32| dense.get().and_then(|d| d.get(g as usize / 64)).is_some_and(|w| w.load(Relaxed) >> (g % 64) & 1 != 0);
        // Per owner found in bulk: the contents, and how many.
        let bulk: Vec<std::sync::OnceLock<(Vec<u64>, usize)>> = (0..n).map(|_| Default::default()).collect();
        let (next, done, next_item, total) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
        // Chunks to expand, and how many there are (checked before locking).
        let chunks: std::sync::Mutex<Vec<Chunk>> = Default::default();
        let queued = AtomicUsize::new(0);
        let out = std::sync::Mutex::new(Vec::new());
        // (Each lane gathers the docs it finds in its own `Top`.)
        let expand = |a: usize, sel: &[u32], top: &mut Top| {
            let at = top.len();
            self.holders(a, sel, |b, d| {
                if let Some(r) = admit(b, d) {
                    top.push(r)
                }
            });
            total.fetch_add(top.len() - at, Relaxed);
        };
        // A selection's docs: right away, or in chunks of about 1k docs (by
        // the docs per content here) when bigger.
        let give = |a: usize, sel: Vec<u32>, top: &mut Top| {
            let s = &self.segs[a];
            let docs: usize = self.users[a].iter().map(|&(_, w)| w as usize).sum();
            let step = (1024 * s.nown / docs.max(1)).max(64);
            if sel.len() <= step {
                return expand(a, &sel, top);
            }
            let sel = std::sync::Arc::new(sel);
            let mut q = chunks.lock().unwrap();
            q.extend((step..sel.len()).step_by(step).map(|at| (a, sel.clone(), at..(at + step).min(sel.len()))));
            queued.store(q.len(), Release);
            drop(q);
            expand(a, &sel[..step], top);
        };
        let select = |a: usize, top: &mut Top| {
            let s = &self.segs[a];
            // An owner outside the scope whose contents few docs under it
            // hold: only those contents.
            if scope[a].is_none() && !global {
                let mut need = Vec::new();
                for (b, t) in self.users[a].iter().map(|&(b, _)| b as usize).filter(|&b| scope[b].is_some()).map(|b| (b, &self.segs[b])) {
                    let (gs, by_gid) = (t.gid_sorted(), t.by_gid());
                    for &(c0, g0, m) in &s.runs {
                        let lo = gs.partition_point(|&x| x < g0);
                        let at = lo..lo + gs[lo..].partition_point(|&x| x < g0 + m);
                        need.extend(at.filter(|&i| !t.is_dead(by_gid[i])).map(|i| (c0 + gs[i] - g0, b as u32, by_gid[i])));
                    }
                    if need.len() > 4096 {
                        break;
                    }
                }
                if need.len() <= 4096 {
                    let n = needed(s, plan, need, |b, d| admit(b, d).map(|r| top.push(r)).is_some());
                    total.fetch_add(n, Relaxed);
                    return;
                }
            }
            let sel = match and_dense(s, plan) {
                Some((bits, k)) if global && k * 8 > s.nown && k >= FIRST => Err((bits, k)),
                Some((bits, k)) => Ok(set_bits(&bits, k)),
                None => match eval(s, plan, 0..s.nown as u32) {
                    Some(v) => Ok(v),
                    None if global => Err((all_bits(s.nown), s.nown)),
                    None => Ok((0..s.nown as u32).collect()),
                },
            };
            match sel {
                Ok(sel) => give(a, sel, top),
                Err((bits, k)) => {
                    let max_gid = self.gids.last().map_or(0, |r| r.0 + r.1) as usize;
                    let dense = dense.get_or_init(|| (0..max_gid.div_ceil(64)).map(|_| Default::default()).collect());
                    for &(c, g, m) in &s.runs {
                        or_bits(dense, g as usize, &bits, c as usize, m as usize);
                    }
                    // Every doc counts: as many as hold them.
                    total.fetch_add(s.refs.sum(&bits), Relaxed);
                    let _ = bulk[a].set((bits, k));
                }
            }
        };
        // Once every owner is done, the segments holding contents found in
        // bulk: each walked best-ranked first to its FIRST best when they make
        // it dense in candidates, or it holds many of one owner's (a walk
        // that doesn't stop early costs no more than finding those by gid);
        // else its few found by gid.
        let items: std::sync::OnceLock<Vec<(usize, bool)>> = Default::default();
        let decide = || {
            let held = (0..n).filter(|&b| scope[b].is_some() && self.sources[b].iter().any(|&(a, _)| bulk[a as usize].get().is_some()));
            held.map(|b| {
                let (mut from, mut many) = (0, false);
                for &(a, w) in &self.sources[b] {
                    if let Some(&(_, k)) = bulk[a as usize].get() {
                        from += w as usize * k / self.segs[a as usize].nown;
                        many |= w > 2048;
                    }
                }
                (b, from * 8 > self.segs[b].ndocs || many)
            })
            .collect()
        };
        let run = |&(b, walk): &(usize, bool), top: &mut Top| {
            let t = &self.segs[b];
            if walk {
                let (by_rank, gids) = (t.by_rank(), t.rank_gid());
                let mut best = Vec::with_capacity(FIRST);
                let mut i = 0;
                while i < by_rank.len() && best.len() < FIRST {
                    if has_dense(gids[i]) && !t.is_dead(by_rank[i]) {
                        best.push(ranked(t, b, by_rank[i]));
                    }
                    i += 1;
                }
                return out.lock().unwrap().push(Cands::Bulk { si: b, top: best, from: i });
            }
            // (The owners counted these.)
            let (gs, by_gid) = (t.gid_sorted(), t.by_gid());
            for &(a, _) in &self.sources[b] {
                let Some((bits, _)) = bulk[a as usize].get() else { continue };
                for &(c0, g0, m) in &self.segs[a as usize].runs {
                    let lo = gs.partition_point(|&x| x < g0);
                    for i in lo..lo + gs[lo..].partition_point(|&x| x < g0 + m) {
                        if has(bits, c0 + gs[i] - g0) && !t.is_dead(by_gid[i]) {
                            top.push(ranked(t, b, by_gid[i]));
                        }
                    }
                }
            }
        };
        // Each lane takes owners first; then chunks and, once every owner is
        // done, what is left.
        let work = || {
            let mut top = Top::new();
            loop {
                if next.load(Relaxed) < owners.len() {
                    if let Some(&a) = owners.get(next.fetch_add(1, Relaxed)) {
                        select(a, &mut top);
                        done.fetch_add(1, Release);
                    }
                    continue;
                }
                let items = (done.load(Acquire) == owners.len()).then(|| items.get_or_init(decide));
                if let Some(item) = items.and_then(|items| items.get(next_item.fetch_add(1, Relaxed))) {
                    run(item, &mut top);
                    continue;
                }
                if queued.load(Acquire) > 0 {
                    let chunk = {
                        let mut q = chunks.lock().unwrap();
                        let c = q.pop();
                        queued.store(q.len(), Release);
                        c
                    };
                    if let Some((a, sel, r)) = chunk {
                        expand(a, &sel[r], &mut top);
                    }
                    continue;
                }
                if items.is_some() {
                    break;
                }
                std::thread::yield_now();
            }
            if top.len() > 0 {
                let c = top.done();
                out.lock().unwrap().push(c);
            }
        };
        run_lanes((docs / 25_000).clamp(1, 8), &work);
        let per = out.into_inner().unwrap();
        let dense = dense.into_inner().map_or(Vec::new(), |d| d.into_iter().map(|w| w.into_inner()).collect());
        Found { per, total: total.into_inner(), dense }
    }

    pub fn search(&self, g: &Grep, filt: &Query) -> GrepResult {
        let Found { mut per, total, dense } = self.candidates(&g.plan(), filt);
        // A candidate whose content's bloom filter lacks one of the pattern's
        // grams can't match: skip it without opening the file.
        let probes = g.probes();
        let path = |&(_, si, d): &Ranked| {
            let s = &self.segs[si as usize];
            let (a, c) = self.content_of(s.doc_gid()[d as usize])?;
            self.segs[a].may_contain(c, &probes).then(|| s.path(d))
        };
        // Most searches are done within the best few hundred candidates:
        // rank those first, and the rest only if reading gets that far.
        let t = std::time::Instant::now();
        let best = take_best(&mut per);
        let (mut r, done) = verify_from(g, best.len(), filt.limit, READERS, t, |i| path(&best[i]));
        if r.files.len() < filt.limit && done == best.len() && best.len() < total {
            // Then the next best few thousand, and the others only if
            // reading gets past those too.
            let mut rest: Vec<Ranked> = par_claim(&per, per.len().min(8), |c| c.rest(&self.segs, &dense)).concat();
            let next = rest.len().min(8 * FIRST);
            if next < rest.len() {
                rest.select_nth_unstable(next);
            }
            rest[..next].sort_unstable();
            let mut at = 0;
            for end in [next, rest.len()] {
                if at == end {
                    continue;
                }
                if at > 0 {
                    rest[at..].par_sort_unstable();
                }
                let (more, done) = verify_from(g, end - at, filt.limit - r.files.len(), READERS, t, |i| path(&rest[at + i]));
                r.files.extend(more.files);
                r.read += more.read;
                r.complete = more.complete;
                if r.files.len() >= filt.limit || done < end - at {
                    break;
                }
                at = end;
            }
        }
        r.candidates = total;
        r
    }
}

/// Part of an owner's selection to find the docs of: the owner, the
/// selection, and the part.
type Chunk = (usize, std::sync::Arc<Vec<u32>>, std::ops::Range<usize>);

/// A search's candidates: in groups, how many in all, and the gids of the
/// contents found in bulk.
struct Found {
    per: Vec<Cands>,
    total: usize,
    dense: Vec<u64>,
}

/// Is gid `g` set in `bits`?
#[inline]
fn has(bits: &[u64], g: u32) -> bool {
    bits.get(g as usize / 64).is_some_and(|w| w >> (g % 64) & 1 != 0)
}

/// Of the docs (`need`: content, segment, doc) holding contents of `s`, give
/// `f` those whose contents the plan selects (evaluated over the range they
/// span), and return how many it took.
fn needed(s: &Segment, plan: &TQ, mut need: Vec<(u32, u32, u32)>, mut f: impl FnMut(usize, u32) -> bool) -> usize {
    if need.is_empty() {
        return 0;
    }
    need.sort_unstable();
    let (lo, hi) = (need[0].0, need[need.len() - 1].0 + 1);
    let sel = eval(s, plan, lo..hi).unwrap_or_else(|| (lo..hi).collect());
    let (mut i, mut n) = (0, 0);
    for &(c, b, d) in &need {
        i = gallop(&sel, i, c);
        n += (sel.get(i) == Some(&c) && f(b as usize, d)) as usize;
    }
    n
}

/// The first position at or after `lo` where ascending `a` holds `x` or
/// more: exponential steps, then a binary search.
fn gallop(a: &[u32], lo: usize, x: u32) -> usize {
    if lo >= a.len() || a[lo] >= x {
        return lo;
    }
    let (mut lo, mut step) = (lo, 1);
    while lo + step < a.len() && a[lo + step] < x {
        lo += step;
        step *= 2;
    }
    let hi = (lo + step).min(a.len());
    lo + 1 + a[lo + 1..hi].partition_point(|&y| y < x)
}

/// Bits `from..from + n` of `src`, or'd into `dst` at `at`.
fn or_bits(dst: &[std::sync::atomic::AtomicU64], at: usize, src: &[u64], from: usize, n: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    let mut k = 0;
    while k < n {
        let (s, t, take) = (from + k, at + k, (n - k).min(64));
        let mut w = src[s / 64] >> (s % 64);
        if s % 64 != 0 && s / 64 + 1 < src.len() {
            w |= src[s / 64 + 1] << (64 - s % 64);
        }
        if take < 64 {
            w &= (1 << take) - 1;
        }
        if w != 0 {
            dst[t / 64].fetch_or(w << (t % 64), Relaxed);
            if t % 64 != 0 && w >> (64 - t % 64) != 0 {
                dst[t / 64 + 1].fetch_or(w >> (64 - t % 64), Relaxed);
            }
        }
        k += take;
    }
}

/// All of `n` bits set.
fn all_bits(n: usize) -> Vec<u64> {
    let mut bits = vec![u64::MAX; n.div_ceil(64)];
    if let Some(w) = bits.last_mut().filter(|_| !n.is_multiple_of(64)) {
        *w = (1 << (n % 64)) - 1;
    }
    bits
}

/// A candidate's place in the ranking, packed so sorting compares ints: your
/// files before dot-dirs/logs, then most recently modified first; ties in
/// segment, then doc order. Then its segment and doc.
type Ranked = (u64, u32, u32);

/// The first part of `Ranked`.
fn rank_key(rank: i8, mtime: u32) -> u64 {
    (((127 - rank as i32) as u64) << 32) | (u32::MAX - mtime) as u64
}

/// Candidates ranked in the first round.
const FIRST: usize = 512;

/// Candidates gathered one at a time, keeping the `FIRST` best apart: below
/// `bar` (the best seen past them) they go to `best`, which is cut back to
/// `FIRST` whenever it reaches 8 times that; the others go to `rest`.
struct Top {
    best: Vec<Ranked>,
    rest: Vec<Ranked>,
    bar: Ranked,
}

impl Top {
    fn new() -> Top {
        Top { best: Vec::new(), rest: Vec::new(), bar: (u64::MAX, u32::MAX, u32::MAX) }
    }

    #[inline]
    fn push(&mut self, r: Ranked) {
        if r >= self.bar {
            return self.rest.push(r);
        }
        self.best.push(r);
        if self.best.len() == 8 * FIRST {
            self.best.select_nth_unstable(FIRST);
            self.bar = self.best[FIRST];
            self.rest.extend(self.best.drain(FIRST..));
        }
    }

    fn len(&self) -> usize {
        self.best.len() + self.rest.len()
    }

    fn done(mut self) -> Cands {
        if self.best.len() > FIRST {
            self.best.select_nth_unstable(FIRST);
            self.rest.extend(self.best.drain(FIRST..));
        }
        Cands::Two(self.best, self.rest)
    }
}

/// A group of candidates.
enum Cands {
    /// All of them, the `FIRST` best in front (unordered).
    List(Vec<Ranked>),
    /// The `FIRST` best (unordered), and the others.
    Two(Vec<Ranked>, Vec<Ranked>),
    /// A segment's docs (for a pattern with nothing to look up): `top`, its
    /// `FIRST` best (in order), and the rest, set in `bits`.
    Walk { si: usize, bits: Vec<u64>, top: Vec<Ranked> },
    /// A segment's docs holding a content found in bulk: `top`, its `FIRST`
    /// best (in order), then the rest, in rank order from `from` on.
    Bulk { si: usize, top: Vec<Ranked>, from: usize },
}

impl Cands {
    /// A list, its `FIRST` best in front.
    fn list(mut v: Vec<Ranked>) -> Cands {
        if v.len() > FIRST {
            v.select_nth_unstable(FIRST);
        }
        Cands::List(v)
    }

    /// What `take_best` left, unordered (`dense`: the gids found in bulk).
    fn rest(&self, segs: &[Segment], dense: &[u64]) -> Vec<Ranked> {
        let ranked = |s: &Segment, si: usize, d: u32| (rank_key(s.rank()[d as usize], s.mtime()[d as usize]), si as u32, d);
        match self {
            Cands::List(v) => v.clone(),
            Cands::Two(_, rest) => rest.clone(),
            Cands::Walk { si, bits, .. } => set_bits(bits, 0).into_iter().map(|d| ranked(&segs[*si], *si, d)).collect(),
            Cands::Bulk { si, from, .. } => {
                let s = &segs[*si];
                let (by_rank, gids) = (s.by_rank(), s.rank_gid());
                (*from..by_rank.len()).filter(|&i| has(dense, gids[i]) && !s.is_dead(by_rank[i])).map(|i| ranked(s, *si, by_rank[i])).collect()
            }
        }
    }
}

/// The docs set in `bits` (`n` of them), ascending.
fn set_bits(bits: &[u64], n: usize) -> Vec<u32> {
    let mut ids = Vec::with_capacity(n);
    for (w, &x) in bits.iter().enumerate() {
        let mut x = x;
        while x != 0 {
            ids.push(w as u32 * 64 + x.trailing_zeros());
            x &= x - 1;
        }
    }
    ids
}

/// `items.iter().map(f).collect()` on `lanes` lanes (see `run_lanes`): each
/// claims the next item.
fn par_claim<T: Sync, R: Send>(items: &[T], lanes: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let next = AtomicUsize::new(0);
    let out = std::sync::Mutex::new(Vec::with_capacity(items.len()));
    run_lanes(lanes, &|| {
        let mut mine = Vec::new();
        loop {
            let i = next.fetch_add(1, Relaxed);
            let Some(x) = items.get(i) else { break };
            mine.push((i, f(x)));
        }
        out.lock().unwrap().extend(mine);
    });
    let mut out = out.into_inner().unwrap();
    out.sort_unstable_by_key(|r| r.0);
    out.into_iter().map(|r| r.1).collect()
}

/// One search's lanes, shared with the helper threads.
struct Lanes {
    n: usize,
    next: std::sync::atomic::AtomicUsize,
    done: std::sync::atomic::AtomicUsize,
    panicked: std::sync::atomic::AtomicBool,
    /// The search's job, its lifetime erased: it is only run for a lane
    /// claimed below `n`, and `run_lanes` returns after all of those end.
    job: *const (dyn Fn() + Sync),
}

// Safety: `job` is Sync and outlives every call (see the field).
unsafe impl Send for Lanes {}
unsafe impl Sync for Lanes {}

impl Lanes {
    fn work(&self) {
        use std::sync::atomic::Ordering::*;
        while self.next.fetch_add(1, Relaxed) < self.n {
            let job = std::panic::AssertUnwindSafe(|| unsafe { (*self.job)() });
            if std::panic::catch_unwind(job).is_err() {
                self.panicked.store(true, Relaxed);
            }
            self.done.fetch_add(1, Release);
        }
    }
}

/// Threads that help searches: the latest search's lanes, and a bell.
struct Helpers {
    latest: std::sync::Mutex<(u64, Option<std::sync::Arc<Lanes>>)>,
    bell: std::sync::Condvar,
}

fn helpers() -> &'static Helpers {
    static H: std::sync::OnceLock<&'static Helpers> = std::sync::OnceLock::new();
    H.get_or_init(|| {
        let h: &'static Helpers = Box::leak(Box::new(Helpers { latest: Default::default(), bell: Default::default() }));
        let n = std::thread::available_parallelism().map_or(1, |n| n.get()).max(SCAN_READERS);
        for i in 1..n {
            let spawned = std::thread::Builder::new().name(format!("fsearch-help-{i}")).spawn(move || {
                // Someone is waiting: keep off the slow cores and out of the
                // throttled IO tiers, and never download iCloud placeholders.
                unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0) };
                crate::no_materialize();
                let mut seen = 0;
                loop {
                    let lanes = {
                        let mut g = h.latest.lock().unwrap();
                        while g.0 == seen {
                            g = h.bell.wait(g).unwrap();
                        }
                        seen = g.0;
                        g.1.clone()
                    };
                    if let Some(l) = lanes {
                        l.work();
                    }
                }
            });
            if spawned.is_err() {
                break;
            }
        }
        h
    })
}

/// Run `job` on `n` lanes at once, this thread taking lanes too, and return
/// when all are done. A lane goes to whichever thread claims it first, so
/// this never waits on a helper still waking up (~0.1 ms when they sleep):
/// one that wakes late finds no lane left.
fn run_lanes(n: usize, job: &(dyn Fn() + Sync)) {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::*};
    if n <= 1 {
        return job();
    }
    let h = helpers();
    let job: *const (dyn Fn() + Sync + '_) = job;
    // Safety: see `Lanes::job`; the wait below is what makes it hold.
    let job: *const (dyn Fn() + Sync + 'static) = unsafe { std::mem::transmute(job) };
    let lanes = std::sync::Arc::new(Lanes { n, next: AtomicUsize::new(0), done: AtomicUsize::new(0), panicked: AtomicBool::new(false), job });
    {
        let mut g = h.latest.lock().unwrap();
        g.0 += 1;
        g.1 = Some(lanes.clone());
    }
    for _ in 1..n {
        h.bell.notify_one();
    }
    lanes.work();
    while lanes.done.load(Acquire) < n {
        std::thread::yield_now();
    }
    assert!(!lanes.panicked.load(Relaxed), "a search lane panicked");
}

/// Take the `FIRST` best-ranked candidates out of the segments', in order.
fn take_best(per: &mut Vec<Cands>) -> Vec<Ranked> {
    let mut top = Vec::new();
    for c in per.iter_mut() {
        match c {
            Cands::List(v) => top.extend(v.drain(..v.len().min(FIRST))),
            Cands::Two(best, _) => top.append(best),
            Cands::Walk { top: t, .. } | Cands::Bulk { top: t, .. } => top.append(t),
        }
    }
    if top.len() > FIRST {
        top.select_nth_unstable(FIRST);
        per.push(Cands::List(top.split_off(FIRST)));
    }
    top.sort_unstable();
    top
}

/// What the name index says should be indexed under `dir` (direct
/// children only unless `recursive`).
pub fn wanted(live: &Live, home: &[u8], dir: &[u8], recursive: bool) -> Docs {
    let mut want = Docs::default();
    if !in_scope(dir, home) {
        return want;
    }
    let idx = &live.base;
    let mut p = Vec::new();
    if let Some(d) = idx.lookup(dir).filter(|&e| !live.is_dead(e)).and_then(|e| idx.dir_of(e)) {
        let range = if recursive { idx.dir_start()[d as usize] as usize..idx.dir_end()[d as usize] as usize } else { idx.children(d) };
        for i in range {
            if idx.kind()[i] & 3 != KIND_FILE || live.is_dead(i as u32) || !name_ok(idx.name(i), idx.size_of(i)) {
                continue;
            }
            if recursive {
                idx.path(i, &mut p);
            } else {
                p = join(dir, idx.name(i));
            }
            if in_scope(&p, home) {
                want.push(&p, idx.size_of(i), idx.mtime()[i]);
            }
        }
    }
    let lo = join(dir, b"");
    for (k, o) in live.over.range(lo.clone()..).take_while(|(k, _)| k.starts_with(&lo)) {
        if o.kind & 3 == KIND_FILE && (recursive || !k[lo.len()..].contains(&b'/')) && eligible(k, o.size, home) {
            want.push(k, o.size, o.mtime);
        }
    }
    want
}

/// The dirs/trees from one batch of changes, each with what should be
/// indexed there. Done under the name-index read lock only.
pub fn wants(live: &Live, home: &[u8], dirs: &[Vec<u8>], trees: &[Vec<u8>]) -> Vec<(Vec<u8>, bool, Docs)> {
    let mut out: Vec<(Vec<u8>, bool)> = Vec::new();
    for (d, r) in dirs.iter().map(|d| (d, false)).chain(trees.iter().map(|d| (d, true))) {
        if in_scope(d, home) {
            out.push((d.clone(), r));
        } else if r && home.starts_with(d) {
            // A subtree containing home (e.g. "/" rescanned): sync all of home.
            out.push((home.to_vec(), true));
        }
    }
    out.sort();
    out.dedup();
    out.into_iter()
        .map(|(d, r)| {
            let mut w = wanted(live, home, &d, r);
            w.sort();
            (d, r, w)
        })
        .collect()
}

pub struct Grep {
    pub pattern: String,
    pub mode: GrepMode,
    pub max_per_file: usize,
    /// Stop reading candidates after this long (None = read them all).
    pub budget: Option<std::time::Duration>,
    /// The matching regex, compiled when first needed (a plain ASCII
    /// literal mostly isn't: `literal` finds it).
    re: std::sync::OnceLock<Regex>,
    src: String,
    case_insensitive: bool,
    literal: Option<Literal>,
}

impl Grep {
    pub fn new(pattern: &str, mode: GrepMode) -> Result<Grep, String> {
        let smart_ci = !pattern.chars().any(|c| c.is_uppercase());
        let src = match mode {
            GrepMode::Literal => regex::escape(pattern),
            GrepMode::Regex => pattern.to_string(),
            // A definition: a declaring keyword, optional generics/modifiers,
            // then the name. ASCII word boundaries keep the regex on the fast
            // DFA path even in files with non-ASCII text.
            GrepMode::Symbol => format!(r"(?-u:\b)(?:{DEFINES})(?:<[^>\n]*>)?[ \t*&]+(?:mut[ \t]+)?{}(?-u:\b)", regex::escape(pattern)),
        };
        let case_insensitive = smart_ci && mode != GrepMode::Symbol;
        let short = (1..=4096).contains(&pattern.len());
        let literal = match mode {
            GrepMode::Symbol if short => Some(Literal::Definition(memchr::memmem::Finder::new(pattern.as_bytes()).into_owned())),
            GrepMode::Literal if short && pattern.is_ascii() => Some(match case_insensitive {
                true => Literal::folded(pattern.as_bytes()),
                false => Literal::Exact(memchr::memmem::Finder::new(pattern.as_bytes()).into_owned()),
            }),
            _ => None,
        };
        let g = Grep {
            pattern: pattern.to_string(),
            mode,
            max_per_file: 5,
            budget: Some(std::time::Duration::from_millis(250)),
            re: std::sync::OnceLock::new(),
            src,
            case_insensitive,
            literal,
        };
        if g.literal.is_none() {
            g.re.set(g.build()?).ok();
        }
        Ok(g)
    }

    fn build(&self) -> Result<Regex, String> {
        RegexBuilder::new(&self.src).case_insensitive(self.case_insensitive).multi_line(true).size_limit(1 << 26).build().map_err(|e| e.to_string())
    }

    fn re(&self) -> &Regex {
        // A literal's regex always compiles (it was 4096 bytes at most).
        self.re.get_or_init(|| self.build().expect("literal regex"))
    }

    /// Hashes of the grams every match holds (see `GRAM`).
    fn probes(&self) -> Vec<u32> {
        if self.mode == GrepMode::Regex {
            return Vec::new();
        }
        let mut out: Vec<u32> = self.pattern.as_bytes().windows(GRAM).map(|w| gram_hash(w.iter().fold(0, |g, &b| g << 8 | fold(b) as u64))).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    fn plan(&self) -> TQ {
        match self.mode {
            // Exactly the docs that define it (plus rare hash collisions,
            // which reading the file weeds out).
            GrepMode::Symbol if plain_identifier(self.pattern.as_bytes()) => TQ::Tri(symbol_key(self.pattern.as_bytes())),
            GrepMode::Literal | GrepMode::Symbol => literal_plan(self.pattern.as_bytes()),
            GrepMode::Regex => regex_syntax::Parser::new().parse(&self.pattern).map_or(TQ::All, |h| regex_plan(&h)),
        }
    }
}

#[derive(Default)]
pub struct GrepResult {
    pub files: Vec<FileMatches>,
    pub candidates: usize,
    pub read: usize,
    /// False if the time budget ran out before every candidate was read.
    pub complete: bool,
}

/// Threads reading candidates (the searching one and helpers): file opens on
/// this Mac stop scaling past ~4 (Endpoint Security clients tax every open;
/// measured on hot files: 7.5 us/file at 4 threads, 9 at 8, 14 at 12).
const READERS: usize = 4;
/// Folders outside the index (`in:/etc`) are read with more threads: their
/// files are mostly small and not in the page cache, so reads wait on the
/// disk more than on the open() tax.
const SCAN_READERS: usize = 8;

/// Run `f` with this thread never downloading iCloud placeholders (as the
/// helper threads), then restore its policy.
fn without_materializing<T>(f: impl FnOnce() -> T) -> T {
    unsafe extern "C" {
        fn getiopolicy_np(iotype: i32, scope: i32) -> i32;
        fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
    }
    // IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD
    let prior = unsafe { getiopolicy_np(3, 1) };
    crate::no_materialize();
    let r = f();
    if prior >= 0 {
        unsafe { setiopolicy_np(3, 1, prior) };
    }
    r
}

pub struct FileMatches {
    pub path: Vec<u8>,
    pub lines: Vec<(usize, String)>,
}

/// Read candidates in rank order until `limit` files have matched or the
/// time budget is spent (best-ranked results first, so a cut-short search
/// still returns the ones you most likely wanted). Each read thread claims
/// the next unread candidate, so the files read are always a prefix of the
/// ranking and reading stops as soon as the `limit`th match is in.
pub fn verify(g: &Grep, paths: &[impl AsRef<[u8]> + Sync], limit: usize) -> GrepResult {
    verify_from(g, paths.len(), limit, SCAN_READERS, std::time::Instant::now(), |i| Some(paths[i].as_ref())).0
}

/// `verify` over `n` candidates with `readers` threads, `path(i)` giving the
/// i-th, or None if the index already rules it out; the budget counts from
/// `t`. Also returns how many candidates it got through.
fn verify_from<'a>(
    g: &Grep,
    n: usize,
    limit: usize,
    readers: usize,
    t: std::time::Instant,
    path: impl Fn(usize) -> Option<&'a [u8]> + Sync,
) -> (GrepResult, usize) {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let (next, found, read) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let hits = std::sync::Mutex::new(Vec::new());
    let work = || {
        while found.load(Relaxed) < limit && g.budget.is_none_or(|b| t.elapsed() <= b) {
            let i = next.fetch_add(1, Relaxed);
            if i >= n {
                break;
            }
            let Some(p) = path(i) else { continue };
            read.fetch_add(1, Relaxed);
            if let Some(m) = match_file(g, p) {
                found.fetch_add(1, Relaxed);
                hits.lock().unwrap().push((i, m));
            }
        }
        // Don't sit on a big file's worth of buffer between searches.
        READ_BUF.with_borrow_mut(|b| {
            if b.capacity() > 256 << 10 {
                *b = Vec::new();
            }
        });
    };
    without_materializing(|| run_lanes(readers, &work));
    let mut hits = hits.into_inner().unwrap();
    hits.sort_unstable_by_key(|h| h.0);
    hits.truncate(limit);
    let done = next.into_inner().min(n);
    let complete = done == n || hits.len() >= limit;
    (GrepResult { files: hits.into_iter().map(|h| h.1).collect(), candidates: n, read: read.into_inner(), complete }, done)
}

thread_local! {
    /// One read buffer per read-pool thread: a fresh ~1 MB Vec per file
    /// costs page faults and an munmap every time. Kept only while a search
    /// runs if it grew past 256 KB.
    static READ_BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn match_file(g: &Grep, path: &[u8]) -> Option<FileMatches> {
    READ_BUF.with_borrow_mut(|buf| {
        use std::io::Read;
        buf.clear();
        open_regular(path)?.take(MAX_FILE * 4).read_to_end(buf).ok()?;
        if memchr::memchr(0, &buf[..buf.len().min(8192)]).is_some() {
            return None;
        }
        let lines = match g.literal.as_ref().filter(|l| !l.needs_regex(buf)) {
            Some(l) => lines_at(g, buf, l.starts(buf)),
            None => lines_at(g, buf, g.re().find_iter(buf).map(|m| m.start())),
        };
        (!lines.is_empty()).then(|| FileMatches { path: path.to_vec(), lines })
    })
}

/// The first `max_per_file` lines holding a match (by where matches start),
/// numbered, as shown.
fn lines_at(g: &Grep, buf: &[u8], starts: impl Iterator<Item = usize>) -> Vec<(usize, String)> {
    let mut lines = Vec::new();
    let (mut line_no, mut counted) = (1usize, 0usize);
    let mut last_line_start = usize::MAX;
    for start in starts {
        line_no += memchr::memchr_iter(b'\n', &buf[counted..start]).count();
        counted = start;
        let ls = memchr::memrchr(b'\n', &buf[..start]).map_or(0, |p| p + 1);
        if ls == last_line_start {
            continue;
        }
        last_line_start = ls;
        let le = memchr::memchr(b'\n', &buf[start..]).map_or(buf.len(), |p| start + p);
        lines.push((line_no, String::from_utf8_lossy(&buf[ls..le.min(ls + 400)]).trim_end().to_string()));
        if lines.len() >= g.max_per_file {
            break;
        }
    }
    lines
}

/// An ASCII literal pattern, found without a regex: its exact bytes (it has
/// an upper-case letter), or else its letters in either case. That is what
/// the case-insensitive regex matches too, but for two non-ASCII letters it
/// folds onto ASCII ones (ſ for s, the Kelvin sign for k): a file holding
/// one of those goes to the regex.
enum Literal {
    Exact(memchr::memmem::Finder<'static>),
    /// A `sym:` name: as a whole word after a declaring keyword on its line
    /// (the definition regex, with its keyword part compiled once).
    Definition(memchr::memmem::Finder<'static>),
    Folded {
        needle: Vec<u8>,
        pair: (usize, usize),
        odd: Vec<memchr::memmem::Finder<'static>>,
    },
}

impl Literal {
    fn folded(pattern: &[u8]) -> Literal {
        let needle: Vec<u8> = pattern.iter().map(|&b| fold(b)).collect();
        // Scan for the two rarest bytes first.
        let common = |b: u8| match b {
            b' ' | b'e' | b't' | b'a' | b'o' | b'i' | b'n' | b's' | b'r' => 3,
            b'h' | b'l' | b'd' | b'c' | b'u' | b'm' | b'\n' | b'\t' => 2,
            b'f' | b'p' | b'g' | b'w' | b'y' | b'b' | b'.' | b',' | b'_' | b'(' | b')' | b'"' | b'=' | b'0'..=b'9' => 1,
            _ => 0,
        };
        let mut by_rarity: Vec<usize> = (0..needle.len()).collect();
        by_rarity.sort_by_key(|&i| (common(needle[i]), i));
        let (a, b) = (by_rarity[0], *by_rarity.get(1).unwrap_or(&by_rarity[0]));
        let odd = [(b's', "\u{17F}"), (b'k', "\u{212A}")].iter().filter(|(c, _)| needle.contains(c));
        let odd = odd.map(|(_, u)| memchr::memmem::Finder::new(u.as_bytes()).into_owned()).collect();
        Literal::Folded { needle, pair: (a.min(b), a.max(b)), odd }
    }

    fn needs_regex(&self, hay: &[u8]) -> bool {
        matches!(self, Literal::Folded { odd, .. } if odd.iter().any(|f| f.find(hay).is_some()))
    }

    /// Where its matches start, left to right.
    fn starts<'a>(&'a self, hay: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
        let len = match self {
            Literal::Exact(f) | Literal::Definition(f) => f.needle().len(),
            Literal::Folded { needle, .. } => needle.len(),
        };
        let mut at = 0;
        std::iter::from_fn(move || {
            loop {
                let p = match self {
                    Literal::Exact(f) | Literal::Definition(f) => f.find(hay.get(at..)?).map(|p| at + p),
                    Literal::Folded { needle, pair, .. } => find_folded(hay, at, needle, *pair),
                }?;
                if !matches!(self, Literal::Definition(_)) {
                    at = p + len;
                    return Some(p);
                }
                at = p + 1;
                if defined_at(hay, p, len) {
                    return Some(p);
                }
            }
        })
    }
}

/// Is the name at `hay[p..p + len]` defined there: an ASCII word boundary
/// after it, and before it on its line a declaring keyword, maybe generics,
/// spaces or `*&`, maybe `mut` (what `sym:`'s regex asks, split at the name)?
fn defined_at(hay: &[u8], p: usize, len: usize) -> bool {
    static KEYWORD: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let word = |b: Option<&u8>| b.is_some_and(|&b| b.is_ascii_alphanumeric() || b == b'_');
    if word(hay[..p + len].last()) == word(hay.get(p + len)) {
        return false;
    }
    let re = KEYWORD.get_or_init(|| Regex::new(&format!(r"(?-u:\b)(?:{DEFINES})(?:<[^>\n]*>)?[ \t*&]+(?:mut[ \t]+)?\z")).unwrap());
    let line = memchr::memrchr(b'\n', &hay[..p]).map_or(0, |i| i + 1);
    re.is_match(&hay[line..p])
}

/// The first place at or after `from` where `hay` holds `needle` (lower
/// case) in either case; `pair` are two positions of rare bytes in it, the
/// ones checked first.
fn find_folded(hay: &[u8], from: usize, needle: &[u8], pair: (usize, usize)) -> Option<usize> {
    let k = needle.len();
    let last = hay.len().checked_sub(k)?;
    let at = |c: usize| hay[c..c + k].iter().zip(needle).all(|(&x, &y)| fold(x) == y);
    let mut i = from;
    #[cfg(target_arch = "aarch64")]
    // Safety: every load reads 16 bytes at i + pair.1 at most, and the loop
    // keeps i + 16 <= last + 1, so they end by hay.len().
    unsafe {
        use std::arch::aarch64::*;
        let (c1, c2) = (needle[pair.0], needle[pair.1]);
        let case = |c: u8| vdupq_n_u8(if c.is_ascii_lowercase() { 0x20 } else { 0 });
        let (v1, v2, m1, m2) = (vdupq_n_u8(c1), vdupq_n_u8(c2), case(c1), case(c2));
        while i + 16 <= last + 1 {
            let p = hay.as_ptr().add(i);
            let eq = vandq_u8(vceqq_u8(vorrq_u8(vld1q_u8(p.add(pair.0)), m1), v1), vceqq_u8(vorrq_u8(vld1q_u8(p.add(pair.1)), m2), v2));
            // Four bits per byte lane.
            let mut bits = vget_lane_u64::<0>(vreinterpret_u64_u8(vshrn_n_u16::<4>(vreinterpretq_u16_u8(eq))));
            while bits != 0 {
                let c = i + (bits.trailing_zeros() / 4) as usize;
                if at(c) {
                    return Some(c);
                }
                bits &= !(0xF << ((c - i) * 4));
            }
            i += 16;
        }
    }
    (i..=last).find(|&c| at(c))
}

/// A trigram query: which docs could possibly match.
#[derive(Debug, Clone)]
pub enum TQ {
    All,
    Tri(u32),
    /// Any trigram starting with these two bytes (the high two of three), or
    /// a doc ending in them.
    Pair(u32),
    And(Vec<TQ>),
    Or(Vec<TQ>),
}

fn literal_plan(s: &[u8]) -> TQ {
    match s {
        [] | [_] => TQ::All,
        &[a, b] => TQ::Pair((fold(a) as u32) << 16 | (fold(b) as u32) << 8),
        _ => TQ::And(trigrams_small(s).into_iter().map(TQ::Tri).collect()),
    }
}

/// A posting list as stored.
#[derive(Clone, Copy)]
enum List<'a> {
    /// Bit d: doc d has the trigram.
    Bits(&'a [u8]),
    /// Ascending doc ids as delta varints.
    Var(Var<'a>),
}

/// A varint list: its skip table (see `SKIPS`; maybe empty) and varints.
#[derive(Clone, Copy)]
struct Var<'a> {
    skips: &'a [u8],
    deltas: &'a [u8],
}

impl<'a> Var<'a> {
    fn new(bytes: &'a [u8], skips: bool) -> Var<'a> {
        if !skips {
            return Var { skips: &[], deltas: bytes };
        }
        let n = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        Var { skips: &bytes[4..4 + 8 * n], deltas: &bytes[4 + 8 * n..] }
    }

    fn iter(&self) -> Varints<'a> {
        Varints { b: self.deltas, last: 0 }
    }

    /// Skip entry `i`: (the content before its run, where the run starts).
    fn skip(&self, i: usize) -> (u32, usize) {
        let e = u64::from_le_bytes(self.skips[8 * i..8 * i + 8].try_into().unwrap());
        (e as u32, (e >> 32) as usize)
    }
}

/// A walk along a varint list that jumps ahead by its skip table.
struct Cursor<'a> {
    var: Var<'a>,
    it: Varints<'a>,
    /// Contents read so far; the last is `cur`.
    read: usize,
    cur: Option<u32>,
}

impl<'a> Cursor<'a> {
    fn new(var: Var<'a>) -> Cursor<'a> {
        let mut it = var.iter();
        let cur = it.next();
        Cursor { var, it, read: 1, cur }
    }

    fn next(&mut self) -> Option<u32> {
        self.cur = self.it.next();
        self.read += 1;
        self.cur
    }

    /// The first content from here on that is `x` or more.
    fn seek(&mut self, x: u32) -> Option<u32> {
        if self.cur.is_none_or(|c| c >= x) {
            return self.cur;
        }
        // The next run starting after `cur`, and the last one past it that
        // starts before `x`: jump there.
        let (j, n) = ((self.read - 1) / SKIP, self.var.skips.len() / 8);
        if j < n && self.var.skip(j).0 < x {
            let (mut lo, mut hi) = (j, n);
            while hi - lo > 1 {
                let mid = (lo + hi) / 2;
                if self.var.skip(mid).0 < x { lo = mid } else { hi = mid }
            }
            let (last, at) = self.var.skip(lo);
            self.it = Varints { b: &self.var.deltas[at..], last };
            self.read = (lo + 1) * SKIP;
            self.next();
        }
        while self.cur.is_some_and(|c| c < x) {
            self.next();
        }
        self.cur
    }
}

/// Decodes a delta-varint list.
struct Varints<'a> {
    b: &'a [u8],
    last: u32,
}

impl Iterator for Varints<'_> {
    type Item = u32;
    #[inline]
    fn next(&mut self) -> Option<u32> {
        let x = *self.b.first()?;
        let (v, n) = if x < 0x80 { (x as u32, 1) } else { varint(self.b) };
        self.b = &self.b[n..];
        self.last += v;
        Some(self.last)
    }
}

impl List<'_> {
    /// Append its docs within `docs`, ascending.
    fn decode(self, docs: std::ops::Range<u32>, out: &mut Vec<u32>) {
        match self {
            List::Bits(b) => and_bits(&[b], docs, out),
            List::Var(v) => {
                let mut c = Cursor::new(v);
                let mut d = c.seek(docs.start);
                while let Some(x) = d.filter(|&x| x < docs.end) {
                    out.push(x);
                    d = c.next();
                }
            }
        }
    }

    /// Keep the docs of `acc` (ascending) that are in the list.
    fn retain(self, acc: &mut Vec<u32>) {
        match self {
            List::Bits(b) => acc.retain(|&d| b.get(d as usize / 8).is_some_and(|x| x >> (d % 8) & 1 != 0)),
            List::Var(v) => {
                let mut c = Cursor::new(v);
                acc.retain(|&d| c.seek(d) == Some(d));
            }
        }
    }
}

/// Append the docs within `docs` set in every bitset, ascending.
fn and_bits(lists: &[&[u8]], docs: std::ops::Range<u32>, out: &mut Vec<u32>) {
    let end = (docs.end as usize).div_ceil(8).min(lists.iter().map(|l| l.len()).min().unwrap_or(0));
    // A list's 64 docs from byte i (none past its end).
    let word = |l: &[u8], i: usize| match l.get(i..i + 8) {
        Some(b) => u64::from_le_bytes(b.try_into().unwrap()),
        None => l[i..].iter().rev().fold(0, |w, &b| w << 8 | b as u64),
    };
    let mut i = docs.start as usize / 8;
    while i < end {
        let mut w = u64::MAX;
        for l in lists {
            w &= word(l, i);
            if w == 0 {
                break;
            }
        }
        while w != 0 {
            let d = i as u32 * 8 + w.trailing_zeros();
            if docs.contains(&d) {
                out.push(d);
            }
            w &= w - 1;
        }
        i += 8;
    }
}

/// The live text docs of a segment, as bits, and how many.
fn live_text(s: &Segment) -> (Vec<u64>, usize) {
    let mut bits: Vec<u64> = s.dead.iter().map(|w| !w).collect();
    for (d, _) in s.rank().iter().enumerate().filter(|&(_, &r)| r == NOT_TEXT) {
        bits[d / 64] &= !(1 << (d % 64));
    }
    if let Some(w) = bits.last_mut().filter(|_| !s.ndocs.is_multiple_of(64)) {
        *w &= (1 << (s.ndocs % 64)) - 1;
    }
    let total = bits.iter().map(|w| w.count_ones() as usize).sum();
    (bits, total)
}

/// For an AND of trigrams whose lists in `s` are all bitsets: the own
/// contents holding all of them, as bits, and how many.
fn and_dense(s: &Segment, q: &TQ) -> Option<(Vec<u64>, usize)> {
    let TQ::And(qs) = q else { return None };
    let lists: Vec<&[u8]> = (qs.iter())
        .map(|q| match q {
            TQ::Tri(t) => s.list(*t).and_then(|l| if let List::Bits(b) = l { Some(b) } else { None }),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if lists.is_empty() {
        return None;
    }
    let mut bits = all_bits(s.nown);
    for l in lists {
        for (w, b) in bits.iter_mut().zip(l.chunks(8)) {
            *w &= match <[u8; 8]>::try_from(b) {
                Ok(b) => u64::from_le_bytes(b),
                Err(_) => b.iter().rev().fold(0, |x, &y| x << 8 | y as u64),
            };
        }
    }
    let total = bits.iter().map(|w| w.count_ones() as usize).sum();
    Some((bits, total))
}

/// Docs within `docs` matching `q` in a segment, ascending; None means
/// every doc. An AND starts from its shortest list and only tests the
/// others, so common trigrams' long lists are never decoded in full.
fn eval(s: &Segment, q: &TQ, docs: std::ops::Range<u32>) -> Option<Vec<u32>> {
    match q {
        TQ::All => None,
        TQ::Tri(t) => {
            let mut out = Vec::new();
            if let Some(l) = s.list(*t) {
                l.decode(docs, &mut out);
            }
            Some(out)
        }
        TQ::Pair(p) => {
            let keys = s.tri_key();
            let mut bits = vec![0u64; s.nown.div_ceil(64)];
            for &k in &keys[keys.partition_point(|&k| k < *p)..keys.partition_point(|&k| k <= p | 0xFF)] {
                match s.list(k) {
                    Some(List::Bits(b)) => {
                        for (w, c) in bits.iter_mut().zip(b.chunks(8)) {
                            *w |= c.iter().rev().fold(0, |x, &y| x << 8 | y as u64);
                        }
                    }
                    Some(List::Var(v)) => v.iter().for_each(|d| bits[d as usize / 64] |= 1 << (d % 64)),
                    None => {}
                }
            }
            Some(set_bits(&bits, 0).into_iter().filter(|d| docs.contains(d)).collect())
        }
        TQ::And(qs) => {
            let (mut bits, mut vars, mut rest) = (Vec::new(), Vec::new(), Vec::new());
            for q in qs {
                match q {
                    TQ::Tri(t) => match s.list(*t) {
                        Some(List::Bits(b)) => bits.push(b),
                        Some(List::Var(b)) => vars.push(b),
                        None => return Some(Vec::new()),
                    },
                    TQ::All => {}
                    q => rest.push(q),
                }
            }
            vars.sort_by_key(|v| v.deltas.len());
            let mut acc = None;
            if let Some((&first, vars)) = vars.split_first() {
                let mut v = Vec::new();
                List::Var(first).decode(docs.clone(), &mut v);
                for &b in &bits {
                    List::Bits(b).retain(&mut v);
                }
                for &b in vars {
                    if v.is_empty() {
                        break;
                    }
                    List::Var(b).retain(&mut v);
                }
                acc = Some(v);
            } else if !bits.is_empty() {
                let mut v = Vec::new();
                and_bits(&bits, docs.clone(), &mut v);
                acc = Some(v);
            }
            for q in rest {
                if acc.as_ref().is_some_and(Vec::is_empty) {
                    break;
                }
                if let Some(r) = eval(s, q, docs.clone()) {
                    acc = Some(match acc {
                        Some(a) => intersect(&a, &r),
                        None => r,
                    });
                }
            }
            acc
        }
        TQ::Or(qs) => {
            let mut acc: Vec<u32> = Vec::new();
            for q in qs {
                acc.extend(eval(s, q, docs.clone())?);
            }
            acc.sort_unstable();
            acc.dedup();
            Some(acc)
        }
    }
}

fn intersect(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len().min(b.len()));
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(a[i]);
                i += 1;
                j += 1;
            }
        }
    }
    out
}

/// What a regex fragment tells us about its matches, as small sets of
/// (case-folded) strings: every match is one of `exact`, starts with one of
/// `prefix` and ends with one of `suffix` (None: no small such set); and
/// every doc holding a match satisfies `q`.
struct Info {
    exact: Option<Set>,
    prefix: Option<Set>,
    suffix: Option<Set>,
    q: TQ,
}

type Set = Vec<Vec<u8>>;

const MAX_EXACT: usize = 16;

impl Info {
    fn exact(set: Set) -> Info {
        Info { exact: Some(set.clone()), prefix: Some(set.clone()), suffix: Some(set), q: TQ::All }
    }

    fn any() -> Info {
        Info { exact: None, prefix: None, suffix: None, q: TQ::All }
    }

    /// All it says about a doc, as one trigram query.
    fn query(self) -> TQ {
        match self.exact {
            Some(_) => and(self.q, exact_query(self.exact)),
            None => and(and(self.q, exact_query(self.prefix)), exact_query(self.suffix)),
        }
    }
}

/// Every string of `a` followed by one of `b`, if that's few enough.
fn cross(a: &Option<Set>, b: &Option<Set>) -> Option<Set> {
    let (a, b) = (a.as_ref()?, b.as_ref()?);
    if a.len() * b.len() > MAX_EXACT {
        return None;
    }
    let mut set: Set = a.iter().flat_map(|x| b.iter().map(move |y| [x.as_slice(), y].concat())).collect();
    set.sort();
    set.dedup();
    Some(set)
}

/// What a set of strings requires of a doc: one of them (All when there is
/// no set, it is empty, or a string in it is too short to have a trigram).
/// Trigrams all of them share are required once, not per string.
fn exact_query(set: Option<Set>) -> TQ {
    let Some(set) = set.filter(|set| !set.is_empty() && set.iter().all(|s| s.len() >= 3)) else { return TQ::All };
    let tris: Vec<Vec<u32>> = set.iter().map(|s| trigrams_small(s)).collect();
    let common: Vec<u32> = tris[0].iter().copied().filter(|t| tris.iter().all(|ts| ts.binary_search(t).is_ok())).collect();
    let rest: Vec<TQ> = tris.iter().map(|ts| TQ::And(ts.iter().filter(|t| !common.contains(t)).map(|&t| TQ::Tri(t)).collect())).collect();
    let mut q = TQ::And(common.into_iter().map(TQ::Tri).collect());
    if rest.iter().all(|r| !matches!(r, TQ::And(v) if v.is_empty())) {
        q = and(q, TQ::Or(rest));
    }
    q
}

fn and(a: TQ, b: TQ) -> TQ {
    match (a, b) {
        (TQ::All, x) | (x, TQ::All) => x,
        (TQ::And(mut x), TQ::And(y)) => {
            x.extend(y);
            TQ::And(x)
        }
        (TQ::And(mut x), y) | (y, TQ::And(mut x)) => {
            x.push(y);
            TQ::And(x)
        }
        (x, y) => TQ::And(vec![x, y]),
    }
}

fn info(h: &Hir) -> Info {
    match h.kind() {
        HirKind::Empty | HirKind::Look(_) => Info::exact(vec![Vec::new()]),
        HirKind::Literal(l) => Info::exact(vec![l.0.iter().map(|&b| fold(b)).collect()]),
        HirKind::Class(c) => class(c),
        HirKind::Capture(c) => info(&c.sub),
        HirKind::Repetition(r) => {
            if r.min == 0 {
                return Info::any();
            }
            let i = info(&r.sub);
            if r.min == 1 && r.max == Some(1) {
                return i;
            }
            // At least one copy, which starts it; one ends it.
            Info { q: and(i.q, exact_query(i.exact)), exact: None, prefix: i.prefix, suffix: i.suffix }
        }
        HirKind::Concat(hs) => hs.iter().map(info).fold(Info::exact(vec![Vec::new()]), concat),
        HirKind::Alternation(hs) => {
            let parts: Vec<Info> = hs.iter().map(info).collect();
            let union = |f: fn(&Info) -> &Option<Set>| {
                let mut set = Set::new();
                for p in &parts {
                    set.extend(f(p).clone()?);
                }
                set.sort();
                set.dedup();
                (set.len() <= MAX_EXACT).then_some(set)
            };
            let (exact, prefix, suffix) = (union(|p| &p.exact), union(|p| &p.prefix), union(|p| &p.suffix));
            if exact.is_some() {
                return Info { exact, prefix, suffix, q: TQ::All };
            }
            let ors: Vec<TQ> = parts.into_iter().map(Info::query).collect();
            let q = if ors.iter().any(|q| matches!(q, TQ::All)) { TQ::All } else { TQ::Or(ors) };
            Info { exact, prefix, suffix, q }
        }
    }
}

/// Up to 8 members are each an exact string; with more, their first bytes,
/// if few (`\s`: tab to CR, space, and four UTF-8 lead bytes), start it.
fn class(c: &Class) -> Info {
    let mut set: Set = match c {
        Class::Unicode(u) => {
            u.ranges().iter().flat_map(|r| r.start()..=r.end()).take(9).map(|ch| ch.to_string().bytes().map(fold).collect()).collect()
        }
        Class::Bytes(b) => b.ranges().iter().flat_map(|r| r.start()..=r.end()).take(9).map(|x| vec![fold(x)]).collect(),
    };
    if set.len() <= 8 {
        set.sort();
        set.dedup();
        return Info::exact(set);
    }
    let lead = |c: char| c.to_string().as_bytes()[0];
    let mut first: Vec<u8> = match c {
        Class::Unicode(u) => u.ranges().iter().flat_map(|r| lead(r.start())..=lead(r.end())).map(fold).collect(),
        Class::Bytes(b) => b.ranges().iter().flat_map(|r| r.start()..=r.end()).map(fold).collect(),
    };
    first.sort();
    first.dedup();
    Info { prefix: (first.len() <= MAX_EXACT).then(|| first.into_iter().map(|b| vec![b]).collect()), ..Info::any() }
}

/// `a` then `b`. A match holds a's suffix right before b's prefix; that
/// pairing is carried up in the prefix or suffix when one side is exact,
/// else required here.
fn concat(a: Info, b: Info) -> Info {
    let exact = cross(&a.exact, &b.exact);
    let ab_prefix = a.exact.as_ref().and(cross(&a.exact, &b.prefix));
    let ab_suffix = b.exact.as_ref().and(cross(&a.suffix, &b.exact));
    let mut q = and(a.q, b.q);
    if exact.is_none() && ab_prefix.is_none() && ab_suffix.is_none() {
        q = match cross(&a.suffix, &b.prefix) {
            Some(j) => and(q, exact_query(Some(j))),
            None => {
                let sa = if a.exact.is_none() { exact_query(a.suffix.clone()) } else { TQ::All };
                let pb = if b.exact.is_none() { exact_query(b.prefix.clone()) } else { TQ::All };
                and(and(q, sa), pb)
            }
        };
    }
    let prefix = if a.exact.is_some() { ab_prefix.or(a.exact) } else { a.prefix };
    let suffix = if b.exact.is_some() { ab_suffix.or(b.exact) } else { b.suffix };
    Info { exact, prefix, suffix, q }
}

fn regex_plan(h: &Hir) -> TQ {
    info(h).query()
}

/// Files to grep where the content index does not reach (e.g. `in:/etc`),
/// picked from the name index instead of crawling, newest first. `q` is the
/// name query restricted to the files worth reading.
pub fn scan_paths(live: &Live, mut q: Query) -> Vec<Vec<u8>> {
    q.kind = Some(KIND_FILE);
    q.limit = 200_000;
    q.size = (q.size.0, q.size.1.min(MAX_FILE));
    let mut files: Vec<(Vec<u8>, u32)> = (crate::query::Searcher { live }.search(&q).into_iter())
        .map(|h| match h.over {
            Some(path) => {
                let m = live.over[&path].mtime;
                (path, m)
            }
            None => {
                let mut p = Vec::new();
                live.base.path(h.idx as usize, &mut p);
                (p, live.base.mtime()[h.idx as usize])
            }
        })
        .collect();
    files.sort_by_key(|(_, m)| std::cmp::Reverse(*m));
    files.into_iter().map(|(p, _)| p).collect()
}

/// Open a path for reading only if it is a regular file, never blocking:
/// O_NONBLOCK keeps a FIFO from hanging open(), and the read threads'
/// "don't materialize dataless files" policy keeps iCloud placeholders from
/// being downloaded just because we searched.
pub fn open_regular(path: &[u8]) -> Option<std::fs::File> {
    open_sized(path).map(|(f, _)| f)
}

/// `open_regular`, and the file's size.
fn open_sized(path: &[u8]) -> Option<(std::fs::File, u64)> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).open(std::ffi::OsStr::from_bytes(path)).ok()?;
    let m = f.metadata().ok()?;
    m.is_file().then_some((f, m.len()))
}

/// `open_regular` for a file about to be indexed, telling the kernel to
/// start reading it now (as much as indexing reads).
fn open_ahead(path: &[u8]) -> Option<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let (f, len) = open_sized(path)?;
    let ra = libc::radvisory { ra_offset: 0, ra_count: len.min(MAX_FILE + 1) as libc::c_int };
    unsafe { libc::fcntl(f.as_raw_fd(), libc::F_RDADVISE, &ra) };
    Some(f)
}
