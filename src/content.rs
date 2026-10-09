//! Content search: a trigram index over the user's text files.
//!
//! Segments are immutable, mmap'd files: a doc table plus, per trigram, the
//! ids of the docs containing it (delta varints), and per doc a small bloom
//! filter of its 5-byte substrings. A query becomes an AND/OR of trigrams,
//! the posting lists pick candidate files, the bloom filters drop most of
//! those that only contain the pattern's trigrams scattered about, and the
//! rest are read fresh from disk and matched for real. Results therefore never
//! show stale content; only candidate selection can trail a file written
//! in the last couple of seconds.
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
const MAGIC: &[u8; 8] = b"FSCSEG04";
/// tri_off high bit: this trigram's list is a bitset over the segment's docs
/// (cheaper than varints once more than 1 in 8 docs contain it).
const BITSET: u32 = 1 << 31;

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
    map: Mmap,
    pub id: u64,
    pub ndocs: usize,
    ndocs1: usize,
    ntri: usize,
    ntri1: usize,
    plen: usize,
    paths_len: usize,
    nwords: usize,
    off: [usize; NS],
    dead: Vec<u64>,
    pub live_docs: usize,
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
    BloomOff,
    Bloom,
}
const NS: usize = 11;

fn lens(ndocs: usize, ntri: usize, plen: usize, paths_len: usize, nwords: usize) -> [usize; NS] {
    [ntri * 4, (ntri + 1) * 4, plen, (ndocs + 1) * 4, paths_len, ndocs * 8, ndocs * 4, ndocs * 4, ndocs, (ndocs + 1) * 4, nwords * 8]
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
    // Per doc, a bloom filter of its GRAM-byte substrings (see `bloom`).
    sec!(bloom_off, S::BloomOff, u32, ndocs1);
    sec!(bloom, S::Bloom, u64, nwords);

    pub fn path(&self, d: u32) -> &[u8] {
        let o = self.path_off();
        &self.paths()[o[d as usize] as usize..o[d as usize + 1] as usize]
    }

    fn bloom_of(&self, d: u32) -> &[u64] {
        let o = self.bloom_off();
        &self.bloom()[o[d as usize] as usize..o[d as usize + 1] as usize]
    }

    /// Can doc `d` hold every gram in `probes`, by its bloom filter?
    fn may_contain(&self, d: u32, probes: &[u32]) -> bool {
        let words = self.bloom_of(d);
        probes.iter().all(|&h| {
            let b = bloom_bit(h, words.len());
            words.get(b / 64).is_some_and(|w| w >> (b % 64) & 1 != 0)
        })
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
        let k = self.tri_key().binary_search(&tri).ok()?;
        let o = self.tri_off();
        let bytes = &self.post()[(o[k] & !BITSET) as usize..(o[k + 1] & !BITSET) as usize];
        Some(if o[k] & BITSET != 0 { List::Bits(bytes) } else { List::Var(bytes) })
    }

    /// The live docs under `prefix` lie in this doc id range (exactly, for a
    /// segment built from sorted paths; a superset after a merge).
    fn doc_range(&self, prefix: &[u8]) -> std::ops::Range<u32> {
        let bp = self.by_path();
        let (Some(&first), Some(&last)) = (bp.first(), bp.last()) else { return 0..0 };
        if self.path(last) < prefix || (self.path(first) > prefix && !self.path(first).starts_with(prefix)) {
            return 0..0;
        }
        let a = bp.partition_point(|&d| self.path(d) < prefix);
        let z = a + bp[a..].partition_point(|&d| self.path(d).starts_with(prefix));
        let (lo, hi) = bp[a..z].iter().fold((u32::MAX, 0), |(lo, hi), &d| (lo.min(d), hi.max(d + 1)));
        lo.min(hi)..hi
    }

    fn list_into(&self, k: usize, out: &mut Vec<u32>) {
        let o = self.tri_off();
        let mut bytes = &self.post()[(o[k] & !BITSET) as usize..(o[k + 1] & !BITSET) as usize];
        if o[k] & BITSET != 0 {
            for (w, &b) in bytes.iter().enumerate() {
                let mut b = b;
                while b != 0 {
                    out.push(w as u32 * 8 + b.trailing_zeros());
                    b &= b - 1;
                }
            }
            return;
        }
        let mut last = 0u32;
        while !bytes.is_empty() {
            let (v, n) = varint(bytes);
            bytes = &bytes[n..];
            last += v;
            out.push(last);
        }
    }

    fn load(dir: &Path, id: u64) -> Option<Segment> {
        let f = std::fs::File::open(seg_path(dir, id)).ok()?;
        let map = unsafe { Mmap::map(&f) }.ok()?;
        let [ndocs, ntri, plen, paths_len, nwords] = fields(&map, MAGIC)?.map(|v| v as usize);
        let (off, total) = layout(&lens(ndocs, ntri, plen, paths_len, nwords));
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
        Some(Segment { map, id, ndocs, ndocs1: ndocs + 1, ntri, ntri1: ntri + 1, plen, paths_len, nwords, off, dead, live_docs })
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

/// Append the sorted distinct case-folded trigrams of a buffer to `out`.
/// `seen` is a 2 MiB scratch bitset, all zero on entry and exit.
fn trigrams(buf: &[u8], seen: &mut [u64], out: &mut Vec<u32>) {
    let start = out.len();
    if buf.len() < 3 {
        return;
    }
    let mut t = (fold(buf[0]) as u32) << 8 | fold(buf[1]) as u32;
    for &b in &buf[2..] {
        t = ((t << 8) | fold(b) as u32) & 0xFF_FFFF;
        let (w, bit) = ((t >> 6) as usize, 1u64 << (t & 63));
        if seen[w] & bit == 0 {
            seen[w] |= bit;
            out.push(t);
        }
    }
    for &t in &out[start..] {
        seen[(t >> 6) as usize] = 0;
    }
    out[start..].sort_unstable();
}

/// Trigrams of a short string (query side), no scratch needed.
fn trigrams_small(s: &[u8]) -> Vec<u32> {
    let mut t: Vec<u32> = s.windows(3).map(|w| (fold(w[0]) as u32) << 16 | (fold(w[1]) as u32) << 8 | fold(w[2]) as u32).collect();
    t.sort_unstable();
    t.dedup();
    t
}

/// Bloom filters hold a doc's case-folded substrings of this many bytes: a
/// match holds all of its pattern's grams, so a doc missing one of them
/// can't match even if it has every trigram.
const GRAM: usize = 5;

/// A gram's 24-bit hash (its folded bytes, big-endian in the low 40 bits).
#[inline]
fn gram_hash(g: u64) -> u32 {
    (g.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40) as u32
}

/// Where a gram hash lands in a bloom filter of `words` u64s.
#[inline]
fn bloom_bit(h: u32, words: usize) -> usize {
    ((h as u64 * words as u64 * 64) >> 24) as usize
}

/// Distinct gram hashes of a buffer, into `out` (cleared). `seen` is a
/// 2 MiB scratch bitset, all zero on entry and exit.
fn grams(buf: &[u8], seen: &mut [u64], out: &mut Vec<u32>) {
    out.clear();
    let mut g = 0u64;
    for (i, &b) in buf.iter().enumerate() {
        g = (g << 8 | fold(b) as u64) & ((1 << (8 * GRAM)) - 1);
        if i + 1 >= GRAM {
            let h = gram_hash(g);
            let (w, bit) = ((h >> 6) as usize, 1u64 << (h & 63));
            if seen[w] & bit == 0 {
                seen[w] |= bit;
                out.push(h);
            }
        }
    }
    for &h in out.iter() {
        seen[(h >> 6) as usize] = 0;
    }
}

/// Append a bloom filter of these gram hashes to `out`: two bits per gram
/// (a gram the doc lacks still passes 39% of the time; one bit, 63%), in
/// whole words.
fn bloom(hashes: &[u32], out: &mut Vec<u64>) {
    let words = (hashes.len() * 2).div_ceil(64);
    let at = out.len();
    out.resize(at + words, 0);
    for &h in hashes {
        let b = bloom_bit(h, words);
        out[at + b / 64] |= 1 << (b % 64);
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

/// Rank of a doc that turned out not to be text: kept so diffs know we
/// looked at it, never a candidate.
const NOT_TEXT: i8 = i8::MIN;

struct DocMeta<'a> {
    path: &'a [u8],
    size: u64,
    mtime: u32,
    rank: i8,
    bloom: &'a [u64],
}

/// One rayon split's output: trigrams, definition keys and bloom filters of
/// its docs, flat, plus where each doc's runs are. Reuses one read buffer
/// and one 2 MiB seen-set.
struct Split {
    seen: Vec<u64>,
    buf: Vec<u8>,
    hashes: Vec<u32>,
    flat: Vec<u32>,
    syms: Vec<u32>,
    blooms: Vec<u64>,
    docs: Vec<SplitDoc>,
}

/// Where one doc's runs are in its split.
struct SplitDoc {
    i: usize,
    text: bool,
    tri: std::ops::Range<usize>,
    sym: std::ops::Range<usize>,
    bloom: std::ops::Range<usize>,
}

/// Build one segment file from docs (any order). Files that turn out not
/// to be text are recorded with no trigrams.
pub fn build_segment(dir: &Path, id: u64, docs: &Docs, range: std::ops::Range<usize>) -> Option<Segment> {
    use std::io::Read;
    let splits: Vec<Split> = range
        .clone()
        .into_par_iter()
        .with_min_len(256)
        .fold(
            || Split {
                seen: vec![0u64; (1 << 24) / 64],
                buf: Vec::new(),
                hashes: Vec::new(),
                flat: Vec::new(),
                syms: Vec::new(),
                blooms: Vec::new(),
                docs: Vec::new(),
            },
            |mut sp, i| {
                sp.buf.clear();
                let text = open_regular(docs.path(i))
                    .and_then(|f| f.take(MAX_FILE + 1).read_to_end(&mut sp.buf).ok())
                    .is_some_and(|n| n as u64 <= MAX_FILE && memchr::memchr(0, &sp.buf[..n.min(8192)]).is_none());
                let (tri, sym, bl) = (sp.flat.len(), sp.syms.len(), sp.blooms.len());
                if text {
                    trigrams(&sp.buf, &mut sp.seen, &mut sp.flat);
                    symbols(&sp.buf, &mut sp.syms);
                    grams(&sp.buf, &mut sp.seen, &mut sp.hashes);
                    bloom(&sp.hashes, &mut sp.blooms);
                }
                sp.docs.push(SplitDoc { i, text, tri: tri..sp.flat.len(), sym: sym..sp.syms.len(), bloom: bl..sp.blooms.len() });
                sp
            },
        )
        .map(|mut sp| {
            sp.seen = Vec::new();
            sp.buf = Vec::new();
            sp.hashes = Vec::new();
            sp
        })
        .collect();
    // Docs in path order: splits cover contiguous runs, in order.
    let order: Vec<(usize, usize)> = splits.iter().enumerate().flat_map(|(si, sp)| (0..sp.docs.len()).map(move |k| (si, k))).collect();
    let meta: Vec<DocMeta> = order
        .iter()
        .map(|&(si, k)| {
            let sd = &splits[si].docs[k];
            let (_, _, size, mtime) = docs.items[sd.i];
            let rank = if sd.text { doc_rank(docs.path(sd.i)) } else { NOT_TEXT };
            DocMeta { path: docs.path(sd.i), size, mtime, rank, bloom: &splits[si].blooms[sd.bloom.clone()] }
        })
        .collect();
    let tris = |d: usize| {
        let (si, k) = order[d];
        &splits[si].flat[splits[si].docs[k].tri.clone()]
    };
    let syms = |d: usize| {
        let (si, k) = order[d];
        &splits[si].syms[splits[si].docs[k].sym.clone()]
    };
    // Definition keys sort after every trigram (they're above 2^24), so they
    // follow the trigrams as sorted (key, doc) pairs in either build.
    let mut sym_pairs: Vec<u64> = (0..order.len()).flat_map(|d| syms(d).iter().map(move |&t| (t as u64) << 32 | d as u64)).collect();
    sym_pairs.sort_unstable();
    let pairs: usize = (0..order.len()).map(|d| tris(d).len()).sum();
    if pairs < 1 << 22 {
        // Small batch (the usual incremental update): sort the pairs. Cost
        // scales with the batch, not with the 16.7M-slot trigram space.
        let mut v: Vec<u64> = Vec::with_capacity(pairs + sym_pairs.len());
        for d in 0..order.len() {
            v.extend(tris(d).iter().map(|&t| (t as u64) << 32 | d as u64));
        }
        v.sort_unstable();
        v.extend_from_slice(&sym_pairs);
        let mut i = 0;
        return write_segment(dir, id, &meta, |list| {
            let t = (*v.get(i)? >> 32) as u32;
            while i < v.len() && (v[i] >> 32) as u32 == t {
                list.push(v[i] as u32);
                i += 1;
            }
            Some(t)
        });
    }
    // Big batch (initial build): counting sort over the whole trigram space.
    let mut count = vec![0u32; 1 << 24];
    for d in 0..order.len() {
        for &x in tris(d) {
            count[x as usize] += 1;
        }
    }
    let keys: Vec<u32> = (0..1u32 << 24).filter(|&t| count[t as usize] != 0).collect();
    let mut start = vec![0usize; keys.len() + 1];
    for (k, &t) in keys.iter().enumerate() {
        start[k + 1] = start[k] + count[t as usize] as usize;
        count[t as usize] = k as u32; // reuse as trigram -> key index
    }
    let mut raw = vec![0u32; start[keys.len()]];
    let mut cur = start.clone();
    for d in 0..order.len() {
        for &x in tris(d) {
            let k = count[x as usize] as usize;
            raw[cur[k]] = d as u32;
            cur[k] += 1;
        }
    }
    drop(count);
    drop(cur);
    let (mut k, mut i) = (0, 0);
    write_segment(dir, id, &meta, |list| {
        if let Some(&t) = keys.get(k) {
            list.extend_from_slice(&raw[start[k]..start[k + 1]]);
            k += 1;
            return Some(t);
        }
        let t = (*sym_pairs.get(i)? >> 32) as u32;
        while i < sym_pairs.len() && (sym_pairs[i] >> 32) as u32 == t {
            list.push(sym_pairs[i] as u32);
            i += 1;
        }
        Some(t)
    })
}

/// Merge segments into one, dropping tombstoned docs. Postings stay in
/// order because docs are renumbered segment by segment.
pub fn merge(dir: &Path, id: u64, segs: &[&Segment]) -> Option<Segment> {
    let mut meta = Vec::new();
    let mut remap: Vec<Vec<u32>> = Vec::with_capacity(segs.len());
    for s in segs {
        let mut r = vec![u32::MAX; s.ndocs];
        for d in 0..s.ndocs as u32 {
            if !s.is_dead(d) {
                r[d as usize] = meta.len() as u32;
                let (size, mtime, rank) = (s.size()[d as usize], s.mtime()[d as usize], s.rank()[d as usize]);
                meta.push(DocMeta { path: s.path(d), size, mtime, rank, bloom: s.bloom_of(d) });
            }
        }
        remap.push(r);
    }
    let mut pos = vec![0usize; segs.len()];
    let mut part = Vec::new();
    write_segment(dir, id, &meta, |list| {
        loop {
            let t = segs.iter().zip(&pos).filter_map(|(s, &p)| s.tri_key().get(p).copied()).min()?;
            for (si, s) in segs.iter().enumerate() {
                if s.tri_key().get(pos[si]) == Some(&t) {
                    part.clear();
                    s.list_into(pos[si], &mut part);
                    list.extend(part.iter().map(|&d| remap[si][d as usize]).filter(|&d| d != u32::MAX));
                    pos[si] += 1;
                }
            }
            if !list.is_empty() {
                return Some(t);
            }
        }
    })
}

/// Encode postings (bitset when dense, delta varints otherwise) and write
/// the segment file. `next` fills one trigram's sorted doc ids into the
/// (cleared) buffer and returns the trigram, ascending, until None.
fn write_segment(dir: &Path, id: u64, docs: &[DocMeta<'_>], mut next: impl FnMut(&mut Vec<u32>) -> Option<u32>) -> Option<Segment> {
    if docs.is_empty() {
        return None;
    }
    let ndocs = docs.len();
    let (mut keys, mut tri_off, mut post) = (Vec::new(), Vec::new(), Vec::new());
    let mut list = Vec::new();
    loop {
        list.clear();
        let Some(t) = next(&mut list) else { break };
        keys.push(t);
        if list.len() * 8 > ndocs {
            tri_off.push(post.len() as u32 | BITSET);
            let at = post.len();
            post.resize(at + ndocs.div_ceil(8), 0);
            for &d in &list {
                post[at + d as usize / 8] |= 1 << (d % 8);
            }
        } else {
            tri_off.push(post.len() as u32);
            let mut last = 0u32;
            for &d in &list {
                put_varint(&mut post, d - last);
                last = d;
            }
        }
    }
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
    let mut bloom_off = vec![0u32];
    let mut blooms = Vec::new();
    for d in docs {
        blooms.extend_from_slice(d.bloom);
        bloom_off.push(blooms.len() as u32);
    }

    let (off, _) = layout(&lens(ndocs, keys.len(), post.len(), paths.len(), blooms.len()));
    let hdr = header(MAGIC, &[ndocs as u64, keys.len() as u64, post.len() as u64, paths.len() as u64, blooms.len() as u64]);
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

/// Does the name query let every indexed doc through (no scope, words,
/// extensions, ranges or patterns)? Then it needn't be checked per doc.
fn passes_every_doc(q: &Query) -> bool {
    q.scope.is_none()
        && q.tokens.is_empty()
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
}

impl Content {
    /// Open the segments the manifest lists, without touching anything: the
    /// view of an engine that follows another process's index.
    pub fn open_shared(dir: PathBuf) -> Content {
        let manifest: Vec<u64> =
            std::fs::read_to_string(dir.join("manifest")).unwrap_or_default().split_whitespace().filter_map(|s| s.parse().ok()).collect();
        let segs: Vec<Segment> = manifest.iter().filter_map(|&id| Segment::load(&dir, id)).collect();
        let next_id = segs.iter().map(|s| s.id + 1).max().unwrap_or(1);
        Content { dir, segs, next_id }
    }

    /// Open as the owner: also delete what the manifest doesn't list.
    pub fn open(dir: PathBuf) -> Content {
        std::fs::create_dir_all(&dir).ok();
        let Content { dir, segs, next_id } = Content::open_shared(dir);
        // Anything not loaded (old format, crashed build) is garbage.
        let keep: Vec<String> = segs.iter().flat_map(|s| [format!("seg-{:06}.fsc", s.id), format!("seg-{:06}.dead", s.id)]).collect();
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("seg-") && !keep.contains(&name) {
                let _ = std::fs::remove_file(e.path());
            }
        }
        Content { dir, segs, next_id }
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
        for (dir, recursive, want) in wants {
            let mut held = vec![false; want.len()];
            let lo = join(&dir, b"");
            for (si, s) in self.segs.iter_mut().enumerate() {
                let ids = if recursive { s.with_prefix(&lo).collect::<Vec<_>>() } else { s.direct_children(&lo) };
                for d in ids {
                    match want.find(s.path(d)) {
                        Some(i) if want.items[i].2 == s.size()[d as usize] && want.items[i].3 == s.mtime()[d as usize] => held[i] = true,
                        _ => touched[si] |= s.kill(d),
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
        for (s, t) in self.segs.iter().zip(&touched) {
            if *t {
                s.save_dead(&self.dir);
            }
        }
        let empty: Vec<u64> = self.segs.iter().filter(|s| s.live_docs == 0).map(|s| s.id).collect();
        if !empty.is_empty() {
            self.drop_segments(&empty);
            self.save_manifest();
        }
        todo.sort();
        todo
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
        self.segs.push(seg);
        self.save_manifest();
    }

    /// Tiered merging: 8 segments of the same size tier become one, so
    /// incremental updates never pile up thousands of tiny segments. Returns
    /// the group to merge (ids), capped so a merge's postings stay small.
    /// First, a segment whose docs were mostly replaced is rewritten alone:
    /// every query decodes the postings of its dead docs too.
    pub fn merge_plan(&self) -> Option<Vec<u64>> {
        if let Some(s) = self.segs.iter().find(|s| s.live_docs > 0 && s.live_docs * 2 < s.ndocs) {
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
        self.save_manifest();
    }

    fn drop_segments(&mut self, ids: &[u64]) {
        self.segs.retain(|s| !ids.contains(&s.id));
        for id in ids {
            let _ = std::fs::remove_file(seg_path(&self.dir, *id));
            let _ = std::fs::remove_file(dead_path(&self.dir, *id));
        }
    }

    /// Candidate docs for a pattern, filtered by the name query: one list
    /// per segment searched, with its `FIRST` best-ranked in front
    /// (unordered).
    fn candidates(&self, plan: &TQ, filt: &Query) -> Vec<Vec<Ranked>> {
        // A scope narrows each segment to the doc range holding its paths.
        let prefix = filt.scope.as_ref().map(|s| [s.as_slice(), b"/"].concat());
        let check = !passes_every_doc(filt);
        let work: Vec<(usize, std::ops::Range<u32>)> = (self.segs.iter().enumerate())
            .filter(|(_, s)| s.live_docs > 0)
            .map(|(si, s)| (si, prefix.as_ref().map_or(0..s.ndocs as u32, |p| s.doc_range(p))))
            .filter(|(_, docs)| !docs.is_empty())
            .collect();
        let one = |(si, docs): &(usize, std::ops::Range<u32>)| {
            let s = &self.segs[*si];
            let ids = eval(s, plan, docs.clone()).unwrap_or_else(|| docs.clone().collect());
            let (rank, mtime) = (s.rank(), s.mtime());
            let mut v: Vec<Ranked> = ids
                .into_iter()
                .filter(|&d| !s.is_dead(d) && rank[d as usize] != NOT_TEXT)
                .filter(|&d| !check || filt.match_path(s.path(d), KIND_FILE, s.size()[d as usize], mtime[d as usize]).is_some())
                .map(|d| ((((127 - rank[d as usize] as i32) as u64) << 32) | (u32::MAX - mtime[d as usize]) as u64, *si as u32, d))
                .collect();
            if v.len() > FIRST {
                v.select_nth_unstable(FIRST);
            }
            v
        };
        // About a lane per 50k docs to search: a small index is done on this
        // thread before a helper would wake.
        let docs: usize = work.iter().map(|(_, docs)| docs.len()).sum();
        par_claim(&work, (docs / 50_000).clamp(1, work.len().max(1)), one)
    }

    pub fn search(&self, g: &Grep, filt: &Query) -> GrepResult {
        let mut per = self.candidates(&g.plan(), filt);
        let total = per.iter().map(Vec::len).sum();
        // A candidate whose bloom filter lacks one of the pattern's grams
        // can't match: skip it without opening the file.
        let probes = g.probes();
        let path = |&(_, si, d): &Ranked| {
            let s = &self.segs[si as usize];
            s.may_contain(d, &probes).then(|| s.path(d))
        };
        // Most searches are done within the best few hundred candidates:
        // rank those first, and the rest only if reading gets that far.
        let t = std::time::Instant::now();
        let best = take_best(&mut per);
        let (mut r, done) = verify_from(g, best.len(), filt.limit, READERS, t, |i| path(&best[i]));
        if r.files.len() < filt.limit && done == best.len() && best.len() < total {
            let mut rest: Vec<Ranked> = per.concat();
            rest.par_sort_unstable();
            let (more, _) = verify_from(g, rest.len(), filt.limit - r.files.len(), READERS, t, |i| path(&rest[i]));
            r.files.extend(more.files);
            r.read += more.read;
            r.complete = more.complete;
        }
        r.candidates = total;
        r
    }
}

/// A candidate's place in the ranking, packed so sorting compares ints: your
/// files before dot-dirs/logs, then most recently modified first; ties in
/// segment, then doc order. Then its segment and doc.
type Ranked = (u64, u32, u32);

/// Candidates ranked in the first round.
const FIRST: usize = 512;

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

/// Take the `FIRST` best-ranked candidates out of the per-segment lists (each
/// with its own best in front), in order.
fn take_best(per: &mut [Vec<Ranked>]) -> Vec<Ranked> {
    let mut top: Vec<Ranked> = per.iter_mut().flat_map(|v| v.drain(..v.len().min(FIRST))).collect();
    if top.len() > FIRST {
        top.select_nth_unstable(FIRST);
        per[0].extend(top.drain(FIRST..));
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
    re: Regex,
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
        let re = RegexBuilder::new(&src)
            .case_insensitive(smart_ci && mode != GrepMode::Symbol)
            .multi_line(true)
            .size_limit(1 << 26)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Grep { pattern: pattern.to_string(), mode, max_per_file: 5, budget: Some(std::time::Duration::from_millis(250)), re })
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
        let mut lines = Vec::new();
        let (mut line_no, mut counted) = (1usize, 0usize);
        let mut last_line_start = usize::MAX;
        for m in g.re.find_iter(buf) {
            line_no += memchr::memchr_iter(b'\n', &buf[counted..m.start()]).count();
            counted = m.start();
            let ls = memchr::memrchr(b'\n', &buf[..m.start()]).map_or(0, |p| p + 1);
            if ls == last_line_start {
                continue;
            }
            last_line_start = ls;
            let le = memchr::memchr(b'\n', &buf[m.start()..]).map_or(buf.len(), |p| m.start() + p);
            let text = String::from_utf8_lossy(&buf[ls..le.min(ls + 400)]).trim_end().to_string();
            lines.push((line_no, text));
            if lines.len() >= g.max_per_file {
                break;
            }
        }
        (!lines.is_empty()).then(|| FileMatches { path: path.to_vec(), lines })
    })
}

/// A trigram query: which docs could possibly match.
#[derive(Debug, Clone)]
pub enum TQ {
    All,
    Tri(u32),
    And(Vec<TQ>),
    Or(Vec<TQ>),
}

fn literal_plan(s: &[u8]) -> TQ {
    if s.len() < 3 {
        return TQ::All;
    }
    TQ::And(trigrams_small(s).into_iter().map(TQ::Tri).collect())
}

/// A posting list as stored.
#[derive(Clone, Copy)]
enum List<'a> {
    /// Bit d: doc d has the trigram.
    Bits(&'a [u8]),
    /// Ascending doc ids as delta varints.
    Var(&'a [u8]),
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
            List::Var(b) => out.extend(Varints { b, last: 0 }.skip_while(|&d| d < docs.start).take_while(|&d| d < docs.end)),
        }
    }

    /// Keep the docs of `acc` (ascending) that are in the list.
    fn retain(self, acc: &mut Vec<u32>) {
        match self {
            List::Bits(b) => acc.retain(|&d| b.get(d as usize / 8).is_some_and(|x| x >> (d % 8) & 1 != 0)),
            List::Var(b) => {
                let mut it = Varints { b, last: 0 };
                let mut cur = it.next();
                acc.retain(|&d| {
                    while cur.is_some_and(|c| c < d) {
                        cur = it.next();
                    }
                    cur == Some(d)
                });
            }
        }
    }
}

/// Append the docs within `docs` set in every bitset, ascending.
fn and_bits(lists: &[&[u8]], docs: std::ops::Range<u32>, out: &mut Vec<u32>) {
    let end = (docs.end as usize).div_ceil(8).min(lists.iter().map(|l| l.len()).min().unwrap_or(0));
    let mut i = docs.start as usize / 8;
    while i < end {
        let k = (end - i).min(8);
        let mut w = u64::MAX;
        for l in lists {
            let mut b = [0u8; 8];
            b[..k].copy_from_slice(&l[i..i + k]);
            w &= u64::from_le_bytes(b);
        }
        while w != 0 {
            let d = i as u32 * 8 + w.trailing_zeros();
            if docs.contains(&d) {
                out.push(d);
            }
            w &= w - 1;
        }
        i += k;
    }
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
            vars.sort_by_key(|b| b.len());
            let mut acc = None;
            if let Some((first, vars)) = vars.split_first() {
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
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).open(std::ffi::OsStr::from_bytes(path)).ok()?;
    f.metadata().ok()?.is_file().then_some(f)
}
