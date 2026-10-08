//! Content search: a trigram index over the user's text files.
//!
//! Segments are immutable, mmap'd files: a doc table plus, per trigram, the
//! ids of the docs containing it (delta varints). A query becomes an AND/OR
//! of trigrams, the posting lists pick candidate files, and the candidates
//! are read fresh from disk and matched for real. Results therefore never
//! show stale content; only candidate selection can trail a file written
//! in the last couple of seconds.
//!
//! The index is kept in sync by diffing, exactly like the name index: for a
//! directory (or subtree), compare the eligible files the live name index
//! knows about with the docs we hold, reindex what changed, tombstone what
//! went away. The first build is just a sync of $HOME.

use crate::index::{HDR, as_bytes, cache_count, fields, header, layout, read_cache, read_cache_text, sec, valid_offsets};
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
}
const NS: usize = 9;

fn lens(ndocs: usize, ntri: usize, plen: usize, paths_len: usize) -> Option<[usize; NS]> {
    let sections =
        [(ntri, 4), (ntri.checked_add(1)?, 4), (plen, 1), (ndocs.checked_add(1)?, 4), (paths_len, 1), (ndocs, 8), (ndocs, 4), (ndocs, 4), (ndocs, 1)];
    let mut lengths = [0usize; NS];
    for (k, (count, size)) in sections.into_iter().enumerate() {
        lengths[k] = count.checked_mul(size)?;
    }
    Some(lengths)
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

    pub fn path(&self, d: u32) -> &[u8] {
        let o = self.path_off();
        &self.paths()[o[d as usize] as usize..o[d as usize + 1] as usize]
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

    fn postings(&self, tri: u32) -> Vec<u32> {
        let mut out = Vec::new();
        if let Ok(k) = self.tri_key().binary_search(&tri) {
            self.list_into(k, &mut out);
        }
        out
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
            let (v, n) = varint(bytes).expect("validated posting varint");
            bytes = &bytes[n..];
            last += v;
            out.push(last);
        }
    }

    fn load(dir: &Path, id: u64) -> Option<Segment> {
        let map = read_cache(&seg_path(dir, id)).ok()?;
        let [ndocs, ntri, plen, paths_len] = fields(&map, MAGIC)?;
        let (ndocs, ntri, plen, paths_len) = (cache_count(ndocs)?, cache_count(ntri)?, cache_count(plen)?, cache_count(paths_len)?);
        let (off, total) = layout(&lens(ndocs, ntri, plen, paths_len)?)?;
        if ndocs == 0 || plen >= BITSET as usize || map.len() != total {
            return None;
        }
        let mut dead = vec![0u64; ndocs.div_ceil(64)];
        match read_cache(&dead_path(dir, id)) {
            Ok(bytes) => {
                if bytes.len() != dead.len().checked_mul(8)? {
                    return None;
                }
                for (word, bytes) in dead.iter_mut().zip(bytes.chunks_exact(8)) {
                    *word = u64::from_le_bytes(bytes.try_into().ok()?);
                }
                if ndocs % 64 != 0 && dead.last()? >> (ndocs % 64) != 0 {
                    return None;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
        let live_docs = ndocs - dead.iter().map(|w| w.count_ones() as usize).sum::<usize>();
        let segment = Segment { map, id, ndocs, ndocs1: ndocs + 1, ntri, ntri1: ntri + 1, plen, paths_len, off, dead, live_docs };
        segment.valid_records().then_some(segment)
    }

    fn valid_records(&self) -> bool {
        if !valid_offsets(self.path_off(), self.paths_len) || self.tri_key().windows(2).any(|w| w[0] >= w[1]) {
            return false;
        }
        for d in 0..self.ndocs {
            let path = self.path(d as u32);
            if !path.starts_with(b"/")
                || path.len() < 2
                || path.contains(&0)
                || path[1..].split(|&b| b == b'/').any(|p| p.is_empty() || p == b"." || p == b"..")
            {
                return false;
            }
        }
        let mut previous: Option<&[u8]> = None;
        for &d in self.by_path() {
            if d as usize >= self.ndocs {
                return false;
            }
            let path = self.path(d);
            if previous.is_some_and(|p| p >= path) {
                return false;
            }
            previous = Some(path);
        }
        let offsets = self.tri_off();
        if offsets[0] & !BITSET != 0 || offsets[self.ntri] as usize != self.plen {
            return false;
        }
        for k in 0..self.ntri {
            let (start, end) = ((offsets[k] & !BITSET) as usize, (offsets[k + 1] & !BITSET) as usize);
            if start >= end || end > self.plen {
                return false;
            }
            let mut bytes = &self.post()[start..end];
            if offsets[k] & BITSET != 0 {
                if bytes.len() != self.ndocs.div_ceil(8) || (self.ndocs % 8 != 0 && bytes.last().unwrap() >> (self.ndocs % 8) != 0) {
                    return false;
                }
            } else {
                let mut last = 0u32;
                let mut first = true;
                while !bytes.is_empty() {
                    let Some((delta, length)) = varint(bytes) else { return false };
                    let Some(d) = last.checked_add(delta) else { return false };
                    if d as usize >= self.ndocs || (!first && delta == 0) {
                        return false;
                    }
                    first = false;
                    last = d;
                    bytes = &bytes[length..];
                }
            }
        }
        true
    }

    fn save_dead(&self, dir: &Path) {
        let bytes: Vec<u8> = self.dead.iter().flat_map(|w| w.to_le_bytes()).collect();
        let tmp = dead_path(dir, self.id).with_extension("tmp");
        if crate::storage::write_private_file(&tmp, &bytes).is_ok() {
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
fn varint(b: &[u8]) -> Option<(u32, usize)> {
    let mut v = 0u32;
    for (i, &x) in b.iter().enumerate().take(5) {
        if i == 4 && x > 0x0f {
            return None;
        }
        v |= ((x & 0x7f) as u32) << (7 * i);
        if x & 0x80 == 0 {
            return (i == 0 || x != 0).then_some((v, i + 1));
        }
    }
    None
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
}

/// One rayon split's output: trigrams and definition keys of its docs,
/// flat, plus where each doc's runs start. Reuses one read buffer and one
/// 2 MiB seen-set.
struct Split {
    seen: Vec<u64>,
    buf: Vec<u8>,
    flat: Vec<u32>,
    syms: Vec<u32>,
    docs: Vec<(usize, u32, u32, bool, u32, u32)>, // (doc, tri start, len, is_text, sym start, len)
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
            || Split { seen: vec![0u64; (1 << 24) / 64], buf: Vec::new(), flat: Vec::new(), syms: Vec::new(), docs: Vec::new() },
            |mut sp, i| {
                sp.buf.clear();
                let ok = open_regular(docs.path(i))
                    .and_then(|f| f.take(MAX_FILE + 1).read_to_end(&mut sp.buf).ok())
                    .is_some_and(|n| n as u64 <= MAX_FILE && memchr::memchr(0, &sp.buf[..n.min(8192)]).is_none());
                let (start, sym) = (sp.flat.len() as u32, sp.syms.len() as u32);
                if ok {
                    trigrams(&sp.buf, &mut sp.seen, &mut sp.flat);
                    symbols(&sp.buf, &mut sp.syms);
                }
                sp.docs.push((i, start, sp.flat.len() as u32 - start, ok, sym, sp.syms.len() as u32 - sym));
                sp
            },
        )
        .map(|mut sp| {
            sp.seen = Vec::new();
            sp.buf = Vec::new();
            sp
        })
        .collect();
    // Docs in path order: splits cover contiguous runs, in order.
    let order: Vec<(usize, usize)> = splits.iter().enumerate().flat_map(|(si, sp)| (0..sp.docs.len()).map(move |k| (si, k))).collect();
    let meta: Vec<DocMeta> = order
        .iter()
        .map(|&(si, k)| {
            let (i, _, _, text, _, _) = splits[si].docs[k];
            let (_, _, size, mtime) = docs.items[i];
            DocMeta { path: docs.path(i), size, mtime, rank: if text { doc_rank(docs.path(i)) } else { NOT_TEXT } }
        })
        .collect();
    let tris = |d: usize| {
        let (si, k) = order[d];
        let (_, st, len, _, _, _) = splits[si].docs[k];
        &splits[si].flat[st as usize..(st + len) as usize]
    };
    let syms = |d: usize| {
        let (si, k) = order[d];
        let (_, _, _, _, st, len) = splits[si].docs[k];
        &splits[si].syms[st as usize..(st + len) as usize]
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
                meta.push(DocMeta { path: s.path(d), size: s.size()[d as usize], mtime: s.mtime()[d as usize], rank: s.rank()[d as usize] });
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
    by_path.sort_by(|&a, &b| docs[a as usize].path.cmp(&docs[b as usize].path));

    let (off, _) = layout(&lens(ndocs, keys.len(), post.len(), paths.len())?)?;
    let hdr = header(MAGIC, &[ndocs as u64, keys.len() as u64, post.len() as u64, paths.len() as u64]);
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
    ];
    let p = seg_path(dir, id);
    let tmp = p.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let file = crate::storage::open_private_file(&tmp)?;
        file.set_len(0)?;
        let mut f = std::io::BufWriter::new(file);
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
    name_ok(name, size) && in_scope(path, home) && crate::content_policy::allows(path)
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
        let mut manifest: Vec<u64> =
            read_cache_text(&dir.join("manifest"), 1 << 20).unwrap_or_default().split_whitespace().filter_map(|s| s.parse().ok()).collect();
        manifest.retain(|&id| id < u64::MAX);
        manifest.sort_unstable();
        manifest.dedup();
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
        if crate::storage::write_private_file(&tmp, s.as_bytes()).is_ok() {
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

    pub fn alloc_id(&mut self) -> Option<u64> {
        let id = self.next_id;
        self.next_id = id.checked_add(1)?;
        Some(id)
    }

    pub fn push(&mut self, seg: Segment) {
        self.segs.push(seg);
        self.save_manifest();
    }

    /// Tiered merging: 8 segments of the same size tier become one, so
    /// incremental updates never pile up thousands of tiny segments. Returns
    /// the group to merge (ids), capped so a merge's postings stay small.
    pub fn merge_plan(&self) -> Option<Vec<u64>> {
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

    /// Swap merged segments for their replacement. Only the content worker
    /// writes, so nothing was tombstoned while the merge ran.
    pub fn replace(&mut self, ids: &[u64], seg: Segment) {
        self.segs.retain(|s| !ids.contains(&s.id));
        for id in ids {
            let _ = std::fs::remove_file(seg_path(&self.dir, *id));
            let _ = std::fs::remove_file(dead_path(&self.dir, *id));
        }
        self.segs.push(seg);
        self.save_manifest();
    }

    /// Candidate docs for a pattern, filtered by the name query.
    fn candidates(&self, plan: &TQ, filt: &Query) -> Vec<(usize, u32)> {
        let mut out: Vec<(usize, u32)> = self
            .segs
            .par_iter()
            .enumerate()
            .flat_map_iter(|(si, s)| {
                let ids = eval(s, plan).unwrap_or_else(|| (0..s.ndocs as u32).collect());
                ids.into_iter()
                    .filter(move |&d| !s.is_dead(d) && s.rank()[d as usize] != NOT_TEXT)
                    .filter(move |&d| filt.match_path(s.path(d), KIND_FILE, s.size()[d as usize], s.mtime()[d as usize]).is_some())
                    .map(move |d| (si, d))
                    .collect::<Vec<_>>()
            })
            .collect();
        // Your files before dot-dirs/logs, then most recently modified first.
        out.sort_by_key(|&(si, d)| {
            let s = &self.segs[si];
            std::cmp::Reverse((s.rank()[d as usize], s.mtime()[d as usize]))
        });
        out
    }

    pub fn search(&self, g: &Grep, filt: &Query) -> GrepResult {
        let plan = g.plan();
        let cands = self.candidates(&plan, filt);
        let paths: Vec<&[u8]> = cands.iter().map(|&(si, d)| self.segs[si].path(d)).collect();
        verify(g, &paths, filt.limit)
    }
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
            if in_scope(&p, home) && crate::content_policy::allows(&p) {
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

/// File opens on this Mac stop scaling past ~4 threads (Endpoint Security
/// clients tax every open; measured 5k files: 34 ms at 4 threads, 81 ms at
/// 16), so candidate reads get their own small pool.
fn read_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .thread_name(|i| format!("fsearch-read-{i}"))
            .start_handler(|_| {
                // Someone is waiting on these reads: keep them off the slow
                // cores and out of the throttled IO tiers.
                unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0) };
                crate::no_materialize()
            })
            .build()
            .unwrap()
    })
}

pub struct FileMatches {
    pub path: Vec<u8>,
    pub lines: Vec<(usize, String)>,
}

/// Read candidates in rank order, in parallel batches, until `limit` files
/// have matched or the time budget is spent (best-ranked results first, so a
/// cut-short search still returns the ones you most likely wanted).
pub fn verify(g: &Grep, paths: &[impl AsRef<[u8]> + Sync], limit: usize) -> GrepResult {
    let t = std::time::Instant::now();
    let mut r = GrepResult { candidates: paths.len(), ..Default::default() };
    let mut at = 0;
    let mut batch = 64;
    while at < paths.len() && r.files.len() < limit {
        if g.budget.is_some_and(|b| t.elapsed() > b) {
            break;
        }
        let end = (at + batch).min(paths.len());
        let found: Vec<Option<FileMatches>> = read_pool().install(|| paths[at..end].par_iter().map(|p| match_file(g, p.as_ref())).collect());
        r.read += end - at;
        r.files.extend(found.into_iter().flatten());
        at = end;
        batch = (batch * 2).min(1024);
    }
    r.complete = at >= paths.len() || r.files.len() >= limit;
    r.files.truncate(limit);
    r
}

thread_local! {
    /// One read buffer per read-pool thread: a fresh ~1 MB Vec per file
    /// costs page faults and an munmap every time.
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
        for m in g.re.find_iter(&buf) {
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

/// Docs matching `q` in a segment; None means "every doc".
fn eval(s: &Segment, q: &TQ) -> Option<Vec<u32>> {
    match q {
        TQ::All => None,
        TQ::Tri(t) => Some(s.postings(*t)),
        TQ::And(qs) => {
            let mut lists: Vec<Vec<u32>> = qs.iter().filter_map(|q| eval(s, q)).collect();
            lists.sort_by_key(Vec::len);
            let mut it = lists.into_iter();
            let mut acc = it.next()?;
            for l in it {
                if acc.is_empty() {
                    break;
                }
                acc = intersect(&acc, &l);
            }
            Some(acc)
        }
        TQ::Or(qs) => {
            let mut acc: Vec<u32> = Vec::new();
            for q in qs {
                acc.extend(eval(s, q)?);
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

/// What a regex fragment tells us: either a small set of exact strings it
/// can match, or just a trigram query every match must satisfy.
struct Info {
    exact: Option<Vec<Vec<u8>>>,
    q: TQ,
}

const MAX_EXACT: usize = 16;

/// What a fragment's exact set requires of a doc (All when there is no set,
/// or a string in it is too short to have a trigram).
fn exact_query(set: Option<Vec<Vec<u8>>>) -> TQ {
    match set {
        Some(set) if set.iter().all(|s| s.len() >= 3) => TQ::Or(set.iter().map(|s| literal_plan(s)).collect()),
        _ => TQ::All,
    }
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
    let all = || Info { exact: None, q: TQ::All };
    match h.kind() {
        HirKind::Empty | HirKind::Look(_) => Info { exact: Some(vec![Vec::new()]), q: TQ::All },
        HirKind::Literal(l) => Info { exact: Some(vec![l.0.iter().map(|&b| fold(b)).collect()]), q: TQ::All },
        HirKind::Class(c) => {
            // Up to 8 members: each is an exact string.
            let mut set: Vec<Vec<u8>> = match c {
                Class::Unicode(u) => {
                    u.ranges().iter().flat_map(|r| r.start()..=r.end()).take(9).map(|ch| ch.to_string().bytes().map(fold).collect()).collect()
                }
                Class::Bytes(b) => b.ranges().iter().flat_map(|r| r.start()..=r.end()).take(9).map(|x| vec![fold(x)]).collect(),
            };
            if set.len() > 8 {
                return all();
            }
            set.sort();
            set.dedup();
            Info { exact: Some(set), q: TQ::All }
        }
        HirKind::Capture(c) => info(&c.sub),
        HirKind::Repetition(r) => {
            if r.min == 0 {
                return all();
            }
            let i = info(&r.sub);
            if r.min == 1 && r.max == Some(1) {
                return i;
            }
            // At least one copy must appear.
            Info { exact: None, q: and(i.q, exact_query(i.exact)) }
        }
        HirKind::Concat(hs) => {
            let mut cur = Info { exact: Some(vec![Vec::new()]), q: TQ::All };
            for h in hs {
                let n = info(h);
                cur = match (cur.exact, n.exact) {
                    (Some(a), Some(b)) if a.len() * b.len() <= MAX_EXACT => {
                        let mut set: Vec<Vec<u8>> = a.iter().flat_map(|x| b.iter().map(move |y| [x.as_slice(), y].concat())).collect();
                        set.sort();
                        set.dedup();
                        Info { exact: Some(set), q: and(cur.q, n.q) }
                    }
                    (a, b) => {
                        let q = and(and(cur.q, exact_query(a)), n.q);
                        match b {
                            Some(b) if b.len() <= MAX_EXACT => Info { exact: Some(b), q },
                            b => Info { exact: None, q: and(q, exact_query(b)) },
                        }
                    }
                };
            }
            cur
        }
        HirKind::Alternation(hs) => {
            let parts: Vec<Info> = hs.iter().map(info).collect();
            if parts.iter().all(|p| p.exact.is_some()) {
                let mut set: Vec<Vec<u8>> = parts.iter().flat_map(|p| p.exact.clone().unwrap()).collect();
                set.sort();
                set.dedup();
                if set.len() <= MAX_EXACT {
                    return Info { exact: Some(set), q: TQ::All };
                }
            }
            let ors: Vec<TQ> = parts.into_iter().map(|p| and(p.q, exact_query(p.exact))).collect();
            if ors.iter().any(|q| matches!(q, TQ::All)) { all() } else { Info { exact: None, q: TQ::Or(ors) } }
        }
    }
}

fn regex_plan(h: &Hir) -> TQ {
    let i = info(h);
    and(i.q, exact_query(i.exact))
}

/// Files to grep where the content index does not reach (e.g. `in:/etc`),
/// picked from the name index instead of crawling, newest first. `q` is the
/// name query restricted to the files worth reading.
pub fn scan_paths(live: &Live, mut q: Query) -> Vec<Vec<u8>> {
    struct Candidate {
        path: Vec<u8>,
        mtime: u32,
    }

    q.kind = Some(KIND_FILE);
    q.limit = 200_000;
    q.size = (q.size.0, q.size.1.min(MAX_FILE));
    let mut files: Vec<Candidate> = (crate::query::Searcher { live }.search(&q).into_iter())
        .map(|h| match h.over {
            Some(path) => {
                let mtime = live.over[&path].mtime;
                Candidate { path, mtime }
            }
            None => {
                let mut p = Vec::new();
                live.base.path(h.idx as usize, &mut p);
                Candidate { path: p, mtime: live.base.mtime()[h.idx as usize] }
            }
        })
        .filter(|candidate| crate::content_policy::allows(&candidate.path))
        .collect();
    files.sort_by_key(|candidate| std::cmp::Reverse(candidate.mtime));
    files.into_iter().map(|candidate| candidate.path).collect()
}

/// Open a path for reading only if it is a regular file, never blocking:
/// O_NONBLOCK keeps a FIFO from hanging open(), and the read threads'
/// "don't materialize dataless files" policy keeps iCloud placeholders from
/// being downloaded just because we searched.
pub fn open_regular(path: &[u8]) -> Option<std::fs::File> {
    crate::content_io::open_regular(path)
}
#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fixture_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("fsearch-segment-tests-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn fixture(dir: &Path) -> Segment {
        let paths: Vec<Vec<u8>> = (0..65).map(|d| format!("/fixture/file-{d:03}.txt").into_bytes()).collect();
        let docs: Vec<DocMeta> = paths.iter().map(|path| DocMeta { path, size: 12, mtime: 123, rank: 0 }).collect();
        let mut key = 0;
        write_segment(dir, 7, &docs, |list| {
            key += 1;
            match key {
                1 => list.extend_from_slice(&[0, 8, 16, 24, 32, 40, 48, 64]),
                2 => list.extend(0..9),
                _ => return None,
            }
            Some(key)
        })
        .unwrap()
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn cache_segment_roundtrip_preserves_sparse_and_dense_postings() {
        // Given a saved segment with sparse varints and dense bitset postings.
        let dir = fixture_dir();
        let original = fixture(&dir);
        assert_eq!(original.ndocs, 65);
        // When the production loader reads the segment.
        let loaded = Segment::load(&dir, 7).expect("valid segment must load");
        // Then its paths, postings, and live document count remain correct.
        assert_eq!(loaded.path(64), b"/fixture/file-064.txt");
        assert_eq!(loaded.postings(1), vec![0, 8, 16, 24, 32, 40, 48, 64]);
        assert_eq!(loaded.postings(2), (0..9).collect::<Vec<_>>());
        assert_eq!(loaded.with_prefix(b"/fixture/").count(), 65);
        assert_eq!(loaded.live_docs, 65);
    }

    #[test]
    fn cache_segment_with_no_trigrams_loads() {
        // Given a saved text document with no indexed trigram.
        let dir = fixture_dir();
        write_segment(&dir, 7, &[DocMeta { path: b"/fixture/empty.txt", size: 0, mtime: 1, rank: 0 }], |_| None).unwrap();
        // When the production loader reads that segment.
        let loaded = Segment::load(&dir, 7).expect("segment without trigrams must load");
        // Then the document remains available and its postings are empty.
        assert_eq!(loaded.path(0), b"/fixture/empty.txt");
        assert_eq!(loaded.postings(1), Vec::<u32>::new());
        assert_eq!(loaded.live_docs, 1);
    }

    #[test]
    fn cache_segment_loader_rejects_truncation_overflow_and_empty_documents() {
        let dir = fixture_dir();
        fixture(&dir);
        let original = std::fs::read(seg_path(&dir, 7)).unwrap();
        for (label, field, value) in
            [("empty documents", 0, 0), ("document count", 0, u64::MAX), ("trigram count", 1, u64::MAX), ("posting length", 2, BITSET as u64)]
        {
            // Given a saved segment with one invalid header count.
            let mut bytes = original.clone();
            bytes[8 + field * 8..16 + field * 8].copy_from_slice(&value.to_le_bytes());
            std::fs::write(seg_path(&dir, 7), bytes).unwrap();
            // When the production loader reads that segment.
            let loaded = Segment::load(&dir, 7);
            // Then it rejects the invalid storage representation.
            assert!(loaded.is_none(), "accepted invalid {label}");
        }
        for length in [7, HDR - 1, original.len() - 1] {
            // Given a saved segment that ends before its complete layout.
            std::fs::write(seg_path(&dir, 7), &original[..length]).unwrap();
            // When the production loader reads that segment.
            let loaded = Segment::load(&dir, 7);
            // Then the incomplete segment is rejected.
            assert!(loaded.is_none(), "accepted segment truncated to {length} bytes");
        }
    }

    #[test]
    fn cache_segment_loader_rejects_invalid_paths_order_ids_and_posting_ranges() {
        let dir = fixture_dir();
        let segment = fixture(&dir);
        let original = std::fs::read(seg_path(&dir, 7)).unwrap();
        for (label, section, element, value) in [
            ("path offset", S::PathOff, 1, u32::MAX),
            ("document id", S::ByPath, 0, 65),
            ("duplicate document id", S::ByPath, 1, 0),
            ("key order", S::TriKey, 1, 1),
            ("posting range", S::TriOff, 1, u32::MAX),
            ("posting origin", S::TriOff, 0, 1),
            ("posting end", S::TriOff, 2, 0),
            ("bitset length", S::TriOff, 1, BITSET | 9),
        ] {
            // Given a saved segment with one invalid record or range.
            let mut bytes = original.clone();
            put_u32(&mut bytes, segment.off[section as usize] + element * 4, value);
            std::fs::write(seg_path(&dir, 7), bytes).unwrap();
            // When the production loader reads that segment.
            let loaded = Segment::load(&dir, 7);
            // Then the invalid record cannot reach segment consumers.
            assert!(loaded.is_none(), "accepted invalid {label}");
        }
        // Given a valid document permutation saved in the wrong path order.
        let mut bytes = original.clone();
        put_u32(&mut bytes, segment.off[S::ByPath as usize], 1);
        put_u32(&mut bytes, segment.off[S::ByPath as usize] + 4, 0);
        std::fs::write(seg_path(&dir, 7), bytes).unwrap();
        // When the production loader reads that permutation.
        let loaded = Segment::load(&dir, 7);
        // Then it rejects the order required by binary path lookup.
        assert!(loaded.is_none(), "accepted unsorted path permutation");
        for (label, offset, byte) in [
            ("relative path", segment.off[S::Paths as usize], b'.'),
            ("NUL path", segment.off[S::Paths as usize] + 1, 0),
            ("bitset padding", segment.off[S::Post as usize] + segment.plen - 1, 2),
        ] {
            // Given a saved segment with invalid path or padding bytes.
            let mut bytes = original.clone();
            bytes[offset] = byte;
            std::fs::write(seg_path(&dir, 7), bytes).unwrap();
            // When the production loader reads that segment.
            let loaded = Segment::load(&dir, 7);
            // Then it rejects that invalid byte representation.
            assert!(loaded.is_none(), "accepted invalid {label}");
        }
    }

    #[test]
    fn cache_segment_loader_rejects_invalid_delta_varints() {
        let dir = fixture_dir();
        let segment = fixture(&dir);
        let original = std::fs::read(seg_path(&dir, 7)).unwrap();
        for (label, prefix) in [
            ("unterminated", vec![0x80; 8]),
            ("overflow", vec![0xff, 0xff, 0xff, 0xff, 0x10]),
            ("delta sum overflow", vec![8, 0xff, 0xff, 0xff, 0xff, 0x0f]),
            ("document out of range", vec![65]),
            ("duplicate document", vec![0, 0]),
            ("noncanonical", vec![0x80, 0]),
        ] {
            // Given a saved sparse posting list with an invalid delta encoding.
            let mut bytes = original.clone();
            let start = segment.off[S::Post as usize];
            bytes[start..start + prefix.len()].copy_from_slice(&prefix);
            std::fs::write(seg_path(&dir, 7), bytes).unwrap();
            // When the production loader reads that segment.
            let loaded = Segment::load(&dir, 7);
            // Then it rejects invalid varints and invalid resulting document IDs.
            assert!(loaded.is_none(), "accepted {label} varint list");
        }
    }

    #[test]
    fn cache_segment_loader_validates_tombstone_length_and_padding() {
        let dir = fixture_dir();
        fixture(&dir);
        let valid: Vec<u8> = [1u64, 0].into_iter().flat_map(u64::to_le_bytes).collect();
        // Given a valid tombstone that marks document zero as deleted.
        std::fs::write(dead_path(&dir, 7), &valid).unwrap();
        // When the production loader reads the segment and its tombstone.
        let loaded = Segment::load(&dir, 7).expect("valid tombstone must load");
        // Then exactly that document is deleted.
        assert_eq!(loaded.live_docs, 64);
        assert!(loaded.is_dead(0));
        assert!(!loaded.is_dead(64));
        for (label, bytes) in
            [("truncated", vec![0; 7]), ("extra word", vec![0; 24]), ("padding bit", [0u64, 2].into_iter().flat_map(u64::to_le_bytes).collect())]
        {
            // Given a tombstone whose size or unused bits are invalid.
            std::fs::write(dead_path(&dir, 7), bytes).unwrap();
            // When the production loader reads the segment and tombstone.
            let loaded = Segment::load(&dir, 7);
            // Then it rejects the segment instead of changing its live count.
            assert!(loaded.is_none(), "accepted {label} tombstone");
        }
    }

    #[test]
    fn cache_manifest_rejects_overflow_id_and_loads_each_segment_once() {
        // Given a manifest with an overflow ID and a repeated valid segment.
        let dir = fixture_dir();
        fixture(&dir);
        std::fs::copy(seg_path(&dir, 7), seg_path(&dir, u64::MAX)).unwrap();
        std::fs::write(dir.join("manifest"), format!("{}\n7\n7\n", u64::MAX)).unwrap();
        // When the production shared-cache loader reads the manifest.
        let mut loaded = Content::open_shared(dir);
        // Then it retains the valid segment once and allocates a valid next ID.
        assert_eq!(loaded.segs.iter().map(|s| s.id).collect::<Vec<_>>(), vec![7]);
        assert_eq!(loaded.next_id, 8);
        assert_eq!(loaded.docs(), 65);
        assert_eq!(loaded.alloc_id(), Some(8));
    }

    #[test]
    fn cache_segment_id_exhaustion_stops_allocation_without_overflow() {
        // Given a valid loaded segment using the last persistable ID.
        let dir = fixture_dir();
        fixture(&dir);
        std::fs::copy(seg_path(&dir, 7), seg_path(&dir, u64::MAX - 1)).unwrap();
        std::fs::write(dir.join("manifest"), format!("{}\n", u64::MAX - 1)).unwrap();
        let mut loaded = Content::open_shared(dir);
        assert_eq!(loaded.next_id, u64::MAX);
        assert_eq!(loaded.docs(), 65);
        // When a caller requests a fresh segment ID.
        let id = loaded.alloc_id();
        // Then it receives an explicit exhaustion result and the cache remains usable.
        assert_eq!(id, None);
        assert_eq!(loaded.next_id, u64::MAX);
        assert_eq!(loaded.docs(), 65);
    }

    #[test]
    fn cache_manifest_rejects_symlinks_and_oversized_files() {
        // Given a manifest reached through a symbolic link.
        let dir = fixture_dir();
        fixture(&dir);
        let target = dir.join("manifest-target");
        std::fs::write(&target, "7\n").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("manifest")).unwrap();
        // When the production shared-cache loader opens that manifest.
        let loaded = Content::open_shared(dir.clone());
        // Then it loads no segment from the indirect manifest.
        assert_eq!(loaded.docs(), 0);

        // Given a regular manifest whose size exceeds 1 MiB.
        let dir = fixture_dir();
        fixture(&dir);
        let manifest = dir.join("manifest");
        std::fs::write(&manifest, "7\n").unwrap();
        std::fs::OpenOptions::new().write(true).open(&manifest).unwrap().set_len((1 << 20) + 1).unwrap();
        // When the production shared-cache loader opens that manifest.
        let loaded = Content::open_shared(dir);
        // Then it rejects the manifest before allocating or parsing its text.
        assert_eq!(loaded.docs(), 0);
    }

    #[test]
    fn cache_segment_rejects_the_previous_content_policy_format() {
        // Given a segment saved with the previous content-policy format.
        let dir = fixture_dir();
        fixture(&dir);
        let mut bytes = std::fs::read(seg_path(&dir, 7)).unwrap();
        bytes[..8].copy_from_slice(b"FSCSEG03");
        std::fs::write(seg_path(&dir, 7), bytes).unwrap();
        // When the production loader opens the old segment.
        let loaded = Segment::load(&dir, 7);
        // Then it rejects that segment so the owner can rebuild with the new policy.
        assert!(loaded.is_none(), "accepted an old content-policy segment");
    }

    #[test]
    fn cache_loaded_segment_survives_source_file_truncation() {
        // Given a valid segment loaded into stable memory.
        let dir = fixture_dir();
        fixture(&dir);
        let loaded = Segment::load(&dir, 7).unwrap();
        assert_eq!(loaded.postings(2), (0..9).collect::<Vec<_>>());
        // When another writer truncates the original segment file.
        std::fs::OpenOptions::new().write(true).open(seg_path(&dir, 7)).unwrap().set_len(0).unwrap();
        // Then both path access and posting decoding remain valid.
        assert_eq!(loaded.path(64), b"/fixture/file-064.txt");
        assert_eq!(loaded.postings(1), vec![0, 8, 16, 24, 32, 40, 48, 64]);
        assert_eq!(loaded.postings(2), (0..9).collect::<Vec<_>>());
    }

    #[test]
    fn cache_save_segment_rejects_a_planted_temporary_symlink() {
        // Given a generated target file and a segment temporary symlink to that target.
        let dir = fixture_dir();
        let target = dir.join("target.txt");
        std::fs::write(&target, b"keep these target bytes").unwrap();
        std::os::unix::fs::symlink(&target, seg_path(&dir, 7).with_extension("tmp")).unwrap();
        // When the production segment writer uses that temporary path.
        let saved = write_segment(&dir, 7, &[DocMeta { path: b"/fixture/empty.txt", size: 0, mtime: 1, rank: 0 }], |_| None);
        // Then it rejects the save and leaves the target bytes unchanged.
        assert!(saved.is_none(), "accepted a symbolic-link temporary segment");
        assert_eq!(std::fs::read(target).unwrap(), b"keep these target bytes");
    }

    #[test]
    fn cache_save_tombstone_rejects_a_planted_temporary_symlink() {
        // Given a deleted document and a tombstone temporary symlink to a generated target.
        let dir = fixture_dir();
        let mut segment = fixture(&dir);
        assert!(segment.kill(0));
        let target = dir.join("target.txt");
        std::fs::write(&target, b"keep these target bytes").unwrap();
        std::os::unix::fs::symlink(&target, dead_path(&dir, 7).with_extension("tmp")).unwrap();
        // When the production tombstone writer uses that temporary path.
        segment.save_dead(&dir);
        // Then the target bytes remain unchanged and no tombstone is published.
        assert_eq!(std::fs::read(target).unwrap(), b"keep these target bytes");
        assert_eq!(Segment::load(&dir, 7).unwrap().live_docs, 65);
    }

    #[test]
    fn cache_save_manifest_rejects_a_planted_temporary_symlink() {
        // Given a content segment and a manifest temporary symlink to a generated target.
        let dir = fixture_dir();
        let segment = fixture(&dir);
        let target = dir.join("target.txt");
        std::fs::write(&target, b"keep these target bytes").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("manifest.tmp")).unwrap();
        let content = Content { dir: dir.clone(), segs: vec![segment], next_id: 8 };
        // When the production manifest writer uses that temporary path.
        content.save_manifest();
        // Then the target bytes remain unchanged and no manifest is published.
        assert_eq!(std::fs::read(target).unwrap(), b"keep these target bytes");
        assert_eq!(Content::open_shared(dir).docs(), 0);
    }

    #[test]
    #[should_panic(expected = "section byte length overflow")]
    fn cache_sections_reject_an_invalid_public_document_count() {
        // Given a valid segment whose public count is changed after loading.
        let dir = fixture_dir();
        let mut segment = fixture(&dir);
        assert_eq!(segment.size().len(), 65);
        segment.ndocs = usize::MAX;
        // When a safe caller asks for the corresponding typed section.
        // Then the accessor fails with the stated bounds error before creating a raw slice.
        segment.size();
    }
}
