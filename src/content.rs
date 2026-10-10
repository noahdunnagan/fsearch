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
const MAGIC: &[u8; 8] = b"FSCSEG03";
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

fn lens(ndocs: usize, ntri: usize, plen: usize, paths_len: usize) -> [usize; NS] {
    [ntri * 4, (ntri + 1) * 4, plen, (ndocs + 1) * 4, paths_len, ndocs * 8, ndocs * 4, ndocs * 4, ndocs]
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
            let (v, n) = varint(bytes);
            bytes = &bytes[n..];
            last += v;
            out.push(last);
        }
    }

    fn load(dir: &Path, id: u64) -> Option<Segment> {
        let f = std::fs::File::open(seg_path(dir, id)).ok()?;
        let map = unsafe { Mmap::map(&f) }.ok()?;
        let [ndocs, ntri, plen, paths_len] = fields(&map, MAGIC)?.map(|v| v as usize);
        // No count can exceed the file; checked first so a corrupt header
        // can't overflow the layout math into a too-small total.
        if [ndocs, ntri, plen, paths_len].iter().any(|&v| v > map.len()) {
            return None;
        }
        let (off, total) = layout(&lens(ndocs, ntri, plen, paths_len));
        if map.len() < total {
            return None;
        }
        let mut dead = vec![0u64; ndocs.div_ceil(64)];
        if let Ok(b) = std::fs::read(dead_path(dir, id)) {
            for (w, c) in dead.iter_mut().zip(b.chunks_exact(8)) {
                *w = u64::from_le_bytes(c.try_into().unwrap());
            }
            // Stray bits past the last doc would make live_docs underflow.
            if let Some(w) = dead.last_mut().filter(|_| ndocs % 64 != 0) {
                *w &= (1 << (ndocs % 64)) - 1;
            }
        }
        let live_docs = ndocs - dead.iter().map(|w| w.count_ones() as usize).sum::<usize>();
        Some(Segment { map, id, ndocs, ndocs1: ndocs + 1, ntri, ntri1: ntri + 1, plen, paths_len, off, dead, live_docs })
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
    by_path.sort_by(|&a, &b| docs[a as usize].path.cmp(docs[b as usize].path));

    let (off, _) = layout(&lens(ndocs, keys.len(), post.len(), paths.len()));
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
    name_ok(name, size) && file_in_scope(path, home)
}

/// A file is in scope when its folder is: the skip lists name folders, and
/// the file's own name is `name_ok`'s business (a script called `build`).
fn file_in_scope(path: &[u8], home: &[u8]) -> bool {
    path.iter().rposition(|&b| b == b'/').is_some_and(|cut| in_scope(&path[..cut], home))
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
    if !crate::live::is_ancestor(home, path) {
        return false;
    }
    let rest = &path[home.len()..];
    let rel = rest.strip_prefix(b"/").unwrap_or(rest);
    if SKIP_UNDER_HOME.iter().any(|p| crate::live::is_ancestor(p, rel)) {
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
            if file_in_scope(&p, home) {
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
/// A change the content index follows: inside home, or a rescanned tree
/// that holds home.
pub(crate) fn follows(path: &[u8], tree: bool, home: &[u8]) -> bool {
    in_scope(path, home) || (tree && crate::live::is_ancestor(path, home))
}

pub fn wants(live: &Live, home: &[u8], dirs: &[Vec<u8>], trees: &[Vec<u8>]) -> Vec<(Vec<u8>, bool, Docs)> {
    let mut out: Vec<(Vec<u8>, bool)> = Vec::new();
    for (d, r) in dirs.iter().map(|d| (d, false)).chain(trees.iter().map(|d| (d, true))) {
        if !follows(d, r, home) {
            continue;
        }
        if in_scope(d, home) {
            out.push((d.clone(), r));
        } else {
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
    ci: bool,
}

/// Smart case: does the pattern spell an uppercase letter? In a regex only
/// literals count, not escapes (`\S`, `\W`), flags (`(?U)`) or group names.
fn has_upper(pattern: &str, mode: GrepMode) -> bool {
    use regex_syntax::ast::{self, Ast, ClassSetItem};
    struct Upper;
    impl ast::Visitor for Upper {
        type Output = ();
        type Err = ();
        fn finish(self) -> Result<(), ()> {
            Ok(())
        }
        fn visit_pre(&mut self, a: &Ast) -> Result<(), ()> {
            match a {
                Ast::Literal(l) if l.c.is_uppercase() => Err(()),
                _ => Ok(()),
            }
        }
        fn visit_class_set_item_pre(&mut self, i: &ClassSetItem) -> Result<(), ()> {
            match i {
                ClassSetItem::Literal(l) if l.c.is_uppercase() => Err(()),
                ClassSetItem::Range(r) if r.start.c.is_uppercase() || r.end.c.is_uppercase() => Err(()),
                _ => Ok(()),
            }
        }
    }
    match mode {
        GrepMode::Regex => ast::parse::Parser::new().parse(pattern).map_or(true, |a| ast::visit(&a, Upper).is_err()),
        _ => pattern.chars().any(|c| c.is_uppercase()),
    }
}

impl Grep {
    pub fn new(pattern: &str, mode: GrepMode) -> Result<Grep, String> {
        let ci = mode != GrepMode::Symbol && !has_upper(pattern, mode);
        let src = match mode {
            GrepMode::Literal => regex::escape(pattern),
            GrepMode::Regex => pattern.to_string(),
            // A definition: a declaring keyword, optional generics/modifiers,
            // then the name. ASCII word boundaries keep the regex on the fast
            // DFA path even in files with non-ASCII text.
            GrepMode::Symbol => format!(r"(?-u:\b)(?:{DEFINES})(?:<[^>\n]*>)?[ \t*&]+(?:mut[ \t]+)?{}(?-u:\b)", regex::escape(pattern)),
        };
        let re = RegexBuilder::new(&src)
            .case_insensitive(ci)
            .multi_line(true)
            // `$` before "\r\n" too, or `foo$` never matches a CRLF file.
            .crlf(true)
            .size_limit(1 << 26)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Grep { pattern: pattern.to_string(), mode, max_per_file: 5, budget: Some(std::time::Duration::from_millis(250)), re, ci })
    }

    fn plan(&self) -> TQ {
        match self.mode {
            // Exactly the docs that define it (plus rare hash collisions,
            // which reading the file weeds out).
            GrepMode::Symbol if plain_identifier(self.pattern.as_bytes()) => TQ::Tri(symbol_key(self.pattern.as_bytes())),
            GrepMode::Literal | GrepMode::Symbol if !self.ci => literal_plan(self.pattern.as_bytes()),
            // Folded the way the regex folds: beyond ASCII (É/é, and k to
            // the Kelvin sign), where the index folds only ASCII, each letter
            // is a small class of exact alternatives.
            _ => {
                let src = if self.mode == GrepMode::Regex { self.pattern.clone() } else { regex::escape(&self.pattern) };
                regex_syntax::ParserBuilder::new().case_insensitive(self.ci).build().parse(&src).map_or(TQ::All, |h| regex_plan(&h))
            }
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
        for m in g.re.find_iter(buf) {
            // An empty match after the final newline (`^`, `$`, `x*`) is
            // not on any line.
            if m.start() == buf.len() && buf.last().is_none_or(|&b| b == b'\n') {
                break;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::Index;
    use crate::live::OEnt;
    use crate::walk::{KIND_DIR, Listing, NONE, RawEnt};
    use std::collections::BTreeMap;
    use std::os::unix::ffi::OsStrExt;
    use std::time::Duration;

    /// A fresh, empty, canonical scratch dir (temp_dir is behind /var -> /private/var).
    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fsearch-content-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    fn put(root: &Path, rel: &str, body: &[u8]) -> Vec<u8> {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p.as_os_str().as_bytes().to_vec()
    }

    fn os(p: &[u8]) -> &std::ffi::OsStr {
        std::ffi::OsStr::from_bytes(p)
    }

    fn docs_of(paths: &[Vec<u8>]) -> Docs {
        let mut d = Docs::default();
        for p in paths {
            let o = crate::live::lstat(p).unwrap();
            d.push(p, o.size, o.mtime);
        }
        d.sort();
        d
    }

    /// A content index holding `files` (relative to `root`) in one segment.
    fn index(root: &Path, files: &[(&str, &[u8])]) -> (Content, Vec<Vec<u8>>) {
        let paths: Vec<Vec<u8>> = files.iter().map(|(r, b)| put(root, r, b)).collect();
        let mut c = Content::open(root.join("idx"));
        add(&mut c, &paths);
        (c, paths)
    }

    fn add(c: &mut Content, paths: &[Vec<u8>]) {
        let d = docs_of(paths);
        let id = c.alloc_id();
        let seg = build_segment(&c.dir, id, &d, 0..d.len()).unwrap();
        c.push(seg);
    }

    fn grep(pattern: &str, mode: GrepMode) -> Grep {
        let mut g = Grep::new(pattern, mode).unwrap();
        g.budget = None;
        g
    }

    fn q(s: &str) -> Query {
        Query::parse(s, "/nonexistent-home").unwrap()
    }

    type Found = Vec<(String, Vec<(usize, String)>)>;

    fn search(c: &Content, pattern: &str, mode: GrepMode) -> Found {
        let r = c.search(&grep(pattern, mode), &q(""));
        assert!(r.complete);
        let mut v: Found = r
            .files
            .into_iter()
            .map(|f| {
                let p = String::from_utf8(f.path).unwrap();
                (p.rsplit('/').next().unwrap().to_string(), f.lines)
            })
            .collect();
        v.sort();
        v
    }

    fn names(c: &Content, pattern: &str, mode: GrepMode) -> Vec<String> {
        search(c, pattern, mode).into_iter().map(|(n, _)| n).collect()
    }

    /// Lines one file matches, straight through match_file.
    fn lines(body: &[u8], pattern: &str, mode: GrepMode) -> Vec<(usize, String)> {
        let root = scratch(&format!("lines-{:x}", symbol_key(pattern.as_bytes()) ^ symbol_key(body)));
        let p = put(&root, "f.txt", body);
        let r = match_file(&grep(pattern, mode), &p).map(|f| f.lines).unwrap_or_default();
        let _ = std::fs::remove_dir_all(root);
        r
    }

    fn l(n: usize, s: &str) -> (usize, String) {
        (n, s.to_string())
    }

    const NONE_FOUND: [&str; 0] = [];

    // ---- eligibility ----

    #[test]
    fn name_and_size_rules() {
        assert!(name_ok(b"main.rs", 10));
        assert!(name_ok(b"README.MD", 10), "extensions are case-insensitive");
        assert!(!name_ok(b"photo.jpg", 10));
        assert!(!name_ok(b"app.min.js", 10));
        assert!(name_ok(b"app.js", 10));
        assert!(!name_ok(b"package-lock.json", 10));
        assert!(!name_ok(b"big.rs", MAX_FILE + 1));
        assert!(name_ok(b"big.rs", MAX_FILE));
        // No extension (or a leading-dot name): small files only.
        assert!(name_ok(b"Makefile", 256 << 10));
        assert!(!name_ok(b"Makefile", (256 << 10) + 1));
        assert!(name_ok(b".zshrc", 100));
        assert!(!name_ok(b"trailing.", 10));
    }

    #[test]
    fn scope_rules() {
        let h = b"/Users/me";
        assert!(in_scope(b"/Users/me", h));
        assert!(in_scope(b"/Users/me/code/a.rs", h));
        assert!(!in_scope(b"/Users/meow/a.rs", h), "prefix of a name is not the home folder");
        assert!(!in_scope(b"/Users/other/a.rs", h));
        assert!(!in_scope(b"/Users/me/p/node_modules/x/a.js", h));
        assert!(!in_scope(b"/Users/me/Library/Prefs/a.plist", h));
        assert!(in_scope(b"/Users/me/p/node_modules_notes/a.md", h));
        assert!(!in_scope(b"/Users/me/go/pkg", h));
        assert!(!in_scope(b"/Users/me/go/pkg/mod/a.go", h));
        assert!(in_scope(b"/Users/me/go/pkgs/a.go", h));
        assert!(in_scope(b"/Users/me/go/src/a.go", h));
        assert!(!in_scope(b"/Users/me/.local/share/x.txt", h));
        assert!(!in_scope(b"/Users/me/Apps/Foo.app/Contents/Info.plist", h));
        assert!(in_scope(b"/Users/me/notes/.app/a.md", h), "a bare suffix is not a bundle");
        assert!(!in_scope(b"/Users/me/a.photoslibrary/db.txt", h));

        assert!(eligible(b"/Users/me/code/a.rs", 10, h));
        assert!(!eligible(b"/Users/me/code/a.png", 10, h));
        assert!(!eligible(b"/Users/me/target/a.rs", 10, h));
        assert!(!eligible(b"/tmp/a.rs", 10, h));
    }

    #[test]
    fn ranks() {
        assert_eq!(doc_rank(b"/h/code/a.rs"), 0);
        assert_eq!(doc_rank(b"/h/.config/a.toml"), -2);
        assert_eq!(doc_rank(b"/h/code/run.log"), -1);
        assert_eq!(doc_rank(b"/h/.claude/t.jsonl"), -3);
    }

    // ---- encoding helpers ----

    #[test]
    fn varints_round_trip() {
        for v in [0u32, 1, 127, 128, 300, 16383, 16384, 1 << 21, u32::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(varint(&b), (v, b.len()));
        }
        // A truncated varint stops at the end instead of running off it.
        assert_eq!(varint(&[0x80, 0x80]).1, 2);
    }

    #[test]
    fn trigram_extraction() {
        let mut seen = vec![0u64; (1 << 24) / 64];
        let mut out = vec![7];
        trigrams(b"ab", &mut seen, &mut out);
        assert_eq!(out, [7], "under 3 bytes: nothing");
        out.clear();
        trigrams(b"AbcABC", &mut seen, &mut out);
        assert_eq!(out, trigrams_small(b"abcabc"), "folded, sorted, distinct");
        assert_eq!(out.len(), 3);
        assert!(seen.iter().all(|&w| w == 0), "scratch left clean");
        assert!(trigrams_small(b"ab").is_empty());
    }

    #[test]
    fn symbol_extraction() {
        let keys = |s: &[u8]| {
            let mut v = Vec::new();
            symbols(s, &mut v);
            v
        };
        let mut want: Vec<u32> = ["main", "func", "Foo", "x", "Bar", "struct", "get"].iter().map(|n| symbol_key(n.as_bytes())).collect();
        want.sort();
        want.dedup();
        let got = keys(b"static func main() {}\ntypedef struct Foo {} Foo;\nlet mut x = 1;\nimpl<T> Bar for T {}\nfn get() {}\nfn get() {}\n");
        assert_eq!(got, want);
        assert!(keys(b"no definitions here").is_empty());
        assert!(plain_identifier(b"foo_1"));
        assert!(plain_identifier(b"_x"));
        assert!(!plain_identifier(b"1x"));
        assert!(!plain_identifier(b"a.b"));
        assert!(!plain_identifier(b""));
        assert!(symbol_key(b"a") >= 1 << 31, "above the trigram space");
    }

    #[test]
    fn docs_sort_find_batch() {
        let mut d = Docs::default();
        d.push(b"/b", 1, 1);
        d.push(b"/a", 2, 2);
        d.push(b"/b", 3, 3);
        d.sort();
        assert_eq!(d.len(), 2);
        assert_eq!(d.find(b"/a"), Some(0));
        assert_eq!(d.find(b"/b"), Some(1));
        assert_eq!(d.find(b"/c"), None);
        assert_eq!(d.find(b"/"), None);
        assert_eq!(d.batches(), vec![0..2]);
        assert!(Docs::default().batches().is_empty());

        let mut big = Docs::default();
        for i in 0..5 {
            big.push(format!("/f{i}").as_bytes(), SEG_BYTES / 2, 0);
        }
        assert_eq!(big.batches(), vec![0..2, 2..4, 4..5]);
    }

    // ---- searching ----

    #[test]
    fn literal_search_and_smart_case() {
        let root = scratch("literal");
        let (c, _) = index(
            &root,
            &[
                ("a.rs", b"fn hello_world() {}\nlet x = HELLO;\n"),
                ("b.md", b"Hello there\n"),
                ("c.txt", b"nothing to see\n"),
                ("dots.txt", b"a.b*c\n"),
            ],
        );
        assert_eq!(names(&c, "hello", GrepMode::Literal), ["a.rs", "b.md"]);
        assert_eq!(names(&c, "Hello", GrepMode::Literal), ["b.md"], "an uppercase letter makes it case-sensitive");
        assert_eq!(names(&c, "HELLO", GrepMode::Literal), ["a.rs"]);
        assert_eq!(names(&c, "a.b*c", GrepMode::Literal), ["dots.txt"], "literal mode escapes regex syntax");
        assert_eq!(names(&c, "axb", GrepMode::Literal), NONE_FOUND);
        // Too short for a trigram: every doc is a candidate.
        assert_eq!(names(&c, "he", GrepMode::Literal), ["a.rs", "b.md"]);
        assert_eq!(c.search(&grep("he", GrepMode::Literal), &q("")).candidates, 4);
        assert_eq!(c.docs(), 4);
        assert!(c.bytes() > 0);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn line_numbers() {
        assert_eq!(lines(b"needle\nx\n", "needle", GrepMode::Literal), [l(1, "needle")]);
        assert_eq!(lines(b"x\ny\nneedle", "needle", GrepMode::Literal), [l(3, "needle")], "last line, no newline");
        assert_eq!(lines(b"a\r\nneedle\r\n", "needle", GrepMode::Literal), [l(2, "needle")], "CRLF trimmed");
        assert_eq!(lines(b"needle needle\nx\nneedle\n", "needle", GrepMode::Literal), [l(1, "needle needle"), l(3, "needle")], "one entry per line");
        assert_eq!(lines("é\nnaïve needle ✓\n".as_bytes(), "needle", GrepMode::Literal), [l(2, "naïve needle ✓")]);
        // A match that spans lines reports the line it starts on.
        assert_eq!(lines(b"x\nfoo\nbar\n", r"foo\nbar", GrepMode::Regex), [l(2, "foo")]);
        assert!(lines(b"", "needle", GrepMode::Literal).is_empty());
        assert!(lines(b"needle\0", "needle", GrepMode::Literal).is_empty(), "binary");
        let many: Vec<u8> = (0..10).flat_map(|_| b"needle\n".iter().copied()).collect();
        assert_eq!(lines(&many, "needle", GrepMode::Literal).len(), 5, "max_per_file");
        // Huge lines are cut to 400 bytes for display.
        let long = [vec![b'a'; 1000], b"needle".to_vec()].concat();
        let got = lines(&long, "a", GrepMode::Literal);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1.len(), 400);
    }

    #[test]
    fn regex_anchors_do_not_invent_a_line_past_the_end() {
        // Blank lines of "a\n\nb\n": only line 2. The empty match at EOF
        // (after the final newline) is not a line.
        assert_eq!(lines(b"a\n\nb\n", "^$", GrepMode::Regex), [l(2, "")]);
        assert_eq!(lines(b"a\nb\n", "^", GrepMode::Regex), [l(1, "a"), l(2, "b")]);
        assert_eq!(lines(b"a\nb", "$", GrepMode::Regex), [l(1, "a"), l(2, "b")]);
        assert!(lines(b"", "^", GrepMode::Regex).is_empty(), "an empty file has no lines");
    }

    #[test]
    fn regex_line_end_in_crlf_files() {
        assert_eq!(lines(b"let a = 1;\r\nlet b = 2\r\n", r";$", GrepMode::Regex), [l(1, "let a = 1;")]);
        assert_eq!(lines(b"x\r\nfoo\r\n", r"^foo$", GrepMode::Regex), [l(2, "foo")]);
    }

    #[test]
    fn regex_smart_case_ignores_escapes() {
        // `\S`, `\W`, `\D` are classes, not uppercase letters.
        assert_eq!(lines(b"x = HELLO\n", r"=\shello", GrepMode::Regex), [l(1, "x = HELLO")]);
        assert_eq!(lines(b"x = HELLO\n", r"\S\shello", GrepMode::Regex), [l(1, "x = HELLO")]);
        assert_eq!(lines(b"x = HELLO\n", r"(?P<Word>hello)", GrepMode::Regex), [l(1, "x = HELLO")]);
        // A real uppercase letter still makes it case-sensitive.
        assert!(lines(b"x = HELLO\n", r"\sHello", GrepMode::Regex).is_empty());
        assert!(lines(b"x = hello\n", r"[H]ello", GrepMode::Regex).is_empty());
        assert!(lines(b"x = hello\n", r"[A-Z]ello", GrepMode::Regex).is_empty());
    }

    #[test]
    fn case_insensitive_non_ascii_is_still_a_candidate() {
        let root = scratch("unicode-ci");
        let (c, _) = index(&root, &[("a.txt", "Bonjour ÉMILE\n".as_bytes()), ("b.txt", "straße\n".as_bytes())]);
        // The regex folds É/é; the index only folds ASCII, so the plan must
        // not demand trigrams of the non-ASCII bytes.
        assert_eq!(names(&c, "émile", GrepMode::Literal), ["a.txt"]);
        assert_eq!(names(&c, "émile", GrepMode::Regex), ["a.txt"]);
        assert_eq!(names(&c, "straße", GrepMode::Literal), ["b.txt"]);
        // Case-sensitive: exact bytes, full plan.
        assert_eq!(names(&c, "Émile", GrepMode::Literal), NONE_FOUND);
        assert_eq!(names(&c, "ÉMILE", GrepMode::Literal), ["a.txt"]);
        let _ = std::fs::remove_dir_all(root);
    }

    /// ASCII letters fold to non-ASCII too: `k` to the Kelvin sign (U+212A),
    /// `s` to the long s (U+017F). The regex matches them, so the plan must
    /// let those files through.
    #[test]
    fn case_insensitive_ascii_folds_to_non_ascii() {
        let root = scratch("kelvin");
        let (c, _) = index(&root, &[("k.txt", "\u{212A}ELVIN scale\n".as_bytes()), ("s.txt", "the \u{17F}un\n".as_bytes())]);
        assert_eq!(names(&c, "kelvin", GrepMode::Literal), ["k.txt"]);
        assert_eq!(names(&c, "kelvin", GrepMode::Regex), ["k.txt"]);
        assert_eq!(names(&c, "the sun", GrepMode::Literal), ["s.txt"]);
        // Still selective: folding doesn't fall back to reading every file.
        for (pat, mode) in
            [("hello world", GrepMode::Literal), ("kelvin", GrepMode::Literal), ("fn \\w+_main", GrepMode::Regex), ("émile", GrepMode::Literal)]
        {
            let plan = Grep::new(pat, mode).unwrap().plan();
            assert!(!matches!(plan, TQ::All), "{pat}: {plan:?}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn regex_search_through_the_index() {
        let root = scratch("regex");
        let (c, _) = index(
            &root,
            &[
                ("a.rs", b"fn parse_args() -> Result<()>\n"),
                ("b.rs", b"fn parse_file(p: &Path)\n"),
                ("c.rs", b"struct Config { verbose: bool }\n"),
                ("d.txt", b"color colour\nfoofoofoo\n"),
            ],
        );
        assert_eq!(names(&c, r"parse_(args|file)", GrepMode::Regex), ["a.rs", "b.rs"]);
        assert_eq!(names(&c, r"parse_\w+\(p", GrepMode::Regex), ["b.rs"]);
        assert_eq!(names(&c, r"colou?r", GrepMode::Regex), ["d.txt"]);
        assert_eq!(names(&c, r"(foo){3}", GrepMode::Regex), ["d.txt"]);
        assert_eq!(names(&c, r"verb[aeiou]se", GrepMode::Regex), ["c.rs"]);
        assert_eq!(names(&c, r"\bConfig\b", GrepMode::Regex), ["c.rs"]);
        assert_eq!(names(&c, r"(?:Res|Opt)ult<", GrepMode::Regex), ["a.rs"]);
        assert_eq!(names(&c, r"[^\x00-\x{10FFFF}]", GrepMode::Regex), NONE_FOUND);
        assert!(Grep::new("(unclosed", GrepMode::Regex).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn regex_plans() {
        let plan = |re: &str| regex_plan(&regex_syntax::Parser::new().parse(re).unwrap());
        let tri = |s: &[u8]| (fold(s[0]) as u32) << 16 | (fold(s[1]) as u32) << 8 | fold(s[2]) as u32;
        assert!(matches!(plan("ab"), TQ::All));
        assert!(matches!(plan("a*"), TQ::All));
        assert!(matches!(plan("."), TQ::All), "a big class has no exact set");
        assert!(matches!(plan(r"\d+x"), TQ::All));
        assert!(matches!(plan("abc|x"), TQ::All), "one branch too short: no constraint");
        let TQ::Or(v) = plan("^ABC$") else { panic!() };
        assert!(matches!(&v[..], [TQ::And(a)] if matches!(a[..], [TQ::Tri(t)] if t == tri(b"abc"))));
        // A small class multiplies out into exact strings.
        let TQ::Or(v) = plan("ab[cd]") else { panic!() };
        assert_eq!(v.len(), 2);
        // A long alternation stops being exact but keeps per-branch trigrams.
        let many: Vec<String> = (0..20).map(|i| format!("w{i:02}x")).collect();
        let TQ::Or(v) = plan(&many.join("|")) else { panic!() };
        assert_eq!(v.len(), 20);
        // Concat of something inexact and a literal keeps both constraints.
        assert!(matches!(plan(r"(abc)+.*xyz"), TQ::And(_)));
        assert!(!matches!(plan(r"(abc){2}"), TQ::All));
        assert!(matches!(plan(r"(?:abc|def)+"), TQ::Or(_)));
        assert!(matches!(plan(r"(?:abc){1}"), TQ::Or(_)));
        assert!(matches!(plan(r"(abc)+(def)+"), TQ::And(v) if v.len() == 2));
        assert!(matches!(plan(r"(?-u:[\x00-\x02])bcd"), TQ::Or(_)));
        // Exact set grows past MAX_EXACT in a concat: fall back to trigrams.
        assert!(!matches!(plan(r"[a-h][a-h]xyz[a-h]"), TQ::All));
        assert!(!matches!(plan(r"(?:aaa|bbb|ccc|ddd|eee)(?:fff|ggg|hhh|iii)"), TQ::All));

        // eval: And with only All children means every doc.
        let root = scratch("plans");
        let (c, _) = index(&root, &[("a.txt", b"abcdef\n"), ("b.txt", b"zzz\n")]);
        let s = &c.segs[0];
        assert_eq!(eval(s, &TQ::And(vec![TQ::All])), None);
        assert_eq!(eval(s, &TQ::Or(vec![TQ::All, TQ::Tri(tri(b"abc"))])), None);
        assert_eq!(eval(s, &TQ::And(vec![TQ::Tri(tri(b"qqq")), TQ::Tri(tri(b"abc"))])), Some(vec![]));
        assert_eq!(eval(s, &TQ::Or(vec![TQ::Tri(tri(b"zzz")), TQ::Tri(tri(b"abc"))])).unwrap().len(), 2);
        assert_eq!(intersect(&[1, 3, 5, 7], &[2, 3, 7, 9]), [3, 7]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn symbol_search() {
        let root = scratch("sym");
        let (c, _) = index(
            &root,
            &[
                ("def.rs", b"pub fn parse_args() {}\n"),
                ("use.rs", b"let a = parse_args();\n"),
                ("other.rs", b"fn parse_args_v2() {}\n"),
                ("swift.swift", b"static func main() {}\n"),
                ("T.java", b"class Parse_Args {}\n"),
            ],
        );
        assert_eq!(names(&c, "parse_args", GrepMode::Symbol), ["def.rs"]);
        assert_eq!(names(&c, "main", GrepMode::Symbol), ["swift.swift"]);
        assert_eq!(names(&c, "Parse_Args", GrepMode::Symbol), ["T.java"], "symbols are case-sensitive");
        // Not a plain identifier: falls back to a literal trigram plan.
        assert_eq!(names(&c, "parse_args_v2() {", GrepMode::Symbol), NONE_FOUND);
        assert_eq!(search(&c, "parse_args", GrepMode::Symbol)[0].1, [l(1, "pub fn parse_args() {}")]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn non_text_files_are_recorded_but_never_matched() {
        let root = scratch("binary");
        let mut big = b"needle\n".to_vec();
        big.resize(MAX_FILE as usize + 10, b'x');
        let (c, _) = index(&root, &[("bin.txt", b"needle\0\x01\x02"), ("big.txt", &big), ("ok.txt", b"needle\n")]);
        assert_eq!(c.docs(), 3, "kept so diffs know they were looked at");
        assert_eq!(names(&c, "needle", GrepMode::Literal), ["ok.txt"]);
        assert_eq!(c.search(&grep("ne", GrepMode::Literal), &q("")).candidates, 1, "not even as an every-doc candidate");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn name_filter_and_rank_order() {
        let root = scratch("filter");
        let (c, paths) = index(&root, &[("src/a.rs", b"needle\n"), ("src/b.md", b"needle\n"), (".hidden/c.rs", b"needle\n"), ("d.log", b"needle\n")]);
        let r = c.search(&grep("needle", GrepMode::Literal), &q("ext:rs"));
        let got: Vec<&[u8]> = r.files.iter().map(|f| f.path.as_slice()).collect();
        assert_eq!(got, [&paths[0][..], &paths[2][..]], "your files before dot-dirs");
        assert_eq!(r.candidates, 2);
        let r = c.search(&grep("needle", GrepMode::Literal), &q(&format!("in:{}", root.join("src").display())));
        assert_eq!(r.files.len(), 2);
        let mut lim = q("");
        lim.limit = 1;
        let r = c.search(&grep("needle", GrepMode::Literal), &lim);
        assert_eq!(r.files.len(), 1);
        assert!(r.complete);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn verify_limits_and_budget() {
        let root = scratch("verify");
        let paths: Vec<Vec<u8>> = (0..150).map(|i| put(&root, &format!("f{i:03}.txt"), b"hit\n")).collect();
        let mut g = grep("hit", GrepMode::Literal);
        let r = verify(&g, &paths, 1000);
        assert_eq!((r.files.len(), r.read, r.candidates, r.complete), (150, 150, 150, true));
        let r = verify(&g, &paths, 10);
        assert_eq!(r.files.len(), 10);
        assert!(r.complete && r.read < 150, "stops reading once the limit is met");
        g.budget = Some(Duration::ZERO);
        let r = verify(&g, &paths, 1000);
        // At most the first batch (a coarse clock may read 0 elapsed once).
        assert!(!r.complete && r.read <= 64);
        let r = verify(&g, &[] as &[Vec<u8>], 10);
        assert!(r.complete && r.files.is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn open_regular_refuses_everything_else() {
        let root = scratch("open");
        let f = put(&root, "f.txt", b"x");
        assert!(open_regular(&f).is_some());
        assert!(open_regular(root.as_os_str().as_bytes()).is_none(), "a directory");
        let link = root.join("link.txt");
        std::os::unix::fs::symlink(root.join("f.txt"), &link).unwrap();
        assert!(open_regular(link.as_os_str().as_bytes()).is_none(), "a symlink");
        let fifo = root.join("pipe.txt");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // Would hang forever without O_NONBLOCK (no writer).
        assert!(open_regular(fifo.as_os_str().as_bytes()).is_none(), "a FIFO");
        assert!(open_regular(b"/nonexistent/x").is_none());
        assert!(match_file(&grep("x", GrepMode::Literal), fifo.as_os_str().as_bytes()).is_none());
        // Build records the FIFO as not-text instead of blocking on it.
        let mut d = Docs::default();
        d.push(fifo.as_os_str().as_bytes(), 0, 0);
        d.push(&f, 1, 0);
        let seg = build_segment(&root, 1, &d, 0..2).unwrap();
        assert_eq!(seg.rank()[0], NOT_TEXT);
        assert_eq!(seg.rank()[1], 0);
        let _ = std::fs::remove_dir_all(root);
    }

    // ---- segments on disk ----

    #[test]
    fn segment_layout_round_trips() {
        let root = scratch("layout");
        // Enough docs sharing a trigram to take the bitset encoding, and a
        // rare one for varints.
        let mut files: Vec<(String, Vec<u8>)> = (0..40).map(|i| (format!("d{i:02}.txt"), format!("common {i}\n").into_bytes())).collect();
        files.push(("rare.txt".into(), b"zebra common\n".to_vec()));
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(a, b)| (a.as_str(), b.as_slice())).collect();
        let (c, paths) = index(&root, &refs);
        let s = &c.segs[0];
        assert_eq!(s.ndocs, 41);
        let com = trigrams_small(b"com")[0];
        let k = s.tri_key().binary_search(&com).unwrap();
        assert!(s.tri_off()[k] & BITSET != 0);
        assert_eq!(s.postings(com).len(), 41);
        let zeb = trigrams_small(b"zeb")[0];
        let k = s.tri_key().binary_search(&zeb).unwrap();
        assert!(s.tri_off()[k] & BITSET == 0);
        assert_eq!(s.postings(zeb).len(), 1);
        assert!(s.postings(trigrams_small(b"qqq")[0]).is_empty());
        let mut sorted = paths.clone();
        sorted.sort();
        let by: Vec<&[u8]> = s.by_path().iter().map(|&d| s.path(d)).collect();
        assert_eq!(by, sorted.iter().map(|p| p.as_slice()).collect::<Vec<_>>());
        assert_eq!(names(&c, "common", GrepMode::Literal).len(), 41);
        assert!(build_segment(&root, 9, &Docs::default(), 0..0).is_none(), "nothing to write");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn big_batch_uses_the_counting_sort() {
        let root = scratch("bigbatch");
        // Over 4M (trigram, doc) pairs: five ~1 MB files of NUL-free noise.
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut paths = Vec::new();
        for i in 0..5 {
            let mut body: Vec<u8> = (0..MAX_FILE as usize - 64)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (x % 255) as u8 + 1
                })
                .collect();
            body.extend_from_slice(format!("\nfn bigsym{i}() {{}}\nmarker{i}\n").as_bytes());
            paths.push(put(&root, &format!("n{i}.txt"), &body));
        }
        let mut c = Content::open(root.join("idx"));
        add(&mut c, &paths);
        assert_eq!(c.segs[0].ndocs, 5);
        assert!(c.segs[0].ntri > 1 << 20);
        assert_eq!(names(&c, "marker3", GrepMode::Literal), ["n3.txt"]);
        assert_eq!(names(&c, "bigsym2", GrepMode::Symbol), ["n2.txt"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_segments_fail_cleanly() {
        let root = scratch("corrupt");
        let (c, _) = index(&root, &[("a.txt", b"hello\n")]);
        let dir = c.dir.clone();
        let id = c.segs[0].id;
        drop(c);
        let good = std::fs::read(seg_path(&dir, id)).unwrap();
        assert!(Segment::load(&dir, id).is_some());

        let rejects = |b: &[u8]| {
            std::fs::write(seg_path(&dir, id), b).unwrap();
            Segment::load(&dir, id).is_none()
        };
        assert!(rejects(&good[..good.len() - 64]), "truncated");
        assert!(rejects(&good[..10]), "truncated header");
        assert!(rejects(b""), "empty");
        let mut bad = good.clone();
        bad[..8].copy_from_slice(b"FSCSEG02");
        assert!(rejects(&bad), "old magic");
        // Absurd header counts must not overflow or allocate their way in.
        for k in 0..4 {
            for v in [u64::MAX, u64::MAX / 4, 1 << 40] {
                let mut bad = good.clone();
                bad[8 + k * 8..16 + k * 8].copy_from_slice(&v.to_le_bytes());
                assert!(rejects(&bad), "field {k} = {v}");
            }
        }
        assert!(Segment::load(&dir, 999).is_none(), "missing");
        // A dead file with stray bits past ndocs doesn't underflow live_docs.
        std::fs::write(seg_path(&dir, id), &good).unwrap();
        std::fs::write(dead_path(&dir, id), u64::MAX.to_le_bytes()).unwrap();
        assert_eq!(Segment::load(&dir, id).unwrap().live_docs, 0);
        // A short dead file is ignored.
        std::fs::write(dead_path(&dir, id), [1u8; 3]).unwrap();
        assert_eq!(Segment::load(&dir, id).unwrap().live_docs, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn open_keeps_the_manifest_and_sweeps_garbage() {
        let root = scratch("open-manifest");
        let (mut c, _) = index(&root, &[("a.txt", b"alpha\n")]);
        add(&mut c, &[put(&root, "b.txt", b"beta\n")]);
        let dir = c.dir.clone();
        let ids: Vec<u64> = c.segs.iter().map(|s| s.id).collect();
        assert_eq!(ids, [1, 2]);
        drop(c);
        std::fs::write(dir.join("seg-000077.fsc"), b"junk").unwrap();
        std::fs::write(dir.join("seg-000001.tmp"), b"junk").unwrap();
        std::fs::write(dir.join("unrelated"), b"keep").unwrap();

        let shared = Content::open_shared(dir.clone());
        assert_eq!(shared.segs.len(), 2);
        assert!(dir.join("seg-000077.fsc").exists(), "a follower never deletes");
        let mut c = Content::open(dir.clone());
        assert!(!dir.join("seg-000077.fsc").exists());
        assert!(!dir.join("seg-000001.tmp").exists());
        assert!(dir.join("unrelated").exists());
        assert_eq!(c.alloc_id(), 3);
        assert_eq!(names(&c, "alpha", GrepMode::Literal), ["a.txt"]);
        assert_eq!(names(&c, "beta", GrepMode::Literal), ["b.txt"]);

        // No manifest: an empty index that starts ids at 1.
        let mut empty = Content::open(root.join("fresh"));
        assert!(empty.segs.is_empty());
        assert_eq!(empty.alloc_id(), 1);
        assert_eq!(empty.docs(), 0);
        let _ = std::fs::remove_dir_all(root);
    }

    // ---- sync ----

    fn want(dir: &[u8], recursive: bool, paths: &[Vec<u8>]) -> (Vec<u8>, bool, Docs) {
        (dir.to_vec(), recursive, docs_of(paths))
    }

    #[test]
    fn diff_tombstones_changes_and_persists() {
        let root = scratch("diff");
        let rb = root.as_os_str().as_bytes().to_vec();
        let (mut c, p) =
            index(&root, &[("a/one.txt", b"one\n"), ("a/two.txt", b"two\n"), ("a/sub/three.txt", b"three\n"), ("ab/four.txt", b"four\n")]);
        let a = join(&rb, b"a");
        // Unchanged: nothing to do.
        let todo = c.diff(vec![want(&a, true, &p[..3])]);
        assert_eq!(todo.len(), 0);
        assert_eq!(c.docs(), 4);

        // two.txt edited, three.txt deleted, five.txt new. "ab" is a sibling
        // with a shared prefix and must be left alone.
        std::fs::write(os(&p[1]), b"two two two\n").unwrap();
        std::fs::remove_file(os(&p[2])).unwrap();
        let five = put(&root, "a/five.txt", b"five\n");
        let todo = c.diff(vec![want(&a, true, &[p[0].clone(), p[1].clone(), five.clone()])]);
        let got: Vec<&[u8]> = (0..todo.len()).map(|i| todo.path(i)).collect();
        assert_eq!(got, [&five[..], &p[1][..]]);
        assert_eq!(c.docs(), 2);
        assert_eq!(names(&c, "three", GrepMode::Literal), NONE_FOUND);
        assert_eq!(names(&c, "four", GrepMode::Literal), ["four.txt"]);
        let id = c.alloc_id();
        c.push(build_segment(&c.dir, id, &todo, 0..todo.len()).unwrap());
        assert_eq!(names(&c, "two two", GrepMode::Literal), ["two.txt"]);
        assert_eq!(c.docs(), 4);

        // Tombstones survive a reopen.
        let dir = c.dir.clone();
        drop(c);
        let mut c = Content::open(dir);
        assert_eq!(c.docs(), 4);

        // Non-recursive: only direct children of "a" are in play, so a/sub/
        // and "ab" stay put.
        let six = put(&root, "a/sub/six.txt", b"six\n");
        add(&mut c, std::slice::from_ref(&six));
        let todo = c.diff(vec![want(&a, false, &[p[0].clone(), five.clone()])]);
        assert_eq!(todo.len(), 0);
        assert_eq!(c.docs(), 4, "two.txt gone; six.txt in a/sub untouched");
        assert_eq!(names(&c, "six", GrepMode::Literal), ["six.txt"]);
        assert_eq!(names(&c, "two", GrepMode::Literal), NONE_FOUND);

        // The whole dir gone (said twice: the second kill is a no-op).
        let todo = c.diff(vec![want(&a, true, &[]), want(&a, true, &[])]);
        assert_eq!(todo.len(), 0);
        assert_eq!(c.docs(), 1);
        assert_eq!(names(&c, "four", GrepMode::Literal), ["four.txt"]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn direct_children_skip_subtrees() {
        let root = scratch("children");
        let (c, _) = index(
            &root,
            &[
                ("d/a.txt", b"x"),
                ("d/sub.txt", b"x"),
                ("d/sub/b.txt", b"x"),
                ("d/sub/deep/c.txt", b"x"),
                ("d/sub0.txt", b"x"),
                ("d/z.txt", b"x"),
                ("d0.txt", b"x"),
            ],
        );
        let s = &c.segs[0];
        let d = join(root.as_os_str().as_bytes(), b"d/");
        let mut got: Vec<String> = s.direct_children(&d).iter().map(|&i| String::from_utf8_lossy(&s.path(i)[d.len()..]).into_owned()).collect();
        got.sort();
        assert_eq!(got, ["a.txt", "sub.txt", "sub0.txt", "z.txt"]);
        assert_eq!(s.with_prefix(&d).count(), 6);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn merge_drops_dead_docs() {
        let root = scratch("merge");
        let (mut c, p) = index(&root, &[("a.txt", b"apple common\n"), ("b.txt", b"banana common\n")]);
        let cd = [put(&root, "c.txt", b"cherry common\n"), put(&root, "d.txt", b"date common\n")];
        add(&mut c, &cd);
        let rb = root.as_os_str().as_bytes().to_vec();
        // Kill b.txt.
        c.diff(vec![want(&rb, false, &[p[0].clone(), cd[0].clone(), cd[1].clone()])]);
        assert_eq!(c.docs(), 3);
        let ids: Vec<u64> = c.segs.iter().map(|s| s.id).collect();
        let id = c.alloc_id();
        let m = merge(&c.dir, id, &c.segments(&ids)).unwrap();
        assert_eq!(m.ndocs, 3);
        c.replace(&ids, m);
        assert_eq!(c.segs.len(), 1);
        for id in &ids {
            assert!(!seg_path(&c.dir, *id).exists());
            assert!(!dead_path(&c.dir, *id).exists());
        }
        assert_eq!(names(&c, "common", GrepMode::Literal), ["a.txt", "c.txt", "d.txt"]);
        assert_eq!(names(&c, "cherry", GrepMode::Literal), ["c.txt"]);
        assert_eq!(names(&c, "banana", GrepMode::Literal), NONE_FOUND);
        let dir = c.dir.clone();
        drop(c);
        let mut c = Content::open(dir);
        assert_eq!(c.segs.len(), 1);
        assert_eq!(c.docs(), 3);

        // Everything dead: nothing to write.
        c.diff(vec![want(&rb, false, &[])]);
        assert!(merge(&c.dir, 50, &c.segments(&[id])).is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn merge_plan_groups_same_tier() {
        let root = scratch("plan");
        let mut c = Content::open(root.join("idx"));
        assert!(c.merge_plan().is_none());
        for i in 0..8 {
            add(&mut c, &[put(&root, &format!("f{i}.txt"), b"same size\n")]);
        }
        let plan = c.merge_plan().unwrap();
        assert_eq!(plan.len(), 8);
        assert_eq!(c.segments(&plan).len(), 8);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn changed_dirs_finds_edits_in_place() {
        let root = scratch("changed");
        let (mut c, p) = index(&root, &[("a/x.txt", b"x\n"), ("b/y.txt", b"y\n"), ("c/z.txt", b"z\n")]);
        let rb = root.as_os_str().as_bytes();
        let far = u32::MAX;
        assert!(c.changed_dirs(far).is_empty());
        assert_eq!(c.changed_dirs(0).len(), 3, "everything is newer than 0");
        std::fs::write(os(&p[0]), b"longer now\n").unwrap();
        std::fs::remove_file(os(&p[1])).unwrap();
        assert_eq!(c.changed_dirs(far), [join(rb, b"a"), join(rb, b"b")]);
        // Dead docs are not checked.
        c.diff(vec![want(&join(rb, b"b"), true, &[])]);
        assert_eq!(c.changed_dirs(far), [join(rb, b"a")]);
        let _ = std::fs::remove_dir_all(root);
    }

    // ---- name-index side ----

    /// A name index of these (path, size, mtime) files.
    fn live_of(files: &[(&str, u64, u32)]) -> Live {
        let mut dirs: BTreeMap<Vec<u8>, u32> = BTreeMap::from([(b"/".to_vec(), 0)]);
        type Ent = (Vec<u8>, u8, u64, u32, u32);
        let mut ents: BTreeMap<u32, Vec<Ent>> = BTreeMap::new();
        for &(path, size, mtime) in files {
            let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
            let mut cur = b"/".to_vec();
            for (k, comp) in comps.iter().enumerate() {
                let parent = dirs[&cur];
                let child = join(&cur, comp.as_bytes());
                if k + 1 == comps.len() {
                    ents.entry(parent).or_default().push((comp.as_bytes().to_vec(), KIND_FILE, size, mtime, NONE));
                } else if !dirs.contains_key(&child) {
                    let id = dirs.len() as u32;
                    dirs.insert(child.clone(), id);
                    ents.entry(parent).or_default().push((comp.as_bytes().to_vec(), KIND_DIR, 0, 0, id));
                }
                cur = child;
            }
        }
        let ls: Vec<Listing> = dirs
            .values()
            .map(|&id| {
                let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
                for (name, kind, size, mtime, child) in ents.remove(&id).unwrap_or_default() {
                    l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, size, mtime, child });
                    l.names.extend_from_slice(&name);
                }
                l
            })
            .collect();
        Live::new(Index::build(ls, 0, 0, b"/h"))
    }

    fn paths_of(d: &Docs) -> Vec<String> {
        let mut v: Vec<String> = (0..d.len()).map(|i| String::from_utf8_lossy(d.path(i)).into_owned()).collect();
        v.sort();
        v
    }

    #[test]
    fn wanted_reads_the_name_index() {
        let mut live = live_of(&[
            ("/h/p/a.rs", 10, 5),
            ("/h/p/img.png", 10, 5),
            ("/h/p/huge.txt", MAX_FILE + 1, 5),
            ("/h/p/sub/b.md", 10, 5),
            ("/h/p/node_modules/x/c.js", 10, 5),
            ("/h/pq/d.rs", 10, 5),
            ("/h/Library/e.txt", 10, 5),
            ("/other/f.rs", 10, 5),
        ]);
        let h = b"/h";
        assert_eq!(paths_of(&wanted(&live, h, b"/h/p", true)), ["/h/p/a.rs", "/h/p/sub/b.md"]);
        assert_eq!(paths_of(&wanted(&live, h, b"/h/p", false)), ["/h/p/a.rs"]);
        assert_eq!(wanted(&live, h, b"/other", true).len(), 0, "out of scope");
        assert_eq!(wanted(&live, h, b"/h/Library", true).len(), 0);
        assert_eq!(wanted(&live, h, b"/h/missing", true).len(), 0);
        // Overlay entries (added since the base was built).
        live.over.insert(b"/h/p/new.rs".to_vec(), OEnt::new(b"new.rs", KIND_FILE, 3, 9));
        live.over.insert(b"/h/p/sub/new2.rs".to_vec(), OEnt::new(b"new2.rs", KIND_FILE, 3, 9));
        live.over.insert(b"/h/p/newdir".to_vec(), OEnt::new(b"newdir", KIND_DIR, 0, 9));
        live.over.insert(b"/h/pq/new3.rs".to_vec(), OEnt::new(b"new3.rs", KIND_FILE, 3, 9));
        assert_eq!(paths_of(&wanted(&live, h, b"/h/p", false)), ["/h/p/a.rs", "/h/p/new.rs"]);
        assert_eq!(paths_of(&wanted(&live, h, b"/h/p", true)), ["/h/p/a.rs", "/h/p/new.rs", "/h/p/sub/b.md", "/h/p/sub/new2.rs"]);
    }

    /// Skip lists name folders: a file called `build` or `cache` (a script
    /// in a project root) is still indexed; files inside such folders aren't.
    #[test]
    fn a_file_named_like_a_skipped_folder_is_indexed() {
        assert!(eligible(b"/h/proj/build", 10, b"/h"));
        assert!(eligible(b"/h/proj/dist", 10, b"/h"));
        assert!(eligible(b"/h/cache", 10, b"/h"));
        assert!(!eligible(b"/h/proj/build/out.rs", 10, b"/h"));
        assert!(!eligible(b"/h/node_modules/x/index.js", 10, b"/h"));
    }

    /// Home written with a trailing slash still holds its files, and a
    /// name prefix of home is not inside it.
    #[test]
    fn in_scope_takes_home_with_a_trailing_slash() {
        assert!(in_scope(b"/h/a.rs", b"/h/"));
        assert!(in_scope(b"/h/p/a.rs", b"/h/"));
        assert!(in_scope(b"/h/a.rs", b"/h"));
        assert!(!in_scope(b"/hx/a.rs", b"/h"));
        assert!(!in_scope(b"/hx/a.rs", b"/h/"));
    }

    #[test]
    fn content_follows_home_and_its_ancestors() {
        let home = b"/Users/me";
        assert!(follows(b"/Users/me/src", false, home));
        assert!(follows(b"/Users", true, home));
        assert!(follows(b"/", true, home));
        assert!(!follows(b"/Users", false, home));
        // Not an ancestor, just a name prefix.
        assert!(!follows(b"/Users/m", true, home));
    }

    #[test]
    fn wants_maps_changes_to_synced_dirs() {
        let live = live_of(&[("/h/p/a.rs", 10, 5), ("/h/q/b.rs", 10, 5), ("/hx/c.rs", 10, 5)]);
        let h = b"/h";
        let keys =
            |w: &[(Vec<u8>, bool, Docs)]| w.iter().map(|(d, r, docs)| (String::from_utf8_lossy(d).into_owned(), *r, docs.len())).collect::<Vec<_>>();
        let w = wants(&live, h, &[b"/h/p".to_vec(), b"/h/p".to_vec(), b"/hx".to_vec()], &[b"/h/q".to_vec()]);
        assert_eq!(keys(&w), [("/h/p".into(), false, 1), ("/h/q".into(), true, 1)]);
        // A rescanned ancestor of home means all of home.
        assert_eq!(keys(&wants(&live, h, &[], &[b"/".to_vec()])), [("/h".into(), true, 2)]);
        // A sibling whose name merely starts like home's is not an ancestor.
        assert!(wants(&live, h, &[], &[b"/hx".to_vec()]).is_empty());
        assert!(wants(&live, b"/Users/me", &[], &[b"/Users/m".to_vec()]).is_empty());
        assert_eq!(keys(&wants(&live, b"/Users/me", &[], &[b"/Users".to_vec()])), [("/Users/me".into(), true, 0)]);
    }

    #[test]
    fn scan_paths_newest_first() {
        let mut live = live_of(&[("/etc/a.conf", 10, 5), ("/etc/b.conf", 10, 50), ("/etc/big.conf", MAX_FILE + 1, 99), ("/etc/sub/x", 1, 1)]);
        live.over.insert(b"/etc/c.conf".to_vec(), OEnt::new(b"c.conf", KIND_FILE, 3, 20));
        let mut sq = q("ext:conf");
        sq.scope = Some(b"/etc".to_vec());
        let got: Vec<String> = scan_paths(&live, sq).into_iter().map(|p| String::from_utf8(p).unwrap()).collect();
        assert_eq!(got, ["/etc/b.conf", "/etc/c.conf", "/etc/a.conf"]);
    }
}
