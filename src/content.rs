//! Content search: a trigram index over the user's text files.
//!
//! Segments are immutable, mmap'd files: a doc table, and the contents first
//! indexed there: per trigram, the ids of the contents holding it (a bitset
//! or interpolative code), and per content a bloom filter of its 5-byte
//! substrings. Each distinct file content is indexed once (most copies are
//! git worktrees): every doc names its content by a gid, and a copy indexed
//! later, even in another segment, just names the same gid. A query becomes
//! an AND/OR of trigrams, the posting lists pick candidate contents, those
//! become the docs holding them, the bloom filter drops most of those that
//! only contain the pattern's trigrams scattered about, and the rest are read
//! fresh from disk and matched for real. Results therefore never show stale
//! content; only candidate selection can trail a file written in the last
//! couple of seconds.
//!
//! The index is kept in sync by diffing, exactly like the name index: for a
//! directory (or subtree), compare the eligible files the live name index
//! knows about with the docs we hold, reindex what changed, tombstone what
//! went away. The first build is just a sync of $HOME.

use crate::index::{HDR, as_bytes, fields, header, layout, sec};
use crate::live::{Live, join};
use crate::query::{GrepMode, Query, fold};
use crate::walk::{KIND_DIR, KIND_FILE};
use memmap2::Mmap;
use rayon::prelude::*;
use regex::bytes::{Regex, RegexBuilder};
use regex_syntax::hir::{Class, Hir, HirKind};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Largest file indexed outside git repos.
pub const MAX_FILE: u64 = 1 << 20;
/// Largest file indexed in a git repo, and grepped anywhere (fff's limit
/// too, as `rg --max-filesize 10M`).
pub const MAX_REPO_FILE: u64 = 10 << 20;
/// File bytes per segment build; bounds the build's transient memory.
const SEG_BYTES: u64 = 64 << 20;
/// Largest merge, in posting bytes; bounds the merge's transient memory.
const MERGE_CAP: usize = 96 << 20;
/// The bytes of deleted and replaced files stay under 1/DEAD of the index
/// (see `Content::merge_plan`).
const DEAD: usize = 16;
const MAGIC: &[u8; 8] = b"FSCSEG16";
/// Docs per front-coded group of paths (see `Segment::path_off`).
const PATHS: usize = 16;
/// A list's offset flag while built: it is a bitset over the segment's
/// contents (kept once more than 1 in 8 contain it: ANDs of common
/// trigrams stay a word at a time).
const BITSET: u32 = 1 << 31;
/// The next flag: this interpolative list has more than BLOCK contents, so
/// a count and a skip table (see `Postings::push`).
const SKIPS: u32 = 1 << 30;
const FLAGS: u32 = BITSET | SKIPS;
/// Posting lists per dictionary block (see `Segment::dict`).
const DICT: usize = 32;
/// The gid of a doc that is not text, or a doc no content holds.
const NONE: u32 = u32::MAX;

/// Directory names whose subtrees are generated, vendored, or caches.
#[rustfmt::skip]
const SKIP_DIRS: &[&[u8]] = &[
    b"node_modules", b".git", b"DerivedData", b"__pycache__", b".venv", b"venv", b"site-packages", b"Pods", b".next",
    b".turbo", b".cache", b"Library", b".build", b".rustup", b".cargo", b".npm", b".bun", b".nvm", b"vendor",
    b".pnpm-store", b"coverage", b".Trash", b".svn", b".hg", b".gradle", b".m2", b".pyenv", b".rbenv", b".gem", b".conda",
    b"miniconda3", b"anaconda3", b".docker", b".orbstack", b".colima", b".lima", b".ollama", b".android", b".expo",
    b".terraform.d", b".wrangler", b".vscode-server",
];

/// Names that are build output or caches only when the folder says so, by
/// holding a marker (Linux's drivers/target is source): the Cache Directory
/// Tagging standard's file (Cargo's target/), CMake's and Ninja's.
const MARKED_DIRS: &[&[u8]] = &[b"target", b"build", b"dist", b"cache", b"Cache", b"caches", b"Caches"];
const MARKERS: &[&[u8]] = &[b"CACHEDIR.TAG", b"CMakeCache.txt", b"build.ninja"];

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

/// Extensions fff takes for binary without reading the file; in a repo the
/// rest are read, and kept as text as `is_text` decides.
#[rustfmt::skip]
const BINARY_EXTS: &[&[u8]] = &[
    b"png", b"jpg", b"jpeg", b"gif", b"bmp", b"ico", b"webp", b"tiff", b"tif", b"avif", b"heic", b"heif", b"jxl", b"jp2", b"j2k",
    b"psd", b"icns", b"cur", b"cr2", b"nef", b"dng", b"tga", b"rgbe", b"hdr", b"exr", b"dds", b"ktx", b"ktx2", b"pvr", b"astc", b"ai",
    b"webarchive", b"mhtml", b"mp4", b"avi", b"mov", b"wmv", b"mkv", b"mp3", b"wav", b"flac", b"ogg", b"m4a", b"aac", b"webm", b"flv",
    b"mpg", b"mpeg", b"wma", b"opus", b"pcm", b"reapeaks", b"zip", b"tar", b"gz", b"bz2", b"xz", b"7z", b"rar", b"zst", b"lz4", b"lzma",
    b"cab", b"cpio", b"jsonlz4", b"deb", b"rpm", b"apk", b"dmg", b"msi", b"iso", b"nupkg", b"whl", b"egg", b"appimage", b"flatpak",
    b"crx", b"pak", b"exe", b"dll", b"so", b"dylib", b"o", b"a", b"lib", b"bin", b"elf", b"pdf", b"doc", b"docx", b"xls", b"xlsx",
    b"ppt", b"pptx", b"db", b"sqlite", b"sqlite3", b"mdb", b"sqlite-wal", b"sqlite-shm", b"sqlite3-wal", b"sqlite3-shm", b"db-wal",
    b"db-shm", b"ldb", b"ttf", b"otf", b"woff", b"woff2", b"eot", b"class", b"pyc", b"pyo", b"wasm", b"dex", b"jar", b"war", b"cmi",
    b"cmt", b"cmti", b"cmx", b"nib", b"swiftdeps", b"swiftdeps~", b"swiftdoc", b"swiftmodule", b"swiftsourceinfo", b"npy", b"npz",
    b"h5", b"hdf5", b"pt", b"onnx", b"safetensors", b"tfrecord", b"tflite", b"gguf", b"ggml", b"joblib", b"glb", b"blend", b"blp",
    b"dia", b"bcmap", b"pb", b"parquet", b"arrow", b"suo",
];

/// Outside git repos, the extensions of text files.
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
    ngroups: usize,
    ntri: usize,
    nblk: usize,
    dict_len: usize,
    plen: usize,
    paths_len: usize,
    nwords: usize,
    /// Contents first indexed here (its own).
    nown: usize,
    nown1: usize,
    off: [usize; NS],
    dead: Vec<u64>,
    pub live_docs: usize,
    /// Per own content, the live docs (in any segment) holding it; kept by
    /// `Content` (see `link`).
    refs: Counts,
    /// Own contents as runs of consecutive gids: (first content, first gid, length).
    runs: Vec<(u32, u32, u32)>,
    /// The first and last path in path order, decoded once: every scoped
    /// search checks them (see `prefix_run`).
    ends: [Vec<u8>; 2],
}

#[derive(Clone, Copy)]
enum S {
    DictIdx,
    Dict,
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
fn lens(ndocs: usize, ntri: usize, plen: usize, paths_len: usize, nwords: usize, nown: usize, dict_len: usize) -> [usize; NS] {
    let (d, c) = (ndocs * 4, nown * 4);
    [ntri.div_ceil(DICT) * 12, dict_len, plen, ndocs.div_ceil(PATHS) * 4, paths_len, d, d, d, ndocs, d, d, d, d, d, c, c, c * 2, c, c + 4, nwords * 8]
}

impl Segment {
    // The posting lists' keys (trigrams, then definition keys), in blocks of
    // DICT: per block, its first key and where its entries and lists start;
    // per list, a varint key delta (0 for a block's first) and a varint
    // byte length << 2 | 1 if a bitset | 2 if an interpolative list with a
    // skip table.
    sec!(dict_idx, S::DictIdx, [u32; 3], nblk);
    sec!(dict, S::Dict, u8, dict_len);
    sec!(post, S::Post, u8, plen);
    // Per doc: its path, front-coded in groups of PATHS docs (per doc, a
    // varint of the bytes it shares with the previous doc's path, 0 for a
    // group's first, a varint of the rest's length, and the rest; and where
    // each group starts), size, mtime; the docs in path order.
    sec!(path_off, S::PathOff, u32, ngroups);
    sec!(paths, S::Paths, u8, paths_len);
    sec!(size, S::Size, u32, ndocs);
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
    // hash of its bytes, and a bloom filter of its SHORT-byte substrings.
    // And the contents in hash order.
    sec!(own_gid, S::OwnGid, u32, nown);
    sec!(own_doc, S::OwnDoc, u32, nown);
    sec!(hash, S::Hash, u64, nown);
    sec!(by_hash, S::ByHash, u32, nown);
    sec!(bloom_off, S::BloomOff, u32, nown1);
    sec!(bloom, S::Bloom, u64, nwords);

    /// Doc `d`'s path: its group's paths decoded up to it.
    pub fn path(&self, d: u32) -> Vec<u8> {
        let (g, k) = (d as usize / PATHS, d as usize % PATHS);
        let mut r = PathReader { b: &self.paths()[self.path_off()[g] as usize..], ..Default::default() };
        r.skip(k + 1);
        r.path
    }

    /// Every doc's path in doc order, in one pass.
    fn all_paths(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
        let mut r = PathReader { b: self.paths(), ..Default::default() };
        (0..self.ndocs).map(move |_| {
            r.skip(1);
            r.path.clone()
        })
    }

    fn bloom_of(&self, c: u32) -> &[u64] {
        let o = self.bloom_off();
        &self.bloom()[o[c as usize] as usize..o[c as usize + 1] as usize]
    }

    fn hash_of(&self, c: u32) -> u64 {
        self.hash()[c as usize]
    }

    /// Can own content `c` hold every gram in `probes`, by its bloom filter?
    fn may_contain(&self, c: u32, probes: &Probes) -> bool {
        let words = self.bloom_of(c);
        probes.short.iter().all(|&h| bloom_bits(h, words.len()).iter().all(|&b| words.get(b / 64).is_some_and(|w| w >> (b % 64) & 1 != 0)))
    }

    /// Own contents a live doc still holds.
    fn live_own(&self) -> usize {
        self.refs.live()
    }

    /// About the bytes a rewrite would drop: dead docs' rows, and the own
    /// contents no live doc holds (their blooms, and about as much again in
    /// postings).
    pub fn dead_bytes(&self) -> usize {
        let (o, mut bytes) = (self.bloom_off(), (self.ndocs - self.live_docs) * (41 + self.paths_len / self.ndocs.max(1)));
        for w in 0..self.nown.div_ceil(64) {
            let mut z = !self.refs.held(w) & u64::MAX >> (64 - (self.nown - 64 * w).min(64));
            while z != 0 {
                let c = 64 * w + z.trailing_zeros() as usize;
                bytes += (o[c + 1] - o[c]) as usize * 16 + 36;
                z &= z - 1;
            }
        }
        bytes
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
    fn with_prefix(&self, prefix: &[u8]) -> impl Iterator<Item = u32> + '_ {
        self.live_at(self.prefix_run(prefix))
    }

    /// The live docs at `run` in path order.
    fn live_at(&self, run: std::ops::Range<usize>) -> impl Iterator<Item = u32> + '_ {
        self.by_path()[run].iter().copied().filter(|&d| !self.is_dead(d))
    }

    /// Where the paths starting with `prefix` lie in path order (positions
    /// in `by_path`): the first and last path settle most segments, else two
    /// binary searches (each probe read into one buffer).
    fn prefix_run(&self, prefix: &[u8]) -> std::ops::Range<usize> {
        let (bp, [first, last]) = (self.by_path(), &self.ends);
        if bp.is_empty() || last.as_slice() < prefix || (first.as_slice() > prefix && !first.starts_with(prefix)) {
            return 0..0;
        }
        if first.starts_with(prefix) && last.starts_with(prefix) {
            return 0..bp.len();
        }
        let mut paths = PathCursor::default();
        let a = bp.partition_point(|&d| paths.get(self, d) < prefix);
        a..a + bp[a..].partition_point(|&d| paths.get(self, d).starts_with(prefix))
    }

    /// Live docs directly inside `prefix` (which ends in '/'), skipping each
    /// subdirectory's run of paths with one binary search.
    fn direct_children(&self, prefix: &[u8]) -> Vec<u32> {
        let bp = self.by_path();
        let mut out = Vec::new();
        let mut i = bp.partition_point(|&d| self.path(d).as_slice() < prefix);
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
                    i += bp[i..].partition_point(|&d| self.path(d) < hi);
                }
            }
        }
        out
    }

    /// The posting list of key `tri`, if any doc here has it: a search of
    /// the blocks' first keys, then a scan of one block's entries (every
    /// query does this per trigram and segment).
    fn list(&self, tri: u32) -> Option<List<'_>> {
        let (idx, dict) = (self.dict_idx(), self.dict());
        let b = idx.partition_point(|e| e[0] <= tri).checked_sub(1)?;
        let [mut key, at, p] = idx[b];
        let (mut at, mut p) = (at as usize, p as usize);
        for _ in b * DICT..((b + 1) * DICT).min(self.ntri) {
            let (d, n) = varint(&dict[at..]);
            let (f, m) = varint(&dict[at + n..]);
            (key, at) = (key + d, at + n + m);
            if key >= tri {
                return (key == tri).then(|| self.list_of(f & 3, &self.post()[p..p + (f >> 2) as usize]));
            }
            p += (f >> 2) as usize;
        }
        None
    }

    /// The posting lists from dictionary block `b` on, by key: (key, list).
    fn lists_from(&self, b: usize) -> impl Iterator<Item = (u32, List<'_>)> + '_ {
        self.entries_from(b).map(|(k, f, bytes)| (k, self.list_of(f, bytes)))
    }

    /// The dictionary entries from block `b` on: (key, flags, list bytes).
    fn entries_from(&self, b: usize) -> impl Iterator<Item = (u32, u32, &[u8])> + '_ {
        let (idx, dict, post) = (self.dict_idx(), self.dict(), self.post());
        let (mut key, mut at, mut p) = (0, 0, 0);
        (b * DICT..self.ntri).map(move |i| {
            if i % DICT == 0 {
                let [k, a, q] = idx[i / DICT];
                (key, at, p) = (k, a as usize, q as usize);
            }
            let (d, n) = varint(&dict[at..]);
            let (f, m) = varint(&dict[at + n..]);
            at += n + m;
            key += d;
            let bytes = &post[p..p + (f >> 2) as usize];
            p += bytes.len();
            (key, f & 3, bytes)
        })
    }

    fn list_of<'a>(&self, f: u32, bytes: &'a [u8]) -> List<'a> {
        if f & 1 != 0 { List::Bits(bytes) } else { List::Ic(Ic::new(bytes, f & 2 != 0, self.nown as u32)) }
    }

    /// The dictionary block holding the first key at or past `key`'s.
    fn block_of(&self, key: u64) -> usize {
        self.dict_idx().partition_point(|e| (e[0] as u64) <= key).saturating_sub(1)
    }

    /// The doc id range holding the docs at `run` in path order (see
    /// `prefix_run`); all of the segment when they are most of it. True if
    /// it holds no other doc, as for a segment built from sorted paths (after
    /// a merge it is a superset).
    fn doc_range(&self, run: std::ops::Range<usize>) -> (std::ops::Range<u32>, bool) {
        let n = run.len();
        if n * 2 > self.ndocs {
            return (0..self.ndocs as u32, n == self.ndocs);
        }
        let (lo, hi) = self.by_path()[run].iter().fold((u32::MAX, 0), |(lo, hi), &d| (lo.min(d), hi.max(d + 1)));
        (lo.min(hi)..hi, (hi - lo.min(hi)) as usize == n)
    }

    fn load(dir: &Path, id: u64) -> Option<Segment> {
        let f = std::fs::File::open(seg_path(dir, id)).ok()?;
        let map = std::sync::Arc::new(unsafe { Mmap::map(&f) }.ok()?);
        let [ndocs, ntri, plen, paths_len, nwords, nown, dict_len] = fields(&map, MAGIC)?.map(|v| v as usize);
        let (off, total) = layout(&lens(ndocs, ntri, plen, paths_len, nwords, nown, dict_len));
        if map.len() < total {
            return None;
        }
        let mut dead = vec![0u64; ndocs.div_ceil(64)];
        if let Ok(b) = std::fs::read(dead_path(dir, id)) {
            for (w, c) in dead.iter_mut().zip(b.as_chunks::<8>().0) {
                *w = u64::from_le_bytes(*c);
            }
            // (Bits past the last doc: a corrupt file.)
            if let Some(w) = dead.last_mut().filter(|_| !ndocs.is_multiple_of(64)) {
                *w &= (1 << (ndocs % 64)) - 1;
            }
        }
        let live_docs = ndocs - dead.iter().map(|w| w.count_ones() as usize).sum::<usize>();
        #[rustfmt::skip]
        let mut s = Segment {
            map, id, ndocs, ngroups: ndocs.div_ceil(PATHS), ntri, nblk: ntri.div_ceil(DICT), dict_len, plen, paths_len, nwords, nown, nown1: nown + 1,
            off, dead, live_docs, refs: Counts::new(nown), runs: Vec::new(), ends: Default::default(),
        };
        let mut runs: Vec<(u32, u32, u32)> = Vec::new();
        for (c, &g) in s.own_gid().iter().enumerate() {
            match runs.last_mut() {
                Some((_, g0, n)) if *g0 + *n == g => *n += 1,
                _ => runs.push((c as u32, g, 1)),
            }
        }
        s.runs = runs;
        let bp = s.by_path();
        s.ends = match (bp.first(), bp.last()) {
            (Some(&a), Some(&b)) => [s.path(a), s.path(b)],
            _ => Default::default(),
        };
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

/// Front-coded paths from a group's start on (see `Segment::path_off`).
#[derive(Default)]
struct PathReader<'a> {
    b: &'a [u8],
    path: Vec<u8>,
    /// Entries read past the one `path` holds, not applied yet: the bytes
    /// each shares with the path before it, and the rest. (A group's first
    /// shares none, which drops those before it: a group's worth at most.)
    ents: [(usize, &'a [u8]); PATHS],
    n: usize,
}

impl<'a> PathReader<'a> {
    /// Read the next entry, to apply later; the bytes it adds.
    fn read(&mut self) -> &'a [u8] {
        let (shared, k) = varint(self.b);
        let (len, m) = varint(&self.b[k..]);
        let rest = &self.b[k + m..][..len as usize];
        self.b = &self.b[k + m + len as usize..];
        if shared == 0 {
            self.n = 0;
        }
        self.ents[self.n] = (shared as usize, rest);
        self.n += 1;
        rest
    }

    /// `path` becomes the last entry read's: each byte copied once, from the
    /// last entry holding it; the bytes before them stay as they are.
    fn build(&mut self) {
        let Some(&(s, rest)) = self.ents[..self.n].last() else { return };
        let (mut parts, mut k, mut end) = ([&[][..]; PATHS], 0, s + rest.len());
        for &(s, rest) in self.ents[..self.n].iter().rev() {
            if s < end {
                (parts[k], k, end) = (&rest[..end - s], k + 1, s);
            }
        }
        self.path.truncate(end);
        for p in parts[..k].iter().rev() {
            self.path.extend_from_slice(p);
        }
        self.n = 0;
    }

    /// On `n` paths (1 to PATHS): the entries in between are only parsed.
    fn skip(&mut self, n: usize) {
        for _ in 0..n {
            self.read();
        }
        self.build();
    }
}

/// Paths of docs asked for in ascending order within a segment: each read
/// on from the last (groups follow each other), not from its group's start,
/// into one buffer.
#[derive(Default)]
struct PathCursor<'a> {
    s: Option<&'a Segment>,
    r: PathReader<'a>,
    /// The doc after the one `r.path` holds.
    next: usize,
}

impl<'a> PathCursor<'a> {
    fn get(&mut self, s: &'a Segment, d: u32) -> &[u8] {
        self.read_to(s, d);
        self.r.build();
        &self.r.path
    }

    /// Doc `d`'s path, unless `keep` turns down the end of it its entry
    /// holds (the bytes past those it shares with the path before): then
    /// None, without building it.
    fn get_if(&mut self, s: &'a Segment, d: u32, keep: impl FnOnce(&[u8]) -> bool) -> Option<&[u8]> {
        let end = self.read_to(s, d);
        if !keep(end) {
            return None;
        }
        self.r.build();
        Some(&self.r.path)
    }

    /// Read on to doc `d`'s entry; the bytes it adds (none if read before).
    fn read_to(&mut self, s: &'a Segment, d: u32) -> &'a [u8] {
        let d = d as usize;
        // Another segment, behind, or a group or more ahead: from the start
        // of d's group.
        if !self.s.is_some_and(|x| std::ptr::eq(x, s)) || d + 1 < self.next || d >= self.next + PATHS {
            (self.s, self.r.b, self.r.n, self.next) = (Some(s), &s.paths()[s.path_off()[d / PATHS] as usize..], 0, d / PATHS * PATHS);
        }
        let mut end = &[][..];
        while self.next <= d {
            end = self.r.read();
            self.next += 1;
        }
        end
    }
}

/// A 64-bit hash of a file's bytes: files with the same hash are taken to
/// hold the same bytes (a million distinct files hold a collision about
/// once in 37 million indexes). Four multiply-fold lanes, 32 bytes a step.
fn content_hash(b: &[u8]) -> u64 {
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
    let (blocks, rem) = b.as_chunks::<32>();
    for w in blocks {
        step(w);
    }
    let mut last = [0u8; 32];
    last[..rem.len()].copy_from_slice(rem);
    step(&last);
    mix(mix(s[0] ^ K[1], s[2] ^ K[2]) ^ s[1], s[3] ^ K[0])
}

/// A file's distinct trigrams and its end-of-file key into `tri`, and the
/// distinct hashes of its SHORT-byte grams into `short` (both cleared,
/// unordered). One pass, with no branch on whether a gram is new. `seen` is
/// two 2 MiB bitsets, all zero on entry and exit.
fn index_grams(buf: &[u8], seen: &mut [u64], tri: &mut Vec<u32>, short: &mut Vec<u32>) {
    tri.clear();
    short.clear();
    let n = buf.len();
    if n < 2 {
        return;
    }
    let (st, ss) = seen.split_at_mut(1 << 18);
    // Its last two bytes and a 0: so a two-byte search finds them too.
    let eof = (fold(buf[n - 2]) as u32) << 16 | (fold(buf[n - 1]) as u32) << 8;
    st[(eof >> 6) as usize] |= 1 << (eof & 63);
    tri.push(eof);
    let (mut nt, mut ns) = (1, 0);
    // A gram's hash into `out` at `k`, which moves past it if it is whole
    // and new.
    let add = |seen: &mut [u64], out: &mut [u32], k: &mut usize, h: u32, whole: bool| {
        let (w, bit) = ((h >> 6) as usize, 1u64 << (h & 63));
        out[*k] = h;
        *k += (whole & (seen[w] & bit == 0)) as usize;
        seen[w] |= bit & 0u64.wrapping_sub(whole as u64);
    };
    let mut g = (fold(buf[0]) as u64) << 8 | fold(buf[1]) as u64;
    // A chunk at a time, with room for each of its grams to be new: the
    // arrays grow with a big file's distinct grams, not with its size.
    const CHUNK: usize = 1 << 20;
    for (c, part) in buf[2..].chunks(CHUNK).enumerate() {
        tri.resize(nt + part.len(), 0);
        short.resize(ns + part.len(), 0);
        for (j, &b) in part.iter().enumerate() {
            let i = 2 + c * CHUNK + j;
            g = g << 8 | fold(b) as u64;
            add(st, tri, &mut nt, (g & 0xFF_FFFF) as u32, true);
            add(ss, short, &mut ns, gram_hash(g & ((1 << (8 * SHORT)) - 1)), i + 1 >= SHORT);
        }
    }
    tri.truncate(nt);
    short.truncate(ns);
    for (seen, out) in [(st, &*tri), (ss, &*short)] {
        for &h in out {
            seen[(h >> 6) as usize] = 0;
        }
    }
}

/// Trigrams of a short string (query side), no scratch needed.
fn trigrams_small(s: &[u8]) -> Vec<u32> {
    let mut t: Vec<u32> = s.windows(3).map(|w| (fold(w[0]) as u32) << 16 | (fold(w[1]) as u32) << 8 | fold(w[2]) as u32).collect();
    t.sort_unstable();
    t.dedup();
    t
}

/// The bloom filter holds a content's case-folded substrings of this length:
/// a match holds all of its pattern's grams, so a content missing one of them
/// can't match even if it has every trigram. A second filter, of 7-byte
/// grams, read 0.66x the files on rare greps (0.82x their time) but took 30%
/// of the index (0.87 bits per content byte).
const SHORT: usize = 5;

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
/// of them, and one allocation beats 500k (see `Paths` for big ones).
#[derive(Default)]
pub struct Docs {
    buf: Paths,
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
    built: std::sync::Mutex<HashMap<u64, u32>>,
    free: std::sync::Mutex<Gids>,
}

/// A segment's own contents, findable by hash while a sync builds.
struct Held {
    map: std::sync::Arc<Mmap>,
    nown: usize,
    off: [usize; NS],
}

impl Held {
    fn find(&self, h: u64) -> Option<u32> {
        let at = |s: S, k: usize| unsafe { (self.map.as_ptr().add(self.off[s as usize]) as *const u32).add(k).read() };
        let hash = |c: u32| unsafe { (self.map.as_ptr().add(self.off[S::Hash as usize]) as *const u64).add(c as usize).read() };
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
    fn find(&self, h: u64) -> Option<u32> {
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

/// A want list's path bytes. A big one has pages of its own, handed back
/// when it goes: macOS malloc keeps a freed big buffer in the process's
/// footprint.
enum Paths {
    Heap(Vec<u8>),
    Mapped(memmap2::MmapMut, usize),
}

impl Default for Paths {
    fn default() -> Paths {
        Paths::Heap(Vec::new())
    }
}

impl Paths {
    /// Room for exactly `n` bytes.
    fn exactly(n: usize) -> Paths {
        let map = (n >= 1 << 20).then(|| memmap2::MmapMut::map_anon(n).ok()).flatten();
        map.map_or_else(|| Paths::Heap(Vec::with_capacity(n)), |m| Paths::Mapped(m, 0))
    }

    fn push(&mut self, b: &[u8]) {
        match self {
            Paths::Heap(v) => v.extend_from_slice(b),
            Paths::Mapped(m, n) => {
                m[*n..*n + b.len()].copy_from_slice(b);
                *n += b.len();
            }
        }
    }
}

impl std::ops::Deref for Paths {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Paths::Heap(v) => v,
            Paths::Mapped(m, n) => &m[..*n],
        }
    }
}

impl Docs {
    fn push(&mut self, path: &[u8], size: u64, mtime: u32) {
        self.items.push((self.buf.len() as u32, path.len() as u32, size, mtime));
        self.buf.push(path);
    }
    pub fn path(&self, i: usize) -> &[u8] {
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
    path: std::borrow::Cow<'a, [u8]>,
    size: u64,
    mtime: u32,
    rank: i8,
    gid: u32,
}

/// One of the contents a segment being written owns.
struct ContentMeta<'a> {
    gid: u32,
    hash: u64,
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
    hash: u64,
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
    // overlap the work on earlier files. A read buffer and two 2 MiB
    // seen-sets go back to a pool after each run, so a build holds one per
    // thread.
    const RUN: usize = 256;
    const AHEAD: usize = 8;
    let dedup = docs.dedup.get_or_init(Dedup::default);
    // Contents new in this build, by hash, numbered as first seen.
    let new = std::sync::Mutex::new(HashMap::<u64, u32>::new());
    let scratch = std::sync::Mutex::new(Vec::new());
    // (A run also ends after RUN_BYTES of files, so big files don't keep
    // one thread busy while the others wait.)
    const RUN_BYTES: u64 = 4 << 20;
    let mut runs: Vec<std::ops::Range<usize>> = Vec::new();
    let (mut start, mut bytes) = (range.start, 0);
    for i in range.clone() {
        if i - start == RUN || bytes >= RUN_BYTES {
            runs.push(start..i);
            (start, bytes) = (i, 0);
        }
        bytes += docs.items[i].2;
    }
    if start < range.end {
        runs.push(start..range.end);
    }
    let splits: Vec<Split> = (runs.into_par_iter())
        .map(|run| {
            let (mut seen, mut buf, mut short, mut tri) =
                scratch.lock().unwrap().pop().unwrap_or_else(|| (vec![0u64; 2 << 18], Vec::new(), Vec::new(), Vec::new()));
            let mut sp = Split { pairs: vec![Vec::new(); 256], syms: Vec::new(), blooms: Vec::new(), docs: Vec::new(), contents: Vec::new() };
            let mut ahead = std::collections::VecDeque::new();
            for i in run.clone() {
                while ahead.len() <= AHEAD && i + ahead.len() < run.end {
                    ahead.push_back(open_ahead(docs.path(i + ahead.len())));
                }
                buf.clear();
                let text = (ahead.pop_front().flatten())
                    .and_then(|f| f.take(MAX_REPO_FILE + 1).read_to_end(&mut buf).ok())
                    .is_some_and(|n| n as u64 <= MAX_REPO_FILE && is_text(&buf));
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
                                index_grams(&buf, &mut seen, &mut tri, &mut short);
                                for &t in &tri {
                                    sp.pairs[(t >> 16) as usize].push((t as u64) << 32 | k as u64);
                                }
                                symbols(&buf, &mut sp.syms);
                                bloom(&short, 3, &mut sp.blooms);
                                let bloom = bl..sp.blooms.len();
                                sp.contents.push(SplitContent { new: k, hash: h, small: buf.len() < SMALL, sym: sym..sp.syms.len(), bloom });
                            }
                            Holds::New(k)
                        }
                    }
                };
                sp.docs.push((i, holds));
            }
            // A big file's buffers go, not back to the pool.
            if buf.capacity() > 4 << 20 {
                buf = Vec::new();
            }
            for v in [&mut short, &mut tri].into_iter().filter(|v| v.capacity() > 1 << 20) {
                *v = Vec::new();
            }
            scratch.lock().unwrap().push((seen, buf, short, tri));
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
            DocMeta { path: docs.path(i).into(), size, mtime, rank: if gid == NONE { NOT_TEXT } else { doc_rank(docs.path(i)) }, gid }
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
    let shared: Vec<(u64, u32)> =
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
        for (i, path) in s.all_paths().enumerate().filter(|&(i, _)| !s.is_dead(i as u32)) {
            let (size, mtime, rank, gid) = (s.size()[i] as u64, s.mtime()[i], s.rank()[i], s.doc_gid()[i]);
            meta.push(DocMeta { path: path.into(), size, mtime, rank, gid });
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
            let mut its: Vec<_> = (segs.iter())
                .map(|s| {
                    s.lists_from(s.block_of(keys.start))
                        .skip_while(|&(k, _)| (k as u64) < keys.start)
                        .take_while(|&(k, _)| (k as u64) < keys.end)
                        .peekable()
                })
                .collect();
            let (mut out, mut list, mut part) = (Postings::default(), Vec::new(), Vec::new());
            while let Some(t) = its.iter_mut().filter_map(|it| it.peek().map(|x| x.0)).min() {
                list.clear();
                for (si, it) in its.iter_mut().enumerate() {
                    if let Some((_, l)) = it.next_if(|x| x.0 == t) {
                        part.clear();
                        l.all_into(&mut part);
                        list.extend(part.iter().map(|&c| remap[si][c as usize]).filter(|&c| c != NONE));
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
    /// when dense, else in interpolative code. Up to BLOCK contents are an
    /// Elias-gamma count and one block; more are a u32 count, a skip entry
    /// per block but the last (its last content, where the next block's bits
    /// start), and the blocks, each within the previous block's last content
    /// and its own (whose last content the skip entry holds).
    fn push(&mut self, n: usize, key: u32, list: &[u32]) {
        self.keys.push(key);
        let at = self.post.len();
        if list.len() * 8 > n {
            self.offs.push(at as u32 | BITSET);
            self.post.resize(at + n.div_ceil(8), 0);
            for &d in list {
                self.post[at + d as usize / 8] |= 1 << (d % 8);
            }
            return;
        }
        let (mut w, top) = (Bits::default(), n as u32 - 1);
        if list.len() <= BLOCK {
            self.offs.push(at as u32);
            let (len, z) = (list.len() as u32, list.len().ilog2());
            w.put((len & ((1 << z) - 1)) << (z + 1) | 1 << z, 2 * z + 1);
            ic_put(&mut w, list, 0, top);
        } else {
            self.offs.push(at as u32 | SKIPS);
            self.post.extend_from_slice(&(list.len() as u32).to_le_bytes());
            let mut lo = 0;
            for (j, blk) in list.chunks(BLOCK).enumerate() {
                if (j + 1) * BLOCK < list.len() {
                    let last = blk[BLOCK - 1];
                    ic_put(&mut w, &blk[..BLOCK - 1], lo, last - 1);
                    self.post.extend_from_slice(&(last as u64 | (w.len() as u64) << 32).to_le_bytes());
                    lo = last + 1;
                } else {
                    ic_put(&mut w, blk, lo, top);
                }
            }
        }
        self.post.extend_from_slice(&w.finish());
    }
}

/// Write the segment file: docs, own contents, and their postings in runs
/// of keys (ascending).
fn write_segment(dir: &Path, id: u64, docs: &[DocMeta<'_>], own: &[ContentMeta<'_>], parts: Vec<Postings>) -> Option<Segment> {
    if docs.is_empty() && own.is_empty() {
        return None;
    }
    let (ndocs, nown) = (docs.len(), own.len());
    // The posting lists' dictionary, in blocks of DICT (see `Segment::dict`).
    let (mut idx, mut dict, mut post, mut ntri, mut last) = (Vec::new(), Vec::new(), Vec::new(), 0usize, 0u32);
    for p in &parts {
        let ends = p.offs.iter().skip(1).map(|&o| (o & !FLAGS) as usize).chain([p.post.len()]);
        for ((&key, &o), end) in p.keys.iter().zip(&p.offs).zip(ends) {
            let at = (o & !FLAGS) as usize;
            if ntri % DICT == 0 {
                idx.push([key, dict.len() as u32, (post.len() + at) as u32]);
                last = key;
            }
            put_varint(&mut dict, key - last);
            put_varint(&mut dict, ((end - at) as u32) << 2 | (o & BITSET != 0) as u32 | ((o & SKIPS != 0) as u32) << 1);
            (last, ntri) = (key, ntri + 1);
        }
        post.extend_from_slice(&p.post);
    }
    drop(parts);
    // Paths front-coded in groups of PATHS docs (see `Segment::path_off`).
    let (mut paths, mut path_off) = (Vec::new(), Vec::with_capacity(ndocs.div_ceil(PATHS)));
    for (i, d) in docs.iter().enumerate() {
        if i % PATHS == 0 {
            path_off.push(paths.len() as u32);
        }
        let shared = if i % PATHS == 0 { 0 } else { d.path.iter().zip(docs[i - 1].path.iter()).take_while(|(a, b)| a == b).count() };
        put_varint(&mut paths, shared as u32);
        put_varint(&mut paths, (d.path.len() - shared) as u32);
        paths.extend_from_slice(&d.path[shared..]);
    }
    // (Docs are files of at most MAX_FILE bytes.)
    let size: Vec<u32> = docs.iter().map(|d| d.size as u32).collect();
    let mtime: Vec<u32> = docs.iter().map(|d| d.mtime).collect();
    let rank: Vec<i8> = docs.iter().map(|d| d.rank).collect();
    let mut by_path: Vec<u32> = (0..ndocs as u32).collect();
    by_path.sort_by(|&a, &b| docs[a as usize].path.cmp(&docs[b as usize].path));
    let mut by_rank: Vec<u32> = (0..ndocs as u32).collect();
    by_rank.sort_by_key(|&d| (rank_key(docs[d as usize].rank, docs[d as usize].mtime), d));
    let doc_gid: Vec<u32> = docs.iter().map(|d| d.gid).collect();
    let rank_gid: Vec<u32> = by_rank.iter().map(|&d| doc_gid[d as usize]).collect();
    let mut by_gid: Vec<u32> = (0..ndocs as u32).collect();
    by_gid.sort_by_key(|&d| doc_gid[d as usize]);
    let gid_sorted: Vec<u32> = by_gid.iter().map(|&d| doc_gid[d as usize]).collect();
    let own_gid: Vec<u32> = own.iter().map(|c| c.gid).collect();
    let own_doc: Vec<u32> = own.iter().map(|c| c.doc).collect();
    let hash: Vec<u64> = own.iter().map(|c| c.hash).collect();
    let mut by_hash: Vec<u32> = (0..nown as u32).collect();
    by_hash.sort_by_key(|&c| own[c as usize].hash);
    let (mut bloom_off, mut blooms) = (vec![0u32], Vec::new());
    for c in own {
        blooms.extend_from_slice(c.bloom);
        bloom_off.push(blooms.len() as u32);
    }

    let (off, _) = layout(&lens(ndocs, ntri, post.len(), paths.len(), blooms.len(), nown, dict.len()));
    let fields = [ndocs, ntri, post.len(), paths.len(), blooms.len(), nown, dict.len()].map(|v| v as u64);
    let hdr = header(MAGIC, &fields);
    let sections: [&[u8]; NS] = [
        as_bytes(&idx),
        &dict,
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

/// Should this file be in the content index? (Resolves its folders from the
/// disk; a sync resolves each folder once, see `Scope`.)
pub fn eligible(path: &[u8], size: u64, home: &[u8]) -> bool {
    Scope::new(home, &on_disk).file(path, size)
}

/// Outside git repos, the text files are known by name and size.
fn name_ok(name: &[u8], size: u64) -> bool {
    if size > MAX_FILE || SKIP_DIRS.contains(&name) {
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

/// A name fff takes for binary without reading it.
fn binary_ext(name: &[u8]) -> bool {
    name.iter().rposition(|&b| b == b'.').filter(|&p| p > 0).is_some_and(|p| BINARY_EXTS.iter().any(|x| x.eq_ignore_ascii_case(&name[p + 1..])))
}

/// A name's extension (after its last dot, not a leading one), or "".
fn ext(name: &[u8]) -> &[u8] {
    name.iter().rposition(|&b| b == b'.').filter(|&p| p > 0).map_or(&b""[..], |p| &name[p + 1..])
}

/// JSON and JSON lines keep the 1 MB cap in git repos too: past that they
/// are transcripts and app state far more often than text to grep.
fn json_ext(name: &[u8]) -> bool {
    [&b"json"[..], b"jsonl", b"ndjson"].iter().any(|x| x.eq_ignore_ascii_case(ext(name)))
}

/// Lockfiles: generated, long, and not what you grep for.
#[rustfmt::skip]
const LOCKFILES: &[&[u8]] = &[
    b"package-lock.json", b"npm-shrinkwrap.json", b"yarn.lock", b"pnpm-lock.yaml", b"bun.lock", b"bun.lockb", b"deno.lock",
    b"Cargo.lock", b"Gemfile.lock", b"poetry.lock", b"Pipfile.lock", b"uv.lock", b"composer.lock", b"go.sum", b"Podfile.lock",
    b"Package.resolved", b"Cartfile.resolved", b"flake.lock", b"mix.lock", b"pubspec.lock", b"packages.lock.json", b"gradle.lockfile",
];

/// Files whose text the index leaves out by name and size, in repos and
/// out (their names stay findable, and a grep of the file itself reads it):
/// lockfiles, JSON of 100 KB and up (data and state; JSON lines transcripts
/// stay), minified or bundled JS and CSS.
fn generated(name: &[u8], size: u64) -> bool {
    let is = |exts: &[&[u8]]| exts.iter().any(|x| x.eq_ignore_ascii_case(ext(name)));
    let has = |w: &[u8]| memchr::memmem::find(name, w).is_some();
    LOCKFILES.contains(&name)
        || is(&[b"json", b"jsonc", b"json5"]) && size >= 100 << 10
        || is(&[b"js", b"mjs", b"cjs", b"css"])
            && (has(b".min.") || has(b".bundle.") || has(b".chunk.") || name.starts_with(b"bundle.") || name.starts_with(b"chunk-"))
}

/// Text, as the content build takes a file's bytes: no NUL byte anywhere (as
/// fff decides), and not minified or generated (`long_lines`). A grep that
/// reads files directly keeps a file by the same test (see `Reading`), so
/// a search answers the same before the build and after.
fn is_text(buf: &[u8]) -> bool {
    memchr::memchr(0, buf).is_none() && !long_lines(buf)
}

/// Minified or generated, by a cheap look: lines averaging over 1000 bytes,
/// in a file of 4 KB and up (fewer than one newline per 1001 bytes, counted
/// only that far). Its name stays findable, its text unindexed.
fn long_lines(buf: &[u8]) -> bool {
    buf.len() >= 4096 && memchr::memchr_iter(b'\n', buf).nth(buf.len() / 1001 - 1).is_none()
}

/// Does home's heuristic skip this folder (`rel`: its path under home;
/// `holds` tells whether it holds a file)?
fn skipped(rel: &[u8], name: &[u8], holds: impl Fn(&[u8]) -> bool) -> bool {
    SKIP_DIRS.contains(&name)
        || SKIP_SUFFIXES.iter().any(|x| name.len() > x.len() && name.ends_with(x))
        || SKIP_UNDER_HOME.contains(&rel)
        || MARKED_DIRS.contains(&name) && MARKERS.iter().any(|m| holds(m))
}

/// Can this path (file or folder) be in the indexed area: under home, not
/// in a `.git`, and past no folder home's heuristics skip unless a git repo
/// holds that folder (then its ignore files decide, see `Scope`)? Cheap: it
/// touches the disk only to look for a repo above a skipped folder.
pub fn in_scope(path: &[u8], home: &[u8]) -> bool {
    let Some(rest) = path.strip_prefix(home) else { return false };
    if !rest.is_empty() && rest[0] != b'/' {
        return false;
    }
    let rel = rest.strip_prefix(b"/").unwrap_or(rest);
    let mut at = 0;
    for c in rel.split(|&b| b == b'/') {
        if c == b".git" {
            return false;
        }
        if skipped(&rel[..at + c.len()], c, |m| on_disk(&join(&path[..home.len() + 1 + at + c.len()], m)).is_some()) {
            let mut above = (0..at).filter(|&i| rel[i] == b'/');
            return above.any(|i| on_disk(&join(&path[..home.len() + 1 + i], b".git")).is_some());
        }
        at += c.len() + 1;
    }
    true
}

/// A path's (kind, size, mtime) on disk.
fn on_disk(path: &[u8]) -> Option<(u8, u64, u32)> {
    crate::live::lstat(path).map(|o| (o.kind, o.size, o.mtime))
}

/// A path's (kind, size, mtime) as the name index has it.
fn in_index(live: &Live, path: &[u8]) -> Option<(u8, u64, u32)> {
    if let Some(o) = live.over.get(path) {
        return Some((o.kind, o.size, o.mtime));
    }
    let i = live.base.lookup(path).filter(|&e| !live.is_dead(e))? as usize;
    Some((live.base.kind(i), live.base.size_of(i), live.base.mtime(i)))
}

/// The user's own folders never to grep inside (their names stay findable,
/// a grep of a file there still reads it): a file in the data dir, one
/// folder a line, `~/` allowed, `#` comments. Empty or missing: none.
pub const SKIP_LIST: &str = "content-skip.txt";

/// The skip list's path (known once the content index opens), and the
/// folders it held when a sync last read it.
static USER_SKIPS: Mutex<UserSkips> = Mutex::new((None, None));
type UserSkips = (Option<PathBuf>, Option<Vec<Vec<u8>>>);

/// The skip list's folders, as absolute paths.
fn skip_list(home: &[u8]) -> Vec<Vec<u8>> {
    let path = USER_SKIPS.lock().unwrap().0.clone();
    let text = path.and_then(|p| std::fs::read(p).ok()).unwrap_or_default();
    (text.split(|&b| b == b'\n').map(<[u8]>::trim_ascii))
        .filter(|l| !l.is_empty() && !l.starts_with(b"#"))
        .map(|l| {
            let l = l.strip_suffix(b"/").unwrap_or(l);
            match l.strip_prefix(b"~") {
                Some(rest) => [home, rest].concat(),
                None if l.starts_with(b"/") => l.to_vec(),
                None => join(home, l),
            }
        })
        .collect()
}

/// Ignore files parsed so far, by path, with the (size, mtime) they were
/// read at; and the repo roots seen, as their `.git` with no globs.
type Parsed = HashMap<Vec<u8>, (u64, u32, Option<Arc<Globs>>)>;
static PARSED: std::sync::LazyLock<Mutex<Parsed>> = std::sync::LazyLock::new(Default::default);

/// A path's (kind, size, mtime) in the name index (or on disk), if there.
type Look<'a> = &'a dyn Fn(&[u8]) -> Option<(u8, u64, u32)>;

/// Decides which folders and files the content index takes. In a git repo,
/// the files git doesn't ignore (as ripgrep and fff read .gitignore,
/// .ignore, .git/info/exclude and the global excludes file), up to 10 MB,
/// but for names fff takes for binary; files holding a NUL byte are then
/// kept as not text. Elsewhere under home, text files by extension, outside
/// dependency, cache and app-data folders. Folders resolve top-down from
/// home, each once.
struct Scope<'a> {
    home: &'a [u8],
    look: Look<'a>,
    global: Option<Arc<Globs>>,
    /// The user's skip list (see SKIP_LIST).
    skips: Vec<Vec<u8>>,
    /// Folders resolved so far (None: out of scope), and the last one.
    dirs: HashMap<Vec<u8>, Option<Place>>,
    last: Option<(Vec<u8>, Option<Place>)>,
}

/// A folder in scope: the ignore files over it, innermost first, and
/// whether it is in a git repo.
#[derive(Clone)]
struct Place {
    rules: Option<Arc<Rules>>,
    repo: bool,
}

/// A folder's ignore files, then the ones further up.
struct Rules {
    /// The folder, with a trailing '/': their globs match paths below it.
    dir: Vec<u8>,
    gitignore: Option<Arc<Globs>>,
    ignore: Option<Arc<Globs>>,
    /// At a repo root: its info/exclude. Git's files above it don't apply.
    root: Option<Option<Arc<Globs>>>,
    up: Option<Arc<Rules>>,
}

impl<'a> Scope<'a> {
    fn new(home: &'a [u8], look: Look<'a>) -> Scope<'a> {
        let mut s = Scope { home, look, global: None, skips: skip_list(home), dirs: HashMap::new(), last: None };
        s.global = s.globs(&excludes_file(home));
        s
    }

    /// An ignore file's globs, parsed once per version of it.
    fn globs(&self, path: &[u8]) -> Option<Arc<Globs>> {
        let (kind, size, mtime) = (self.look)(path)?;
        if kind & 3 != KIND_FILE {
            return None;
        }
        let mut parsed = PARSED.lock().unwrap();
        if let Some((s, m, g)) = parsed.get(path)
            && (*s, *m) == (size, mtime)
        {
            return g.clone();
        }
        let g = std::fs::read(OsStr::from_bytes(path)).ok().and_then(|t| Globs::parse(&t)).map(Arc::new);
        parsed.insert(path.to_vec(), (size, mtime, g.clone()));
        g
    }

    /// Did this folder's ignore files or repo root change since a sync last
    /// resolved it (or appear in a folder it never saw)? Then everything
    /// below it may have changed eligibility.
    fn rules_changed(&self, dir: &[u8]) -> bool {
        let mut parsed = PARSED.lock().unwrap();
        let mut changed = false;
        for name in [&b".git"[..], b".gitignore", b".ignore"] {
            let p = join(dir, name);
            let (now, was) = ((self.look)(&p), parsed.get(&p).map(|e| (e.0, e.1)));
            // (A .git folder's mtime moves with every git command.)
            changed |= if name == b".git" { now.is_some() != was.is_some() } else { now.map(|(_, s, m)| (s, m)) != was };
            if now.is_none() {
                parsed.remove(&p);
            }
        }
        changed
    }

    /// Is `dir` a linked git worktree: its `.git` a file pointing into another
    /// repo's `.git/worktrees/` (a submodule's points into `.git/modules/`)?
    /// Its text is mostly its main checkout's: left out.
    fn linked_worktree(&self, dir: &[u8]) -> bool {
        let dot = join(dir, b".git");
        if (self.look)(&dot).is_none_or(|(kind, ..)| kind & 3 != KIND_FILE) {
            return false;
        }
        let text = std::fs::read(OsStr::from_bytes(&dot)).unwrap_or_default();
        let to = text.strip_prefix(b"gitdir:").map_or(&b""[..], <[u8]>::trim_ascii);
        to.strip_suffix(b"/").unwrap_or(to).rsplit(|&b| b == b'/').nth(1) == Some(&b"worktrees"[..])
    }

    /// The place of a folder (None: out of scope).
    fn place(&mut self, dir: &[u8]) -> Option<Place> {
        if let Some(p) = self.dirs.get(dir) {
            return p.clone();
        }
        let p = if dir == self.home {
            Some(self.enter(dir, Place { rules: None, repo: false }))
        } else {
            let cut = dir.iter().rposition(|&b| b == b'/').filter(|&c| dir.starts_with(self.home) && c >= self.home.len())?;
            let up = self.place(&dir[..cut])?;
            let name = &dir[cut + 1..];
            let skip = if up.repo { name == b".git" } else { skipped(&dir[self.home.len() + 1..], name, |m| (self.look)(&join(dir, m)).is_some()) };
            let skip = skip || self.skips.iter().any(|s| s == dir) || self.linked_worktree(dir);
            (!skip && !ignored(&up.rules, self.global.as_deref(), dir, true)).then(|| self.enter(dir, up))
        };
        self.dirs.insert(dir.to_vec(), p.clone());
        p
    }

    /// A folder's place: its own ignore files and repo root on its parent's.
    fn enter(&self, dir: &[u8], up: Place) -> Place {
        // Home itself is never taken for a repo: it holds everything else.
        let git = (dir != self.home).then(|| (self.look)(&join(dir, b".git"))).flatten();
        let (gitignore, ignore) = (self.globs(&join(dir, b".gitignore")), self.globs(&join(dir, b".ignore")));
        if git.is_none() && gitignore.is_none() && ignore.is_none() {
            return up;
        }
        let root = git.map(|(kind, ..)| {
            PARSED.lock().unwrap().insert(join(dir, b".git"), (0, 0, None));
            git_dir(dir, kind).and_then(|g| self.globs(&join(&g, b"info/exclude")))
        });
        let rules = Rules { dir: join(dir, b""), gitignore, ignore, root, up: up.rules };
        Place { repo: up.repo || rules.root.is_some(), rules: Some(Arc::new(rules)) }
    }

    /// Should the file at `path` be indexed?
    fn file(&mut self, path: &[u8], size: u64) -> bool {
        let cut = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
        let (dir, name) = (&path[..cut], &path[cut + 1..]);
        let place = match &self.last {
            Some((d, p)) if d == dir => p.clone(),
            _ => {
                let p = self.place(dir);
                self.last = Some((dir.to_vec(), p.clone()));
                p
            }
        };
        let Some(place) = place else { return false };
        let cap = if json_ext(name) { MAX_FILE } else { MAX_REPO_FILE };
        // A zero-byte file can't match a grep: never opened. (If it grows,
        // its folder's next resync picks it up with the new size.)
        let ok = size > 0 && if place.repo { size <= cap && name != b".git" && !binary_ext(name) } else { name_ok(name, size) };
        ok && !generated(name, size) && !ignored(&place.rules, self.global.as_deref(), path, false)
    }

    /// What should be indexed under `dir` (direct children only unless
    /// `recursive`), by the name index.
    fn wanted(&mut self, live: &Live, dir: &[u8], recursive: bool) -> Docs {
        let mut want = Docs::default();
        if self.place(dir).is_none() {
            return want;
        }
        let idx = &live.base;
        let path = |i: usize, p: &mut Vec<u8>| if recursive { idx.path(i, p) } else { *p = join(dir, &idx.name(i)) };
        // The files first, then their paths into buffers of just their size:
        // grown a push at a time, a big list's freed buffers stay in the
        // process's footprint (macOS malloc), a new copy each sync.
        let (mut p, mut picked, mut bytes) = (Vec::new(), Vec::new(), 0);
        if let Some(d) = idx.lookup(dir).filter(|&e| !live.is_dead(e)).and_then(|e| idx.dir_of(e)) {
            let range = if recursive { idx.dir_start(d as usize) as usize..idx.dir_end(d as usize) as usize } else { idx.children(d) };
            picked.reserve_exact(range.len());
            for i in range {
                let (name, size) = (idx.name(i), idx.size_of(i));
                if idx.kind(i) & 3 != KIND_FILE || live.is_dead(i as u32) || size > MAX_REPO_FILE || binary_ext(&name) {
                    continue;
                }
                path(i, &mut p);
                if self.file(&p, size) {
                    picked.push(i);
                    bytes += p.len();
                }
            }
        }
        let lo = join(dir, b"");
        let over: Vec<_> = (live.over.range(lo.clone()..).take_while(|(k, _)| k.starts_with(&lo)))
            .filter(|(k, o)| o.kind & 3 == KIND_FILE && (recursive || !k[lo.len()..].contains(&b'/')) && self.file(k, o.size))
            .collect();
        want.items.reserve_exact(picked.len() + over.len());
        want.buf = Paths::exactly(bytes + over.iter().map(|(k, _)| k.len()).sum::<usize>());
        for i in picked {
            path(i, &mut p);
            want.push(&p, idx.size_of(i), idx.mtime(i));
        }
        for (k, o) in over {
            want.push(k, o.size, o.mtime);
        }
        want
    }
}

/// The global excludes file, as git finds it: core.excludesFile in the
/// user's git config, else ~/.config/git/ignore.
fn excludes_file(home: &[u8]) -> Vec<u8> {
    for config in [&b"/.gitconfig"[..], b"/.config/git/config"] {
        let Ok(text) = std::fs::read(OsStr::from_bytes(&[home, config].concat())) else { continue };
        let (mut core, mut found) = (false, None);
        for l in text.split(|&b| b == b'\n').map(<[u8]>::trim_ascii) {
            if l.starts_with(b"[") {
                core = l.eq_ignore_ascii_case(b"[core]");
            } else if let Some(eq) = l.iter().position(|&b| b == b'=')
                && core
                && l[..eq].trim_ascii().eq_ignore_ascii_case(b"excludesfile")
            {
                let v = l[eq + 1..].trim_ascii();
                let v = v.strip_prefix(b"\"").and_then(|v| v.strip_suffix(b"\"")).unwrap_or(v);
                found = Some(v.strip_prefix(b"~").map_or(v.to_vec(), |r| [home, r].concat()));
            }
        }
        if let Some(f) = found {
            return f;
        }
    }
    [home, b"/.config/git/ignore"].concat()
}

/// The git dir of the repo rooted at `dir`: its `.git`, or for a worktree
/// or submodule (a `.git` file), the common dir it points to.
fn git_dir(dir: &[u8], kind: u8) -> Option<Vec<u8>> {
    let dot = join(dir, b".git");
    if kind & 3 == KIND_DIR {
        return Some(dot);
    }
    let text = std::fs::read(OsStr::from_bytes(&dot)).ok()?;
    let to = text.strip_prefix(b"gitdir:")?.trim_ascii();
    let git = if to.starts_with(b"/") { to.to_vec() } else { join(dir, to) };
    Some(match std::fs::read(OsStr::from_bytes(&join(&git, b"commondir"))) {
        Ok(c) if c.trim_ascii().starts_with(b"/") => c.trim_ascii().to_vec(),
        Ok(c) => join(&git, c.trim_ascii()),
        Err(_) => git,
    })
}

/// Do the ignore files over `path` (innermost first) ignore it? As ripgrep
/// decides: the innermost .ignore that says either way, else the innermost
/// .gitignore up to the repo root, else the root's info/exclude, else the
/// global excludes. Git's files count only in a repo.
fn ignored(rules: &Option<Arc<Rules>>, global: Option<&Globs>, path: &[u8], dir: bool) -> bool {
    let (mut ig, mut gi, mut ex, mut root) = (None, None, None, None);
    let mut r = rules.as_deref();
    while let Some(l) = r {
        let rel = &path[l.dir.len()..];
        ig = ig.or_else(|| l.ignore.as_ref()?.decide(rel, dir));
        if root.is_none() {
            gi = gi.or_else(|| l.gitignore.as_ref()?.decide(rel, dir));
            if let Some(x) = &l.root {
                ex = x.as_ref().and_then(|x| x.decide(rel, dir));
                root = Some(rel);
            }
        }
        r = l.up.as_deref();
    }
    match root {
        Some(rel) => ig.or(gi).or(ex).or_else(|| global?.decide(rel, dir)),
        None => ig,
    }
    .unwrap_or(false)
}

/// One ignore file's globs as regexes over paths relative to its folder,
/// with (whitelist, folders only) per glob: a path's last match decides.
struct Globs {
    set: regex::bytes::RegexSet,
    kinds: Vec<(bool, bool)>,
}

impl Globs {
    fn parse(text: &[u8]) -> Option<Globs> {
        let (mut res, mut kinds): (Vec<String>, Vec<(bool, bool)>) = (Vec::new(), Vec::new());
        for (re, white, dir) in text.split(|&b| b == b'\n').filter_map(ignore_line) {
            res.push(re);
            kinds.push((white, dir));
        }
        // A glob that won't compile is left out, as ripgrep leaves it out.
        let set = match regex::bytes::RegexSet::new(&res) {
            Ok(set) => set,
            Err(_) => {
                let ok: Vec<bool> = res.iter().map(|r| regex::bytes::Regex::new(r).is_ok()).collect();
                kinds = kinds.into_iter().zip(&ok).filter(|(_, ok)| **ok).map(|(k, _)| k).collect();
                regex::bytes::RegexSet::new(res.iter().zip(&ok).filter(|(_, ok)| **ok).map(|(r, _)| r)).ok()?
            }
        };
        (!kinds.is_empty()).then_some(Globs { set, kinds })
    }

    /// Some(true): the last glob matching `rel` ignores it; Some(false): it
    /// whitelists it.
    fn decide(&self, rel: &[u8], dir: bool) -> Option<bool> {
        if !self.set.is_match(rel) {
            return None;
        }
        self.set.matches(rel).iter().rev().map(|i| self.kinds[i]).find(|k| !k.1 || dir).map(|k| !k.0)
    }
}

/// A gitignore line as ripgrep's `ignore` crate reads it: (regex, whitelist,
/// folders only), or None for blanks and comments.
fn ignore_line(line: &[u8]) -> Option<(String, bool, bool)> {
    if line.starts_with(b"#") {
        return None;
    }
    let mut l = if line.ends_with(b"\\ ") { line } else { line.trim_ascii_end() };
    let (mut white, mut anchored, mut dir) = (false, false, false);
    if l.starts_with(b"\\!") || l.starts_with(b"\\#") {
        l = &l[1..];
    } else {
        if let Some(r) = l.strip_prefix(b"!") {
            (white, l) = (true, r);
        }
        if let Some(r) = l.strip_prefix(b"/") {
            (anchored, l) = (true, r);
        }
    }
    if let Some(r) = l.strip_suffix(b"/") {
        dir = true;
        l = r.strip_suffix(b"\\").unwrap_or(r);
    }
    if l.is_empty() {
        return None;
    }
    // No slash: it matches at any depth.
    let mut glob = if !anchored && !l.contains(&b'/') && !l.starts_with(b"**/") && l != b"**" { [b"**/", l].concat() } else { l.to_vec() };
    // `x/**` matches what is inside x, not x.
    if glob.ends_with(b"/**") {
        glob.extend_from_slice(b"/*");
    }
    Some((glob_regex(&glob)?, white, dir))
}

/// A glob as a regex, as ripgrep's globset builds it for ignore files: `*`
/// and `?` stop at '/', `**` spans folders as a whole component, `[...]`
/// classes, `{a,b}` alternatives, backslash escapes. None if malformed.
fn glob_regex(g: &[u8]) -> Option<String> {
    use std::fmt::Write;
    enum T {
        Lit(u8),
        Any,
        Star,
        Pre,
        Suf,
        Mid,
        Class(String),
        Alt(Vec<Vec<T>>),
    }
    // The tokens read so far; inside {}, one list per alternative after it.
    let mut stack: Vec<Vec<T>> = vec![Vec::new()];
    let mut i = 0;
    while i < g.len() {
        let depth = stack.len();
        let top = stack.last_mut()?;
        match g[i] {
            b'?' => top.push(T::Any),
            b'*' if g.get(i + 1) != Some(&b'*') => top.push(T::Star),
            b'*' => {
                // "**": recursive only as a whole path component.
                let (prev, next) = (i.checked_sub(1).map(|p| g[p]), g.get(i + 2).copied());
                i += 1;
                let end = next.is_none() || (depth > 1 && matches!(next, Some(b',' | b'}')));
                if top.is_empty() && next.is_none_or(|n| n == b'/') {
                    top.push(T::Pre);
                    i += next.is_some() as usize;
                } else if top.is_empty() || prev != Some(b'/') || !(end || next == Some(b'/')) {
                    top.extend([T::Star, T::Star]);
                } else {
                    i += (next == Some(b'/')) as usize;
                    // It takes the place of the '/' before it.
                    match top.pop()? {
                        t @ (T::Pre | T::Suf) => top.push(t),
                        _ => top.push(if end { T::Suf } else { T::Mid }),
                    }
                }
            }
            b'[' => {
                // A class; unclosed, a literal '['.
                let neg = matches!(g.get(i + 1), Some(b'!' | b'^'));
                let start = i + 1 + neg as usize;
                match (start + 1..g.len()).find(|&j| g[j] == b']') {
                    Some(end) => {
                        let mut ranges: Vec<(u8, u8)> = Vec::new();
                        let mut j = start;
                        while j < end {
                            if g[j] == b'-' && j > start && j + 1 < end {
                                let last = ranges.last_mut()?;
                                last.1 = g[j + 1];
                                if last.1 < last.0 {
                                    return None;
                                }
                                j += 2;
                            } else {
                                ranges.push((g[j], g[j]));
                                j += 1;
                            }
                        }
                        let mut re = String::from(if neg { "[^" } else { "[" });
                        for (a, b) in ranges {
                            let _ = if a == b { write!(re, "\\x{a:02x}") } else { write!(re, "\\x{a:02x}-\\x{b:02x}") };
                        }
                        re.push(']');
                        top.push(T::Class(re));
                        i = end;
                    }
                    None => top.push(T::Lit(b'[')),
                }
            }
            b'{' if depth > 1 => return None,
            b'{' => stack.push(Vec::new()),
            // (A stray '}' matches nothing.)
            b'}' => {
                let alts = stack.split_off(1);
                stack[0].push(T::Alt(alts));
            }
            b',' if depth > 1 => stack.push(Vec::new()),
            b'\\' => {
                i += 1;
                top.push(T::Lit(*g.get(i)?));
            }
            c => top.push(T::Lit(c)),
        }
        i += 1;
    }
    if stack.len() > 1 {
        return None;
    }
    fn render(ts: &[T], re: &mut String) {
        for t in ts {
            let _ = match t {
                T::Lit(b) if b.is_ascii_alphanumeric() || *b == b'/' || *b == b'_' => write!(re, "{}", *b as char),
                T::Lit(b) => write!(re, "\\x{b:02x}"),
                T::Any => write!(re, "[^/]"),
                T::Star => write!(re, "[^/]*"),
                T::Pre => write!(re, "(?:/?|.*/)"),
                T::Suf => write!(re, "/.*"),
                T::Mid => write!(re, "(?:/|/.*/)"),
                T::Class(c) => write!(re, "{c}"),
                T::Alt(parts) => {
                    let parts: Vec<String> = (parts.iter())
                        .map(|p| {
                            let mut s = String::new();
                            render(p, &mut s);
                            s
                        })
                        .filter(|s| !s.is_empty())
                        .collect();
                    if parts.is_empty() { Ok(()) } else { write!(re, "(?:{})", parts.join("|")) }
                }
            };
        }
    }
    let mut re = String::from("(?s-u)^");
    match stack[0].as_slice() {
        [T::Pre] => re.push_str(".*"),
        ts => render(ts, &mut re),
    }
    re.push('$');
    Some(re)
}

/// Does the name query let every indexed doc under its scope (if any)
/// through: no words, extensions, ranges or patterns? Then a segment wholly
/// in scope needn't be checked doc by doc.
fn only_scope(q: &Query) -> bool {
    q.exts.is_empty() && nothing_else(q)
}

/// Does the name query ask only for extensions (see `path_ok`)?
fn only_exts(q: &Query) -> bool {
    q.scope.is_none() && !q.exts.is_empty() && nothing_else(q)
}

/// No words, ranges or patterns in the name query, and files let through.
fn nothing_else(q: &Query) -> bool {
    q.tokens.is_empty()
        && q.kind_ok(KIND_FILE)
        && q.size == (0, u64::MAX)
        && q.mtime == (0, u32::MAX)
        && q.name_re.is_none()
        && q.path_re.is_none()
        && q.not_exts.is_empty()
        && q.globs.is_empty()
}

/// Does doc `d` of `s` pass the name query? The end of its path its entry
/// holds can settle an extension asked for (`ext_only`: all it asks) before
/// the path is built.
fn path_ok<'a>(filt: &Query, ext_only: bool, paths: &mut PathCursor<'a>, s: &'a Segment, d: u32) -> bool {
    let mut by_end = None;
    let keep = |end: &[u8]| {
        by_end = filt.ext_by_end(end);
        by_end.is_none() || (by_end == Some(true) && !ext_only)
    };
    match paths.get_if(s, d, keep) {
        Some(p) => filt.match_path(p, KIND_FILE, s.size()[d as usize] as u64, s.mtime()[d as usize]).is_some(),
        None => by_end == Some(true),
    }
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
        (0..self.n.div_ceil(64)).map(|w| self.held(w).count_ones() as usize).sum()
    }

    /// Word `w` of which are held at all.
    fn held(&self, w: usize) -> u64 {
        self.planes.iter().fold(0, |x, p| x | p[w])
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
        USER_SKIPS.lock().unwrap().0 = dir.parent().map(|d| d.join(SKIP_LIST));
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
        let (s, cp, own) = (&self.segs[a], &self.copies[a], self.segs[a].own_doc());
        if cp.contents.is_empty() {
            for &c in sel {
                let first = own[c as usize];
                if first != NONE && !s.is_dead(first) {
                    f(a, first);
                }
            }
            return;
        }
        let mut k = 0;
        for &c in sel {
            let first = own[c as usize];
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
                    match want.find(&s.path(d)) {
                        // (A doc whose content is gone is indexed again.)
                        Some(k)
                            if want.items[k].2 == s.size()[i] as u64
                                && want.items[k].3 == s.mtime()[i]
                                && (g == NONE || content_of(gids, g).is_some()) =>
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
                .filter(|&(s, d)| crate::live::lstat(&s.path(d)).is_none_or(|o| o.mtime >= since || o.size != s.size()[d as usize] as u64))
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

    /// The segments to merge into one next (ids), if any. First, once the
    /// bytes of deleted and replaced files (see `Segment::dead_bytes`) pass
    /// 1/DEAD of the index, the segment with the largest dead share is
    /// rewritten alone: the most bytes back for the least rewriting (every
    /// query decodes dead contents' postings too). Then tiered merging: 8
    /// segments of the same size tier become one, so incremental updates
    /// never pile up thousands of tiny segments, capped so a merge's
    /// postings stay small.
    pub fn merge_plan(&self) -> Option<Vec<u64>> {
        let dead: Vec<usize> = self.segs.iter().map(Segment::dead_bytes).collect();
        if dead.iter().sum::<usize>() * DEAD > self.bytes() {
            let share = |(s, d): &(&Segment, &usize)| ((**d as u128) << 32) / s.map.len() as u128;
            return self.segs.iter().zip(&dead).max_by_key(share).map(|(s, _)| vec![s.id]);
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
    fn candidates<'c>(&'c self, plan: &TQ, filt: &Query) -> Found {
        // A scope narrows each segment to its paths under it (a run in path
        // order) and the doc range holding those; None: no live doc there
        // under it. A range holding only those needs no path checked.
        let prefix = filt.scope.as_ref().map(|s| [s.as_slice(), b"/"].concat());
        let (only_scope, ext_only) = (only_scope(filt), only_exts(filt));
        let runs: Vec<std::ops::Range<usize>> = self.segs.iter().map(|s| prefix.as_ref().map_or(0..s.ndocs, |p| s.prefix_run(p))).collect();
        let scope: Vec<Option<(std::ops::Range<u32>, bool)>> = (self.segs.iter().zip(&runs))
            .map(|(s, run)| {
                let (docs, exact) = s.doc_range(run.clone());
                (s.live_docs > 0 && !docs.is_empty()).then_some((docs, !(only_scope && exact)))
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
                let (mut v, mut paths) = (Vec::with_capacity(ids.len()), PathCursor::default());
                v.extend(
                    ids.into_iter()
                        .filter(|&d| !s.is_dead(d) && s.rank()[d as usize] != NOT_TEXT)
                        .filter(|&d| !check || path_ok(filt, ext_only, &mut paths, s, d))
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
        // A candidate doc under the scope (`paths` reads its path).
        let admit = |b: usize, d: u32, paths: &mut PathCursor<'c>| -> Option<Ranked> {
            let (docs, check) = scope[b].as_ref()?;
            let t = &self.segs[b];
            let ok = docs.contains(&d) && (!check || path_ok(filt, ext_only, paths, t, d));
            ok.then(|| ranked(t, b, d))
        };
        // A scope holding few of the docs (up to 1 in 16): the contents its
        // docs hold, per owner, then which of those the plan selects (in the
        // range they span).
        let few = self.segs.iter().map(|s| s.ndocs).sum::<usize>() / 16;
        let within: Vec<usize> = (0..self.segs.len()).filter(|&b| scope[b].is_some()).collect();
        let under: Option<Vec<(usize, Vec<u32>)>> = (prefix.is_some() && !global && within.iter().map(|&b| runs[b].len()).sum::<usize>() <= few)
            .then(|| within.iter().map(|&b| (b, self.segs[b].live_at(runs[b].clone()).collect())).collect());
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
                let (mut top, mut paths) = (Top::new(), PathCursor::default());
                let n = needed(&self.segs[a], plan, need[a].clone(), |b, d| admit(b, d, &mut paths).map(|r| top.push(r)).is_some());
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
            if global {
                // No scope to check; the ranks of the segment's docs at hand.
                let mut seg = (usize::MAX, &[][..], &[][..]);
                self.holders(a, sel, |b, d| {
                    if b != seg.0 {
                        seg = (b, self.segs[b].rank(), self.segs[b].mtime());
                    }
                    top.push((rank_key(seg.1[d as usize], seg.2[d as usize]), b as u32, d));
                });
            } else {
                let mut paths = PathCursor::default();
                self.holders(a, sel, |b, d| {
                    if let Some(r) = admit(b, d, &mut paths) {
                        top.push(r)
                    }
                });
            }
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
                    let mut paths = PathCursor::default();
                    let n = needed(s, plan, need, |b, d| admit(b, d, &mut paths).map(|r| top.push(r)).is_some());
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
        self.search_with(g, filt, &[])
    }

    /// `search`, reading `fresh` first: files the index may not hold as
    /// they are now (see `Dirty`), newest first.
    pub fn search_with(&self, g: &Grep, filt: &Query, fresh: &[Vec<u8>]) -> GrepResult {
        let Found { mut per, total, dense } = self.candidates(&g.plan(), filt);
        // A candidate whose content's bloom filter lacks one of the pattern's
        // grams can't match: skip it without opening the file. (A fresh one
        // was read already.)
        let probes = g.probes();
        let read: std::collections::HashSet<&[u8]> = fresh.iter().map(Vec::as_slice).collect();
        let path = |&(_, si, d): &Ranked| {
            let s = &self.segs[si as usize];
            let (a, c) = self.content_of(s.doc_gid()[d as usize])?;
            self.segs[a].may_contain(c, &probes).then(|| s.path(d)).filter(|p| read.is_empty() || !read.contains(p.as_slice())).map(Into::into)
        };
        let t = std::time::Instant::now();
        let limit = filt.limit;
        // A later page passes over the candidates the pages before read.
        let mut skip = g.skip;
        let mut from = |n: usize| {
            let f = skip.min(n);
            skip -= f;
            f
        };
        let (mut r, done) = match fresh.len() {
            0 => (GrepResult { complete: true, ..Default::default() }, 0),
            n => verify_from(g, from(n), n, limit, Reading::Fresh, t, |i| Some(fresh[i].as_slice().into())),
        };
        // Then most searches are done within the best few hundred
        // candidates: rank those first, and the rest only if reading gets
        // that far.
        let add = |r: &mut GrepResult, more: GrepResult, base: usize| {
            r.files.extend(more.files);
            r.read += more.read;
            r.complete = more.complete;
            r.next = more.next.map(|x| base + x);
        };
        if r.files.len() < limit && done == fresh.len() {
            let best = take_best(&mut per);
            let (more, done) = verify_from(g, from(best.len()), best.len(), limit - r.files.len(), Reading::Index, t, |i| path(&best[i]));
            add(&mut r, more, fresh.len());
            if r.files.len() < limit && done == best.len() && best.len() < total {
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
                    let f = at + from(end - at);
                    let (more, done) = verify_from(g, f, end, limit - r.files.len(), Reading::Index, t, |i| path(&rest[i]));
                    add(&mut r, more, fresh.len() + best.len());
                    if r.files.len() >= limit || done < end {
                        break;
                    }
                    at = end;
                }
            }
        }
        r.candidates = total + fresh.len();
        r.next = r.next.filter(|&x| x < r.candidates);
        r
    }

    /// Does a live doc lie under this folder?
    pub fn holds(&self, dir: &[u8]) -> bool {
        let lo = join(dir, b"");
        self.segs.iter().any(|s| s.with_prefix(&lo).next().is_some())
    }

    /// Which of `want` (what should be indexed under `dir`) no live doc
    /// holds as it is now: what a sync of it would index.
    fn unheld(&self, dir: &[u8], recursive: bool, want: &Docs) -> Vec<usize> {
        let mut held = vec![false; want.len()];
        let lo = join(dir, b"");
        for s in &self.segs {
            let ids = if recursive { s.with_prefix(&lo).collect::<Vec<_>>() } else { s.direct_children(&lo) };
            for d in ids {
                if let Some(k) = want.find(&s.path(d))
                    && (want.items[k].2, want.items[k].3) == (s.size()[d as usize] as u64, s.mtime()[d as usize])
                {
                    held[k] = true;
                }
            }
        }
        (0..want.len()).filter(|&k| !held[k]).collect()
    }
}

/// Files changed since their folder's last content sync, by (folder,
/// recursive): the index may not hold their text yet (a folder waits for
/// its changes to settle), so searches read them directly, first.
#[derive(Default)]
pub struct Dirty(Mutex<Changed>);

/// Per folder (and whether its subtree), its changed files: path, size, mtime.
type Changed = HashMap<(Vec<u8>, bool), Vec<(Vec<u8>, u64, u32)>>;

/// Past this many changed files in one folder, the rest wait for the sync.
const DIRTY_MAX: usize = 4096;

impl Dirty {
    /// Note the files under these folders (`wanted_now`) the index doesn't
    /// hold as they are now.
    pub fn mark(&self, content: &Content, wants: Vec<(Vec<u8>, bool, Docs)>) {
        let mut m = self.0.lock().unwrap();
        for (dir, recursive, want) in wants {
            let files: Vec<_> = content
                .unheld(&dir, recursive, &want)
                .into_iter()
                .take(DIRTY_MAX)
                .map(|k| (want.path(k).to_vec(), want.items[k].2, want.items[k].3))
                .collect();
            if files.is_empty() {
                m.remove(&(dir, recursive));
            } else {
                m.insert((dir, recursive), files);
            }
        }
    }

    /// These folders' changes are in the index now.
    pub fn clear(&self, synced: &[(Vec<u8>, bool)]) {
        let mut m = self.0.lock().unwrap();
        for k in synced {
            m.remove(k);
        }
    }

    /// The changed files the query's name filters let through, newest first.
    pub fn files(&self, q: &Query) -> Vec<Vec<u8>> {
        let m = self.0.lock().unwrap();
        let mut out: Vec<(u32, &Vec<u8>)> = (m.values().flatten())
            .filter(|(p, size, mtime)| q.match_path(p, KIND_FILE, *size, *mtime).is_some())
            .map(|(p, _, mtime)| (*mtime, p))
            .collect();
        out.sort_unstable_by(|a, b| b.cmp(a));
        out.dedup_by(|a, b| a.1 == b.1);
        out.into_iter().map(|(_, p)| p.clone()).collect()
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
    let look = |p: &[u8]| in_index(live, p);
    Scope::new(home, &look).wanted(live, dir, recursive)
}

/// What should be indexed under these folders (direct children unless
/// recursive) as the name index has them now, for `Dirty::mark`.
pub fn wanted_now(live: &Live, home: &[u8], dirs: &[(Vec<u8>, bool)]) -> Vec<(Vec<u8>, bool, Docs)> {
    let look = |p: &[u8]| in_index(live, p);
    let mut scope = Scope::new(home, &look);
    (dirs.iter())
        .map(|(d, r)| {
            let mut w = scope.wanted(live, d, *r);
            w.sort();
            (d.clone(), *r, w)
        })
        .collect()
}

/// The dirs/trees from one batch of changes, each with what should be
/// indexed there. Done under the name-index read lock only.
pub fn wants(live: &Live, home: &[u8], dirs: &[Vec<u8>], trees: &[Vec<u8>]) -> Vec<(Vec<u8>, bool, Docs)> {
    let look = |p: &[u8]| in_index(live, p);
    let mut scope = Scope::new(home, &look);
    let mut out: Vec<(Vec<u8>, bool)> = Vec::new();
    // A changed skip list changes what's wanted anywhere: all of home.
    let mut skips = USER_SKIPS.lock().unwrap();
    if skips.1.as_ref().is_some_and(|was| *was != scope.skips) {
        out.push((home.to_vec(), true));
    }
    skips.1 = Some(scope.skips.clone());
    drop(skips);
    for (d, r) in dirs.iter().map(|d| (d, false)).chain(trees.iter().map(|d| (d, true))) {
        if in_scope(d, home) {
            // A folder whose ignore files changed: so may all below it.
            out.push((d.clone(), r || scope.rules_changed(d)));
        } else if r && home.starts_with(d) && (d.ends_with(b"/") || home[d.len()..].starts_with(b"/")) {
            // A subtree containing home (e.g. "/" rescanned): sync all of home.
            out.push((home.to_vec(), true));
        }
    }
    out.sort();
    out.dedup();
    out.into_iter()
        .map(|(d, r)| {
            let mut w = scope.wanted(live, &d, r);
            w.sort();
            (d, r, w)
        })
        .collect()
}

/// Grep the docs `wanted` lists by reading them all: the content index's
/// first build is still running, and its partial answer would be missing
/// files. Reads them in the order the built index will rank them (it
/// numbers a first build's docs in path order), so the answer is the same.
pub fn grep_unindexed(g: &Grep, mut docs: Docs, filt: &Query) -> GrepResult {
    docs.sort();
    let mut order: Vec<(u64, u32)> = (0..docs.len())
        .filter_map(|i| {
            let (p, (_, _, size, mtime)) = (docs.path(i), docs.items[i]);
            filt.match_path(p, KIND_FILE, size, mtime)?;
            Some((rank_key(doc_rank(p), mtime), i as u32))
        })
        .collect();
    order.sort_unstable();
    let n = order.len();
    let mut r =
        verify_from(g, g.skip.min(n), n, filt.limit, Reading::Scan, std::time::Instant::now(), |k| Some(docs.path(order[k].1 as usize).into())).0;
    r.next = r.next.filter(|&x| x < n);
    r
}

/// A pattern's gram hashes, as `may_contain` checks them.
struct Probes {
    short: Vec<u32>,
}

/// Does the pattern hold a non-ASCII letter with another case (é, É)? A
/// case-insensitive match may then hold other bytes for it.
fn cased(pattern: &str) -> bool {
    pattern.chars().any(|c| !c.is_ascii() && !c.to_lowercase().eq(c.to_uppercase()))
}

/// How a pattern's letter case matters.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub enum Case {
    /// Insensitive unless the pattern has an upper-case letter.
    #[default]
    Smart,
    Sensitive,
    Insensitive,
}

impl Case {
    fn insensitive(self, pattern: &str) -> bool {
        match self {
            Case::Smart => !pattern.chars().any(|c| c.is_uppercase()),
            Case::Sensitive => false,
            Case::Insensitive => true,
        }
    }

    /// For a regex, smart case counts what ripgrep counts: its literal
    /// characters (in classes too), not escapes like `\S` or `\pL`; with
    /// none at all it is exact.
    fn regex_insensitive(self, pattern: &str) -> bool {
        use regex_syntax::ast::{self, Ast, ClassSetItem};
        struct Lits(bool, bool);
        impl Lits {
            fn add(&mut self, c: char) {
                (self.0, self.1) = (true, self.1 || c.is_uppercase());
            }
        }
        impl ast::Visitor for Lits {
            type Output = bool;
            type Err = ();
            fn finish(self) -> Result<bool, ()> {
                Ok(self.0 && !self.1)
            }
            fn visit_pre(&mut self, a: &Ast) -> Result<(), ()> {
                if let Ast::Literal(l) = a {
                    self.add(l.c);
                }
                Ok(())
            }
            fn visit_class_set_item_pre(&mut self, i: &ClassSetItem) -> Result<(), ()> {
                match i {
                    ClassSetItem::Literal(l) => self.add(l.c),
                    ClassSetItem::Range(r) => [r.start.c, r.end.c].into_iter().for_each(|c| self.add(c)),
                    _ => {}
                }
                Ok(())
            }
        }
        match (self, ast::parse::Parser::new().parse(pattern)) {
            (Case::Smart, Ok(a)) => ast::visit(&a, Lits(false, false)).unwrap_or(false),
            _ => self.insensitive(pattern),
        }
    }
}

pub struct Grep {
    pub pattern: String,
    pub mode: GrepMode,
    pub max_per_file: usize,
    /// Stop reading candidates after this long (None = read them all).
    pub budget: Option<std::time::Duration>,
    /// Lines of context to give before and after each matched line.
    pub before: usize,
    pub after: usize,
    /// Tell which matched lines define the name they matched (`Hit::def`).
    pub defs: bool,
    /// Candidates to pass over: the `next` of the page before.
    pub skip: usize,
    /// The matching regex, compiled when first needed (a plain ASCII
    /// literal mostly isn't: `literal` finds it).
    re: std::sync::OnceLock<Regex>,
    src: String,
    case_insensitive: bool,
    literal: Option<Literal>,
}

impl Grep {
    /// A pattern in smart case.
    pub fn new(pattern: &str, mode: GrepMode) -> Result<Grep, String> {
        Grep::with_case(pattern, mode, Case::Smart)
    }

    pub fn with_case(pattern: &str, mode: GrepMode, case: Case) -> Result<Grep, String> {
        let src = match mode {
            GrepMode::Literal => regex::escape(pattern),
            GrepMode::Regex => pattern.to_string(),
            // A definition: a declaring keyword, optional generics/modifiers,
            // then the name. ASCII word boundaries keep the regex on the fast
            // DFA path even in files with non-ASCII text.
            GrepMode::Symbol => format!(r"(?-u:\b)(?:{DEFINES})(?:<[^>\n]*>)?[ \t*&]+(?:mut[ \t]+)?{}(?-u:\b)", regex::escape(pattern)),
        };
        // (A definition's name is exact unless asked otherwise.)
        let case_insensitive = match mode {
            GrepMode::Symbol => case == Case::Insensitive,
            GrepMode::Regex => case.regex_insensitive(pattern),
            _ => case.insensitive(pattern),
        };
        let short = (1..=4096).contains(&pattern.len());
        let literal = match mode {
            GrepMode::Symbol if short && !case_insensitive => Some(Literal::Definition(memchr::memmem::Finder::new(pattern.as_bytes()).into_owned())),
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
            before: 0,
            after: 0,
            defs: false,
            skip: 0,
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

    /// Lines holding any of these literals. Smart case is insensitive only
    /// when none of them has an upper-case letter.
    pub fn any_of(patterns: &[impl AsRef<str>], case: Case) -> Result<Grep, String> {
        let pats: Vec<&str> = patterns.iter().map(|p| p.as_ref()).filter(|p| !p.is_empty()).collect();
        if pats.is_empty() {
            return Err("no pattern".into());
        }
        let case = if pats.iter().all(|p| case.insensitive(p)) { Case::Insensitive } else { Case::Sensitive };
        Grep::with_case(&pats.iter().map(|p| regex::escape(p)).collect::<Vec<_>>().join("|"), GrepMode::Regex, case)
    }

    fn build(&self) -> Result<Regex, String> {
        // CRLF: `$` also matches before a \r\n line end (Windows files).
        let b = RegexBuilder::new(&self.src).case_insensitive(self.case_insensitive).multi_line(true).crlf(true).size_limit(1 << 26).build();
        b.map_err(|e| e.to_string())
    }

    fn re(&self) -> &Regex {
        // A literal's regex always compiles (it was 4096 bytes at most).
        self.re.get_or_init(|| self.build().expect("literal regex"))
    }

    /// Hashes of the grams every match holds (see `SHORT`).
    fn probes(&self) -> Probes {
        // (A non-ASCII letter's other case may be other bytes.)
        let cased = self.case_insensitive && cased(&self.pattern);
        let grams = |n: usize| {
            let mut out: Vec<u32> = if self.mode == GrepMode::Regex {
                Vec::new()
            } else {
                let grams = self.pattern.as_bytes().windows(n).filter(|w| !cased || w.is_ascii());
                grams.map(|w| gram_hash(w.iter().fold(0, |g, &b| g << 8 | fold(b) as u64))).collect()
            };
            out.sort_unstable();
            out.dedup();
            out
        };
        Probes { short: grams(SHORT) }
    }

    fn plan(&self) -> TQ {
        let q = match self.mode {
            // Exactly the docs that define it (plus rare hash collisions,
            // which reading the file weeds out).
            GrepMode::Symbol if plain_identifier(self.pattern.as_bytes()) => return TQ::Tri(symbol_key(self.pattern.as_bytes())),
            GrepMode::Literal | GrepMode::Symbol => literal_plan(self.pattern.as_bytes()),
            GrepMode::Regex => regex_syntax::Parser::new().parse(&self.pattern).map_or(TQ::All, |h| regex_plan(&h)),
        };
        // The index folds ASCII only: a non-ASCII letter's other case is
        // other bytes.
        if self.case_insensitive && cased(&self.pattern) { ascii_only(q) } else { q }
    }
}

#[derive(Default)]
pub struct GrepResult {
    pub files: Vec<FileMatches>,
    pub candidates: usize,
    pub read: usize,
    /// False if the time budget ran out before every candidate was read.
    pub complete: bool,
    /// Where the next page starts (as `Grep::skip`), if there may be more.
    pub next: Option<usize>,
}

/// Threads reading candidates (the searching one and helpers): opens on this
/// Mac stop scaling past ~4 (the kernel's read authorization contends;
/// measured on hot files: 7.5 us/file at 4 threads, 9 at 8, 14 at 12). Past
/// the first FIRST candidates of a search reading alone, up to two more
/// threads join (`readers_more`), which match what was read while at most
/// OPENING threads open files.
const READERS: usize = 4;
const READERS_MORE: usize = 6;
const OPENING: usize = 4;

/// The read threads of a search reading alone past its FIRST candidates:
/// READERS_MORE, but no more than the cores above the efficiency ones. An M4
/// mini (4 performance, 6 efficiency) ran all-matches greps 1.4-1.6x slower
/// with the two extra threads (on efficiency cores, and the gate's waiting
/// spins on performance ones); the M6 (2 + 4 above its 6) gains 0.85x.
fn readers_more() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        let get = |name: &str| {
            let name = std::ffi::CString::new(name).ok()?;
            let (mut v, mut len) = (0i32, std::mem::size_of::<i32>());
            let ok = unsafe { libc::sysctlbyname(name.as_ptr(), (&raw mut v).cast(), &mut len, std::ptr::null_mut(), 0) } == 0;
            (ok && v > 0).then_some(v as usize)
        };
        // The levels run fastest first; the last one is the efficiency cores.
        let fast = match get("hw.nperflevels") {
            Some(n) if n > 1 => (0..n - 1).filter_map(|i| get(&format!("hw.perflevel{i}.physicalcpu"))).sum(),
            _ => get("hw.physicalcpu").unwrap_or(READERS),
        };
        fast.clamp(READERS, READERS_MORE)
    })
}
/// Index searches reading candidates now (see READERS).
static READING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
/// Folders outside the index (`in:/etc`) are read with more threads: their
/// files are mostly small and not in the page cache, so reads wait on the
/// disk more than on the open() tax.
const SCAN_READERS: usize = 8;

/// A scan's thread, once it has read AHEAD_AFTER files, takes SCAN_RUN of
/// them at a time and keeps AHEAD open, their reads started (as the build
/// reads). A big folder's files come from the disk even when warm (macOS
/// keeps ~250k vnodes, and a file's cached pages go with its vnode): one read
/// at a time per thread waits on each, and threads taking every other file
/// wait on the same folders. Every match in Chromium's 467k files, M6:
/// 11.5-15.2 -> 6.6-6.7 s. First pages that fill early read as before.
const AHEAD: usize = 8;
const AHEAD_AFTER: usize = 64;
const SCAN_RUN: usize = 64;

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
    /// The lines holding a match: number, and text (the line's first 400
    /// bytes, trailing space trimmed).
    pub lines: Vec<(usize, String)>,
    /// Per line, where its matches are and the lines around it.
    pub hits: Vec<Hit>,
}

/// One matched line's matches and context.
#[derive(Clone, Default)]
pub struct Hit {
    /// Byte column of its first match.
    pub col: usize,
    /// Its matches as byte ranges in the line's text.
    pub ranges: Vec<(usize, usize)>,
    /// One of them is where the name it matched is defined (with `Grep::defs`).
    pub def: bool,
    /// The lines before and after it (`Grep::before`, `Grep::after`).
    pub before: Vec<String>,
    pub after: Vec<String>,
}

/// Read candidates in rank order until `limit` files have matched or the
/// time budget is spent (best-ranked results first, so a cut-short search
/// still returns the ones you most likely wanted). Each read thread claims
/// the next unread candidate, so the files read are always a prefix of the
/// ranking and reading stops as soon as the `limit`th match is in. A file
/// counts only if the content build would take it for text (`is_text`).
pub fn verify(g: &Grep, paths: &[impl AsRef<[u8]> + Sync], limit: usize) -> GrepResult {
    verify_as(g, paths, limit, Reading::Scan)
}

/// Grep one file the user named: its text is read whatever it looks like
/// (minified, a NUL byte past its first 8 KB), unlike a file a search
/// comes across, which counts only as the index would hold it.
pub fn grep_file(g: &Grep, path: &[u8]) -> GrepResult {
    verify_as(g, &[path], 1, Reading::Named)
}

fn verify_as(g: &Grep, paths: &[impl AsRef<[u8]> + Sync], limit: usize, how: Reading) -> GrepResult {
    let mut r = verify_from(g, g.skip.min(paths.len()), paths.len(), limit, how, std::time::Instant::now(), |i| Some(paths[i].as_ref().into())).0;
    r.next = r.next.filter(|&x| x < paths.len());
    r
}

/// What a search reads, which says how it reads them and whether a file
/// must pass the content build's text test (`is_text`) to count: a file
/// read directly answers as the index will once it holds the file.
#[derive(Clone, Copy)]
enum Reading {
    /// The content index's candidates (the build took them for text).
    Index,
    /// Files changed since their folder's last sync, read as candidates.
    Fresh,
    /// Files read without the index (its first build, folders it doesn't
    /// cover): more threads, opened ahead (see SCAN_READERS, AHEAD).
    Scan,
    /// One file the user named, read whatever its text looks like.
    Named,
}

impl Reading {
    fn scan(self) -> bool {
        matches!(self, Reading::Scan | Reading::Named)
    }

    fn text_test(self) -> bool {
        matches!(self, Reading::Fresh | Reading::Scan)
    }
}

/// `verify` over candidates `from..n`, `path(i)` giving the i-th, or None
/// if the index already rules it out; the budget counts from `t`. Also
/// returns how far it got through them.
fn verify_from<'a>(
    g: &Grep,
    from: usize,
    n: usize,
    limit: usize,
    how: Reading,
    t: std::time::Instant,
    path: impl Fn(usize) -> Option<std::borrow::Cow<'a, [u8]>> + Sync,
) -> (GrepResult, usize) {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let (scan, text) = (how.scan(), how.text_test());
    let (next, found, read, opening) = (AtomicUsize::new(from), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let hits = std::sync::Mutex::new(Vec::new());
    let work = || {
        // Files taken, each read before the thread stops (so all before
        // `next` are); a scan gone deep takes runs and opens ahead (`AHEAD`).
        let (mut taken, mut mine, mut run) = (std::collections::VecDeque::new(), 0, 0..0);
        loop {
            let deep = scan && mine >= AHEAD_AFTER;
            let depth = if deep { AHEAD } else { 1 };
            while taken.len() < depth {
                if run.is_empty() {
                    if found.load(Relaxed) >= limit || g.budget.is_some_and(|b| t.elapsed() > b) {
                        break;
                    }
                    let k = if deep { SCAN_RUN } else { 1 };
                    let at = next.fetch_add(k, Relaxed);
                    if at >= n {
                        break;
                    }
                    run = at..(at + k).min(n);
                }
                let i = run.next().unwrap();
                let Some(p) = path(i) else { continue };
                let f = deep.then(|| open_ahead_sized(&p));
                taken.push_back((i, p, f));
            }
            let Some((i, p, f)) = taken.pop_front() else { break };
            read.fetch_add(1, Relaxed);
            mine += 1;
            let m = match f {
                Some(f) => f.and_then(|(file, size)| match_open(g, &p, file, size, text)),
                None => match_file(g, &p, (!scan).then_some(&opening), text),
            };
            if let Some(m) = m {
                found.fetch_add(1, Relaxed);
                hits.lock().unwrap().push((i, m));
            }
        }
        // Don't sit on a big file's worth of buffer between searches.
        READ_BUF.with_borrow_mut(|b| {
            if b.capacity() as u64 > READ_BUF_MAX {
                *b = Vec::new();
            }
        });
    };
    let others = if scan { 0 } else { READING.fetch_add(1, Relaxed) };
    let readers = if scan {
        SCAN_READERS
    } else if n - from > FIRST && others == 0 {
        readers_more()
    } else {
        READERS
    };
    without_materializing(|| run_lanes(readers, &work));
    if !scan {
        READING.fetch_sub(1, Relaxed);
    }
    let mut hits = hits.into_inner().unwrap();
    hits.sort_unstable_by_key(|h| h.0);
    hits.truncate(limit);
    let done = next.into_inner().min(n);
    let complete = done == n || hits.len() >= limit;
    // The next page: past the last file shown, or where reading stopped.
    let more = if hits.len() >= limit { hits.last().map(|h| h.0 + 1) } else { (done < n).then_some(done) };
    let files = hits.into_iter().map(|h| h.1).collect();
    (GrepResult { files, candidates: n, read: read.into_inner(), complete, next: more }, done)
}

thread_local! {
    /// One read buffer per read-pool thread, for files up to READ_BUF_MAX
    /// (kept: a fresh Vec per file costs page faults every time, and a
    /// freed big one stays in the footprint anyway).
    static READ_BUF: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}
const READ_BUF_MAX: u64 = 1 << 20;

/// A file's matches (see `matches_in`).
fn match_file(g: &Grep, path: &[u8], opening: Option<&std::sync::atomic::AtomicUsize>, text: bool) -> Option<FileMatches> {
    let (file, size) = match opening {
        Some(at) => open_gated(path, at),
        None => open_sized(path),
    }?;
    match_open(g, path, file, size, text)
}

/// `match_file` on a file opened at `size` bytes.
fn match_open(g: &Grep, path: &[u8], mut file: std::fs::File, size: u64, text: bool) -> Option<FileMatches> {
    use std::io::{Read, Seek};
    if size > MAX_REPO_FILE {
        return None;
    }
    // A big file gets pages of its own, handed back when done: macOS malloc
    // keeps a freed big buffer in the process's footprint, a new one for
    // each such file read. (One that grew since is read whole, below.)
    if size > READ_BUF_MAX {
        let mut map = memmap2::MmapMut::map_anon(size as usize + 1).ok()?;
        let mut n = 0;
        while n < map.len() {
            match file.read(&mut map[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        if n <= size as usize {
            return matches_in(g, path, &map[..n], text);
        }
        file.rewind().ok()?;
    }
    READ_BUF.with_borrow_mut(|buf| {
        buf.clear();
        file.take(MAX_REPO_FILE + 1).read_to_end(buf).ok()?;
        matches_in(g, path, buf, text)
    })
}

/// The matching lines of a file's text (None if it's past the size limit,
/// or not text: a NUL byte in its first 8 KB, or with `text`, the content
/// build's whole test, decided only for a file that matched).
fn matches_in(g: &Grep, path: &[u8], buf: &[u8], text: bool) -> Option<FileMatches> {
    if buf.len() as u64 > MAX_REPO_FILE || memchr::memchr(0, &buf[..buf.len().min(8192)]).is_some() {
        return None;
    }
    let (lines, hits) = match g.literal.as_ref().filter(|l| !l.needs_regex(buf)) {
        Some(l) => lines_at(g, buf, l.starts(buf).map(|p| (p, p + l.len()))),
        None => lines_at(g, buf, on_lines(g.re(), buf)),
    };
    (!lines.is_empty() && (!text || is_text(buf))).then(|| FileMatches { path: path.to_vec(), lines, hits })
}

/// The first `max_per_file` lines holding a match (by where matches start),
/// numbered, as shown, and where the matches on them are.
fn lines_at(g: &Grep, buf: &[u8], found: impl Iterator<Item = (usize, usize)>) -> (Vec<(usize, String)>, Vec<Hit>) {
    let (mut lines, mut hits) = (Vec::new(), Vec::<Hit>::new());
    let (mut line_no, mut counted) = (1usize, 0usize);
    // The current line, as it is shown.
    let (mut ls, mut le, mut raw, mut utf8) = (0, 0, &buf[..0], true);
    for (start, end) in found {
        if hits.is_empty() || start > le {
            if lines.len() >= g.max_per_file {
                break;
            }
            line_no += memchr::memchr_iter(b'\n', &buf[counted..start]).count();
            counted = start;
            ls = memchr::memrchr(b'\n', &buf[..start]).map_or(0, |p| p + 1);
            le = memchr::memchr(b'\n', &buf[start..]).map_or(buf.len(), |p| start + p);
            raw = &buf[ls..le.min(ls + 400)];
            let text = String::from_utf8_lossy(raw);
            utf8 = matches!(text, std::borrow::Cow::Borrowed(_));
            lines.push((line_no, text.trim_end().to_string()));
            let (before, after) = (lines_before(buf, ls, g.before), lines_after(buf, le, g.after));
            hits.push(Hit { col: start - ls, before, after, ..Default::default() });
        }
        // Offsets in the shown text (past invalid UTF-8, after its replacements).
        let text = &lines.last().unwrap().1;
        let at = |off: usize| if utf8 { off.min(raw.len()) } else { String::from_utf8_lossy(&raw[..off.min(raw.len())]).len() }.min(text.len());
        let (a, b) = (at(start - ls), at(end.min(le) - ls));
        let hit = hits.last_mut().unwrap();
        if start - ls < raw.len() {
            hit.ranges.push((a, b.max(a)));
        }
        hit.def |= g.defs && defined_at(buf, start, end - start);
    }
    (lines, hits)
}

/// A regex's matches as ripgrep finds them, each within its line: the lines
/// a match runs across are searched again one at a time. Past a final
/// newline (or in an empty file) there is no line, so no match either.
fn on_lines<'a>(re: &'a Regex, buf: &'a [u8]) -> impl Iterator<Item = (usize, usize)> + 'a {
    let lines_end = buf.len() + buf.last().is_some_and(|&b| b != b'\n') as usize;
    let (mut at, mut last, mut queue) = (0, None, std::collections::VecDeque::new());
    std::iter::from_fn(move || {
        loop {
            if let Some(m) = queue.pop_front() {
                return Some(m);
            }
            let m = re.find_at(buf, at.min(buf.len())).filter(|_| at <= buf.len())?;
            // (As find_iter: no empty match where the last one ended.)
            if m.is_empty() && last == Some(m.end()) {
                at += 1;
                continue;
            }
            if memchr::memchr(b'\n', m.as_bytes()).is_none() {
                (at, last) = (m.end(), Some(m.end()));
                return Some((m.start(), m.end()));
            }
            let mut ls = memchr::memrchr(b'\n', &buf[..m.start()]).map_or(0, |p| p + 1);
            let end = memchr::memchr(b'\n', &buf[m.end()..]).map_or(buf.len(), |p| m.end() + p);
            for line in buf[ls..end].split(|&b| b == b'\n') {
                let found = re.find_iter(line).map(|x| (ls + x.start(), ls + x.end()));
                queue.extend(found.filter(|x| x.0 >= at && (x.1 > at || last != Some(at))));
                ls += line.len() + 1;
            }
            (at, last) = (end + 1, None);
        }
    })
    .take_while(move |m| m.0 < lines_end)
}

/// A line as shown: its first 400 bytes, trailing space trimmed.
fn shown(line: &[u8]) -> String {
    String::from_utf8_lossy(&line[..line.len().min(400)]).trim_end().to_string()
}

/// Up to `n` lines before the line starting at `ls`, in order.
fn lines_before(buf: &[u8], mut ls: usize, n: usize) -> Vec<String> {
    let mut out = Vec::new();
    while out.len() < n && ls > 0 {
        let s = memchr::memrchr(b'\n', &buf[..ls - 1]).map_or(0, |p| p + 1);
        out.push(shown(&buf[s..ls - 1]));
        ls = s;
    }
    out.reverse();
    out
}

/// Up to `n` lines after the line ending at `le` (its newline, or the end).
fn lines_after(buf: &[u8], mut le: usize, n: usize) -> Vec<String> {
    let mut out = Vec::new();
    while out.len() < n && le + 1 < buf.len() {
        let s = le + 1;
        le = memchr::memchr(b'\n', &buf[s..]).map_or(buf.len(), |p| s + p);
        out.push(shown(&buf[s..le]));
    }
    out
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

    fn len(&self) -> usize {
        match self {
            Literal::Exact(f) | Literal::Definition(f) => f.needle().len(),
            Literal::Folded { needle, .. } => needle.len(),
        }
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

/// A plan without the trigrams and pairs holding non-ASCII bytes.
fn ascii_only(q: TQ) -> TQ {
    match q {
        TQ::Tri(t) if t < 1 << 24 && t.to_be_bytes()[1..].iter().any(|&b| b >= 0x80) => TQ::All,
        TQ::Pair(p) if p.to_be_bytes()[1..3].iter().any(|&b| b >= 0x80) => TQ::All,
        TQ::And(v) => TQ::And(v.into_iter().map(ascii_only).collect()),
        TQ::Or(v) => TQ::Or(v.into_iter().map(ascii_only).collect()),
        q => q,
    }
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
    /// Ascending contents in interpolative code.
    Ic(Ic<'a>),
}

/// Contents per block of an interpolative list (see `Postings::push`).
const BLOCK: usize = 128;

/// Bits to write any of 0..=r.
#[inline]
fn width(r: u32) -> u32 {
    32 - r.leading_zeros()
}

/// A bit stream being written, least significant bit first.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl Bits {
    /// Append the low `w` (at most 32) bits of `v` (`v` < 2^w).
    fn put(&mut self, v: u32, w: u32) {
        self.acc |= (v as u64) << self.n;
        self.n += w;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            (self.acc, self.n) = (self.acc >> 8, self.n - 8);
        }
    }

    fn len(&self) -> usize {
        self.out.len() * 8 + self.n as usize
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// `w` (at most 32) bits of `b` from bit `pos` (zeros past its end).
#[inline]
fn get_bits(b: &[u8], pos: usize, w: u32) -> u32 {
    let at = pos / 8;
    let word = match b.get(at..at + 8) {
        Some(x) => u64::from_le_bytes(x.try_into().unwrap()),
        None => b.get(at..).unwrap_or(&[]).iter().rev().fold(0, |x, &y| x << 8 | y as u64),
    };
    (word >> (pos % 8) & ((1u64 << w) - 1)) as u32
}

/// Write ascending `a`, all within lo..=hi, in binary interpolative code:
/// the middle value in as few bits as its bounds allow, then each half
/// within the bounds that leaves. Contents of one folder cluster, and a run
/// of consecutive ones costs nothing.
fn ic_put(w: &mut Bits, a: &[u32], lo: u32, hi: u32) {
    let m = a.len() / 2;
    let Some(&x) = a.get(m) else { return };
    let low = lo + m as u32;
    w.put(x - low, width(hi - (a.len() - 1 - m) as u32 - low));
    ic_put(w, &a[..m], lo, x.wrapping_sub(1));
    ic_put(w, &a[m + 1..], x + 1, hi);
}

/// Read what `ic_put` wrote of `out.len()` values within lo..=hi, from bit `pos`.
fn ic_get(b: &[u8], pos: &mut usize, out: &mut [u32], lo: u32, hi: u32) {
    let n = out.len();
    if (hi - lo) as usize + 1 == n {
        for (k, o) in out.iter_mut().enumerate() {
            *o = lo + k as u32;
        }
        return;
    }
    let m = n / 2;
    let low = lo + m as u32;
    let k = width(hi - (n - 1 - m) as u32 - low);
    let x = low + get_bits(b, *pos, k);
    *pos += k as usize;
    out[m] = x;
    let (left, right) = out.split_at_mut(m);
    if m > 0 {
        ic_get(b, pos, left, lo, x - 1);
    }
    if m + 1 < n {
        ic_get(b, pos, &mut right[1..], x + 1, hi);
    }
}

/// Whether what `ic_put` wrote of `n` values within lo..=hi, from bit `pos`,
/// holds `x`: the middle value, then only the half `x` would be in (a lower
/// half passed over is decoded, to find where the upper one starts). About
/// half the values are read, on average. (`passed`: room for those.)
fn ic_has(b: &[u8], mut pos: usize, mut n: usize, mut lo: u32, mut hi: u32, x: u32, passed: &mut [u32]) -> bool {
    while n > 0 && (lo..=hi).contains(&x) {
        if (hi - lo) as usize + 1 == n {
            return true;
        }
        let m = n / 2;
        let low = lo + m as u32;
        let k = width(hi - (n - 1 - m) as u32 - low);
        let v = low + get_bits(b, pos, k);
        pos += k as usize;
        if x <= v {
            if x == v {
                return true;
            }
            (n, hi) = (m, v - 1);
        } else {
            if m > 0 {
                ic_get(b, &mut pos, &mut passed[..m], lo, v - 1);
            }
            (n, lo) = (n - m - 1, v + 1);
        }
    }
    false
}

/// An interpolative list (see `Postings::push`): its contents, below `n`.
#[derive(Clone, Copy)]
struct Ic<'a> {
    len: usize,
    n: u32,
    /// Per block but the last: its last content and where the next block's
    /// bits start (u32 each).
    skips: &'a [u8],
    bits: &'a [u8],
    /// Where the first block's bits start.
    start: usize,
}

impl<'a> Ic<'a> {
    fn new(bytes: &'a [u8], skips: bool, n: u32) -> Ic<'a> {
        if skips {
            let len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            let t = 4 + 8 * (len.div_ceil(BLOCK) - 1);
            return Ic { len, n, skips: &bytes[4..t], bits: &bytes[t..], start: 0 };
        }
        // An Elias-gamma count.
        let z = get_bits(bytes, 0, 32).trailing_zeros();
        let len = (1 << z | get_bits(bytes, z as usize + 1, z)) as usize;
        Ic { len, n, skips: &[], bits: bytes, start: 2 * z as usize + 1 }
    }

    fn blocks(&self) -> usize {
        self.len.div_ceil(BLOCK)
    }

    /// Skip entry `j`: (block j's last content, where block j + 1 starts).
    fn skip(&self, j: usize) -> (u32, usize) {
        let e = u64::from_le_bytes(self.skips[8 * j..8 * j + 8].try_into().unwrap());
        (e as u32, (e >> 32) as usize)
    }

    /// Where block `j` starts: the least content it can hold, and its bits.
    fn start_of(&self, j: usize) -> (u32, usize) {
        if j == 0 { (0, self.start) } else { (self.skip(j - 1).0 + 1, self.skip(j - 1).1) }
    }

    /// The first block from `from` on ending at or past `x` (else the last):
    /// steps doubling along the skip entries, then a binary search.
    fn block_at(&self, from: usize, x: u32) -> usize {
        let last = self.blocks() - 1;
        let (mut lo, mut hi, mut step) = (from, from, 1);
        while hi < last && self.skip(hi).0 < x {
            (lo, hi, step) = (hi + 1, (hi + step).min(last), step * 2);
        }
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.skip(mid).0 < x { lo = mid + 1 } else { hi = mid }
        }
        lo
    }

    /// Whether block `j` holds `x`, without decoding all of it (see `ic_has`).
    fn has(&self, j: usize, x: u32, tmp: &mut [u32; BLOCK]) -> bool {
        let (lo, pos) = self.start_of(j);
        if j + 1 < self.blocks() {
            let last = self.skip(j).0;
            return x == last || (x < last && ic_has(self.bits, pos, BLOCK - 1, lo, last - 1, x, tmp));
        }
        ic_has(self.bits, pos, self.len - BLOCK * j, lo, self.n - 1, x, tmp)
    }

    /// Block `j`'s contents into `out`; how many.
    fn block(&self, j: usize, out: &mut [u32; BLOCK]) -> usize {
        let (lo, mut pos) = self.start_of(j);
        if j + 1 < self.blocks() {
            let last = self.skip(j).0;
            ic_get(self.bits, &mut pos, &mut out[..BLOCK - 1], lo, last - 1);
            out[BLOCK - 1] = last;
            return BLOCK;
        }
        let n = self.len - BLOCK * j;
        ic_get(self.bits, &mut pos, &mut out[..n], lo, self.n - 1);
        n
    }

    /// All its contents, appended to `out`.
    fn decode_into(&self, out: &mut Vec<u32>) {
        let mut buf = [0; BLOCK];
        for j in 0..self.blocks() {
            let n = self.block(j, &mut buf);
            out.extend_from_slice(&buf[..n]);
        }
    }
}

/// A walk along an interpolative list, a block at a time.
struct Cursor<'a> {
    ic: Ic<'a>,
    /// The block at hand (`len` of it decoded into `buf`), and the position
    /// in it.
    j: usize,
    buf: [u32; BLOCK],
    len: usize,
    i: usize,
}

impl<'a> Cursor<'a> {
    /// (Its first block is read when first needed.)
    fn new(ic: Ic<'a>) -> Cursor<'a> {
        Cursor { ic, j: 0, buf: [0; BLOCK], len: 0, i: 0 }
    }

    fn load(&mut self, j: usize) {
        (self.j, self.len, self.i) = (j, self.ic.block(j, &mut self.buf), 0);
    }

    fn next(&mut self) -> Option<u32> {
        self.i += 1;
        if self.i == self.len && self.j + 1 < self.ic.blocks() {
            self.load(self.j + 1);
        }
        self.buf[..self.len].get(self.i).copied()
    }

    /// The first content from here on that is `x` or more.
    fn seek(&mut self, x: u32) -> Option<u32> {
        if self.buf[..self.len].last().is_none_or(|&l| l < x) {
            let from = if self.len == 0 { 0 } else { self.j + 1 };
            if from < self.ic.blocks() {
                self.load(self.ic.block_at(from, x));
            }
        }
        self.i = gallop(&self.buf[..self.len], self.i.min(self.len), x);
        self.buf[..self.len].get(self.i).copied()
    }
}

impl List<'_> {
    /// Append all its docs, ascending.
    fn all_into(self, out: &mut Vec<u32>) {
        match self {
            List::Bits(bytes) => {
                for (w, &b) in bytes.iter().enumerate() {
                    let mut b = b;
                    while b != 0 {
                        out.push(w as u32 * 8 + b.trailing_zeros());
                        b &= b - 1;
                    }
                }
            }
            List::Ic(ic) => ic.decode_into(out),
        }
    }

    /// Append its docs within `docs`, ascending.
    fn decode(self, docs: std::ops::Range<u32>, out: &mut Vec<u32>) {
        match self {
            List::Bits(b) => and_bits(&[b], docs, out),
            List::Ic(ic) => {
                let mut c = Cursor::new(ic);
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
            // Fewer to find than it has blocks: each tested in its block.
            List::Ic(ic) if acc.len() < ic.blocks() => {
                let (mut j, mut tmp) = (0, [0; BLOCK]);
                acc.retain(|&d| {
                    j = ic.block_at(j, d);
                    ic.has(j, d, &mut tmp)
                });
            }
            List::Ic(ic) => {
                let mut c = Cursor::new(ic);
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
            let (mut bits, mut buf) = (vec![0u64; s.nown.div_ceil(64)], Vec::new());
            let lists = s.lists_from(s.block_of(*p as u64)).skip_while(|&(k, _)| k < *p).take_while(|&(k, _)| k <= p | 0xFF);
            for (_, l) in lists {
                match l {
                    List::Bits(b) => {
                        for (w, c) in bits.iter_mut().zip(b.chunks(8)) {
                            *w |= c.iter().rev().fold(0, |x, &y| x << 8 | y as u64);
                        }
                    }
                    List::Ic(ic) => {
                        buf.clear();
                        ic.decode_into(&mut buf);
                        buf.iter().for_each(|&d| bits[d as usize / 64] |= 1 << (d % 64));
                    }
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
                        Some(List::Ic(b)) => vars.push(b),
                        None => return Some(Vec::new()),
                    },
                    TQ::All => {}
                    q => rest.push(q),
                }
            }
            vars.sort_by_key(|v| v.len);
            let mut acc = None;
            if let Some((&first, vars)) = vars.split_first() {
                let mut v = Vec::new();
                List::Ic(first).decode(docs.clone(), &mut v);
                for &b in &bits {
                    List::Bits(b).retain(&mut v);
                }
                for &b in vars {
                    if v.is_empty() {
                        break;
                    }
                    List::Ic(b).retain(&mut v);
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
                (p, live.base.mtime(h.idx as usize))
            }
        })
        .collect();
    files.sort_by_key(|(_, m)| std::cmp::Reverse(*m));
    files.into_iter().map(|(p, _)| p).collect()
}

/// `open_sized` once fewer than OPENING of a search's read threads (`at`
/// counts them) are opening a file (see READERS); waits are an open or two
/// long, so they spin. Per search: across searches a shared limit only
/// makes waiters crowd out the threads opening.
fn open_gated(path: &[u8], at: &std::sync::atomic::AtomicUsize) -> Option<(std::fs::File, u64)> {
    use std::sync::atomic::Ordering::*;
    while at.fetch_add(1, Acquire) >= OPENING {
        at.fetch_sub(1, Relaxed);
        while at.load(Relaxed) >= OPENING {
            std::hint::spin_loop();
        }
    }
    let f = open_sized(path);
    at.fetch_sub(1, Release);
    f
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
    let f =
        std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | crate::walk::NOFOLLOW).open(std::ffi::OsStr::from_bytes(path)).ok()?;
    let m = f.metadata().ok()?;
    m.is_file().then_some((f, m.len()))
}

/// `open_regular` for a file about to be indexed, telling the kernel to
/// start reading it now (as much as indexing reads).
fn open_ahead(path: &[u8]) -> Option<std::fs::File> {
    open_ahead_sized(path).map(|(f, _)| f)
}

/// `open_ahead`, and the file's size.
fn open_ahead_sized(path: &[u8]) -> Option<(std::fs::File, u64)> {
    use std::os::unix::io::AsRawFd;
    let (f, len) = open_sized(path)?;
    let ra = libc::radvisory { ra_offset: 0, ra_count: len.min(MAX_REPO_FILE + 1) as libc::c_int };
    unsafe { libc::fcntl(f.as_raw_fd(), libc::F_RDADVISE, &ra) };
    Some((f, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walk::{Listing, RawEnt};

    /// The lines of `buf` a grep shows.
    fn lines(g: &Grep, buf: &[u8]) -> Vec<(usize, String)> {
        matches_in(g, b"/f", buf, false).map_or(Vec::new(), |f| f.lines)
    }

    /// A zero-byte file is never opened for indexing; once it is
    /// non-empty again, its folder's resync picks it up.
    #[test]
    fn zero_byte_files_are_never_picked() {
        let want_for = |size: u64| {
            let dir = |id: u32, name: &[u8], child: u32| Listing {
                id,
                names: name.to_vec(),
                ents: vec![RawEnt { name_off: 0, name_len: name.len() as u16, kind: KIND_DIR, size: 0, mtime: 0, child }],
            };
            let names = b"empty.txtfull.txt".to_vec();
            let ents = vec![
                RawEnt { name_off: 0, name_len: 9, kind: KIND_FILE, size, mtime: 1, child: crate::walk::NONE },
                RawEnt { name_off: 9, name_len: 8, kind: KIND_FILE, size: 3, mtime: 1, child: crate::walk::NONE },
            ];
            let idx = crate::index::Index::build(vec![dir(0, b"t", 1), dir(1, b"d", 2), Listing { id: 2, names, ents }], 0, 0, b"/t/d");
            let live = Live::new(idx);
            let want = wanted(&live, b"/t", b"/t/d", true);
            (0..want.len()).map(|i| want.path(i).to_vec()).collect::<Vec<_>>()
        };
        assert_eq!(want_for(0), vec![b"/t/d/full.txt".to_vec()]);
        assert_eq!(want_for(3), vec![b"/t/d/empty.txt".to_vec(), b"/t/d/full.txt".to_vec()]);
    }

    /// `$` ends a line before a \r\n as before a \n.
    #[test]
    fn crlf_line_ends() {
        let g = Grep::new("foo$", GrepMode::Regex).unwrap();
        assert_eq!(lines(&g, b"foo\r\nbar\r\nfoo"), [(1, "foo".to_string()), (3, "foo".to_string())]);
    }

    /// A case-insensitive search through the index finds what the regex
    /// folds to: ÉMILE for émile. Plans without such letters stay as they
    /// were.
    #[test]
    fn case_folds_through_the_index() {
        let d = std::env::temp_dir().join(format!("fsearch-fold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let mut docs = Docs::default();
        // Real, as the index holds paths: files are opened refusing links.
        let d = d.canonicalize().unwrap();
        for (name, text) in [("b.txt", "dear ÉMILE\n"), ("c.txt", "a key for émile\n"), ("d.txt", "none\n")] {
            let p = d.join(name);
            std::fs::write(&p, text).unwrap();
            docs.push(p.as_os_str().as_bytes(), text.len() as u64, 1);
        }
        docs.sort();
        let mut c = Content::open(d.join("idx"));
        let id = c.alloc_id();
        c.push(build_segment(&c.dir, id, &docs, 0..docs.len()).unwrap());
        let found = |pattern: &str, mode: GrepMode| {
            let mut g = Grep::new(pattern, mode).unwrap();
            g.budget = None;
            let r = c.search(&g, &Query::parse("", "/h").unwrap());
            let mut f: Vec<String> = r.files.iter().map(|f| String::from_utf8_lossy(&f.path[d.as_os_str().len() + 1..]).into_owned()).collect();
            f.sort();
            f
        };
        let r = [found("émile", GrepMode::Literal), found("é", GrepMode::Regex)];
        let _ = std::fs::remove_dir_all(&d);
        let e = vec!["b.txt".to_string(), "c.txt".into()];
        assert_eq!(r, [e.clone(), e]);
        let plan = |p: &str| format!("{:?}", Grep::new(p, GrepMode::Literal).unwrap().plan());
        assert_eq!(plan("hello world"), format!("{:?}", literal_plan(b"hello world")));
    }

    /// A rescan of a folder above home syncs all of home; one of a sibling
    /// whose name home's starts with (/Users/m for /Users/me) does not.
    #[test]
    fn trees_above_home() {
        let dir = |off, len, child| RawEnt { name_off: off, name_len: len, kind: KIND_DIR, size: 0, mtime: 0, child };
        let ls = vec![
            Listing { id: 0, names: b"Users".to_vec(), ents: vec![dir(0, 5, 1)] },
            Listing { id: 1, names: b"mme".to_vec(), ents: vec![dir(0, 1, 2), dir(1, 2, 3)] },
            Listing { id: 2, ..Default::default() },
            Listing { id: 3, ..Default::default() },
        ];
        let live = Live::new(crate::index::Index::build(ls, 0, 0, b"/Users/me"));
        let synced = |tree: &[u8]| wants(&live, b"/Users/me", &[], &[tree.to_vec()]).into_iter().map(|w| (w.0, w.1)).collect::<Vec<_>>();
        assert_eq!(synced(b"/Users/m"), []);
        for above in [&b"/"[..], b"/Users"] {
            assert_eq!(synced(above), [(b"/Users/me".to_vec(), true)]);
        }
    }

    /// Bits past the last doc in a `.dead` file (it is only ever written
    /// whole, so a corrupt one) are not counted as dead docs.
    #[test]
    fn dead_bits_past_the_docs() {
        let d = std::env::temp_dir().join(format!("fsearch-dead-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("a.txt");
        std::fs::write(&p, "text\n").unwrap();
        let mut docs = Docs::default();
        docs.push(p.as_os_str().as_bytes(), 5, 1);
        let seg = build_segment(&d, 1, &docs, 0..1).unwrap();
        assert_eq!(seg.live_docs, 1);
        std::fs::write(dead_path(&d, 1), u64::MAX.to_le_bytes()).unwrap();
        let seg = Segment::load(&d, 1);
        let _ = std::fs::remove_dir_all(&d);
        assert_eq!(seg.unwrap().live_docs, 0);
    }
}
