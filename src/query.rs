//! Name search: parse a query, scan the index in parallel, rank, top-k.

use crate::index::{BM_DOUBLE, BM_FIRST, BM_SECOND, BM_START, CLASSES, Index, ZONE, Zone, char_bit, start_bit};
use crate::live::Live;
use crate::walk::{FLAG_HIDDEN, KIND_DIR, KIND_FILE, KIND_LINK};
use rayon::prelude::*;
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Fuzzy,
    Exact,
    Prefix,
    Suffix,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub text: Vec<u8>,
    pub mask: u64,
    pub mode: Mode,
    pub negate: bool,
    /// Edits a typo match may take (`typo_score`): 0 when the token takes no
    /// typos.
    pub edits: u32,
    /// Typos that cost a wider search (see `Query::deepen`): a wrong, extra,
    /// missing or swapped first letter, and a second edit past what one
    /// edit leaves possible. Otherwise a typo match keeps the first letter.
    pub deep: bool,
    /// `index::start_bit` of the first letter when the token takes typos,
    /// and when deep with two edits of the second: unless the first letter
    /// is wrong, extra, missing or swapped and the rest right, a typo match
    /// is in a word starting with one of them.
    pub start: u64,
    /// The char classes past the first char: a name the token matches deep
    /// with a wrong, extra, missing or swapped first letter has them all.
    pub rest: u64,
    /// Written after a '/' in its word ("a/b"): the positive token before
    /// it names a folder above what it names.
    pub under: bool,
}

/// What a name's bitmaps or mask leave possible for a token: a clean match,
/// a typo match, a space in it (a word to look for typos in). Each is true
/// unless the work it gates is sure to fail.
type May = (bool, bool, bool);

impl Token {
    /// Can a name with mask `m` (`index::name_mask`) match? Cleanly it has
    /// every char class; with a typo, a word starts like the token and it
    /// lacks at most `lacks` of the `loose` classes (an edit costs one at
    /// most), or, deep, the classes past the first char are all there (see
    /// `TokenBits::words`).
    #[inline(always)]
    fn may(&self, m: u64) -> May {
        let miss = self.mask & !m;
        let near = (miss & !self.loose() == 0) & (miss.count_ones() <= self.lacks()) & (m & self.start != 0);
        (miss == 0, (self.edits > 0) & (near | self.deep & (self.rest & !m == 0)), m & char_bit(b' ') != 0)
    }

    /// How many classes a typo match may lack.
    fn lacks(&self) -> u32 {
        if self.deep { self.edits } else { 1 }
    }

    /// The classes a typo match may lack: any, deep with two edits (the
    /// first letter may be extra), else all but the first letter's.
    fn loose(&self) -> u64 {
        if self.deep && self.edits > 1 { self.mask } else { self.mask & !char_bit(self.text[0]) }
    }

    /// Set `edits`, `start` and `rest` for `deep`.
    fn set_typos(&mut self, deep: bool) {
        self.edits = typo_edits(&self.text, self.mode);
        self.deep = deep && self.edits > 0;
        self.rest = self.text.iter().skip(1).fold(0, |m, &b| m | char_bit(b));
        self.start = match self.edits {
            0 => 0,
            e => start_bit(self.text[0]) | if self.deep && e > 1 { start_bit(self.text[1]) } else { 0 },
        };
    }

    #[inline(always)]
    fn fits(&self, m: u64) -> bool {
        let (clean, typo, _) = self.may(m);
        clean | typo
    }

    /// A token for a lowercase literal a name must contain.
    fn literal(text: Vec<u8>) -> Token {
        let mask = text.iter().fold(0, |m, &b| m | char_bit(b));
        Token { text, mask, mode: Mode::Exact, negate: false, edits: 0, deep: false, start: 0, rest: mask, under: false }
    }
}

/// A name `Searcher::ranked` scored, and the bound on its entries' scores.
struct Cand {
    bound: i32,
    k: u32,
    score: i16,
    flags: u8,
}

/// One word of `Searcher::spread`: the names starting with it and the
/// folders among them, best first, and how many of each were visited; the
/// subtrees of those folders, merged; what bounds the rest of each (a
/// match elsewhere, names past OWN_MAX, folders not looked for or too big
/// to visit).
struct Word {
    own: Vec<(i32, u32)>,
    oc: usize,
    dirs: Vec<(i32, u32, u32)>,
    dc: usize,
    trees: Vec<(u32, u32)>,
    own_pin: i32,
    dir_pin: i32,
}

impl Word {
    /// The best name and folder left.
    fn heads(&self) -> (Option<i32>, Option<i32>) {
        (self.own.get(self.oc).map(|x| x.0), self.dirs.get(self.dc).map(|x| x.0))
    }

    /// What its own name and its folders can bring an entry not seen yet.
    fn term(&self) -> (i32, i32) {
        let (a, b) = self.heads();
        (a.map_or(self.own_pin, |a| a.max(self.own_pin)), b.map_or(self.dir_pin, |b| b.max(self.dir_pin)))
    }
}

/// A value alone on its cache line: per-thread scratch that is written in a
/// hot loop must not share a line with another thread's.
#[derive(Clone, Copy)]
#[repr(align(128))]
struct Line<T>(T);

/// A token's `TokenBits::words` for a pair of words, on its own line.
type Pair = Line<[(u64, u64, u64); 2]>;

/// One token's view of the name bitmaps (`index::BM_FIRST` and on): which
/// of 64 names at a time it can match, before any name is read.
struct TokenBits<'a> {
    /// Each char's class: (first-half, second-half) bitmaps.
    seq: Vec<[&'a [u64]; 2]>,
    /// The token's classes and the ones it has twice (as the bitmap of names
    /// with them twice, in both slots), rarest first, each with whether a
    /// typo match may lack it (`Token::loose`) and whether `Token::rest` has
    /// it.
    classes: Vec<([&'a [u64]; 2], bool, bool)>,
    /// Typo-taking tokens: for each letter of `Token::start` (one twice if
    /// it has one), the names with a word starting with it (or a letter
    /// hashing alike) and the names with it in their first half: a typo
    /// match starts the name, unless the name has a space.
    start: Option<[[&'a [u64]; 2]; 2]>,
    /// Names with a space; with the first and with the second letter in
    /// their first half.
    spaced: [&'a [u64]; 2],
    early: [&'a [u64]; 2],
    lacks: u32,
    /// Deep with two edits: the first letter may be extra or swapped.
    skip0: bool,
    deep: bool,
}

impl<'a> TokenBits<'a> {
    fn new(idx: &'a Index, t: &Token) -> TokenBits<'a> {
        let class = |b: u8| char_bit(b).trailing_zeros() as usize;
        let pair = |c: usize| [idx.bitmap(BM_FIRST + c), idx.bitmap(BM_SECOND + c)];
        let (counts, doubles) = (idx.class_counts(), idx.double_counts());
        // The classes, and the classes the token has twice (which a name
        // needs twice too), rarest first.
        let twice = crate::index::doubled(&t.text);
        let mut classes: Vec<(u32, [&[u64]; 2], bool, bool)> = (0..CLASSES)
            .filter(|&c| t.mask & (1 << c) != 0)
            .map(|c| (counts[c], pair(c), t.loose() & (1 << c) != 0, t.rest & (1 << c) != 0))
            .collect();
        classes.extend((0..CLASSES).filter(|&c| twice & (1 << c) != 0).map(|c| (doubles[c], [idx.bitmap(BM_DOUBLE + c); 2], true, false)));
        classes.sort_by_key(|x| x.0);
        let first = |b: u8| idx.bitmap(BM_FIRST + class(b));
        let start = |b: u8| [idx.bitmap(BM_START + crate::index::start_hash(b)), first(b)];
        let skip0 = t.deep && t.edits > 1;
        TokenBits {
            seq: t.text.iter().map(|&b| pair(class(b))).collect(),
            classes: classes.into_iter().map(|x| (x.1, x.2, x.3)).collect(),
            start: (t.edits > 0).then(|| [start(t.text[0]), start(t.text[skip0 as usize])]),
            spaced: pair(class(b' ')),
            early: [first(t.text[0]), first(t.text[(t.text.len() > 1) as usize])],
            lacks: t.lacks(),
            skip0,
            deep: t.deep,
        }
    }

    /// For the 64 names of word `w`: (can match: `Token::fits`, narrowed by
    /// the halves test; can match cleanly; may match with a typo). Cleanly,
    /// the name has every class of the token (twice where the token has it
    /// twice), and some prefix of the token fits the classes of its first
    /// half and the rest its second half. With a typo (`typo_score`), either
    /// the first letter is right and starts a word (deep with two edits, or
    /// the second does: the first is extra or swapped), `Token::lacks` of
    /// those are missing at most (an edit costs the name one at most) and
    /// so does the halves test with as many chars left out (every edit
    /// leaves the rest of the token in order; the first letter stays unless
    /// it may be extra); or, deep, the first letter is wrong, extra, missing
    /// or swapped and the rest right, and the rest passes both tests.
    #[inline]
    fn word(&self, w: usize) -> (u64, u64, u64) {
        self.words::<1>(w)[0]
    }

    /// `word` for words `w..w + B`, side by side: a pair fills a NEON
    /// register, and the loops exit when both words are done, which is
    /// easier to predict than each word on its own.
    #[inline(always)]
    fn words<const B: usize>(&self, w: usize) -> [(u64, u64, u64); B] {
        if self.deep { self.scan::<B, true>(w) } else { self.scan::<B, false>(w) }
    }

    /// `words`, with the deep typo tests only when DEEP.
    #[inline(always)]
    fn scan<const B: usize, const DEEP: bool>(&self, w: usize) -> [(u64, u64, u64); B] {
        let has = |b: &[&[u64]; 2], j: usize| b[0][w + j] | b[1][w + j];
        let none = |x: &[[u64; B]]| x.iter().flatten().fold(0, |a, &b| a | b) == 0;
        // Deep, a typo match starts the name (so in its first half) unless
        // the name has a space.
        let start: [u64; B] = self.start.map_or([0; B], |s| {
            std::array::from_fn(|j| match DEEP {
                false => s[0][0][w + j],
                true => s.iter().fold(0, |a, [st, early]| a | (st[w + j] & (early[w + j] | has(&self.spaced, j)))),
            })
        });
        let twice = if DEEP && self.lacks > 1 { !0 } else { 0 };
        // Names with every class so far; ones starting a word like the
        // token missing one (or two); deep, ones with every class of the
        // rest (and its first letter early, or a space).
        let (mut all, mut one, mut two) = ([!0; B], [0; B], [0; B]);
        let mut rest: [u64; B] = std::array::from_fn(|j| if DEEP { self.early[0][w + j] | self.early[1][w + j] | has(&self.spaced, j) } else { 0 });
        for &(ref b, may_miss, in_rest) in &self.classes {
            if none(&[all, one, two, rest]) {
                break;
            }
            let lack = if may_miss { !0 } else { 0 };
            for j in 0..B {
                let x = has(b, j);
                if DEEP {
                    two[j] = ((two[j] & x) | (one[j] & !x & lack)) & twice;
                    rest[j] &= if in_rest { x } else { !0 };
                }
                one[j] = (one[j] & x) | (all[j] & !x & start[j] & lack);
                all[j] &= x;
            }
        }
        // Names whose first half holds the token so far, and names where
        // the token so far ends in the second half; then the same with one
        // (or two) chars left out, for names starting a word like the
        // token; deep, then for the rest of the token alone.
        let near: [u64; B] = std::array::from_fn(|j| (all[j] | one[j] | two[j]) & start[j]);
        let (mut first, mut second): ([u64; B], _) = (std::array::from_fn(|j| all[j] | near[j]), [0; B]);
        let (mut first1, mut second1, mut first2, mut second2) = ([0; B], [0; B], [0; B], [0; B]);
        let (mut first_r, mut second_r) = (rest, [0; B]);
        for (k, b) in self.seq.iter().enumerate() {
            if none(&[first, second, first1, second1]) && (!DEEP || none(&[first2, second2, first_r, second_r])) {
                break;
            }
            let skip = if k > 0 || self.skip0 { !0 } else { 0 };
            for j in 0..B {
                let (b0, b1) = (b[0][w + j], b[1][w + j]);
                if DEEP {
                    second2[j] = ((second2[j] | first2[j]) & b1) | (second1[j] & near[j] & twice);
                    first2[j] = (first2[j] & b0) | (first1[j] & near[j] & twice);
                    if k > 0 {
                        second_r[j] = (second_r[j] | first_r[j]) & b1;
                        first_r[j] &= b0;
                    }
                }
                second1[j] = ((second1[j] | first1[j]) & b1) | (second[j] & near[j] & skip);
                first1[j] = (first1[j] & b0) | (first[j] & near[j] & skip);
                second[j] = (second[j] | first[j]) & b1;
                first[j] &= b0;
            }
        }
        std::array::from_fn(|j| {
            let clean = (first[j] | second[j]) & all[j];
            let typo = ((first[j] | second[j] | first1[j] | second1[j] | first2[j] | second2[j]) & near[j]) | ((first_r[j] | second_r[j]) & rest[j]);
            (clean | typo, clean, typo)
        })
    }
}

/// What `score_names` holds for name `k`, scored on its own (from its mask
/// rather than the bitmaps): the same hit, or None for the same names.
/// `joined` is `q.joined()`.
#[allow(clippy::too_many_arguments)]
fn name_hit(idx: &Index, q: &Query, pos: &[&Token], neg: &[&Token], joined: &[u8], re: Option<&regex::bytes::Regex>, k: u32) -> Option<NameHit> {
    let nm = idx.uname(k);
    let name: &[u8] = &nm;
    let m = crate::index::name_mask(name);
    let mut h = NameHit { score: 0, bits: 0, flags: name_flags(name), best: [0; 4] };
    for (t, tok) in pos.iter().enumerate() {
        if tok.fits(m)
            && let Some(s) = token_score(name, nm.wide(), tok.may(m), tok)
        {
            h.bits |= 1 << t;
            let s16 = s.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            h.score = h.score.saturating_add(s16);
            if t < 4 {
                h.best[t] = s16.max(0);
            }
        }
    }
    if pos.len() > 1 && h.bits as u32 == (1 << pos.len()) - 1 && !pos.iter().any(|t| t.under) {
        h.score = h.score.saturating_add(spelled(name, joined) as i16);
    }
    if neg.iter().any(|t| token_matches(name, t)) {
        h.flags |= NF_NEG;
    }
    let ok = (pos.is_empty() || h.bits != 0)
        && h.flags & NF_NEG == 0
        && (q.exts.is_empty() || ext_ok(name, &q.exts))
        && q.name_ok(name)
        && re.is_none_or(|re| re.is_match(name));
    if ok {
        h.flags |= NF_OK;
    }
    (ok || h.bits != 0 || h.flags & NF_NEG != 0).then_some(h)
}

/// Lowercased literals one of which starts every match of `re` (so a name
/// it matches contains it), if the regex has a short list of them.
fn re_literals(re: &regex::bytes::Regex) -> Option<Vec<Vec<u8>>> {
    let hir = regex_syntax::ParserBuilder::new().utf8(false).build().parse(re.as_str()).ok()?;
    let mut lits: Vec<Vec<u8>> =
        regex_syntax::hir::literal::Extractor::new().extract(&hir).literals()?.iter().map(|l| l.as_bytes().to_ascii_lowercase()).collect();
    lits.sort();
    lits.dedup();
    lits.iter().all(|l| !l.is_empty()).then_some(lits)
}

/// Lowercased literals one of which ends every path `re` matches, if it is
/// anchored at the end ("swift$") and they hold no '/': then a match's own
/// name, the path's last part, ends with one of them.
fn path_suffixes(re: &regex::bytes::Regex) -> Option<Vec<Vec<u8>>> {
    use regex_syntax::hir::{Look, literal::ExtractKind};
    let hir = regex_syntax::ParserBuilder::new().utf8(false).build().parse(re.as_str()).ok()?;
    if !hir.properties().look_set_suffix().contains(Look::End) {
        return None;
    }
    let seq = regex_syntax::hir::literal::Extractor::new().kind(ExtractKind::Suffix).extract(&hir);
    let mut lits: Vec<Vec<u8>> = seq.literals()?.iter().map(|l| l.as_bytes().to_ascii_lowercase()).collect();
    lits.sort();
    lits.dedup();
    lits.iter().all(|l| !l.is_empty() && !l.contains(&b'/')).then_some(lits)
}

/// Does `name` end with `s` (lowercase), ignoring ASCII case?
fn ends_with_fold(name: &[u8], s: &[u8]) -> bool {
    name.len() >= s.len() && name[name.len() - s.len()..].iter().zip(s).all(|(&a, &b)| fold(a) == b)
}

/// Fuzzy words this long forgive one typo, and this long two (see
/// `typo_score`).
const TYPO_MIN_LEN: usize = 5;
const TYPO2_MIN_LEN: usize = 8;
/// What a typo costs, so clean matches of the same quality rank first.
const TYPO_COST: i32 = 60;

/// How many edits a token's typo matches may take.
fn typo_edits(text: &[u8], mode: Mode) -> u32 {
    if mode != Mode::Fuzzy {
        return 0;
    }
    (text.len() >= TYPO_MIN_LEN) as u32 + (text.len() >= TYPO2_MIN_LEN) as u32
}

#[derive(Clone, Default)]
pub struct Query {
    pub tokens: Vec<Token>,
    pub kind: Option<u8>,
    /// `type:app`: a folder kind also takes symlinks, since the system apps
    /// in /Applications link into the cryptex (/Applications/Safari.app).
    pub apps: bool,
    pub exts: Vec<Vec<u8>>,
    /// Extensions a match may not have (`!*.md`).
    pub not_exts: Vec<Vec<u8>>,
    /// Globs and folders (`src/**/*.rs`, `test/`, `!build/`), all of which
    /// a match passes.
    pub globs: Vec<Glob>,
    pub scope: Option<Vec<u8>>,
    pub size: (u64, u64),
    pub mtime: (u32, u32),
    pub name_re: Option<regex::bytes::Regex>,
    pub path_re: Option<regex::bytes::Regex>,
    pub limit: usize,
    /// Content search: handled by the content layer, carried here so one
    /// query string can say everything.
    pub grep: Option<String>,
    pub grep_mode: GrepMode,
    /// The words in the other Unicode normalization form, if that differs
    /// (see `other_form`): `Searcher::search` looks for those too.
    pub alt: Option<Vec<Token>>,
}

#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub enum GrepMode {
    #[default]
    Literal,
    Regex,
    Symbol,
}

pub struct Hit {
    pub score: i32,
    /// Base entry, or u32::MAX for an overlay entry (then `over` is its path).
    pub idx: u32,
    pub over: Option<Vec<u8>>,
}

#[rustfmt::skip]
const TYPES: &[(&str, &[&str])] = &[
    ("image", &["png", "jpg", "jpeg", "gif", "heic", "heif", "webp", "tiff", "tif", "bmp", "svg", "raw", "cr2", "cr3", "nef", "arw", "dng", "psd", "ico", "icns", "avif", "jxl"]),
    ("video", &["mp4", "mov", "m4v", "mkv", "avi", "webm", "wmv", "flv", "mpg", "mpeg", "3gp", "hevc"]),
    ("audio", &["mp3", "m4a", "aac", "wav", "flac", "aiff", "aif", "ogg", "opus", "alac", "caf", "mid", "midi", "m4r"]),
    ("doc", &["pdf", "doc", "docx", "pages", "txt", "md", "rtf", "odt", "key", "ppt", "pptx", "numbers", "xls", "xlsx", "csv", "epub", "tex"]),
    ("code", &["rs", "c", "h", "cc", "cpp", "hpp", "m", "mm", "swift", "go", "py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "java", "kt", "rb", "php", "cs", "sh", "zsh", "bash", "fish", "lua", "sql", "html", "css", "scss", "json", "yaml", "yml", "toml", "xml", "vue", "svelte", "zig", "nim", "hs", "ml", "ex", "exs", "erl", "clj", "dart", "r", "jl", "metal", "glsl", "wgsl", "proto", "graphql", "nix"]),
    ("archive", &["zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "dmg", "pkg", "iso", "zst", "lz4", "xip"]),
    ("font", &["ttf", "otf", "woff", "woff2", "ttc", "dfont"]),
];

impl Query {
    /// Parse the human query language. Plain words are fuzzy tokens;
    /// `'x` exact, `^x` prefix, `x$` suffix, `!x` negate; globs (`*.rs`,
    /// `src/**/*.{c,h}`) and folders (`test/`), each negated by `!`;
    /// filters are `ext: type: kind: in: size: mtime: re: path: limit:
    /// grep: regex: sym:`.
    pub fn parse(s: &str, home: &str) -> Result<Query, String> {
        let mut q = Query::parse_form(s, home)?;
        // An accented word may be stored composed (as keyboards type it) or
        // decomposed ("é" as "e" and U+0301, as HFS+ and some apps write
        // names): its other form is searched too.
        if !s.is_ascii()
            && let Some(o) = other_form(s)
            && let Ok(oq) = Query::parse_form(&o, home)
            && oq.tokens.len() == q.tokens.len()
        {
            q.alt = Some(oq.tokens);
        }
        Ok(q)
    }

    fn parse_form(s: &str, home: &str) -> Result<Query, String> {
        let mut q = Query { size: (0, u64::MAX), mtime: (0, u32::MAX), limit: 50, ..Default::default() };
        for word in split_words(s) {
            if let Some((k, v)) = word.split_once(':')
                && q.filter(k, v, home)?
            {
                continue;
            }
            let (negate, w) = word.strip_prefix('!').map_or((false, word.as_str()), |w| (true, w));
            if w.bytes().any(|b| matches!(b, b'*' | b'?' | b'[' | b'{')) || (w.len() > 1 && w.ends_with('/')) {
                q.push_glob(w, negate)?;
                continue;
            }
            for (i, piece) in word.split('/').filter(|p| !p.is_empty()).enumerate() {
                let n = q.tokens.len();
                q.push_token(piece);
                let grew = q.tokens.len() > n;
                if let Some(t) = q.tokens.last_mut().filter(|t| i > 0 && grew && !t.negate) {
                    t.under = true;
                }
            }
        }
        q.fold_glob_exts();
        Ok(q)
    }

    /// A glob whose names are all `*.ext` (`src/**/*.{c,h}`) leaves the
    /// name test to `exts`, which the name bitmaps answer at once.
    fn fold_glob_exts(&mut self) {
        for g in self.globs.iter_mut().filter(|g| !g.negate) {
            let Some(exts) = g.alts.iter().map(|a| a.name.as_ref()?.ext()).collect::<Option<Vec<_>>>() else { continue };
            self.exts = if self.exts.is_empty() { exts } else { self.exts.iter().filter(|e| exts.contains(e)).cloned().collect() };
            if self.exts.is_empty() {
                // Both kinds wanted: no name has a '/'.
                self.exts.push(b"/".to_vec());
            }
            for a in &mut g.alts {
                a.name = Some(Part::Star(vec![Vec::new(), Vec::new()]));
            }
        }
    }

    /// Add a glob or folder word (see `Glob`); `*.rs` and `*.{c,h}` are
    /// extensions.
    pub fn push_glob(&mut self, w: &str, negate: bool) -> Result<(), String> {
        let alts = expand_braces(w);
        let ext = |a: &String| {
            a.strip_prefix("*.").filter(|e| !e.is_empty() && !e.contains(['*', '?', '[', '/', '.'])).map(|e| e.to_ascii_lowercase().into_bytes())
        };
        if let Some(exts) = alts.iter().map(ext).collect::<Option<Vec<_>>>() {
            (if negate { &mut self.not_exts } else { &mut self.exts }).extend(exts);
            return Ok(());
        }
        self.globs.push(Glob { negate, text: w.to_string(), alts: alts.iter().map(|a| glob_alt(a)).collect::<Result<_, _>>()? });
        Ok(())
    }

    pub fn push_token(&mut self, w: &str) {
        let (mut t, mut negate, mut mode) = (w, false, Mode::Fuzzy);
        if let Some(r) = t.strip_prefix('!') {
            (t, negate, mode) = (r, true, Mode::Exact);
        }
        if let Some(r) = t.strip_prefix('\'') {
            (t, mode) = (r, Mode::Exact);
        } else if let Some(r) = t.strip_prefix('^') {
            (t, mode) = (r, Mode::Prefix);
        } else if let Some(r) = t.strip_suffix('$') {
            (t, mode) = (r, Mode::Suffix);
        }
        if t.is_empty() {
            return;
        }
        // Positive tokens are tracked in a u8 bitset: past 8, the first goes
        // (a long path's top folders tell the least).
        if !negate && self.tokens.iter().filter(|t| !t.negate).count() >= 8 {
            let first = self.tokens.iter().position(|t| !t.negate).unwrap();
            self.tokens.remove(first);
            if let Some(t) = self.tokens[first..].iter_mut().find(|t| !t.negate) {
                t.under = false;
            }
        }
        let text: Vec<u8> = t.bytes().map(|b| b.to_ascii_lowercase()).collect();
        let mask = text.iter().fold(0, |m, &b| m | char_bit(b));
        let mut t = Token { text, mask, mode, negate, edits: 0, deep: false, start: 0, rest: 0, under: false };
        t.set_typos(false);
        self.tokens.push(t);
    }

    /// Path words ("a/b"), as bits of the positive tokens: those written
    /// after a '/' (`Token::under`), and the last of them, which names the
    /// entry itself.
    fn path_bits(&self) -> (u32, u32) {
        let under = self.tokens.iter().filter(|t| !t.negate).enumerate().fold(0, |m, (i, t)| m | (t.under as u32) << i);
        (under, if under == 0 { 0 } else { 1 << (31 - under.leading_zeros()) })
    }

    /// The positive words run together, delimiters left out (`spelled`):
    /// empty with fewer than two, or with a path ("a/b" spells folders).
    fn joined(&self) -> Vec<u8> {
        let pos: Vec<&Token> = self.tokens.iter().filter(|t| !t.negate).collect();
        if pos.len() < 2 || pos.iter().any(|t| t.under) {
            return Vec::new();
        }
        pos.iter().flat_map(|t| t.text.iter().copied().filter(|&b| !is_delim(b))).collect()
    }

    /// The name tests past `ext:` and `re:`: `!*.ext`, and the globs' (see
    /// `Glob::name_ok`).
    fn name_ok(&self, name: &[u8]) -> bool {
        (self.not_exts.is_empty() || !ext_ok(name, &self.not_exts)) && self.globs.iter().all(|g| g.name_ok(name))
    }

    /// This query with deep typos (`Token::deep`).
    pub fn deepen(&self) -> Query {
        let mut q = self.clone();
        for t in q.tokens.iter_mut().filter(|t| !t.negate && t.edits > 0) {
            t.set_typos(true);
        }
        q
    }

    /// Apply filter `k:v`; false if `k` is not a filter name.
    pub fn filter(&mut self, k: &str, v: &str, home: &str) -> Result<bool, String> {
        match k {
            "ext" => self.exts.extend(v.split(',').map(|e| e.trim_start_matches('.').to_ascii_lowercase().into_bytes())),
            "type" => {
                for t in v.split(',') {
                    if t == "app" {
                        self.kind = Some(KIND_DIR);
                        self.apps = true;
                        self.exts.push(b"app".to_vec());
                        continue;
                    }
                    let (_, exts) = TYPES.iter().find(|(n, _)| *n == t).ok_or(format!("unknown type {t}"))?;
                    self.exts.extend(exts.iter().map(|e| e.as_bytes().to_vec()));
                }
            }
            "kind" => {
                self.kind = Some(match v {
                    "file" | "f" => KIND_FILE,
                    "dir" | "folder" | "d" => KIND_DIR,
                    "link" | "symlink" | "l" => KIND_LINK,
                    _ => return Err(format!("unknown kind {v}")),
                })
            }
            "in" => {
                let p = v.strip_prefix('~').map_or(v.to_string(), |r| format!("{home}{r}"));
                self.scope = Some(real_path(p).trim_end_matches('/').as_bytes().to_vec());
            }
            "size" => self.size = range(v, parse_size)?,
            "mtime" | "modified" => {
                // mtime:<7d means "modified within the last 7 days".
                let now = now_secs();
                let (lo, hi) = range(v, parse_age)?;
                self.mtime = (now.saturating_sub(hi.min(now as u64) as u32), now.saturating_sub(lo as u32));
                if hi == u64::MAX {
                    self.mtime.0 = 0;
                }
            }
            "re" => self.name_re = Some(regex::bytes::Regex::new(&format!("(?i){v}")).map_err(|e| e.to_string())?),
            "path" => self.path_re = Some(regex::bytes::Regex::new(&format!("(?i){v}")).map_err(|e| e.to_string())?),
            "limit" => self.limit = v.parse().map_err(|_| "bad limit")?,
            "grep" | "content" => (self.grep, self.grep_mode) = (Some(v.to_string()), GrepMode::Literal),
            "regex" => (self.grep, self.grep_mode) = (Some(v.to_string()), GrepMode::Regex),
            "sym" | "symbol" => (self.grep, self.grep_mode) = (Some(v.to_string()), GrepMode::Symbol),
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The parts of a query that pick files for a content scan.
    pub fn clone_for_scan(&self) -> Query {
        Query { grep: None, ..self.clone() }
    }

    #[inline(always)]
    pub fn kind_ok(&self, kind: u8) -> bool {
        match self.kind {
            None => true,
            Some(want) => kind & 3 == want || (self.apps && kind & 3 == KIND_LINK),
        }
    }

    /// Does a full path pass every filter and token? Returns the match score.
    /// Used where there is no dir memo: the overlay and content-search docs.
    pub fn match_path(&self, path: &[u8], kind: u8, size: u64, mtime: u32) -> Option<i32> {
        self.match_path_with(path, kind, size, mtime, |dirs| self.dir_match(dirs))
    }

    /// Whether a path ending in `end` (its last bytes, maybe fewer than its
    /// name's) has an extension asked for, when `end` tells: None if none
    /// are asked for, or the name's extension may begin before `end`. (Lets
    /// a caller skip building a front-coded path.)
    pub fn ext_by_end(&self, end: &[u8]) -> Option<bool> {
        let i = end.iter().rposition(|&b| b == b'.' || b == b'/').filter(|_| !self.exts.is_empty())?;
        Some(end[i] == b'.' && ext_ok(&end[i..], &self.exts))
    }

    /// `match_path`, with the folder half (`dir_match` of the path's folder
    /// part) supplied by the caller, who can memoize it per folder.
    pub fn match_path_with(&self, path: &[u8], kind: u8, size: u64, mtime: u32, dirs: impl FnOnce(&[u8]) -> DirMatch) -> Option<i32> {
        if let Some(s) = &self.scope
            && !(path.starts_with(s) && path.get(s.len()) == Some(&b'/'))
        {
            return None;
        }
        let cut = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
        let name = &path[cut + 1..];
        if name.is_empty()
            || !self.kind_ok(kind)
            || (!self.exts.is_empty() && !ext_ok(name, &self.exts))
            || size < self.size.0
            || size > self.size.1
            || mtime < self.mtime.0
            || mtime > self.mtime.1
        {
            return None;
        }
        if self.tokens.is_empty() {
            let re_ok = self.name_re.as_ref().is_none_or(|re| re.is_match(name)) && self.path_re.as_ref().is_none_or(|re| re.is_match(path));
            let globs_ok = self.name_ok(name) && self.globs.iter().all(|g| g.matches_path(path, self.scope.as_deref()));
            return (re_ok && globs_ok).then_some(0);
        }
        // A hit needs some token in its own name; most paths fail here,
        // before the folders are looked at.
        let mut pos = self.tokens.iter().filter(|t| !t.negate).peekable();
        let m = crate::index::name_mask(name);
        if pos.peek().is_some() && !pos.any(|t| t.fits(m) && token_score(name, None, t.may(m), t).is_some()) {
            return None;
        }
        if self.tokens.iter().any(|t| t.negate && token_matches(name, t)) {
            return None;
        }
        let d = dirs(&path[..cut]);
        if d.negated {
            return None;
        }
        let pos: Vec<&Token> = self.tokens.iter().filter(|t| !t.negate).collect();
        let all = (1u32 << pos.len()) - 1;
        let (mut got, mut inherited, mut score) = (0u32, 0u32, 0i32);
        for (t, tok) in pos.iter().enumerate() {
            if let Some(s) = token_score(name, None, tok.may(m), tok) {
                got |= 1 << t;
                score += s;
            } else if let Some(s) = d.best[t] {
                inherited |= 1 << t;
                score += s * 3 / 4;
            }
        }
        if !pos.is_empty() && (got == 0 || (got | inherited) != all) {
            return None;
        }
        if pos.len() > 1 && got == all && !pos.iter().any(|t| t.under) {
            score += spelled(name, &self.joined());
        }
        let (under, leaf) = self.path_bits();
        if under != 0 {
            let up = path[..cut].rsplit(|&b| b == b'/').next().unwrap_or_default();
            let parent = pos.iter().enumerate().fold(0, |m, (t, tok)| m | (token_score(up, None, (true, true, true), tok).is_some() as u32) << t);
            score += path_fit(got, parent, under, leaf);
        }
        if self.name_re.as_ref().is_some_and(|re| !re.is_match(name)) || self.path_re.as_ref().is_some_and(|re| !re.is_match(path)) {
            return None;
        }
        (self.name_ok(name) && self.globs.iter().all(|g| g.matches_path(path, self.scope.as_deref()))).then_some(score)
    }

    /// How the folders of a path (`/a/b` for `/a/b/name`) match the tokens:
    /// the best score per positive token, and whether a negated one hits.
    pub fn dir_match(&self, dirs: &[u8]) -> DirMatch {
        let comps = || dirs.split(|&b| b == b'/').filter(|c| !c.is_empty());
        let mut d = DirMatch { negated: false, best: [None; 8] };
        d.negated = self.tokens.iter().any(|t| t.negate && comps().any(|c| token_matches(c, t)));
        for (t, tok) in self.tokens.iter().filter(|t| !t.negate).enumerate() {
            d.best[t] = comps().filter_map(|c| token_score(c, None, (true, true, true), tok)).max();
        }
        d
    }
}

/// See `Query::dir_match`.
#[derive(Clone, Copy)]
pub struct DirMatch {
    negated: bool,
    best: [Option<i32>; 8],
}

/// A glob or folder word: `src/**/*.rs`, `*test*`, `test/`, `a/b/`.
/// Without a '/' it is a name at any depth; a trailing '/' means anything
/// under folders so named, anywhere below the scope (as fff's `dir/`).
/// With a '/' inside it is a path below the scope (`./` too; anywhere
/// without one; `/` from the disk's root). `*` and `?` stay in a name,
/// `**` spans folders, braces expand to alternatives.
#[derive(Clone, Debug)]
pub struct Glob {
    pub negate: bool,
    /// As typed, for the name table's cache key.
    pub text: String,
    alts: Vec<Alt>,
}

/// One alternative of a `Glob`: the folders an entry is in, then its name
/// (None: anything at any depth under them).
#[derive(Clone, Debug)]
struct Alt {
    from: Anchor,
    dirs: Vec<Part>,
    name: Option<Part>,
}

/// Where an `Alt`'s folders start: under any folder below the scope, at
/// the scope (anywhere if none), at the disk's root.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Anchor {
    Anywhere,
    Scope,
    Root,
}

/// One folder or name of a glob: `**` (any run of folders), a literal
/// (lowercase), literals between stars (`*test*`, `t*.rs`: the pieces,
/// lowercase), or a pattern within one name with its longest literal run.
#[derive(Clone, Debug)]
enum Part {
    Any,
    Lit(Vec<u8>),
    Star(Vec<Vec<u8>>),
    Pat(regex::bytes::Regex, Vec<u8>),
}

impl PartialEq for Part {
    fn eq(&self, o: &Part) -> bool {
        match (self, o) {
            (Part::Any, Part::Any) => true,
            (Part::Lit(a), Part::Lit(b)) => a == b,
            (Part::Star(a), Part::Star(b)) => a == b,
            (Part::Pat(a, _), Part::Pat(b, _)) => a.as_str() == b.as_str(),
            _ => false,
        }
    }
}

impl Part {
    fn of(s: &str) -> Result<Part, String> {
        if s == "**" {
            return Ok(Part::Any);
        }
        if !s.contains(['*', '?', '[']) {
            return Ok(Part::Lit(s.to_ascii_lowercase().into_bytes()));
        }
        if !s.contains(['?', '[']) {
            return Ok(Part::Star(s.split('*').map(|p| p.to_ascii_lowercase().into_bytes()).collect()));
        }
        // `*` any run, `?` one byte, `[..]` (or `[!..]`) a class; ASCII case.
        let (mut re, mut run, mut longest) = (String::from("(?is-u)^"), String::new(), String::new());
        let mut cs = s.char_indices();
        while let Some((i, c)) = cs.next() {
            let close = s[i + 1..].find(']').filter(|_| c == '[');
            if matches!(c, '*' | '?') || close.is_some() {
                if run.len() > longest.len() {
                    longest = std::mem::take(&mut run);
                }
                run.clear();
            }
            match (c, close) {
                ('*', _) => re.push_str(".*"),
                ('?', _) => re.push('.'),
                (_, Some(j)) => {
                    let class = &s[i + 1..i + 1 + j];
                    re.push('[');
                    if let Some(c) = class.strip_prefix('!') {
                        re.push('^');
                        re.push_str(&c.replace(['\\', '[', '&', '~'], ""));
                    } else {
                        re.push_str(&class.replace(['\\', '[', '&', '~'], ""));
                    }
                    re.push(']');
                    cs.by_ref().take_while(|&(k, _)| k < i + 1 + j).for_each(drop);
                }
                _ => {
                    re.push_str(&regex_syntax::escape(c.encode_utf8(&mut [0; 4])));
                    run.push(c);
                }
            }
        }
        if run.len() > longest.len() {
            longest = run;
        }
        re.push('$');
        Ok(Part::Pat(regex::bytes::Regex::new(&re).map_err(|e| e.to_string())?, longest.to_ascii_lowercase().into_bytes()))
    }

    fn matches(&self, name: &[u8]) -> bool {
        match self {
            Part::Any => true,
            Part::Lit(l) => name.eq_ignore_ascii_case(l),
            Part::Star(p) => {
                let (head, tail) = (&p[0], &p[p.len() - 1]);
                if name.len() < head.len() + tail.len() || !name[..head.len()].eq_ignore_ascii_case(head) || !ends_with_fold(name, tail) {
                    return false;
                }
                // The middle pieces in order, between head and tail.
                let mut rest = &name[head.len()..name.len() - tail.len()];
                p[1..p.len() - 1].iter().all(|m| find_ci(rest, m).inspect(|&i| rest = &rest[i + m.len()..]).is_some())
            }
            Part::Pat(re, _) => re.is_match(name),
        }
    }

    /// The longest run of literal bytes in every matching name (lowercase).
    fn literal(&self) -> &[u8] {
        match self {
            Part::Any => b"",
            Part::Star(p) => p.iter().max_by_key(|p| p.len()).unwrap(),
            Part::Lit(l) | Part::Pat(_, l) => l,
        }
    }

    /// The extension `*.ext` stands for.
    fn ext(&self) -> Option<Vec<u8>> {
        match self {
            Part::Star(p) if p.len() == 2 && p[0].is_empty() => {
                p[1].strip_prefix(b".").filter(|e| !e.is_empty() && !e.contains(&b'.')).map(<[u8]>::to_vec)
            }
            _ => None,
        }
    }
}

impl Glob {
    /// Whether `name_ok` can turn a name down.
    fn tests_names(&self) -> bool {
        if self.negate { self.names_only() } else { self.alts.iter().all(|a| a.name.is_some()) }
    }

    /// Whether the glob's test is the name alone (no folders anywhere).
    fn names_only(&self) -> bool {
        self.alts.iter().all(|a| a.from == Anchor::Anywhere && a.dirs.is_empty() && a.name.is_some())
    }

    /// The name test `Searcher::glob_ranges` leaves to the name table: a
    /// name some alternative allows; negated and names only, none.
    fn name_ok(&self, name: &[u8]) -> bool {
        match self.negate {
            false => self.alts.iter().any(|a| a.name.as_ref().is_none_or(|p| p.matches(name))),
            true => !self.names_only() || !self.alts.iter().any(|a| a.name.as_ref().is_some_and(|p| p.matches(name))),
        }
    }

    /// Whether the name test and the folder ranges together are the glob
    /// (else entries that pass them get `matches_path` too): every
    /// alternative tests the same folders, or none tests folders.
    fn split(&self) -> bool {
        let a = &self.alts[0];
        let same = |b: &Alt| b.from == a.from && b.dirs == a.dirs;
        self.names_only() || (!self.negate && self.alts.iter().all(same)) || (self.negate && self.alts.iter().all(|a| a.name.is_none()))
    }

    /// Does the path (absolute) pass, `scope` being the query's?
    fn matches_path(&self, path: &[u8], scope: Option<&[u8]>) -> bool {
        let hit = self.alts.iter().any(|a| {
            let rel = match (a.from, scope) {
                (Anchor::Root, _) | (_, None) => path,
                (_, Some(s)) => match path.strip_prefix(s) {
                    Some(r) if r.first() == Some(&b'/') => r,
                    _ => return false,
                },
            };
            let floating = a.from == Anchor::Anywhere || (a.from == Anchor::Scope && scope.is_none());
            let comps: Vec<&[u8]> = rel.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
            // The folders, ending at the last of `names` (starting anywhere
            // when floating).
            let dirs = |names: &[&[u8]]| (0..=if floating { names.len() } else { 0 }).any(|k| parts_match(&a.dirs, &names[k..]));
            match (&a.name, comps.split_last()) {
                (Some(p), Some((last, up))) => p.matches(last) && dirs(up),
                (None, Some((_, up))) => (0..=up.len()).any(|j| dirs(&up[..j])),
                _ => false,
            }
        });
        hit != self.negate
    }
}

/// Do `parts` spell the folder names `names` exactly (`**` any run)?
fn parts_match(parts: &[Part], names: &[&[u8]]) -> bool {
    match parts.split_first() {
        None => names.is_empty(),
        Some((Part::Any, rest)) => (0..=names.len()).any(|k| parts_match(rest, &names[k..])),
        Some((p, rest)) => names.split_first().is_some_and(|(n, more)| p.matches(n) && parts_match(rest, more)),
    }
}

/// `w` with its brace groups expanded: `*.{c,h}` is `*.c` and `*.h`.
fn expand_braces(w: &str) -> Vec<String> {
    let Some(open) = w.find('{') else { return vec![w.to_string()] };
    let Some(len) = w[open..].find('}') else { return vec![w.to_string()] };
    let (head, body, tail) = (&w[..open], &w[open + 1..open + len], &w[open + len + 1..]);
    let tails = expand_braces(tail);
    body.split(',').flat_map(|b| tails.iter().map(move |t| format!("{head}{b}{t}"))).take(64).collect()
}

/// An `Alt` from one brace-free alternative.
fn glob_alt(a: &str) -> Result<Alt, String> {
    let (from, rest) = match a.strip_prefix("./") {
        Some(r) => (Anchor::Scope, r),
        None if a.starts_with('/') => (Anchor::Root, a),
        None => (if a.trim_end_matches('/').contains('/') && a.contains(['*', '?', '[']) { Anchor::Scope } else { Anchor::Anywhere }, a),
    };
    let mut parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    let name = if rest.ends_with('/') { None } else { parts.pop().map(Part::of).transpose()? };
    Ok(Alt { from, dirs: parts.into_iter().map(Part::of).collect::<Result<_, _>>()?, name })
}

/// The real path of `p` (the index holds real paths: /etc is
/// /private/etc), or `p` if it has none. Resolving costs a few syscalls
/// (~4 us), as much as a whole search in a small folder, and searches in
/// one folder come in a row (typing): the last answer holds for a second,
/// less than the index takes to see most changes anyway.
fn real_path(p: String) -> String {
    static LAST: std::sync::Mutex<Option<(String, String, std::time::Instant)>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap();
    if let Some((from, to, at)) = &*last
        && *from == p
        && at.elapsed() < std::time::Duration::from_secs(1)
    {
        return to.clone();
    }
    let to = std::fs::canonicalize(&p).map_or_else(|_| p.clone(), |c| c.to_string_lossy().into_owned());
    *last = Some((p, to.clone(), std::time::Instant::now()));
    to
}

/// `s` in the other Unicode normalization form, if it differs: decomposed
/// if `s` is composed, else composed.
fn other_form(s: &str) -> Option<String> {
    let c = normalized(s, 2)?;
    let o = if c == s { normalized(s, 0)? } else { c };
    (o != s).then_some(o)
}

/// `s` in Unicode normalization form `form` (0: D, 2: C), by CoreFoundation,
/// loaded on first use as in fsevents.rs (linking it costs every process
/// ~1 ms at launch).
fn normalized(s: &str, form: isize) -> Option<String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (s, form);
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        use std::ffi::{CStr, c_char, c_void};
        type Fns = (
            unsafe extern "C" fn(*const c_void, isize) -> *mut c_void,
            unsafe extern "C" fn(*mut c_void, *const c_char, u32),
            unsafe extern "C" fn(*mut c_void, isize),
            unsafe extern "C" fn(*const c_void, *mut c_char, isize, u32) -> u8,
            unsafe extern "C" fn(*const c_void),
        );
        static CF: std::sync::OnceLock<Option<Fns>> = std::sync::OnceLock::new();
        unsafe fn sym<T>(h: *mut c_void, name: &CStr) -> Option<T> {
            let p = unsafe { libc::dlsym(h, name.as_ptr()) };
            (!h.is_null() && !p.is_null()).then(|| unsafe { std::mem::transmute_copy(&p) })
        }
        let f = CF
            .get_or_init(|| unsafe {
                let h = libc::dlopen(c"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation".as_ptr(), libc::RTLD_LAZY);
                Some((
                    sym(h, c"CFStringCreateMutable")?,
                    sym(h, c"CFStringAppendCString")?,
                    sym(h, c"CFStringNormalize")?,
                    sym(h, c"CFStringGetCString")?,
                    sym(h, c"CFRelease")?,
                ))
            })
            .as_ref()?;
        const UTF8: u32 = 0x0800_0100;
        let c = std::ffi::CString::new(s).ok()?;
        let mut out = vec![0u8; 4 * s.len() + 16];
        unsafe {
            let m = (f.0)(std::ptr::null(), 0);
            if m.is_null() {
                return None;
            }
            (f.1)(m, c.as_ptr(), UTF8);
            (f.2)(m, form);
            let ok = (f.3)(m, out.as_mut_ptr() as *mut c_char, out.len() as isize, UTF8) != 0;
            (f.4)(m);
            let n = out.iter().position(|&b| b == 0)?;
            ok.then(|| String::from_utf8(out[..n].to_vec()).ok()).flatten()
        }
    }
}

/// Split on spaces, keeping "double quoted" runs together.
fn split_words(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (Vec::new(), String::new(), false);
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn range(v: &str, p: fn(&str) -> Option<u64>) -> Result<(u64, u64), String> {
    let bad = || format!("bad range {v}");
    if let Some(r) = v.strip_prefix(">=").or(v.strip_prefix('>')) {
        return Ok((p(r).ok_or_else(bad)?, u64::MAX));
    }
    if let Some(r) = v.strip_prefix("<=").or(v.strip_prefix('<')) {
        return Ok((0, p(r).ok_or_else(bad)?));
    }
    if let Some((a, b)) = v.split_once("..") {
        return Ok((p(a).ok_or_else(bad)?, p(b).ok_or_else(bad)?));
    }
    let x = p(v).ok_or_else(bad)?;
    Ok((x, x))
}

fn split_unit(s: &str) -> (f64, String) {
    let i = s.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(s.len());
    (s[..i].parse().unwrap_or(f64::NAN), s[i..].to_ascii_lowercase())
}

fn parse_size(s: &str) -> Option<u64> {
    let (n, u) = split_unit(s);
    let m = match u.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1e3,
        "m" | "mb" => 1e6,
        "g" | "gb" => 1e9,
        "t" | "tb" => 1e12,
        _ => return None,
    };
    (!n.is_nan()).then_some((n * m) as u64)
}

fn parse_age(s: &str) -> Option<u64> {
    let (n, u) = split_unit(s);
    let m = match u.as_str() {
        "s" => 1.0,
        "m" | "min" => 60.0,
        "h" => 3600.0,
        "" | "d" => 86400.0,
        "w" => 604800.0,
        "mo" => 2592000.0,
        "y" => 31536000.0,
        _ => return None,
    };
    (!n.is_nan()).then_some((n * m) as u64)
}

pub fn now_secs() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as u32)
}

#[inline(always)]
pub(crate) fn fold(b: u8) -> u8 {
    b | (((b.wrapping_sub(b'A') < 26) as u8) << 5)
}

#[inline(always)]
fn is_subseq(name: &[u8], q: &[u8]) -> bool {
    let mut j = 0;
    for &b in name {
        if fold(b) == q[j] {
            j += 1;
            if j == q.len() {
                return true;
            }
        }
    }
    false
}

fn find_ci(name: &[u8], q: &[u8]) -> Option<usize> {
    if q.len() > name.len() {
        return None;
    }
    (0..=name.len() - q.len()).find(|&i| name[i..i + q.len()].iter().zip(q).all(|(&a, &b)| fold(a) == b))
}

#[derive(Clone, Copy, PartialEq)]
enum Class {
    Lower,
    Upper,
    Digit,
    Delim,
    Other,
}

#[inline(always)]
fn class(b: u8) -> Class {
    match b {
        b'a'..=b'z' => Class::Lower,
        b'A'..=b'Z' => Class::Upper,
        b'0'..=b'9' => Class::Digit,
        b' ' | b'_' | b'-' | b'.' | b'/' | b'(' | b')' | b'[' | b']' | b',' | b'+' | b'@' => Class::Delim,
        _ => Class::Other,
    }
}

const SCORE_MATCH: i32 = 16;
const GAP_START: i32 = -3;
const GAP_EXT: i32 = -1;
const BONUS_BOUNDARY: i32 = 8;
const BONUS_CAMEL: i32 = 7;
const BONUS_CONSEC: i32 = 4;

#[inline(always)]
fn bonus(prev: Class, cur: Class) -> i32 {
    match (prev, cur) {
        (Class::Delim, c) if c != Class::Delim => BONUS_BOUNDARY,
        (Class::Lower, Class::Upper) | (Class::Lower | Class::Upper, Class::Digit) => BONUS_CAMEL,
        _ => 0,
    }
}

/// A dotfile named as typed past its dot ("keep" for .keep) is meant as
/// much as a visible name: its placement undoes the hidden-file tweak and
/// puts it above a stem match ("keep" for keep.icon).
const DOT_WHOLE: i32 = 16;
/// The placement bonus uncapped (see `fuzzy_score_capped`).
const FULL: i32 = 100 + DOT_WHOLE;

/// fzf-v1 style: leftmost-ending match, shrunk from the right, then scored
/// with boundary/camel/consecutive bonuses. Returns None when no match.
pub fn fuzzy_score(name: &[u8], q: &[u8]) -> Option<i32> {
    fuzzy_score_capped(name, None, q, FULL)
}

/// A name's 64 bytes in the index from its start, if it is no longer
/// (`Index::uname_wide`): what follows it is masked off.
type Wide<'a> = Option<&'a [u8; 64]>;

/// `fuzzy_score` with the whole-name/stem/prefix bonus capped at `cap`.
fn fuzzy_score_capped(name: &[u8], wide: Wide, q: &[u8], cap: i32) -> Option<i32> {
    if let Some(s) = prefix_score(name, q, cap) {
        return Some(s);
    }
    #[cfg(not(target_arch = "aarch64"))]
    let _ = wide;
    #[cfg(target_arch = "aarch64")]
    if name.len() <= 64 && q.len() <= 32 {
        if let Some(w) = wide {
            return fuzzy_masked(name, w, q, cap);
        }
        let mut buf = [0u8; 64];
        buf[..name.len()].copy_from_slice(name);
        return fuzzy_masked(name, &buf, q, cap);
    }
    // Leftmost-ending match: jump to each query byte in turn (memchr is
    // SIMD; most names fail on the first or second byte).
    let mut end = 0;
    let mut from = 0;
    for &c in q {
        end = from + find_folded(&name[from..], c)?;
        from = end + 1;
    }
    let next = |k: usize, from: usize, to: usize| Some(from + find_folded(&name[from..=to], q[k])?);
    fuzzy_from(name, q, cap, end, next, |k, to| rfind_folded(&name[..to], q[k]))
}

/// A name's first `len` (at most 64) bytes from `src`, ASCII-folded: where
/// a byte is in them, as one 64-bit mask (bit p for position p), takes a
/// few NEON compares over the whole name at once.
#[cfg(target_arch = "aarch64")]
struct Folded {
    v: [std::arch::aarch64::uint8x16_t; 4],
    valid: u64,
}

#[cfg(target_arch = "aarch64")]
impl Folded {
    #[inline(always)]
    fn new(src: &[u8; 64], len: usize) -> Folded {
        use std::arch::aarch64::*;
        // Safety (here and below): NEON is part of aarch64; loads stay in `src`.
        let v = std::array::from_fn(|i| unsafe {
            let x = vld1q_u8(src.as_ptr().add(16 * i));
            vorrq_u8(x, vandq_u8(vcltq_u8(vsubq_u8(x, vdupq_n_u8(b'A')), vdupq_n_u8(26)), vdupq_n_u8(0x20)))
        });
        Folded { v, valid: u64::MAX.checked_shr(64 - len as u32).unwrap_or(0) }
    }

    /// Where bytes folding to `c` are.
    #[inline(always)]
    fn places(&self, c: u8) -> u64 {
        use std::arch::aarch64::*;
        self.pack(|x| unsafe { vceqq_u8(x, vdupq_n_u8(c)) })
    }

    /// Where ASCII digits are.
    #[inline(always)]
    fn digits(&self) -> u64 {
        use std::arch::aarch64::*;
        self.pack(|x| unsafe { vcltq_u8(vsubq_u8(x, vdupq_n_u8(b'0')), vdupq_n_u8(10)) })
    }

    /// A compare per byte as a mask: byte i weighed by bit i % 8, then
    /// pairwise adds pack the 64 compares into 64 bits.
    #[inline(always)]
    fn pack(&self, f: impl Fn(std::arch::aarch64::uint8x16_t) -> std::arch::aarch64::uint8x16_t) -> u64 {
        use std::arch::aarch64::*;
        const W: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
        unsafe {
            let weight = vld1q_u8(W.as_ptr());
            let m = |i: usize| vandq_u8(f(self.v[i]), weight);
            let s = vpaddq_u8(vpaddq_u8(m(0), m(1)), vpaddq_u8(m(2), m(3)));
            vgetq_lane_u64(vreinterpretq_u64_u8(vpaddq_u8(s, s)), 0) & self.valid
        }
    }
}

/// `Folded` without NEON: the same masks, a byte at a time.
#[cfg(not(target_arch = "aarch64"))]
struct Folded {
    b: [u8; 64],
    valid: u64,
}

#[cfg(not(target_arch = "aarch64"))]
impl Folded {
    fn new(src: &[u8; 64], len: usize) -> Folded {
        Folded { b: src.map(fold), valid: u64::MAX.checked_shr(64 - len as u32).unwrap_or(0) }
    }
    fn mask(&self, f: impl Fn(u8) -> bool) -> u64 {
        self.b.iter().enumerate().fold(0, |m, (i, &b)| m | (f(b) as u64) << i) & self.valid
    }
    fn places(&self, c: u8) -> u64 {
        self.mask(|b| b == c)
    }
    fn digits(&self) -> u64 {
        self.mask(|b| b.is_ascii_digit())
    }
}

/// `fuzzy_score_capped` past the prefix test, for a name of at most 64
/// bytes starting `src`: each query byte's places in the name as one
/// 64-bit mask (`Folded`) stand in for memchr's scans, which cost several
/// times more per name tried.
#[cfg(target_arch = "aarch64")]
fn fuzzy_masked(name: &[u8], src: &[u8; 64], q: &[u8], cap: i32) -> Option<i32> {
    let f = Folded::new(src, name.len());
    let mut masks = [0u64; 32];
    let (mut end, mut from) = (0, 0);
    for i in 0..q.len() {
        let c = q[i];
        let m = if let Some(prev) = q[..i].iter().rposition(|&x| x == c) { masks[prev] } else { f.places(c) };
        masks[i] = m;
        let x = if from < 64 { m >> from << from } else { 0 };
        if x == 0 {
            return None;
        }
        end = x.trailing_zeros() as usize;
        from = end + 1;
    }
    let next = |k: usize, from: usize, to: usize| {
        let x = masks[k] >> from << from & u64::MAX >> (63 - to);
        (x != 0).then(|| x.trailing_zeros() as usize)
    };
    let prev = |k: usize, to: usize| {
        let x = masks[k] & u64::MAX.checked_shr(64 - to as u32).unwrap_or(0);
        (x != 0).then(|| 63 - x.leading_zeros() as usize)
    };
    fuzzy_from(name, q, cap, end, next, prev)
}

/// The rest of `fuzzy_score_capped` once the leftmost-ending match ends at
/// `end`: `next(k, from, to)` finds query byte k's first place in
/// from..=to, `prev(k, to)` its last one before `to`.
#[inline(always)]
fn fuzzy_from(
    name: &[u8],
    q: &[u8],
    cap: i32,
    end: usize,
    next: impl Fn(usize, usize, usize) -> Option<usize>,
    prev: impl Fn(usize, usize) -> Option<usize>,
) -> Option<i32> {
    if q.len() == 1 {
        return Some(single_score(name, end, cap));
    }
    // Shrink from the right: the latest start that still ends at `end`.
    let mut start = end + 1;
    for k in (0..q.len()).rev() {
        start = prev(k, start)?;
    }
    // Score the greedy match from `start`, jumping between matched bytes:
    // each gap costs GAP_START then GAP_EXT per byte, a run of consecutive
    // matches carries its strongest boundary bonus along.
    let mut score = 0;
    let (mut at, mut first_bonus) = (start, 0);
    for k in 0..q.len() {
        let mut run = false;
        if k > 0 {
            let last = at;
            at = next(k, last + 1, end)?;
            run = at == last + 1;
            if !run {
                score += GAP_START + (at - last - 2) as i32 * GAP_EXT;
            }
        }
        let prev = if at == 0 { Class::Delim } else { class(name[at - 1]) };
        let mut b = bonus(prev, class(name[at]));
        if run {
            if b >= BONUS_BOUNDARY && b > first_bonus {
                first_bonus = b;
            }
            b = b.max(first_bonus).max(BONUS_CONSEC);
        } else {
            first_bonus = b;
        }
        score += SCORE_MATCH + if k == 0 { b * 2 } else { b };
    }
    // Whole-name and stem matches are what people mean most of the time. A
    // leading dot doesn't count: "zshrc" means ~/.zshrc. A stem match is
    // as good as a whole one, its length the stem's: "powercap" means
    // powercap.rst as much as a folder powercap (files go first on ties,
    // see `entry_key`).
    let off = (name.len() > 1 && name[0] == b'.') as usize;
    let at_stem = || end + 1 == name.iter().rposition(|&b| b == b'.').filter(|&p| p > off).unwrap_or(name.len());
    let (placed, len) = if start != off || end + 1 - start != q.len() {
        (0, name.len())
    } else if end + 1 == name.len() {
        (100 + DOT_WHOLE * off as i32, end + 1)
    } else if at_stem() {
        (100, end + 1)
    } else {
        (30, name.len())
    };
    Some(score + placed.min(cap) - (len as i32).min(80) / 3)
}

/// `fuzzy_score_capped` of a name that starts with the query (past a
/// leading dot, unless the query starts with one): the match is the prefix,
/// so the score comes from one pass over it. None if the name does not.
#[inline]
fn prefix_score(name: &[u8], q: &[u8], cap: i32) -> Option<i32> {
    let off = (name.len() > 1 && name[0] == b'.') as usize;
    let end = off + q.len();
    if (off == 1 && q[0] == b'.') || name.len() < end || !name[off..end].iter().zip(q).all(|(&a, &b)| fold(a) == b) {
        return None;
    }
    // The first byte follows a delimiter (or nothing); each next one runs on
    // from the one before it.
    let mut first = bonus(Class::Delim, class(name[off]));
    let mut score = SCORE_MATCH + first * 2;
    for i in off + 1..end {
        let b = bonus(class(name[i - 1]), class(name[i]));
        if b >= BONUS_BOUNDARY && b > first {
            first = b;
        }
        score += SCORE_MATCH + b.max(first).max(BONUS_CONSEC);
    }
    let (placed, len) = if end == name.len() {
        (100 + DOT_WHOLE * off as i32, end)
    } else if name[end] == b'.' && !name[end + 1..].contains(&b'.') {
        (100, end)
    } else {
        (30, name.len())
    };
    Some(score + placed.min(cap) - (len as i32).min(80) / 3)
}

/// First byte of `s` that folds to `c` (an already-lowercased query byte).
#[inline(always)]
fn find_folded(s: &[u8], c: u8) -> Option<usize> {
    if c.is_ascii_lowercase() { memchr::memchr2(c, c - 32, s) } else { memchr::memchr(c, s) }
}

/// Last byte of `s` that folds to `c`.
#[inline(always)]
fn rfind_folded(s: &[u8], c: u8) -> Option<usize> {
    if c.is_ascii_lowercase() { memchr::memrchr2(c, c - 32, s) } else { memchr::memrchr(c, s) }
}

/// `fuzzy_score` for a one-byte query matched at `i`: the general scoring
/// loop collapses to one step.
#[inline]
fn single_score(name: &[u8], i: usize, cap: i32) -> i32 {
    let prev = if i == 0 { Class::Delim } else { class(name[i - 1]) };
    let mut score = SCORE_MATCH + bonus(prev, class(name[i])) * 2;
    let off = (name.len() > 1 && name[0] == b'.') as usize;
    let mut len = name.len();
    if i == off {
        let stem = name.iter().rposition(|&b| b == b'.').filter(|&p| p > off).unwrap_or(name.len());
        let whole = i + 1 == name.len() || i + 1 == stem;
        score += cap.min(if i + 1 == name.len() {
            100 + DOT_WHOLE * off as i32
        } else if whole {
            100
        } else {
            30
        });
        if whole {
            len = i + 1;
        }
    }
    score - (len as i32).min(80) / 3
}

/// Best score for `q` read with one typo (see `one_edit_prefix`) at the
/// start of `name` or of a space-separated word in it: scored as if the
/// right letters had been typed, minus TYPO_COST, and never placed above a
/// prefix: "manif" is "manifest" being typed, not a typo of "manic".
/// `spaced` is false if the name has no space. Other word starts (`_`, `-`,
/// camelCase) would cost a scan of every name per query, ~10x the price.
fn typo_score(name: &[u8], wide: Wide, spaced: bool, q: &[u8]) -> Option<i32> {
    let mut best = typo_at(name, wide, (name.len() > 1 && name[0] == b'.') as usize, q);
    if spaced {
        for sp in memchr::memchr_iter(b' ', name) {
            best = best.max(typo_at(name, wide, sp + 1, q));
        }
    }
    best
}

fn typo_at(name: &[u8], wide: Wide, s: usize, q: &[u8]) -> Option<i32> {
    if name.get(s).is_none_or(|&b| fold(b) != q[0]) {
        return None;
    }
    let mut fixed = [0u8; 128];
    let fixed = fixed.get_mut(..one_edit_prefix(&name[s..], q)?)?;
    for (f, &b) in fixed.iter_mut().zip(&name[s..]) {
        *f = fold(b);
    }
    Some(fuzzy_score_capped(name, wide, fixed, 30)? - TYPO_COST)
}

/// How long a prefix of `w` the query `q` spells with exactly one edit (a
/// wrong, extra, missing or swapped letter), if it does. Digits are never
/// edited: "hat_18" is another file than "hat_98", not a typo of it.
fn one_edit_prefix(w: &[u8], q: &[u8]) -> Option<usize> {
    let starts = |w: &[u8], q: &[u8]| w.len() >= q.len() && w.iter().zip(q).all(|(&a, &b)| fold(a) == b);
    // The first difference; none means `q` is a clean prefix, not a typo.
    let i = (0..q.len()).find(|&i| i >= w.len() || fold(w[i]) != q[i])?;
    if q[i].is_ascii_digit() || w.get(i).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let rest = &q[i + 1..];
    let after = w.get(i + 1..).unwrap_or_default();
    if i + 1 < q.len() && i + 1 < w.len() && fold(w[i]) == q[i + 1] && fold(w[i + 1]) == q[i] && starts(&w[i + 2..], &q[i + 2..]) {
        return Some(q.len());
    }
    if i < w.len() && starts(after, rest) {
        return Some(q.len());
    }
    if starts(&w[i..], rest) {
        return Some(q.len() - 1);
    }
    (i < w.len() && starts(after, &q[i..])).then_some(q.len() + 1)
}

/// `typo_score` for a deep token (`Token::deep`): at most `k` typos (see
/// `edits`), the first letter's too.
fn deep_typo_score(name: &[u8], wide: Wide, q: &[u8], k: u32) -> Option<i32> {
    if q.len() > 64 {
        return None;
    }
    // The first 63 bytes, so that every end of a match is a bit.
    let n = name.len().min(63);
    let f = match wide {
        Some(w) => Folded::new(w, n),
        None => {
            let mut buf = [0u8; 64];
            buf[..n].copy_from_slice(&name[..n]);
            Folded::new(&buf, n)
        }
    };
    let off = (name.len() > 1 && name[0] == b'.') as usize;
    let starts = (1u64 << off) | f.places(b' ') << 1;
    // The fewest edits from any word start, then the earliest start. Most
    // names fail whatever the edits touch: digits are told apart after.
    let best = |editable: u64| {
        // The set bits only: a long name would take 64 tests.
        let mut b = starts;
        let words = std::iter::from_fn(|| {
            let s = b.trailing_zeros() as usize;
            b &= b.wrapping_sub(1);
            (s < 64).then_some(s)
        });
        words.filter_map(|s| Some((edits(&f, q, 1 << s, editable, n, k)?, s))).min_by_key(|&((d, _), s)| (d, s))
    };
    let mut found = best(f.valid)?;
    let digits = f.digits();
    if digits != 0 {
        found = best(f.valid & !digits)?;
    }
    let ((d, e), s) = found;
    let mut fixed = [0u8; 64];
    let fixed = &mut fixed[..e - s];
    for (x, &b) in fixed.iter_mut().zip(&name[s..]) {
        *x = fold(b);
    }
    Some(fuzzy_score_capped(name, wide, fixed, 30)? - TYPO_COST * d as i32)
}

/// The fewest edits (1 to `k`, none if the query is spelled right) that
/// make the query spell a part of the name starting where `start` has its
/// bit, and where the shortest such part ends. Bit p of a state is "the
/// query so far spells the name up to position p": each query byte moves
/// every state on at once, for each number of edits so far
/// (Damerau-Levenshtein, a swap of neighbors one edit). `editable` holds
/// the name's bytes an edit may touch (not digits: "hat_18" is another file
/// than "hat_98", not a typo of it), `n` its length. Each query byte's
/// places in the name are found as the search gets to it: most names fail
/// within a few bytes.
fn edits(f: &Folded, q: &[u8], start: u64, editable: u64, n: usize, k: u32) -> Option<(u32, usize)> {
    let k = k as usize;
    let ends = u64::MAX >> (63 - n);
    // Edits so far 0..=k: up to the last byte, and the one before it.
    let (mut cur, mut prev) = ([0u64; 3], [0u64; 3]);
    cur[0] = start;
    for d in 1..=k {
        // Letters missing from the start of the word.
        cur[d] = cur[d - 1] | (cur[d - 1] & editable) << 1;
    }
    let mut last = 0;
    for (i, &c) in q.iter().enumerate() {
        let (mut next, here) = ([0u64; 3], f.places(c));
        let swap = i > 0 && q[i - 1] != c && !q[i - 1].is_ascii_digit();
        let before = if swap { last } else { 0 };
        last = here;
        for d in 0..=k {
            let mut x = (cur[d] & here) << 1;
            if d > 0 {
                if !c.is_ascii_digit() {
                    // Wrong letter, extra letter, swapped neighbors.
                    x |= (cur[d - 1] & editable) << 1 | cur[d - 1];
                    x |= ((prev[d - 1] & here) << 1 & before) << 1;
                }
                // A letter missing.
                x |= (next[d - 1] & editable) << 1;
            }
            next[d] = x & ends;
        }
        if next[k] == 0 {
            return None;
        }
        (prev, cur) = (cur, next);
    }
    if cur[0] != 0 {
        return None;
    }
    let d = (1..=k).find(|&d| cur[d] != 0)?;
    Some((d as u32, cur[d].trailing_zeros() as usize))
}

/// Does `q`, one word, spell `name` as an abbreviation of two or more of
/// its words ("regcapserfac" for RegionalCapabilitiesServiceFactory): runs
/// of two chars or more, each one starting a word (as `bonus` sees it).
fn abbreviates(name: &[u8], q: &[u8]) -> bool {
    if q.iter().any(|&b| is_delim(b)) {
        return false;
    }
    let starts = |i: usize| i == 0 || bonus(class(name[i - 1]), class(name[i])) > 0;
    let (mut at, mut runs, mut run) = (0, 0, 0);
    for &c in q {
        if run > 0 && name.get(at).is_some_and(|&b| fold(b) == c) {
            (at, run) = (at + 1, run + 1);
            continue;
        }
        let Some(i) = (at..name.len()).find(|&i| starts(i) && fold(name[i]) == c) else { return false };
        if run == 1 {
            return false;
        }
        (at, run, runs) = (i + 1, 1, runs + 1);
    }
    run > 1 && runs > 1
}

/// Score a token against a name, honoring its mode. `may` is what the
/// name's bitmaps or mask leave possible (all true when unknown): it only
/// skips work.
#[inline]
fn token_score(name: &[u8], wide: Wide, may: May, t: &Token) -> Option<i32> {
    match t.mode {
        Mode::Fuzzy if t.edits > 0 => {
            let clean = if may.0 { fuzzy_score_capped(name, wide, &t.text, FULL) } else { None };
            // A typo match scores at most 24 per char + 8, with up to one
            // char more per edit, a placement of 30, less TYPO_COST per edit.
            let best_typo = 24 * t.text.len() as i32 + 2 - (name.len() as i32).min(80) / 3;
            if !may.1 || clean.is_some_and(|c| c >= best_typo) {
                return clean;
            }
            clean.max(if t.deep { deep_typo_score(name, wide, &t.text, t.edits) } else { typo_score(name, wide, may.2, &t.text) })
        }
        Mode::Fuzzy => fuzzy_score_capped(name, wide, &t.text, FULL),
        Mode::Exact => find_ci(name, &t.text).map(|p| 40 + if p == 0 { 30 } else { 0 } - (name.len() as i32).min(80) / 3),
        Mode::Prefix => {
            (name.len() >= t.text.len() && name.iter().zip(&t.text).all(|(&a, &b)| fold(a) == b)).then(|| 60 - (name.len() as i32).min(80) / 3)
        }
        Mode::Suffix => (name.len() >= t.text.len() && name[name.len() - t.text.len()..].iter().zip(&t.text).all(|(&a, &b)| fold(a) == b))
            .then(|| 50 - (name.len() as i32).min(80) / 3),
    }
}

#[inline]
fn token_matches(name: &[u8], t: &Token) -> bool {
    match t.mode {
        Mode::Fuzzy => is_subseq(name, &t.text),
        _ => token_score(name, None, (true, true, true), t).is_some(),
    }
}

/// Top k by (score, then lower entry index): a total order, so the result
/// does not depend on which thread saw which entry first. Candidates above
/// the floor collect in a buffer that is cut back to k now and then, which
/// is cheaper than a heap when most of the disk matches.
struct TopK {
    k: usize,
    buf: Vec<u64>,
    /// Keys at or below this cannot get in.
    floor: u64,
}

/// A sort key: score, then files before folders (bit 31: a file and a
/// folder named alike tie, see `fuzzy_from`), then the lower entry index.
/// `key(score, 0)` is above every entry's key with that score: the bound
/// for one.
#[inline(always)]
fn key(score: i32, i: u32) -> u64 {
    (((score as i64 - i32::MIN as i64) as u64) << 32) | (!i) as u64
}

/// `key` for entry `i`, a file or not.
#[inline(always)]
fn entry_key(score: i32, i: u32, file: bool) -> u64 {
    key(score, i | 1 << 31) | (file as u64) << 31
}

impl TopK {
    fn new(k: usize, floor: u64) -> TopK {
        TopK { k, buf: Vec::new(), floor: if k == 0 { u64::MAX } else { floor } }
    }
    #[inline]
    fn push(&mut self, key: u64) {
        if key > self.floor {
            self.buf.push(key);
            if self.buf.len() >= (2 * self.k).max(64) {
                self.cut();
            }
        }
    }
    /// Keep the k best; the k-th becomes the floor.
    fn cut(&mut self) {
        if self.buf.len() > self.k {
            self.buf.select_nth_unstable_by(self.k - 1, |a, b| b.cmp(a));
            self.buf.truncate(self.k);
            self.floor = self.buf[self.k - 1];
        }
    }
}

/// `f(state, i)` for each `i` in `0..n`, results in order, on the pool: the
/// calling thread starts at once, taking items in order from a shared
/// counter; one helper is queued, and each helper once running queues the
/// next before it takes items too. Threads asleep wake one after another off
/// the caller's path, and a helper that runs after the items are gone (the
/// caller runs any still queued when it is done) returns at once: no one
/// waits for a thread to wake, and no thread sits on a share of the work
/// while it does. `state` is each thread's scratch.
fn par_each<S, T: Send>(n: usize, state: impl Fn() -> S + Sync, f: impl Fn(&mut S, usize) -> T + Sync) -> Vec<T> {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let out = Cells::new((0..n).map(|_| None));
    let next = AtomicUsize::new(0);
    let work = || {
        let mut st = state();
        loop {
            let i = next.fetch_add(1, Relaxed);
            if i >= n {
                break;
            }
            // Safety: the counter hands each index to one thread only.
            unsafe { out.set(i, Some(f(&mut st, i))) };
        }
    };
    // Helpers still to queue (each one queues the next).
    let left = AtomicUsize::new((rayon::current_num_threads() - 1).min(n.saturating_sub(1)));
    fn helper<'s>(s: &rayon::Scope<'s>, left: &'s AtomicUsize, next: &'s AtomicUsize, n: usize, work: &'s (dyn Fn() + Sync)) {
        s.spawn(move |s| {
            if next.load(Relaxed) < n {
                if left.fetch_sub(1, Relaxed) > 1 {
                    helper(s, left, next, n, work);
                }
                work();
            }
        });
    }
    rayon::scope(|s| {
        if left.load(Relaxed) > 0 {
            helper(s, &left, &next, n, &work);
        }
        work();
    });
    out.0.into_iter().map(|x| x.into_inner().unwrap()).collect()
}

/// One value per index that threads read and write without locks: each
/// index belongs to one thread at a time (in `par_each`, the one the
/// counter handed it to).
struct Cells<T>(Vec<std::cell::UnsafeCell<T>>);

unsafe impl<T: Send> Sync for Cells<T> {}

impl<T> Cells<T> {
    fn new(v: impl Iterator<Item = T>) -> Cells<T> {
        Cells(v.map(std::cell::UnsafeCell::new).collect())
    }

    /// Safety: no other thread uses index `i` meanwhile.
    unsafe fn set(&self, i: usize, v: T) {
        unsafe { *self.0[i].get() = v };
    }

    /// Safety: no other thread uses index `i` meanwhile.
    unsafe fn take(&self, i: usize) -> T
    where
        T: Default,
    {
        unsafe { std::mem::take(&mut *self.0[i].get()) }
    }
}

/// Top `k` over `0..n` items with keys above `floor`: a few contiguous
/// pieces per thread, each with its own heap, then one selection over their
/// survivors (merging heaps pairwise costs more than the scan when `k` is
/// large). Up to INLINE_VISITS entries to `visit` in all take less time
/// than waking threads.
fn top_k(n: usize, k: usize, visits: usize, floor: u64, visit: impl Fn(std::ops::Range<usize>, &mut TopK) + Sync) -> Vec<Hit> {
    let piece = |r: std::ops::Range<usize>| {
        let mut top = TopK::new(k, floor);
        visit(r, &mut top);
        top.cut();
        top
    };
    let tops: Vec<TopK> = if visits <= INLINE_VISITS {
        vec![piece(0..n)]
    } else {
        let pieces = (rayon::current_num_threads() * 4).min(n.max(1));
        let step = n.div_ceil(pieces).max(1);
        par_each(pieces, || (), |_, p| piece((p * step).min(n)..((p + 1) * step).min(n)))
    };
    // A full piece's k-th best already bounds the overall k-th from below.
    let floor = tops.iter().filter(|t| t.buf.len() == k).map(|t| t.floor).max().unwrap_or(0);
    let mut keys: Vec<u64> = tops.into_iter().flat_map(|t| t.buf).filter(|&x| x >= floor).collect();
    if keys.len() > k {
        if k == 0 {
            return Vec::new();
        }
        keys.select_nth_unstable_by(k - 1, |a, b| b.cmp(a));
        keys.truncate(k);
    }
    keys.into_iter().map(|x| Hit { score: ((x >> 32) as i64 + i32::MIN as i64) as i32, idx: !(x as u32) & !(1 << 31), over: None }).collect()
}

/// `f` of each piece of `0..words`, in parallel pieces (one if few).
fn par_words<T: Send>(words: usize, f: impl Fn(std::ops::Range<usize>) -> T + Sync) -> Vec<T> {
    let pieces = if words <= INLINE_WORDS { 1 } else { rayon::current_num_threads() * 2 };
    let step = words.div_ceil(pieces);
    let piece = |p: usize| f(p * step..((p + 1) * step).min(words));
    if pieces == 1 { vec![piece(0)] } else { par_each(pieces, || (), |_, p| piece(p)) }
}

/// Sorted ranges, overlapping ones joined.
fn merge(mut r: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    r.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(r.len());
    for (a, b) in r {
        match out.last_mut() {
            Some(l) if a <= l.1 => l.1 = l.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

/// What two sorted ranges have in common.
fn intersect(x: &[(u32, u32)], y: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let (mut out, mut j) = (Vec::new(), 0);
    for &(a, b) in x {
        while j < y.len() && y[j].1 <= a {
            j += 1;
        }
        let mut k = j;
        while k < y.len() && y[k].0 < b {
            out.push((a.max(y[k].0), b.min(y[k].1)));
            k += 1;
        }
    }
    out
}

/// Sorted ranges `x` less sorted ranges `cut`.
fn subtract(x: &[(u32, u32)], cut: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for &(mut a, b) in x {
        for &(c, d) in cut.iter().skip(cut.partition_point(|r| r.1 <= a)).take_while(|r| r.0 < b) {
            if c > a {
                out.push((a, c));
            }
            a = a.max(d);
        }
        if a < b {
            out.push((a, b));
        }
    }
    out
}

#[inline]
fn in_ranges(r: &[(u32, u32)], i: u32) -> bool {
    r.get(r.partition_point(|x| x.1 <= i)).is_some_and(|x| x.0 <= i)
}

fn ext_ok(name: &[u8], exts: &[Vec<u8>]) -> bool {
    let Some(dot) = name.iter().rposition(|&b| b == b'.') else { return false };
    let e = &name[dot + 1..];
    exts.iter().any(|x| x.len() == e.len() && x.iter().zip(e).all(|(&a, &b)| a == fold(b)))
}

/// How many top hits `Searcher::well_found` looks at.
const WELL_TOP: usize = 8;
/// Below this many entries carrying a matching name, a query visits just
/// those entries (via the name -> entries list) instead of every entry.
const SELECTIVE: usize = 60_000;
/// Bitset words (64 name ids each) per chunk of a name table: the unit of
/// parallel scoring and of hit storage (so a chunk's rank fits a u16).
const CHUNK_WORDS: usize = 64;
/// Restricted scoring with at most this many words to look at runs on the
/// calling thread.
const INLINE_WORDS: usize = 4096;
/// Entry scoring with at most this many entries to visit runs on the
/// calling thread.
const INLINE_VISITS: usize = 4096;
/// One-token searches expected to match this many names go `ranked`;
/// below BORDERLINE they do not, in between the bitmaps tell (`rankable`).
const RANKED_MIN: f64 = 20_000.0;
const BORDERLINE: f64 = 1_000.0;
/// `driven` tries a token expected to match at most this many names, the
/// rarest first, DRIVEN_TRIES of them at most.
const DRIVEN_NAMES: f64 = 20_000.0;
const DRIVEN_TRIES: usize = 2;
/// A word the name bitmaps let through for at most this many names may be
/// rare enough for `driven` (they let through several times the names
/// that match).
const DRIVEN_FITS: f64 = 80_000.0;
/// `spread` visits about SPREAD_FIRST entries first, then twice as many
/// each round, and gives up past SPREAD_BUDGET; a folder holding more than
/// TREE_MAX entries stays a bound. Per word, the OWN_MAX best names
/// starting with it are sources (the rest a bound), and the folders among
/// their first FOLD_SCAN entries.
const SPREAD_FIRST: usize = 4096;
const SPREAD_BUDGET: usize = 48 << 10;
const TREE_MAX: u32 = 1 << 16;
const OWN_MAX: usize = 4096;
const FOLD_SCAN: usize = 1 << 12;
/// The entries whose folder's location prior is above the level all but
/// about this many are at or below: `spread` visits them first.
const PRIOR_ENTRIES: usize = 4096;
/// Cheap bounds `ranked` tells apart: BINS of them from -BIN0.
const BINS: usize = 1024;
const BIN0: i32 = 256;
/// `ranked` scores the names best bound first in batches, the first about
/// this many names, then four times as many each time up to LAST_BATCH;
/// batches up to INLINE_NAMES run on the calling thread.
const FIRST_BATCH: usize = 64;
const LAST_BATCH: usize = 4096;
const INLINE_NAMES: usize = 512;
/// Overlay candidates a thread scores at a time (all of them on the calling
/// thread if no more).
const OVERLAY_CHUNK: usize = 256;

pub struct Searcher<'a> {
    pub live: &'a Live,
}

impl Searcher<'_> {
    /// Entry range to scan, from the `in:` scope.
    pub fn scope_range(&self, q: &Query) -> Option<(usize, usize)> {
        let idx = &self.live.base;
        let Some(scope) = &q.scope else { return Some((1, idx.n)) };
        let e = idx.lookup(scope)?;
        let d = idx.dir_of(e)? as usize;
        Some((idx.dir_start(d) as usize, idx.dir_end(d) as usize))
    }

    /// The entries in `lo..hi` the globs' folders allow, as sorted ranges;
    /// None if they allow all (see `Glob`). A glob's folders are a set of
    /// folders standing for their subtrees or their children, each one
    /// range: the index lays entries out folder by folder.
    fn glob_ranges(&self, q: &Query, lo: usize, hi: usize) -> Option<Vec<(u32, u32)>> {
        let (mut keep, mut cut) = (None, Vec::new());
        for g in q.globs.iter().filter(|g| !g.names_only()) {
            let alts: Option<Vec<Vec<(u32, u32)>>> = g.alts.iter().map(|a| self.alt_ranges(q, a)).collect();
            match (alts, g.negate) {
                (Some(r), false) => {
                    let r = merge(r.concat());
                    keep = Some(keep.map_or(r.clone(), |k: Vec<(u32, u32)>| intersect(&k, &r)));
                }
                // Negated, only folders: what is under them goes.
                (Some(r), true) if g.split() => cut.extend(r.concat()),
                _ => {}
            }
        }
        if keep.is_none() && cut.is_empty() {
            return None;
        }
        Some(subtract(&intersect(&keep.unwrap_or(vec![(0, u32::MAX)]), &[(lo as u32, hi as u32)]), &merge(cut)))
    }

    /// The entries one glob alternative's folders allow: None if all.
    fn alt_ranges(&self, q: &Query, a: &Alt) -> Option<Vec<(u32, u32)>> {
        let idx = &self.live.base;
        let floating = a.from == Anchor::Anywhere || (a.from == Anchor::Scope && q.scope.is_none());
        if floating && a.dirs.is_empty() && a.name.is_some() {
            return None;
        }
        let scope = q.scope.as_ref().and_then(|s| idx.dir_of(idx.lookup(s)?));
        let from = if a.from == Anchor::Root { 0 } else { scope.unwrap_or(0) };
        // Under the folders (no name) or `**` last: their subtrees, else
        // their children.
        let mut parts = a.dirs.clone();
        let mut subtree = a.name.is_none();
        while matches!(parts.last(), Some(Part::Any)) {
            parts.pop();
            subtree = true;
        }
        let (start, len, end) = (|d: u32| idx.dir_start(d as usize), |d: u32| idx.dir_len(d as usize), |d: u32| idx.dir_end(d as usize));
        // `**` alone: all of the scope.
        if parts.is_empty() && subtree && Some(from) == scope.or(Some(0)) {
            return None;
        }
        let dirs = if parts.is_empty() { vec![from] } else { self.glob_dirs(from, floating, &parts) };
        Some(dirs.iter().map(|&d| (start(d), if subtree { end(d) } else { start(d) + len(d) })).collect())
    }

    /// The folders below `from` whose path from there `parts` spells
    /// (from any depth when `floating`). With a literal folder, from the
    /// folders so named (the last literal's): no walk over a whole subtree.
    fn glob_dirs(&self, from: u32, floating: bool, parts: &[Part]) -> Vec<u32> {
        let idx = &self.live.base;
        let mut out = Vec::new();
        match parts.iter().rposition(|p| matches!(p, Part::Lit(_))) {
            Some(j) if floating => {
                let (de, dp) = (idx.dir_entries(), idx.dir_parents());
                let (lo, hi) = (idx.dir_start(from as usize), idx.dir_end(from as usize));
                for d in self.dirs_named(parts[j].literal(), lo, hi) {
                    // Names from below `from` down to d.
                    let mut names = Vec::new();
                    let mut k = d;
                    while k != from && k != 0 {
                        names.push(idx.name(de.get(k as usize) as usize).to_vec());
                        k = dp.get(k as usize);
                    }
                    names.reverse();
                    let names: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
                    if (0..=names.len()).any(|i| parts_match(&parts[..=j], &names[i..])) {
                        self.walk(d, &parts[j + 1..], &mut out);
                    }
                }
            }
            _ if floating => self.walk(from, &[&[Part::Any][..], parts].concat(), &mut out),
            _ => self.walk(from, parts, &mut out),
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The folders from `d` down that `parts` spells.
    fn walk(&self, d: u32, parts: &[Part], out: &mut Vec<u32>) {
        let idx = &self.live.base;
        // d's child folders: dir ids follow entry order.
        let (s, l, de) = (idx.dir_start(d as usize), idx.dir_len(d as usize), idx.dir_entries());
        let kids = idx.dirs_before(s) as u32..idx.dirs_before(s + l) as u32;
        match parts.split_first() {
            None => out.push(d),
            Some((Part::Any, rest)) => {
                self.walk(d, rest, out);
                kids.for_each(|c| self.walk(c, parts, out));
            }
            Some((p, rest)) => kids.filter(|&c| p.matches(&idx.name(de.get(c as usize) as usize))).for_each(|c| self.walk(c, rest, out)),
        }
    }

    /// The folders named `l` (ignoring case) among entries `lo..hi`.
    fn dirs_named(&self, l: &[u8], lo: u32, hi: u32) -> Vec<u32> {
        let idx = &self.live.base;
        let tb = TokenBits::new(idx, &Token::literal(l.to_vec()));
        let mut out = Vec::new();
        for w in 0..idx.words {
            let mut m = tb.word(w).1;
            while m != 0 {
                let k = (w * 64) as u32 + m.trailing_zeros();
                m &= m - 1;
                if idx.uname(k).eq_ignore_ascii_case(l) {
                    out.extend(idx.ents(k).filter(|&e| (lo..hi).contains(&e) && idx.kind(e as usize) & 3 == KIND_DIR).filter_map(|e| idx.dir_of(e)));
                }
            }
        }
        out
    }

    /// The top `q.limit` hits. A word that takes typos and that no top hit
    /// has well (as typed, or with typos keeping the first letter) is
    /// likely misspelled worse: then the search runs again, deep.
    /// Words in two Unicode forms (`Query::alt`) are looked for in both.
    pub fn search(&self, q: &Query) -> Vec<Hit> {
        let Some(alt) = &q.alt else { return self.search_form(q) };
        let other = Query { tokens: alt.clone(), alt: None, ..q.clone() };
        let mut hits = self.search_form(q);
        // Without a deep typo search of its own: a form the disk may not
        // hold at all would run one every time.
        hits.extend(self.search_once(&other));
        // An entry both find, once, at its best.
        hits.sort_by_cached_key(|h| std::cmp::Reverse(self.sort_key(h)));
        let mut seen = std::collections::HashSet::new();
        hits.retain(|h| seen.insert((h.idx, h.over.clone())));
        hits.truncate(q.limit);
        hits
    }

    fn search_form(&self, q: &Query) -> Vec<Hit> {
        let hits = self.search_once(q);
        if q.tokens.iter().any(|t| !t.negate && t.edits > 0 && !t.deep) && !self.well_found(q, &hits) {
            return self.search_once(&q.deepen());
        }
        hits
    }

    /// Whether every positive word that takes typos is in a part of the path
    /// of one of the first WELL_TOP hits as typed from a word start on (all
    /// its chars in a row: 23 per char and 7 more at least, as scored), with
    /// typos keeping the first letter, or as an abbreviation of it.
    fn well_found(&self, q: &Query, hits: &[Hit]) -> bool {
        let toks: Vec<&Token> = q.tokens.iter().filter(|t| !t.negate && t.edits > 0).collect();
        let mut found = vec![false; toks.len()];
        let mut p = Vec::new();
        for h in hits.iter().take(WELL_TOP) {
            if found.iter().all(|&f| f) {
                break;
            }
            match &h.over {
                Some(path) => p.clone_from(path),
                None => self.live.base.path(h.idx as usize, &mut p),
            }
            for (f, t) in found.iter_mut().zip(&toks) {
                let row = 23 * t.text.len() as i32 + 7;
                let well = |c: &[u8]| {
                    fuzzy_score_capped(c, None, &t.text, FULL).is_some_and(|s| s + (c.len() as i32).min(80) / 3 >= row)
                        || typo_score(c, None, true, &t.text).is_some()
                        || abbreviates(c, &t.text)
                        || at_word(c, &t.text)
                };
                *f = *f || p.rsplit(|&b| b == b'/').any(|c| !c.is_empty() && well(c));
            }
        }
        found.iter().all(|&f| f)
    }

    fn search_once(&self, q: &Query) -> Vec<Hit> {
        let mut hits = self.search_base(q);
        hits.extend(self.search_overlay(q));
        // Each hit's key once: a scan for grep lists up to 200k hits.
        hits.sort_by_cached_key(|h| std::cmp::Reverse(self.sort_key(h)));
        hits.truncate(q.limit);
        hits
    }

    /// A hit's `entry_key`; an overlay entry's sorts after the base's.
    fn sort_key(&self, h: &Hit) -> u64 {
        let file = match &h.over {
            Some(p) => self.live.over.get(p).is_some_and(|o| o.kind & 3 == KIND_FILE),
            None => self.live.base.kind(h.idx as usize) & 3 == KIND_FILE,
        };
        entry_key(h.score, h.idx.min(i32::MAX as u32), file)
    }

    fn search_base(&self, q: &Query) -> Vec<Hit> {
        let Some((lo, hi)) = self.scope_range(q) else { return Vec::new() };
        let ranges = self.glob_ranges(q, lo, hi);
        let ranges = ranges.as_deref();
        if ranges.is_some_and(|r| r.is_empty()) {
            return Vec::new();
        }
        if ranges.is_none()
            && let Some((t, tentative)) = self.rankable(q, lo, hi)
        {
            let scope = (q.scope.is_some() && hi - lo <= self.live.base.u / 4).then(|| self.scope_names(lo, hi));
            if let Some(hits) = self.ranked(q, t, lo, hi, scope.as_deref(), tentative) {
                return hits;
            }
        }
        let pos: Vec<&Token> = q.tokens.iter().filter(|t| !t.negate).collect();
        let neg: Vec<&Token> = q.tokens.iter().filter(|t| t.negate).collect();
        if (pos.len() > 1 || !neg.is_empty())
            && let Some(hits) = self.driven(q, &pos, &neg, lo, hi, ranges)
        {
            return hits;
        }
        if ranges.is_none()
            && let Some(hits) = self.spread(q, &pos, &neg, lo, hi)
        {
            return hits;
        }
        // Step 1: every name-only predicate, once per distinct name (~2M)
        // rather than once per entry (~7.5M); reused while you type.
        let scored = self.names(q, &pos, &neg, lo, hi);
        let need_dirs = pos.len() > 1 || !neg.is_empty();
        let s = Scan::new(q, self.live, &scored.names, pos.len(), need_dirs, ranges);
        // Step 2: score entries. Few candidates: just the entries carrying a
        // matching name. Many: one sequential pass over every entry.
        let fast = !scored.names.all && !FULL_PASS.load(std::sync::atomic::Ordering::Relaxed);
        if fast && scored.names.ok_entries <= SELECTIVE {
            return s.selective(lo, hi);
        }

        let memo = if s.need_dirs { Some(lazy(&scored.memo, || self.dir_tokens(&scored.names))) } else { None };
        s.full(ranges.unwrap_or(&[(lo as u32, hi as u32)]), memo.map(|m| m.as_slice()))
    }

    /// The query's token if `ranked` can answer it: one fuzzy token (and any
    /// negated ones), no filter on the entries themselves, and broad enough
    /// to be worth it, going by how many names have each of its classes.
    /// That guess misses words whose letters go together ("delivery": 1,349
    /// names guessed, 25k candidates): an unscoped word (letters only; with
    /// a dot, digit or delimiter a token names a file) it puts between
    /// BORDERLINE and RANKED_MIN names gets its candidates counted in every
    /// 64th bitmap word, and if those are many, a tentative try (true).
    fn rankable<'q>(&self, q: &'q Query, lo: usize, hi: usize) -> Option<(&'q Token, bool)> {
        let mut pos = q.tokens.iter().filter(|t| !t.negate);
        let (Some(t), None) = (pos.next(), pos.next()) else { return None };
        if t.mode != Mode::Fuzzy || q.kind.is_some() || q.size != (0, u64::MAX) || q.mtime != (0, u32::MAX) || q.path_re.is_some() || q.limit == 0 {
            return None;
        }
        // Typing on from a table (the last query was narrow): narrowing it
        // is cheaper.
        let scope = (q.scope.is_some() && hi - lo <= self.live.base.u / 4).then_some((lo, hi));
        let key = NameKey::of(q, scope);
        if self.live.names_cache.last.lock().unwrap().as_ref().is_some_and(|p| key.narrows(&p.key)) {
            return None;
        }
        let (idx, u) = (&self.live.base, self.live.base.u as f64);
        let counts = idx.class_counts();
        let est = (0..CLASSES).filter(|&c| t.mask & (1 << c) != 0).fold(u, |e, c| e * counts[c] as f64 / u);
        if est >= RANKED_MIN {
            return Some((t, false));
        }
        if est < BORDERLINE || q.scope.is_some() || !t.text.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        let tb = TokenBits::new(idx, t);
        let found = (0..idx.words).step_by(64).map(|w| tb.word(w).0.count_ones() as f64).sum::<f64>() * 64.0;
        (found >= RANKED_MIN).then_some((t, true))
    }

    /// A broad one-token search ("a", "de"): its top `limit` comes from a few
    /// dozen of the million names it matches. Names are scored in batches,
    /// in falling order of a bound on their entries' scores read without the
    /// name (`index::NameInfo`): 24 per char + 8, the placement bonus its
    /// length and stem leave possible if it starts with the token's first
    /// byte, the best location prior among its folders and the best rank
    /// tweak. Each batch's entries are visited best prior first, until no
    /// name left can beat the limit-th entry found. Names that cannot start
    /// with the token come from a list of the highest keys, or, if the floor
    /// ends up below it, from a pass over them all.
    /// None if fewer than `limit` hits turn up among the few thousand names
    /// with the best bounds: then a name table, which typing can narrow from,
    /// costs about the same.
    fn ranked(&self, q: &Query, t: &Token, lo: usize, hi: usize, within: Option<&NameSet>, tentative: bool) -> Option<Vec<Hit>> {
        let idx = &self.live.base;
        let (prior, info) = (idx.name_prior(), idx.name_info());
        let tb = TokenBits::new(idx, t);
        let start = idx.bitmap(BM_START + crate::index::start_hash(t.text[0]));
        let space = char_bit(b' ').trailing_zeros() as usize;
        let space = [idx.bitmap(BM_FIRST + space), idx.bitmap(BM_SECOND + space)];
        let tweak = |flags: u8| 10 + if flags & NF_APP != 0 { 25 } else { 0 } - if flags & NF_DOT != 0 { 8 } else { 0 };
        let neg: Vec<&Token> = q.tokens.iter().filter(|t| t.negate).collect();
        let scoped = within.is_some();
        let within = |w: usize| within.map_or(!0, |s| s.bits[w]);
        // Name k, given its word's `TokenBits::word`: its hit and the bound
        // on its entries.
        let score = |k: u32, (_, clean, typo): (u64, u64, u64), re: Option<&regex::bytes::Regex>| -> Option<Cand> {
            let (w, i) = (k as usize / 64, k % 64);
            let nm = idx.uname(k);
            let name: &[u8] = &nm;
            let spaced = (space[0][w] | space[1][w]) >> i & 1 != 0;
            let s = token_score(name, nm.wide(), (clean >> i & 1 != 0, typo >> i & 1 != 0, spaced), t)?;
            if !(q.exts.is_empty() || ext_ok(name, &q.exts))
                || !q.name_ok(name)
                || re.is_some_and(|re| !re.is_match(name))
                || neg.iter().any(|t| token_matches(name, t))
            {
                return None;
            }
            let score = s.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
            let flags = name_flags(name) | NF_OK;
            Some(Cand { bound: score as i32 + prior[k as usize] as i32 + tweak(flags), k, score, flags })
        };
        // The cheap bound: 24 per char + 8 (16 less if the token starts with
        // a delimiter, which takes no boundary bonus), plus the placement
        // bonus its length and stem leave possible if the name starts with
        // the token's first byte, plus its key.
        let (m, t0) = (t.text.len() as i32, t.text[0]);
        let base = 24 * m + 8 - if class(t0) == Class::Delim { 16 } else { 0 };
        // A stem match's length penalty is the stem's, not the name's.
        let cheap = |x: crate::index::NameInfo| {
            base + x.key as i32
                + match x.head == t0 {
                    false => 0,
                    true if x.len as i32 == m => 100 + DOT_WHOLE,
                    true if x.stem as i32 == m => 100 + (x.len as i32 + 1).min(80) / 3 - (x.stem as i32).min(80) / 3,
                    true => 30,
                }
        };
        let none = NameTable::new(Vec::new(), Vec::new(), Vec::new(), 0, false);
        let scan = Scan::new(q, self.live, &none, 1, false, None);
        let entries = |k: u32| idx.ents(k);
        let (dir_prior, de, dp, en) = (idx.dir_prior(), idx.dir_entries(), idx.dir_parents(), idx.ent_names());
        // Whether a folder on the path to dir `d` has a negated token's name.
        let negated = |d: u32, cache: &mut HashMap<u32, bool, crate::index::Fx>| {
            let mut chain = Vec::new();
            let mut k = d;
            let mut out = loop {
                if k == 0 {
                    break false;
                }
                if let Some(&b) = cache.get(&k) {
                    break b;
                }
                chain.push(k);
                k = dp.get(k as usize);
            };
            for &k in chain.iter().rev() {
                out = out || neg.iter().any(|t| token_matches(&idx.uname(en.get(de.get(k as usize) as usize)), t));
                cache.insert(k, out);
            }
            out
        };
        // The entries of `names` that beat `floor` (a `key`). A name's run
        // stops once `limit` of its entries are in: that many at most count
        // as work.
        let visit = |names: &[Cand], floor: u64| {
            let visits = names.iter().map(|x| entries(x.k).len().min(q.limit)).sum();
            top_k(names.len(), q.limit, visits, floor, |r, top| {
                let (mut pbuf, mut cache) = (Vec::new(), HashMap::default());
                for c in &names[r] {
                    let nh = NameHit { score: c.score, bits: 1, flags: c.flags, best: [0; 4] };
                    for e in entries(c.k).filter(|&e| (lo..hi).contains(&(e as usize))) {
                        let p = idx.parent(e as usize);
                        // Entries come best prior first: the rest cannot make it either.
                        if key(c.score as i32 + dir_prior[p as usize] as i32 + tweak(c.flags), 0) <= top.floor {
                            break;
                        }
                        if !neg.is_empty() && negated(p, &mut cache) {
                            continue;
                        }
                        if let Some(key) = scan.score(e as usize, p, nh, DirMemo::default(), top.floor, &mut pbuf, None) {
                            top.push(key);
                        }
                    }
                }
            })
        };
        // The best `limit` hits so far, the limit-th one's score (i32::MIN if
        // fewer) and key (0 if fewer).
        let best = |mut hits: Vec<Hit>| {
            hits.sort_by_cached_key(|h| std::cmp::Reverse(self.sort_key(h)));
            hits.truncate(q.limit);
            let last = hits.get(q.limit - 1).map(|h| (h.score, self.sort_key(h)));
            let (floor, fkey) = last.unwrap_or((i32::MIN, 0));
            (hits, floor, fkey)
        };
        // The names that can start with the token (the only ones that can
        // get a placement bonus), best cheap bound first, with how many fall
        // in each bin.
        let bin = |b: i32| (b + BIN0).clamp(0, BINS as i32 - 1) as usize;
        let sorted = |got: Vec<(i32, u32)>, h: Vec<u32>| {
            let mut at = vec![0u32; BINS];
            let mut acc = 0;
            for b in (0..BINS).rev() {
                at[b] = acc;
                acc += h[b];
            }
            let mut sorted = vec![(0, 0); got.len()];
            for x in got {
                let b = bin(x.0);
                sorted[at[b] as usize] = x;
                at[b] += 1;
            }
            (sorted, h)
        };
        let by_key = idx.by_key();
        // How far a run of batches got: the best hits so far, the limit-th
        // one's score and key, the bin from which on every name is scored,
        // the next batch's size and how much of `by_key.list` is done.
        struct Run {
            hits: Vec<Hit>,
            floor: i32,
            fkey: u64,
            top: usize,
            want: usize,
            listed: usize,
        }
        // Names with their cheap bounds, best first, and how many per bin.
        type Part = (Vec<(i32, u32)>, Vec<u32>);
        // Score them best bin first, a batch at a time, until no name left
        // can beat the limit-th entry found. With `complete` false `parts`
        // holds only some of them, the rest bounded by `cover + 29` over
        // base: unless that settles the search, how far it got.
        let run = |parts: Vec<Part>, complete: bool, r: Run| -> Result<Option<Vec<Hit>>, Run> {
            let Run { mut hits, mut floor, mut fkey, mut top, mut want, mut listed } = r;
            let mut hist = vec![0usize; BINS];
            for (_, h) in &parts {
                hist.iter_mut().zip(h).for_each(|(a, &b)| *a += b as usize);
            }
            // Names that cannot start with the token get no placement bonus:
            // base + key bounds them. The highest keys come in order, the
            // rest only matter if the floor ends up below them.
            for (key, &n) in (by_key.cover..=i8::MAX as i32).zip(&by_key.counts) {
                hist[bin(base + key)] += n as usize;
            }
            let mut taken: Vec<usize> = parts.iter().map(|(items, _)| items.iter().take_while(|x| bin(x.0) >= top).count()).collect();
            let done = |floor: i32, top: usize| floor != i32::MIN && (top == 0 || floor > top as i32 - 1 - BIN0);
            // Without all of them, names bounded by `cover + 29` over base
            // cannot settle it.
            let least = if complete { 0 } else { bin(base + by_key.cover + 30) };
            while want <= LAST_BATCH && !done(floor, top) && top > least {
                let low = if floor == i32::MIN { 0 } else { bin(floor) }.max(least);
                let (mut cut, mut n) = (top, 0);
                while cut > low && n < want {
                    cut -= 1;
                    n += hist[cut];
                }
                let ends: Vec<usize> =
                    parts.iter().zip(&taken).map(|((items, _), &a)| a + items[a..].iter().take_while(|x| bin(x.0) >= cut).count()).collect();
                let lend = listed + by_key.list[listed..].iter().take_while(|x| bin(base + x.0 as i32) >= cut).count();
                let one = |p: usize| {
                    let re = q.name_re.clone();
                    let items = &parts[p].0[taken[p]..ends[p]];
                    items
                        .iter()
                        .filter_map(|&(_, k)| score(k, tb.word(k as usize / 64), re.as_ref()).filter(|c| c.bound >= floor))
                        .collect::<Vec<_>>()
                };
                let mut batch: Vec<Cand> = if n <= INLINE_NAMES {
                    (0..parts.len()).flat_map(one).collect()
                } else {
                    par_each(parts.len(), || (), |_, p| one(p)).into_iter().flatten().collect()
                };
                let re = q.name_re.clone();
                batch.extend(by_key.list[listed..lend].iter().filter_map(|&(_, k)| {
                    let (w, i) = (k as usize / 64, k % 64);
                    if info[k as usize].head == t0 || within(w) >> i & 1 == 0 {
                        return None;
                    }
                    let x = tb.word(w);
                    (x.0 >> i & 1 != 0).then(|| score(k, x, re.as_ref())).flatten().filter(|c| c.bound >= floor)
                }));
                (taken, listed) = (ends, lend);
                (hits, floor, fkey) = best(hits.into_iter().chain(visit(&batch, fkey)).collect());
                top = cut;
                want *= 4;
                // A tentative try that one batch does not settle has few good
                // matches: a name table costs no more and typing can narrow
                // it. So does any try whose first two batches turn up a
                // handful of hits.
                if tentative && !(done(floor, top) && floor >= base + by_key.cover) || hits.len() < q.limit / 4 && want > FIRST_BATCH * 4 {
                    if !complete {
                        break;
                    }
                    return Ok(None);
                }
            }
            // Then, if the floor is low, every other name that can still
            // beat it, in one pass.
            if done(floor, top) && floor >= base + by_key.cover && (complete || floor > base + by_key.cover + 29) {
                return Ok(Some(hits));
            }
            if !complete {
                return Err(Run { hits, floor, fkey, top, want, listed });
            }
            if floor == i32::MIN {
                return Ok(None);
            }
            let scored = |k: usize| {
                let x = info[k];
                let placed = x.head == t0;
                bin(cheap(x)) >= top && (placed || x.key as i32 >= by_key.cover)
            };
            let rest = par_each(
                idx.words.div_ceil(CHUNK_WORDS),
                || q.name_re.clone(),
                |re, c| {
                    let mut out = Vec::new();
                    for w in c * CHUNK_WORDS..((c + 1) * CHUNK_WORDS).min(idx.words) {
                        let mut m = within(w);
                        if m == 0 {
                            continue;
                        }
                        let x = tb.word(w);
                        m &= x.0;
                        while m != 0 {
                            let k = w * 64 + m.trailing_zeros() as usize;
                            m &= m - 1;
                            if cheap(info[k]) >= floor
                                && !scored(k)
                                && let Some(c) = score(k as u32, x, re.as_ref()).filter(|c| c.bound >= floor)
                            {
                                out.push(c);
                            }
                        }
                    }
                    out
                },
            )
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            Ok(Some(best(hits.into_iter().chain(visit(&rest, fkey)).collect()).0))
        };
        let mut from = Run { hits: Vec::new(), floor: i32::MIN, fkey: 0, top: BINS, want: FIRST_BATCH, listed: 0 };
        // A short token first tries the names starting with it that it can
        // find without a pass over every word: those with the highest keys,
        // and those it can match whole (`index::ByKey`). Any other such name
        // has no bonus above 30 and a key below `cover`. If that does not
        // settle it, the pass goes on from there.
        if t.text.len() <= crate::index::SHORT && !scoped {
            let m = t.text.len();
            let whole = |k: &u32| {
                let x = info[*k as usize];
                (x.len as usize == m || x.stem as usize == m) && (x.key as i32) < by_key.cover
            };
            let (mut got, mut h) = (Vec::new(), vec![0u32; BINS]);
            for &k in by_key.heads[t0 as usize].iter().chain(by_key.short[t0 as usize].iter().filter(|k| whole(k))) {
                if tb.word(k as usize / 64).0 >> (k % 64) & 1 != 0 {
                    let c = cheap(info[k as usize]);
                    h[bin(c)] += 1;
                    got.push((c, k));
                }
            }
            match run(vec![sorted(got, h)], false, from) {
                Ok(found) => return found,
                Err(r) => from = r,
            }
        }
        // Otherwise all of them, from a pass over the words in pieces.
        let pieces = if idx.words <= INLINE_WORDS { 1 } else { rayon::current_num_threads() * 2 };
        let step = idx.words.div_ceil(pieces);
        let piece = |p: usize| {
            let (mut got, mut h) = (Vec::new(), vec![0u32; BINS]);
            for (w, &s) in start.iter().enumerate().take(((p + 1) * step).min(idx.words)).skip(p * step) {
                let mut x = s & within(w);
                if x == 0 {
                    continue;
                }
                x &= tb.word(w).0;
                while x != 0 {
                    let k = w * 64 + x.trailing_zeros() as usize;
                    x &= x - 1;
                    if info[k].head == t0 {
                        let c = cheap(info[k]);
                        h[bin(c)] += 1;
                        got.push((c, k as u32));
                    }
                }
            }
            sorted(got, h)
        };
        let parts = if pieces == 1 { vec![piece(0)] } else { par_each(pieces, || (), |_, p| piece(p)) };
        run(parts, true, from).ok().flatten()
    }

    /// Several fuzzy words, most of the disk matching some (a short or
    /// common word, or one being typed): a hit has each word in its own
    /// name or a folder above it, and its top `limit` comes from the names
    /// and folders that start with a word. Those are visited best first, a
    /// name's entries or a folder's subtree, every entry scored in full,
    /// until the limit-th hit beats what an entry not yet seen can score:
    /// per word, the best name or folder starting with it left, or a match
    /// elsewhere in a name (24 per char + 8 less the length penalty; through
    /// a folder 3/4 of that), plus the location prior and tweak. Names the
    /// words spell (+100), apps (+25) and the few folders with the highest
    /// priors go first. A source that cannot lower that bound (a word held
    /// up by a folder too big to visit) waits until nothing else can. None
    /// if it does not settle within a budget (few hits, each of which
    /// counts, or a big folder in the way).
    fn spread(&self, q: &Query, pos: &[&Token], neg: &[&Token], lo: usize, hi: usize) -> Option<Vec<Hit>> {
        let idx = &self.live.base;
        if pos.len() < 2
            || pos.iter().any(|t| t.mode != Mode::Fuzzy)
            || q.kind.is_some()
            || q.size != (0, u64::MAX)
            || q.mtime != (0, u32::MAX)
            || q.path_re.is_some()
            || q.limit == 0
        {
            return None;
        }
        let (info, en) = (idx.name_info(), idx.ent_names());
        let (dstart, dend, dlen, dprior) =
            (|d: u32| idx.dir_start(d as usize), |d: u32| idx.dir_end(d as usize), |d: u32| idx.dir_len(d as usize), idx.dir_prior());
        let scope = (q.scope.is_some() && hi - lo <= idx.u / 4).then(|| self.scope_names(lo, hi));
        let within = |w: usize| scope.as_ref().map_or(!0, |s| s.bits[w]);
        let dot = idx.bitmap(crate::index::BM_DOT);
        let m = pos.len();
        let pen = |len: usize| (len as i32).min(80) / 3;
        // A word's match brings 24 per char + 8 at most (16 less if it
        // starts with a delimiter), its placement aside; through a folder,
        // 3/4 of the folder's for the first four words, 6 for the rest.
        let base: Vec<i32> = pos.iter().map(|t| 24 * t.text.len() as i32 + 8 - if class(t.text[0]) == Class::Delim { 16 } else { 0 }).collect();
        let by_dir = |i: usize, s: i32| if i < 4 { s.max(0) * 3 / 4 } else { 6 };
        let tbs: Vec<TokenBits> = pos.iter().map(|t| TokenBits::new(idx, t)).collect();
        // In one pass over the name bitmaps: per word, the names starting
        // with it past a leading dot and their score (`prefix_score`); the
        // names the words spell (+100) and apps (+25), which go first.
        let joined = q.joined();
        let heads = [joined.first().copied().unwrap_or(0), b'_', b'-', b'.', b' '];
        let spell: Vec<&[u64]> =
            if joined.is_empty() { Vec::new() } else { heads.iter().map(|&h| idx.bitmap(BM_START + crate::index::start_hash(h))).collect() };
        let app = idx.bitmap(crate::index::BM_APP);
        let starts: Vec<&[u64]> = pos.iter().map(|t| idx.bitmap(BM_START + crate::index::start_hash(t.text[0]))).collect();
        let found = par_words(idx.words, |r| {
            let (mut own, mut first, mut any) = (vec![Vec::new(); m], Vec::new(), Vec::with_capacity(r.len()));
            for w in r {
                let within = within(w);
                if within == 0 {
                    any.push(0);
                    continue;
                }
                // Names that may be spelled: every word fits them; names
                // some word fits.
                let (mut sp, mut fit) = (spell.iter().fold(0, |a, b| a | b[w]) & within, 0);
                for (i, t) in pos.iter().enumerate() {
                    let (t0, n) = (t.text[0], t.text.len());
                    let (fits, clean, _) = tbs[i].word(w);
                    let mut x = starts[i][w] & within;
                    sp &= fits;
                    fit |= fits;
                    if n > 1 {
                        x &= clean;
                    }
                    while x != 0 {
                        let k = (w * 64) as u32 + x.trailing_zeros();
                        x &= x - 1;
                        let y = info[k as usize];
                        if y.head != t0 || (y.len as usize) < n {
                            continue;
                        }
                        // One letter: the name's length says it all.
                        if n == 1 {
                            let off = (dot[w] >> (k % 64) & 1) as usize;
                            let placed = if y.len == 1 {
                                100 + DOT_WHOLE * off as i32
                            } else if y.stem == 1 {
                                100
                            } else {
                                30
                            };
                            own[i].push((base[i] + placed - pen(if placed >= 100 { off + 1 } else { off + y.len as usize }), k));
                            continue;
                        }
                        let nm = idx.uname(k);
                        let name: &[u8] = &nm;
                        let off = (name.len() > 1 && name[0] == b'.') as usize;
                        let e = off + n;
                        if name.len() >= e && name[off + 1..e].iter().zip(&t.text[1..]).all(|(&a, &b)| fold(a) == b) {
                            let placed = if e == name.len() {
                                100 + DOT_WHOLE * off as i32
                            } else if name[e] == b'.' && !name[e + 1..].contains(&b'.') {
                                100
                            } else {
                                30
                            };
                            own[i].push((base[i] + placed - pen(if placed >= 100 { e } else { name.len() }), k));
                        }
                    }
                }
                while sp != 0 {
                    let k = (w * 64) as u32 + sp.trailing_zeros();
                    sp &= sp - 1;
                    if heads.contains(&info[k as usize].head) && spelled(&idx.uname(k), &joined) > 0 {
                        first.push(k);
                    }
                }
                let mut x = app[w] & within;
                if x != 0 {
                    x &= tbs.iter().fold(0, |a, t| a | t.word(w).0);
                }
                while x != 0 {
                    first.push((w * 64) as u32 + x.trailing_zeros());
                    x &= x - 1;
                }
                any.push(fit & within);
            }
            (own, first, any)
        });
        let mut names: Vec<u32> = found.iter().flat_map(|f| f.1.iter().copied()).collect();
        let fits: Vec<u64> = found.iter().flat_map(|f| f.2.iter().copied()).collect();
        // Per word: those names best first, OWN_MAX of them, and their
        // folders.
        let mut words = Vec::with_capacity(m);
        for (i, t) in pos.iter().enumerate() {
            let mut v: Vec<(i32, u32)> = found.iter().flat_map(|f| f.0[i].iter().copied()).collect();
            let mut own_pin = base[i] - pen(t.text.len());
            if v.len() > OWN_MAX {
                v.select_nth_unstable_by(OWN_MAX, |a, b| b.cmp(a));
                own_pin = own_pin.max(v[OWN_MAX].0);
                v.truncate(OWN_MAX);
            }
            v.sort_unstable_by(|a, b| b.cmp(a));
            // Their folders, best first, among the names' first FOLD_SCAN
            // entries (for a word of one letter, those of the names it is
            // whole); the rest a bound.
            let (mut dirs, mut dir_pin) = (Vec::new(), by_dir(i, own_pin));
            if i < 4 {
                let end = if t.text.len() == 1 { v.partition_point(|x| x.0 > base[i] + 30) } else { v.len() };
                let (mut ents, mut looked) = (Vec::new(), 0);
                for &(s, k) in &v[..end] {
                    let e = idx.ents(k);
                    looked += e.len();
                    if looked > FOLD_SCAN {
                        dir_pin = dir_pin.max(by_dir(i, s));
                        break;
                    }
                    ents.extend(e.filter(|&e| idx.kind(e as usize) & 3 == KIND_DIR).map(|e| (by_dir(i, s), e)));
                }
                if let Some(x) = v.get(end) {
                    dir_pin = dir_pin.max(by_dir(i, x.0));
                }
                let of = |c: &[(i32, u32)]| {
                    c.iter()
                        .filter_map(|&(s, e)| {
                            let d = idx.dir_of(e)?;
                            let (a, b) = (dstart(d).max(lo as u32), dend(d).min(hi as u32));
                            (a < b).then_some((s, d, b - a))
                        })
                        .collect::<Vec<_>>()
                };
                let chunks: Vec<&[(i32, u32)]> = ents.chunks(256).collect();
                dirs = if chunks.len() <= 1 {
                    chunks.iter().flat_map(|c| of(c)).collect()
                } else {
                    par_each(chunks.len(), || (), |_, c| of(chunks[c])).concat()
                };
                // Of a bound, the biggest first: one too big to visit holds
                // its word's bound there, and the rest need not be visited.
                dirs.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(b.2.cmp(&a.2)));
            }
            let trees = merge(dirs.iter().map(|&(_, d, _)| (dstart(d).max(lo as u32), dend(d).min(hi as u32))).collect());
            words.push(Word { own: v, oc: 0, dirs, dc: 0, trees, own_pin, dir_pin });
        }
        let (p0, high) = self.priors();
        let mut trees: Vec<(u32, u32)> =
            high.iter().map(|&d| (dstart(d).max(lo as u32), (dstart(d) + dlen(d)).min(hi as u32))).filter(|r| r.0 < r.1).collect();

        let none = NameTable::new(Vec::new(), Vec::new(), Vec::new(), 0, false);
        let scan = Scan::new(q, self.live, &none, m, true, None);
        let path = if q.path_bits().0 != 0 { PATH_HIT } else { 0 };
        // The most a word brings an entry through its folders.
        let most: Vec<i32> = (0..m).map(|i| by_dir(i, base[i] + FULL - pen(pos[i].text.len() + 1))).collect();
        let best = |mut hits: Vec<Hit>| {
            hits.sort_by_cached_key(|h| std::cmp::Reverse(self.sort_key(h)));
            hits.truncate(q.limit);
            let last = hits.get(q.limit - 1).map(|h| (h.score, self.sort_key(h)));
            let (floor, fkey) = last.unwrap_or((i32::MIN, 0));
            (hits, floor, fkey)
        };
        // What an entry not seen yet can score: per word, the most its own
        // name or a folder brings (its own name at least one's), plus the
        // path bonus, the prior and the tweak.
        let tau_of = |t: &[(i32, i32)]| {
            t.iter().map(|&(a, b)| a.max(b)).sum::<i32>() - t.iter().map(|&(a, b)| (b - a).max(0)).min().unwrap_or(0) + path + p0 + 10
        };
        let (mut seen_names, mut seen) = (vec![0u64; idx.words], Vec::new());
        let (mut hits, mut floor, mut fkey): (Vec<Hit>, i32, u64) = (Vec::new(), i32::MIN, 0);
        let (mut want, mut work) = (SPREAD_FIRST, 0);
        loop {
            // The next sources, about `want` entries: a word at a time, its
            // best one if it can lower the bound (above what its sources
            // cannot), then, when none can, any that can still hold a hit.
            // (A source picked lowers its word's bound only once visited:
            // what can still beat the floor goes by the bounds before.)
            let t: Vec<(i32, i32)> = words.iter().map(Word::term).collect();
            let (mut n, mut lower) = (0, true);
            while n < want {
                let mut took = false;
                for (i, w) in words.iter_mut().enumerate() {
                    let (a, b) = w.heads();
                    let (dir, s) = match (a, b) {
                        (Some(a), Some(b)) if b > a => (true, b),
                        (Some(a), _) => (false, a),
                        (None, Some(b)) => (true, b),
                        (None, None) => continue,
                    };
                    if lower && s <= w.own_pin.max(w.dir_pin) {
                        continue;
                    }
                    // Past one that cannot beat the floor, none can.
                    let rest: i32 = t.iter().enumerate().filter(|&(j, _)| j != i).map(|(_, &(a, b))| a.max(b)).sum::<i32>() + path + p0 + 10;
                    if hits.len() == q.limit && key(s + rest, 0) <= fkey {
                        if dir {
                            w.dc = w.dirs.len();
                        } else {
                            w.oc = w.own.len();
                        }
                        took = true;
                        continue;
                    }
                    took = true;
                    // Its sources of that bound: the first, then the rest
                    // while the round is not past eight times what it wants.
                    let (mut first, cap) = (true, n.max(8 * want));
                    while std::mem::take(&mut first) || n < cap {
                        let (a, b) = w.heads();
                        if !dir && a == Some(s) {
                            let k = w.own[w.oc].1;
                            w.oc += 1;
                            if seen_names[k as usize >> 6] >> (k & 63) & 1 == 0 {
                                names.push(k);
                                n += idx.ents(k).len();
                            }
                        } else if dir && b == Some(s) {
                            let (s, d, size) = w.dirs[w.dc];
                            w.dc += 1;
                            if size > TREE_MAX {
                                w.dir_pin = w.dir_pin.max(s);
                                if lower {
                                    break;
                                }
                            } else {
                                trees.push((dstart(d).max(lo as u32), dend(d).min(hi as u32)));
                                n += size as usize;
                            }
                        } else {
                            break;
                        }
                    }
                }
                if !took {
                    if !lower {
                        break;
                    }
                    lower = false;
                }
            }
            // Nothing new to visit: dropping what cannot make it may have
            // settled it. Past the budget, the name table is cheaper.
            if names.is_empty() && trees.is_empty() {
                return (hits.len() == q.limit && floor > tau_of(&words.iter().map(Word::term).collect::<Vec<_>>())).then_some(hits);
            }
            if work + n > SPREAD_BUDGET {
                return None;
            }
            // The names' entries not in a range seen, and the ranges not seen
            // yet but for the entries of names seen.
            names.sort_unstable();
            names.dedup();
            names.retain(|&k| seen_names[k as usize >> 6] >> (k & 63) & 1 == 0);
            let fresh = subtract(&merge(std::mem::take(&mut trees)), &seen);
            seen = merge([&seen[..], &fresh[..]].concat());
            let mut items: Vec<(u32, u32)> = fresh.iter().flat_map(|&(a, b)| (a..b).step_by(1024).map(move |x| (x, (x + 1024).min(b)))).collect();
            items.extend(names.iter().map(|&k| (k, u32::MAX)));
            let visits: usize = items.iter().map(|&(a, b)| if b == u32::MAX { idx.ents(a).len() } else { (b - a) as usize }).sum();
            work += visits;
            let got = top_k(items.len(), q.limit, visits, fkey, |r, top| {
                let (mut pbuf, mut memo) = (Vec::new(), HashMap::<u32, DirMemo, crate::index::Fx>::default());
                let mut cache = HashMap::<u32, Option<NameHit>, crate::index::Fx>::default();
                let re = q.name_re.clone();
                let mut hit = |k: u32| *cache.entry(k).or_insert_with(|| name_hit(idx, q, pos, neg, &joined, re.as_ref(), k));
                for &(a, b) in &items[r] {
                    if b == u32::MAX {
                        let Some(nh) = hit(a).filter(|h| h.flags & NF_OK != 0) else { continue };
                        // Entries come best prior first: past one that cannot
                        // make it, none can.
                        // The words not in it come from folders: at most what
                        // their best ones bring, outside those what the rest
                        // do.
                        let tweak = 10 + if nh.flags & NF_APP != 0 { 25 } else { 0 };
                        let up = || (0..m).filter(move |&t| nh.bits >> t & 1 == 0);
                        let lift = up().map(|t| most[t]).sum::<i32>() + path + tweak;
                        for e in idx.ents(a) {
                            if !(lo..hi).contains(&(e as usize)) || in_ranges(&seen, e) {
                                continue;
                            }
                            let p = idx.parent(e as usize);
                            let at = nh.score as i32 + dprior[p as usize] as i32;
                            if key(at + lift, 0) <= top.floor {
                                break;
                            }
                            let near = |t: usize| if in_ranges(&words[t].trees, e) { most[t] } else { words[t].dir_pin };
                            if key(at + up().map(near).sum::<i32>() + path + tweak, 0) <= top.floor {
                                continue;
                            }
                            let dm = scan.memo_of(p, &mut memo, &mut hit);
                            if let Some(x) = scan.score(e as usize, p, nh, dm, top.floor, &mut pbuf, None) {
                                top.push(x);
                            }
                        }
                        continue;
                    }
                    for (run, p) in idx.blocks(a as usize, b as usize) {
                        let mut dm = None;
                        for i in run {
                            // A name no word fits holds no hit.
                            let k = en.get(i);
                            if (fits[k as usize >> 6] & !seen_names[k as usize >> 6]) >> (k & 63) & 1 == 0 {
                                continue;
                            }
                            let Some(nh) = hit(k).filter(|h| h.flags & NF_OK != 0) else { continue };
                            let dm = *dm.get_or_insert_with(|| scan.memo_of(p, &mut memo, &mut hit));
                            if let Some(x) = scan.score(i, p, nh, dm, top.floor, &mut pbuf, None) {
                                top.push(x);
                            }
                        }
                    }
                }
            });
            for &k in &names {
                seen_names[k as usize >> 6] |= 1 << (k & 63);
            }
            (hits, floor, fkey) = best(hits.into_iter().chain(got).collect());
            let t: Vec<(i32, i32)> = words.iter().map(Word::term).collect();
            let tau = tau_of(&t);
            // All the sources could lower it to: if the limit-th hit is not
            // above that, a match elsewhere in a name may beat it (the name
            // table settles that), or there are few hits, each of which
            // counts.
            let least = tau_of(&words.iter().map(|w| (w.own_pin, w.dir_pin)).collect::<Vec<_>>());
            if hits.len() == q.limit && floor > tau {
                return Some(hits);
            }
            if hits.len() < q.limit || floor <= least {
                return None;
            }
            names.clear();
            want *= 2;
        }
    }

    /// See `NameCache::priors`.
    fn priors(&self) -> &(i32, Vec<u32>) {
        self.live.names_cache.priors.get_or_init(|| {
            let idx = &self.live.base;
            let prior = idx.dir_prior();
            let mut n = [0usize; 256];
            for (d, &p) in prior.iter().enumerate() {
                n[(p as i32 + 128) as usize] += idx.dir_len(d) as usize;
            }
            let (mut p0, mut above) = (i8::MAX as i32, 0);
            while p0 > i8::MIN as i32 && above + n[(p0 + 128) as usize] <= PRIOR_ENTRIES {
                above += n[(p0 + 128) as usize];
                p0 -= 1;
            }
            (p0, (0..idx.d as u32).filter(|&d| prior[d as usize] as i32 > p0).collect())
        })
    }

    /// Several tokens: a hit has each in its own name or in a folder above
    /// it, so the names the rarest token matches and the subtrees of folders
    /// so named hold every hit. When those are few, they are all that gets
    /// looked at: their names and folders are scored as they come up, not
    /// all two million names up front. None if they are many.
    fn driven(&self, q: &Query, pos: &[&Token], neg: &[&Token], lo: usize, hi: usize, ranges: Option<&[(u32, u32)]>) -> Option<Vec<Hit>> {
        let idx = &self.live.base;
        // In a small scope, only its names count (see `scope_names`).
        let scope = (q.scope.is_some() && hi - lo <= idx.u / 4).then(|| self.scope_names(lo, hi));
        let within = |w: usize| scope.as_ref().map_or(!0, |s| s.bits[w]);
        // Rarest first, by a guess from how many names have each of its
        // letters. A rare name can still hold too much (a big folder:
        // "developer" is ~/Developer); found out early, the next one gets a
        // try. Then the words the guess put not far past the limit, by the
        // name bitmaps (every 64th word of them, or a scope's all): letters
        // that go together fool it ("bubble" fits 2.6k names, not 58k).
        let (counts, u) = (idx.class_counts(), idx.u as f64);
        let guess: Vec<f64> = pos.iter().map(|t| (0..CLASSES).filter(|&c| t.mask & (1 << c) != 0).fold(u, |e, c| e * counts[c] as f64 / u)).collect();
        let fits = |t: &Token| {
            let tb = TokenBits::new(idx, t);
            let words = (0..idx.words).step_by(if scope.is_some() { 1 } else { 64 }).filter(|&w| within(w) != 0);
            words.map(|w| (tb.word(w).0 & within(w)).count_ones() as f64).sum::<f64>() * if scope.is_some() { 1.0 } else { 64.0 }
        };
        let mut order: Vec<usize> = (0..pos.len()).filter(|&t| guess[t] <= DRIVEN_NAMES).collect();
        order.sort_by(|&a, &b| guess[a].total_cmp(&guess[b]));
        let more = || {
            let near = (0..pos.len()).filter(|&t| guess[t] > DRIVEN_NAMES && guess[t] <= 16.0 * DRIVEN_NAMES);
            let mut v: Vec<(f64, usize)> = near.map(|t| (fits(pos[t]), t)).filter(|x| x.0 <= DRIVEN_FITS).collect();
            v.sort_by(|a, b| a.0.total_cmp(&b.0));
            v.into_iter().map(|x| x.1)
        };
        for t in order.into_iter().chain(std::iter::once_with(more).flatten()).take(DRIVEN_TRIES) {
            match self.drive(q, pos, neg, lo, hi, ranges, scope.as_deref(), t) {
                Ok(hits) => return Some(hits),
                Err(true) => continue,
                Err(false) => return None,
            }
        }
        None
    }

    /// `driven` from token `t`'s names (those `within` holds, if given);
    /// Err(true) if it gave up within the first sixteenth of the names.
    #[allow(clippy::too_many_arguments)]
    fn drive(
        &self,
        q: &Query,
        pos: &[&Token],
        neg: &[&Token],
        lo: usize,
        hi: usize,
        ranges: Option<&[(u32, u32)]>,
        within: Option<&NameSet>,
        t: usize,
    ) -> Result<Vec<Hit>, bool> {
        let idx = &self.live.base;
        let tb = TokenBits::new(idx, pos[t]);
        let space = char_bit(b' ').trailing_zeros() as usize;
        let space = [idx.bitmap(BM_FIRST + space), idx.bitmap(BM_SECOND + space)];
        let en = idx.ent_names();
        // The names' entries, and the subtrees of those that are folders
        // (from above `lo` too: the scope's own ancestors). Past SELECTIVE
        // entries in all, give up, or as soon as the chunks so far (handed
        // out in order; a sixteenth at least) say twice that many are coming.
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
        let chunks = idx.words.div_ceil(CHUNK_WORDS);
        let (seen, quit, early) = (AtomicUsize::new(0), AtomicBool::new(false), AtomicBool::new(false));
        let over = || quit.load(Relaxed);
        let spaced = |w: usize, i: u32| (space[0][w] | space[1][w]) >> i & 1 != 0;
        let found = par_each(
            chunks,
            || (),
            |_, c| {
                let (mut ents, mut trees) = (Vec::new(), Vec::new());
                for w in c * CHUNK_WORDS..((c + 1) * CHUNK_WORDS).min(idx.words) {
                    let only = within.map_or(!0, |s| s.bits[w]);
                    if over() {
                        break;
                    }
                    if only == 0 {
                        continue;
                    }
                    let (fits, clean, typo) = tb.word(w);
                    let mut m = fits & only;
                    while m != 0 {
                        let i = m.trailing_zeros();
                        m &= m - 1;
                        let k = w * 64 + i as usize;
                        let may = (clean >> i & 1 != 0, typo >> i & 1 != 0, spaced(w, i));
                        let nm = idx.uname(k as u32);
                        if token_score(&nm, nm.wide(), may, pos[t]).is_none() {
                            continue;
                        }
                        let mut n = 0;
                        for e in idx.ents(k as u32) {
                            if n > SELECTIVE {
                                break;
                            }
                            if (lo..hi).contains(&(e as usize)) {
                                ents.push(e);
                                n += 1;
                            }
                            if idx.kind(e as usize) & 3 == KIND_DIR
                                && let Some(d) = idx.dir_of(e)
                            {
                                let (a, b) = (idx.dir_start(d as usize).max(lo as u32), idx.dir_end(d as usize).min(hi as u32));
                                if a < b {
                                    trees.push((a, b));
                                    n += (b - a) as usize;
                                }
                            }
                        }
                        if seen.fetch_add(n, Relaxed) + n > SELECTIVE {
                            quit.store(true, Relaxed);
                            early.fetch_or(c < chunks / 16, Relaxed);
                        }
                    }
                }
                if c >= chunks / 16 && seen.load(Relaxed) * chunks / (c + 1) > 2 * SELECTIVE {
                    quit.store(true, Relaxed);
                }
                (ents, trees)
            },
        );
        let (mut ents, mut trees): (Vec<u32>, Vec<(u32, u32)>) = (Vec::new(), Vec::new());
        for (e, t) in found {
            ents.extend(e);
            trees.extend(t);
        }
        if over() {
            return Err(early.load(Relaxed));
        }
        trees.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::new();
        for (a, b) in trees {
            match merged.last_mut() {
                Some(l) if a <= l.1 => l.1 = l.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        // In those subtrees, entries whose name has the token are in `ents`.
        let first = ents.len();
        if first + merged.iter().map(|&(a, b)| (b - a) as usize).sum::<usize>() > SELECTIVE {
            return Err(false);
        }
        ents.extend(merged.iter().flat_map(|&(a, b)| a..b));
        if ents.len() <= INLINE_VISITS {
            // Few (one thread's worth): names and folders scored as they
            // come up.
            let none = NameTable::new(Vec::new(), Vec::new(), Vec::new(), 0, false);
            let scan = Scan::new(q, self.live, &none, pos.len(), true, ranges);
            let joined = q.joined();
            return Ok(top_k(ents.len(), q.limit, ents.len(), 0, |r, top| {
                let (mut pbuf, mut memo) = (Vec::new(), HashMap::<u32, DirMemo, crate::index::Fx>::default());
                let mut hits = HashMap::<u32, Option<NameHit>, crate::index::Fx>::default();
                let re = q.name_re.clone();
                let mut hit = |k: u32| *hits.entry(k).or_insert_with(|| name_hit(idx, q, pos, neg, &joined, re.as_ref(), k));
                for j in r {
                    let i = ents[j] as usize;
                    let Some(nh) = hit(en.get(i)).filter(|h| h.flags & NF_OK != 0 && (j < first || h.bits >> t & 1 == 0)) else { continue };
                    let p = idx.parent(i);
                    let m = scan.memo_of(p, &mut memo, &mut hit);
                    if let Some(key) = scan.score(i, p, nh, m, top.floor, &mut pbuf, q.path_re.as_ref()) {
                        top.push(key);
                    }
                }
            }));
        }
        // Many: score the names of those entries and of the folders above
        // them once, in one table, rather than per thread as they come up.
        let (de, dp) = (idx.dir_entries(), idx.dir_parents());
        let (mut bits, mut seen_dir) = (vec![0u64; idx.words], vec![0u64; idx.d.div_ceil(64)]);
        for &e in &ents {
            let k = en.get(e as usize);
            bits[k as usize >> 6] |= 1 << (k & 63);
            let mut d = idx.parent(e as usize);
            while d != 0 && seen_dir[d as usize >> 6] >> (d & 63) & 1 == 0 {
                seen_dir[d as usize >> 6] |= 1 << (d & 63);
                let k = en.get(de.get(d as usize) as usize);
                bits[k as usize >> 6] |= 1 << (k & 63);
                d = dp.get(d as usize);
            }
        }
        let names = self.score_names(q, pos, neg, None, Some(&NameSet { busy: true, ..NameSet::new(bits) }));
        let scan = Scan::new(q, self.live, &names, pos.len(), true, ranges);
        Ok(top_k(ents.len(), q.limit, ents.len(), 0, |r, top| {
            let (mut pbuf, mut memo) = (Vec::new(), HashMap::<u32, DirMemo, crate::index::Fx>::default());
            let path_re = q.path_re.clone();
            for j in r {
                let i = ents[j] as usize;
                let Some(nh) = names.get(en.get(i)).filter(|h| h.flags & NF_OK != 0 && (j < first || h.bits >> t & 1 == 0)) else { continue };
                let p = idx.parent(i);
                let m = scan.memo_of(p, &mut memo, &mut |k| names.get(k));
                if let Some(key) = scan.score(i, p, nh, m, top.floor, &mut pbuf, path_re.as_ref()) {
                    top.push(key);
                }
            }
        }))
    }

    /// The name table for this query: cached for a repeat of the last one
    /// (the second, longer page of results), narrowed from the last one when
    /// this query only extends it (typing), else scored from scratch.
    fn names(&self, q: &Query, pos: &[&Token], neg: &[&Token], lo: usize, hi: usize) -> std::sync::Arc<Scored> {
        // A small `in:` scope scores just the names found in it.
        let scope = (q.scope.is_some() && hi - lo <= self.live.base.u / 4).then_some((lo, hi));
        let key = NameKey::of(q, scope);
        let prev = self.live.names_cache.last.lock().unwrap().clone();
        if let Some(p) = &prev
            && p.key == key
        {
            return p.clone();
        }
        let from = prev.as_ref().filter(|p| key.narrows(&p.key)).map(|p| &p.names);
        let within = scope.filter(|_| from.is_none()).map(|(lo, hi)| self.scope_names(lo, hi));
        let scored = std::sync::Arc::new(Scored {
            at: std::time::Instant::now(),
            key,
            names: self.score_names(q, pos, neg, from, within.as_deref()),
            memo: std::sync::OnceLock::new(),
        });
        *self.live.names_cache.last.lock().unwrap() = Some(scored.clone());
        scored
    }

    /// Bitset of the names of entries `lo..hi` (a folder's subtree) and of
    /// the folder and its ancestors, whose names folder tokens match. The
    /// last one is kept: searches in a folder tend to come in a row.
    fn scope_names(&self, lo: usize, hi: usize) -> std::sync::Arc<NameSet> {
        let mut cache = self.live.names_cache.scope.lock().unwrap();
        if let Some((r, set)) = &*cache
            && *r == (lo, hi)
        {
            return set.clone();
        }
        let idx = &self.live.base;
        let (en, de, dp) = (idx.ent_names(), idx.dir_entries(), idx.dir_parents());
        let mut bits = vec![0u64; idx.words];
        let mut set = |k: u32| bits[k as usize >> 6] |= 1 << (k & 63);
        for i in lo..hi {
            set(en.get(i));
        }
        let mut d = if lo < hi { idx.parent(lo) } else { 0 };
        while d != 0 {
            set(en.get(de.get(d as usize) as usize));
            d = dp.get(d as usize);
        }
        let set = std::sync::Arc::new(NameSet::new(bits));
        *cache = Some(((lo, hi), set.clone()));
        set
    }

    /// Score distinct names against the query's name-only predicates: every
    /// name, or only the ones `from` matched and `within` holds.
    fn score_names(&self, q: &Query, pos: &[&Token], neg: &[&Token], from: Option<&NameTable>, within: Option<&NameSet>) -> NameTable {
        let idx = &self.live.base;
        // A `path:` anchored at the end says how a match's own name ends.
        let tails = q.path_re.as_ref().and_then(path_suffixes);
        let names_tested = !q.not_exts.is_empty() || q.globs.iter().any(Glob::tests_names);
        if pos.is_empty() && neg.is_empty() && q.exts.is_empty() && q.name_re.is_none() && tails.is_none() && !names_tested {
            // Every name passes with score 0; only its flags differ.
            return NameTable::new(Vec::new(), Vec::new(), Vec::new(), idx.n, true);
        }
        // One token, no negation and an `ext:`: no folder memo reads the
        // table, so only names with an allowed extension matter.
        let by_ext = pos.len() == 1 && neg.is_empty() && !q.exts.is_empty();
        let toks: Vec<TokenBits> = pos.iter().chain(neg).map(|t| TokenBits::new(idx, t)).collect();
        let space = char_bit(b' ').trailing_zeros() as usize;
        let space = [idx.bitmap(BM_FIRST + space), idx.bitmap(BM_SECOND + space)];
        // Name filters as bitmap prefilters: a name passing `ext:` contains
        // ".ext"; one passing `re:` contains a literal every match starts with.
        let filter = |lits: Vec<Vec<u8>>| lits.into_iter().map(Token::literal).collect::<Vec<_>>();
        let re_toks = q.name_re.as_ref().and_then(re_literals).map(filter);
        let re_bits = re_toks.as_ref().map(|t| t.iter().map(|t| TokenBits::new(idx, t)).collect::<Vec<_>>());
        // A glob testing names: each alternative's name has its longest
        // literal run.
        let glob_toks: Vec<Vec<Token>> = q
            .globs
            .iter()
            .filter(|g| !g.negate && g.tests_names())
            .filter_map(|g| {
                g.alts.iter().map(|a| a.name.as_ref().map(Part::literal).filter(|l| !l.is_empty()).map(|l| Token::literal(l.to_vec()))).collect()
            })
            .collect();
        let glob_bits: Vec<Vec<TokenBits>> = glob_toks.iter().map(|g| g.iter().map(|t| TokenBits::new(idx, t)).collect()).collect();
        // `ext:` as the extension slots it allows (see `Index::name_ext`):
        // only a name whose extension is not in the table needs reading.
        let ext_slots = idx.name_ext();
        let mut allow = [0u64; 4];
        for e in &q.exts {
            let s = idx.ext_slot(e) as usize;
            allow[s / 64] |= 1 << (s % 64);
        }
        let ext_ok_k = |k: usize, name: &[u8]| {
            let s = ext_slots[k] as usize;
            allow[s / 64] >> (s % 64) & 1 != 0 && (s != 255 || ext_ok(name, &q.exts))
        };
        // The names of word w whose slot the filter allows.
        let ext_word = |w: usize| -> u64 {
            if q.exts.is_empty() {
                return !0;
            }
            let slots = &ext_slots[w * 64..(w * 64 + 64).min(idx.u)];
            slots.iter().enumerate().fold(0, |m, (i, &s)| m | (allow[s as usize / 64] >> (s % 64) & 1) << i)
        };
        let (dot, app) = (idx.bitmap(crate::index::BM_DOT), idx.bitmap(crate::index::BM_APP));
        let (joined, all) = (q.joined(), (1u8 << pos.len().min(8)).wrapping_sub(1));
        // Name k is bit i of lane j of `per` (each token's
        // `TokenBits::words`). `re` is the task's own copy of `name_re`:
        // sharing one regex's cache pool across threads costs more than the
        // match.
        let score_one =
            |k: usize, i: u32, per: &[Pair], j: usize, spaced: bool, re: Option<&regex::bytes::Regex>, ok_entries: &mut usize| -> Option<NameHit> {
                let nm = idx.uname(k as u32);
                let name: &[u8] = &nm;
                let (w, bit) = (k / 64, |x: u64| x >> i & 1 != 0);
                // A filter alone reads no name for its flags.
                let flags = match pos.is_empty() {
                    true => (if bit(dot[w]) { NF_DOT } else { 0 }) | (if bit(app[w]) { NF_APP } else { 0 }),
                    false => name_flags(name),
                };
                let mut h = NameHit { score: 0, bits: 0, flags, best: [0; 4] };
                for (t, tok) in pos.iter().enumerate() {
                    let (fits, clean, typo) = per[t].0[j];
                    if bit(fits)
                        && let Some(s) = token_score(name, nm.wide(), (bit(clean), bit(typo), spaced), tok)
                    {
                        h.bits |= 1 << t;
                        let s16 = s.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                        h.score = h.score.saturating_add(s16);
                        if t < 4 {
                            h.best[t] = s16.max(0);
                        }
                    }
                }
                if !joined.is_empty() && h.bits == all {
                    h.score = h.score.saturating_add(spelled(name, &joined) as i16);
                }
                if neg.iter().zip(&per[pos.len()..]).any(|(t, p)| bit(p.0[j].0) && token_matches(name, t)) {
                    h.flags |= NF_NEG;
                }
                // As a file match it must hit a token and pass name filters;
                // as a folder on someone's path, the raw token bits matter.
                let ok = (pos.is_empty() || h.bits != 0)
                    && h.flags & NF_NEG == 0
                    && (q.exts.is_empty() || ext_ok_k(k, name))
                    && (!names_tested || q.name_ok(name))
                    && tails.as_ref().is_none_or(|t| t.iter().any(|t| ends_with_fold(name, t)))
                    && re.is_none_or(|re| re.is_match(name));
                if ok {
                    h.flags |= NF_OK;
                    *ok_entries += idx.ents(k as u32).len();
                }
                (ok || h.bits != 0 || h.flags & NF_NEG != 0).then_some(h)
            };
        // One chunk of name ids: its words of the bitset and rank, and its
        // hits in id order (into a spare buffer). Words with candidates go
        // in pairs where they can (see `TokenBits::words`). `per` is the
        // task's scratch.
        let chunk = |c: usize, bits: &mut [u64], rank: &mut [u16], mut hits: Vec<NameHit>, per: &mut [Pair]| {
            let mut ok = 0;
            let (lo, n) = (c * CHUNK_WORDS, bits.len());
            // The chunk's words with candidates, as a bitset.
            let mut todo: Todo = std::array::from_fn(|g| 1u64.checked_shl(n.saturating_sub(g * 64) as u32).map_or(!0, |b| b - 1));
            if let Some(f) = from {
                let words = if f.hits[c].is_empty() { Todo::default() } else { nonzero(&f.bits[lo..lo + n]) };
                todo = std::array::from_fn(|g| todo[g] & words[g]);
            }
            if let Some(s) = within {
                todo = std::array::from_fn(|g| todo[g] & s.todo[c][g]);
            }
            if todo == Todo::default() {
                return (hits, ok);
            }
            let re = q.name_re.clone();
            let cand_of = |w: usize| from.map_or(!0, |f| f.bits[w]) & within.map_or(!0, |s| s.bits[w]);
            let has = |todo: &[u64], wi: usize| wi < n && todo[wi / 64] >> (wi % 64) & 1 != 0;
            for g in 0..todo.len() {
                while todo[g] != 0 {
                    let wi = g * 64 + todo[g].trailing_zeros() as usize;
                    todo[g] &= todo[g] - 1;
                    let pair = has(&todo, wi + 1);
                    if pair {
                        todo[(wi + 1) / 64] &= !(1 << ((wi + 1) % 64));
                    }
                    let w = lo + wi;
                    for (p, tb) in per.iter_mut().zip(&toks) {
                        p.0 = if pair { tb.words::<2>(w) } else { [tb.word(w), (0, 0, 0)] };
                    }
                    for j in 0..1 + pair as usize {
                        // A word's rank counts the chunk's hits before it
                        // (read only for words with a hit).
                        let (wi, w) = (wi + j, w + j);
                        rank[wi] = hits.len() as u16;
                        let mut any = per.iter().take(toks.len()).fold(0, |a, p| a | p.0[j].0);
                        // With no positive token every name is a candidate,
                        // unless a name filter says which can pass.
                        if pos.is_empty() {
                            let re = re_bits.as_ref().map_or(!0, |f| f.iter().fold(0, |a, t| a | t.word(w).0));
                            let globs = glob_bits.iter().fold(!0, |m, g| m & g.iter().fold(0, |a, t| a | t.word(w).0));
                            any |= !0 >> (64 - (idx.u - w * 64).min(64)) & ext_word(w) & re & globs;
                        } else if by_ext && any != 0 {
                            any &= ext_word(w);
                        }
                        let mut cand = cand_of(w) & any;
                        while cand != 0 {
                            let i = cand.trailing_zeros();
                            cand &= cand - 1;
                            let spaced = (space[0][w] | space[1][w]) >> i & 1 != 0;
                            if let Some(h) = score_one(w * 64 + i as usize, i, per, j, spaced, re.as_ref(), &mut ok) {
                                hits.push(h);
                                bits[wi] |= 1 << i;
                            }
                        }
                    }
                }
            }
            (hits, ok)
        };
        // A spare pair from the last table (its bits cleared; ranks are only
        // read where a bit is set), or fresh ones.
        let spare_bits = BITS_POOL.lock().unwrap().pop().filter(|(b, _)| b.len() == idx.words);
        let (mut bits, mut rank) = spare_bits.unwrap_or_else(|| (vec![0; idx.words], vec![0; idx.words]));
        // A few thousand words to look at (a small index, a scope, a
        // narrowed table) take less time than waking threads.
        let few = from.map_or(within.map_or(idx.words, |s| if s.busy { s.names } else { s.words }), |f| f.len) <= INLINE_WORDS;
        let mut spare = std::mem::take(&mut *HIT_POOL.lock().unwrap());
        spare.resize_with(idx.words.div_ceil(CHUNK_WORDS), Vec::new);
        let scratch = || vec![Line([(0, 0, 0); 2]); toks.len()];
        let chunks = bits.chunks_mut(CHUNK_WORDS).zip(rank.chunks_mut(CHUNK_WORDS)).zip(spare);
        let out: Vec<(Vec<NameHit>, usize)> = if few {
            let mut per = scratch();
            chunks.enumerate().map(|(c, ((b, r), h))| chunk(c, b, r, h, &mut per)).collect()
        } else {
            let slots = Cells::new(chunks.map(Some));
            par_each(slots.0.len(), scratch, |per, c| {
                // Safety: par_each runs each chunk once.
                let ((b, r), h) = unsafe { slots.take(c) }.unwrap();
                chunk(c, b, r, h, per)
            })
        };
        let ok_entries = out.iter().map(|c| c.1).sum();
        let hits: Vec<Vec<NameHit>> = out.into_iter().map(|c| c.0).collect();
        NameTable::new(bits, rank, hits, ok_entries, false)
    }

    /// The overlay (entries added since the last compaction) has no dir
    /// memo: each candidate's path components stand in for it. Its top
    /// `limit` is all the merge can use.
    fn search_overlay(&self, q: &Query) -> Vec<Hit> {
        let now = now_secs();
        let pos: Vec<&Token> = q.tokens.iter().filter(|t| !t.negate).collect();
        // A hit needs some positive token in its own name.
        let flat = &self.live.flat;
        let cands: Vec<&(Vec<u8>, crate::live::OEnt)> = flat
            .masks
            .iter()
            .zip(&flat.items)
            .filter(|&(&m, _)| m != 0 && (pos.is_empty() || pos.iter().any(|t| t.fits(m))))
            .map(|(_, item)| item)
            .collect();
        if cands.is_empty() {
            return Vec::new();
        }
        // Overlay entries cluster in a few busy folders: match each folder's
        // components once per folder, not per entry.
        let score = |items: &[&(Vec<u8>, crate::live::OEnt)]| {
            let mut memo = HashMap::<&[u8], DirMatch, crate::index::Fx>::default();
            let mut out = Vec::new();
            for &&(ref path, o) in items {
                let cut = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
                let dir = &path[..cut];
                if let Some(score) = q.match_path_with(path, o.kind, o.size, o.mtime, |_| *memo.entry(dir).or_insert_with(|| q.dir_match(dir))) {
                    let score = score + o.prior as i32 + rank_tweaks(name_flags(&path[cut + 1..]), o.kind, o.mtime, now);
                    out.push(Hit { score, idx: u32::MAX, over: Some(path.clone()) });
                }
            }
            out
        };
        let mut hits = if cands.len() <= OVERLAY_CHUNK { score(&cands) } else { cands.par_chunks(OVERLAY_CHUNK).flat_map_iter(score).collect() };
        // Best first, equal scores by path (the overlay map's order).
        hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.over.cmp(&b.over)));
        hits.truncate(q.limit);
        hits
    }

    /// For each dir: which tokens its name or an ancestor's matches, with the
    /// best score per token (first 4); bits == u32::MAX if a negated token does.
    fn dir_tokens(&self, names: &NameTable) -> Vec<DirMemo> {
        let idx = &self.live.base;
        let de = idx.dir_entries();
        let en = idx.ent_names();
        // Each dir's own name, written in parallel into a spare buffer.
        let mut out = MEMO_POOL.lock().unwrap().pop().unwrap_or_default();
        (0..idx.d)
            .into_par_iter()
            .with_min_len(1 << 12)
            .map(|k| if k > 0 { DirMemo::own(names.get(en.get(de.get(k) as usize))) } else { DirMemo::default() })
            .collect_into_vec(&mut out);
        // Fold ancestors in, parents first. A dir's descendants are one
        // contiguous id range, so the children of huge dirs go one by one,
        // then every small subtree in parallel.
        let dp = idx.dir_parents();
        let plan = idx.memo_plan();
        for &k in &plan.upper {
            out[k as usize] = out[k as usize].under(out[dp.get(k as usize) as usize]);
        }
        let roots: Vec<(u32, DirMemo)> = plan.chunks.iter().map(|(c, _)| (*c, out[*c as usize])).collect();
        let mut slices = Vec::with_capacity(plan.chunks.len());
        let mut rest: &mut [DirMemo] = &mut out;
        let mut at = 0usize;
        for (_, r) in &plan.chunks {
            let (_, tail) = std::mem::take(&mut rest).split_at_mut(r.start as usize - at);
            let (mine, tail) = tail.split_at_mut((r.end - r.start) as usize);
            slices.push(mine);
            rest = tail;
            at = r.end as usize;
        }
        slices.into_par_iter().zip(&plan.chunks).zip(roots).for_each(|((slice, (_, r)), (c, root))| {
            let a = r.start as usize;
            for k in a..r.end as usize {
                let p = dp.get(k);
                let pm = if p == c { root } else { slice[p as usize - a] };
                slice[k - a] = slice[k - a].under(pm);
            }
        });
        out
    }
}

/// Debug switch: always take the full pass (for checking the selective one).
pub static FULL_PASS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// One query's entry scoring, shared by the two strategies.
#[derive(Clone, Copy)]
struct Scan<'a> {
    q: &'a Query,
    live: &'a Live,
    names: &'a NameTable,
    npos: usize,
    need_dirs: bool,
    now: u32,
    /// `Query::path_bits`.
    paths: (u32, u32),
    /// The entries the globs allow (`Searcher::glob_ranges`), if not all,
    /// and whether some glob needs the path too (`Glob::split`).
    ranges: Option<&'a [(u32, u32)]>,
    slow: bool,
}

impl<'a> Scan<'a> {
    fn new(q: &'a Query, live: &'a Live, names: &'a NameTable, npos: usize, need_dirs: bool, ranges: Option<&'a [(u32, u32)]>) -> Scan<'a> {
        let slow = q.globs.iter().any(|g| !g.split());
        Scan { q, live, names, npos, need_dirs, now: now_secs(), paths: q.path_bits(), ranges, slow }
    }

    /// Score entry `i` (parent dir `p`) whose name scored `nh`, given its
    /// parent's memo.
    /// `None` if it fails a filter or cannot beat `floor`.
    #[inline(always)]
    /// `re` is the caller's own copy of `path_re` (see `score_names`).
    #[allow(clippy::too_many_arguments)]
    fn score(&self, i: usize, p: u32, nh: NameHit, memo: DirMemo, floor: u64, pbuf: &mut Vec<u8>, re: Option<&regex::bytes::Regex>) -> Option<u64> {
        let idx = &self.live.base;
        let q = self.q;
        let k = idx.kind(i);
        if !q.kind_ok(k) || self.ranges.is_some_and(|r| !in_ranges(r, i as u32)) {
            return None;
        }
        if q.size != (0, u64::MAX) {
            let sz = crate::index::dec_size(idx.size_raw(i));
            if sz < q.size.0 || sz > q.size.1 {
                return None;
            }
        }
        let mtime = idx.mtime(i);
        if q.mtime != (0, u32::MAX) && (mtime < q.mtime.0 || mtime > q.mtime.1) {
            return None;
        }
        let mut score = nh.score as i32;
        if self.need_dirs {
            let all = (1u32 << self.npos) - 1;
            if memo.bits == u32::MAX || (nh.bits as u32 | memo.bits) & all != all {
                return None;
            }
            for t in 0..self.npos {
                if nh.bits & (1 << t) == 0 {
                    // Matched by a folder on the path instead.
                    score += memo.best.get(t).map_or(6, |&b| b as i32 * 3 / 4);
                }
            }
            if self.paths.0 != 0 {
                score += path_fit(nh.bits as u32, memo.bits >> 8 & 0xff, self.paths.0, self.paths.1);
            }
        }
        if self.live.is_dead(i as u32) {
            return None;
        }
        score += idx.dir_prior()[p as usize] as i32 + rank_tweaks(nh.flags, k, mtime, self.now);
        let key = entry_key(score, i as u32, k & 3 == KIND_FILE);
        if key <= floor {
            return None;
        }
        if let Some(re) = re {
            idx.path(i, pbuf);
            if !re.is_match(pbuf) {
                return None;
            }
        }
        // Globs the folder ranges and name tests don't settle alone.
        if self.slow {
            idx.path(i, pbuf);
            if !q.globs.iter().filter(|g| !g.split()).all(|g| g.matches_path(pbuf, q.scope.as_deref())) {
                return None;
            }
        }
        Some(key)
    }

    /// One sequential pass over every entry in `ranges`.
    fn full(&self, ranges: &[(u32, u32)], memo: Option<&[DirMemo]>) -> Vec<Hit> {
        let idx = &self.live.base;
        let (ent_name, zones) = (idx.ent_names(), idx.zones());
        let dense = self.names.dense(idx);
        let q = self.q;
        // Runs of entries none of which passes the size/mtime/kind filters
        // are skipped whole.
        let filtered = q.kind.is_some() || q.size != (0, u64::MAX) || q.mtime != (0, u32::MAX);
        let zone_ok = |z: &Zone| {
            crate::index::dec_size(z.max_size) >= q.size.0
                && z.max_mtime >= q.mtime.0
                && z.min_mtime <= q.mtime.1
                && q.kind.is_none_or(|k| z.kinds & (1 << k) != 0 || (q.apps && z.kinds & (1 << KIND_LINK) != 0))
        };
        // The ranges back to back; each entry in them is let through here.
        let scan = Scan { ranges: None, ..*self };
        let ends: Vec<usize> = ranges.iter().scan(0, |n, r| Some(*n + (r.1 - r.0) as usize).inspect(|&e| *n = e)).collect();
        let n = ends.last().copied().unwrap_or(0);
        top_k(n, q.limit, n, 0, |r, top| {
            let (mut pbuf, re) = (Vec::new(), q.path_re.clone());
            let mut k = ends.partition_point(|&e| e <= r.start);
            while let Some(&(ra, rb)) = ranges.get(k).filter(|_| k == 0 || ends[k - 1] < r.end) {
                let from = if k == 0 { 0 } else { ends[k - 1] };
                let (mut a, b) = (ra as usize + r.start.saturating_sub(from), (rb as usize).min(ra as usize + r.end - from));
                k += 1;
                while a < b {
                    let end = ((a / ZONE + 1) * ZONE).min(b);
                    if filtered && !zone_ok(&zones[a / ZONE]) {
                        a = end;
                        continue;
                    }
                    for (run, p) in idx.blocks(a, end) {
                        let m = memo.map_or(DirMemo::default(), |m| m[p as usize]);
                        for i in run {
                            let s = dense[ent_name.get(i) as usize];
                            if s.flags & NF_OK == 0 {
                                continue;
                            }
                            let nh = NameHit { score: s.score, bits: s.bits, flags: s.flags, best: [0; 4] };
                            if let Some(k) = scan.score(i, p, nh, m, top.floor, &mut pbuf, re.as_ref()) {
                                top.push(k);
                            }
                        }
                    }
                    a = end;
                }
            }
        })
    }

    /// Visit only the entries carrying a matching name; folder tokens are
    /// checked by walking each candidate's ancestors (memoized per piece).
    fn selective(&self, lo: usize, hi: usize) -> Vec<Hit> {
        let idx = &self.live.base;
        let ok: Vec<(u32, NameHit)> = self.names.iter().filter(|(_, h)| h.flags & NF_OK != 0).collect();
        top_k(ok.len(), self.q.limit, self.names.ok_entries, 0, |r, top| {
            let (mut pbuf, mut memo) = (Vec::new(), HashMap::<u32, DirMemo, crate::index::Fx>::default());
            let re = self.q.path_re.clone();
            for &(id, nh) in &ok[r] {
                for e in idx.ents(id) {
                    let i = e as usize;
                    if i < lo || i >= hi {
                        continue;
                    }
                    let p = idx.parent(i);
                    let m = if self.need_dirs { self.memo_of(p, &mut memo, &mut |k| self.names.get(k)) } else { DirMemo::default() };
                    if let Some(k) = self.score(i, p, nh, m, top.floor, &mut pbuf, re.as_ref()) {
                        top.push(k);
                    }
                }
            }
        })
    }

    /// The dir memo of `d` (see `dir_tokens`), its parent's first, each one
    /// kept in `cache`.
    fn memo_of(&self, d: u32, cache: &mut HashMap<u32, DirMemo, crate::index::Fx>, hit: &mut impl FnMut(u32) -> Option<NameHit>) -> DirMemo {
        if d == 0 {
            return DirMemo::default();
        }
        if let Some(&m) = cache.get(&d) {
            return m;
        }
        let idx = &self.live.base;
        let up = self.memo_of(idx.dir_parents().get(d as usize), cache, hit);
        let m = DirMemo::own(hit(idx.ent_names().get(idx.dir_entries().get(d as usize) as usize))).under(up);
        cache.insert(d, m);
        m
    }
}

/// The dir memo is ~13 MB; reusing it saves a page-fault storm per query.
static MEMO_POOL: std::sync::Mutex<Vec<Vec<DirMemo>>> = std::sync::Mutex::new(Vec::new());

/// What the name table depends on: two queries with the same key score
/// every name the same.
#[derive(PartialEq)]
struct NameKey {
    tokens: Vec<(Vec<u8>, Mode, bool, bool)>,
    exts: Vec<Vec<u8>>,
    /// `Query::not_exts` and the globs (as typed), which test names too.
    not_exts: Vec<Vec<u8>>,
    globs: Vec<(String, bool)>,
    name_re: Option<String>,
    /// The entry range whose names alone were scored, if not all.
    scope: Option<(usize, usize)>,
}

impl NameKey {
    fn of(q: &Query, scope: Option<(usize, usize)>) -> NameKey {
        NameKey {
            tokens: q.tokens.iter().map(|t| (t.text.clone(), t.mode, t.negate, t.deep)).collect(),
            exts: q.exts.clone(),
            not_exts: q.not_exts.clone(),
            globs: q.globs.iter().map(|g| (g.text.clone(), g.negate)).collect(),
            name_re: q.name_re.as_ref().map(|r| r.as_str().to_string()),
            scope,
        }
    }

    /// Can only match names `prev` matched: same filters, same tokens, each
    /// positive token the same or longer in a way that only narrows it.
    fn narrows(&self, prev: &NameKey) -> bool {
        self.exts == prev.exts
            && self.not_exts == prev.not_exts
            && self.globs == prev.globs
            && self.name_re == prev.name_re
            && self.scope == prev.scope
            && self.tokens.len() == prev.tokens.len()
            && self.tokens.iter().any(|t| !t.2)
            && self.tokens.iter().zip(&prev.tokens).all(|(a, b)| {
                a.1 == b.1
                    && a.2 == b.2
                    && a.3 == b.3
                    && if a.2 {
                        a.0 == b.0
                    } else if a.1 == Mode::Suffix {
                        a.0.ends_with(&b.0)
                    } else {
                        // Gaining a typo widens the match: score afresh.
                        let typos = |t: &(Vec<u8>, Mode, bool, bool)| typo_edits(&t.0, t.1).min(1 + t.3 as u32);
                        a.0.starts_with(&b.0) && typos(a) == typos(b)
                    }
            })
    }
}

/// The last query's name table (and dir memo, built on first use).
pub struct Scored {
    at: std::time::Instant,
    key: NameKey,
    names: NameTable,
    memo: std::sync::OnceLock<Vec<DirMemo>>,
}

impl Drop for Scored {
    fn drop(&mut self) {
        if let Some(v) = self.memo.take() {
            let mut pool = MEMO_POOL.lock().unwrap();
            if pool.is_empty() {
                pool.push(v);
            }
        }
    }
}

/// Lives with the index it was scored against (`Live`).
#[derive(Default)]
pub struct NameCache {
    last: std::sync::Mutex<Option<std::sync::Arc<Scored>>>,
    /// The last `in:` scope's names (see `Searcher::scope_names`).
    #[allow(clippy::type_complexity)]
    scope: std::sync::Mutex<Option<((usize, usize), std::sync::Arc<NameSet>)>>,
    /// A location prior and the folders above it, whose own entries are
    /// about PRIOR_ENTRIES at most (see `Searcher::spread`).
    priors: std::sync::OnceLock<(i32, Vec<u32>)>,
}

impl NameCache {
    /// Drop the cached table and spare buffers once searching has stopped:
    /// tens of MB after a broad query, worth keeping only while typing.
    pub fn trim_if_idle(&self, idle: std::time::Duration) {
        let mut g = self.last.lock().unwrap();
        if g.as_ref().is_some_and(|s| s.at.elapsed() > idle) {
            *g = None;
            drop(g);
            *self.scope.lock().unwrap() = None;
            trim_pools();
        }
    }
}

/// Bits 0..8 of `bits`: the tokens a dir's name or an ancestor's matches;
/// bits 8..16: those its own name does (`Searcher::path_bits`).
#[derive(Clone, Copy, Default)]
pub struct DirMemo {
    bits: u32,
    best: [i16; 4],
}

impl DirMemo {
    /// A dir's own name's contribution.
    #[inline]
    fn own(hit: Option<NameHit>) -> DirMemo {
        match hit {
            Some(h) if h.flags & NF_NEG != 0 => DirMemo { bits: u32::MAX, best: [0; 4] },
            Some(h) => DirMemo { bits: h.bits as u32 * 0x101, best: h.best },
            None => DirMemo::default(),
        }
    }

    /// This dir's memo with its parent's folded in.
    #[inline]
    fn under(self, p: DirMemo) -> DirMemo {
        if p.bits == u32::MAX || self.bits == u32::MAX {
            return DirMemo { bits: u32::MAX, best: self.best };
        }
        let mut best = self.best;
        for (b, &q) in best.iter_mut().zip(&p.best) {
            *b = (*b).max(q);
        }
        DirMemo { bits: self.bits | (p.bits & 0xff), best }
    }
}

/// Spare hit buffers, one per name table chunk (tens of MB after a broad
/// query), so the next broad query doesn't page-fault fresh ones in.
static HIT_POOL: std::sync::Mutex<Vec<Vec<NameHit>>> = std::sync::Mutex::new(Vec::new());

/// Free the spare buffers searches keep for speed (after a quiet spell).
pub fn trim_pools() {
    BITS_POOL.lock().unwrap().clear();
    HIT_POOL.lock().unwrap().clear();
    DENSE_POOL.lock().unwrap().clear();
    MEMO_POOL.lock().unwrap().clear();
}

/// A spare name table bitset and rank (344 KB on this disk): allocating
/// and freeing them each search cost page faults and madvise.
#[allow(clippy::type_complexity)]
static BITS_POOL: std::sync::Mutex<Vec<(Vec<u64>, Vec<u16>)>> = std::sync::Mutex::new(Vec::new());

/// Spare `NameTable::dense` views (8.9 MB on this disk).
static DENSE_POOL: std::sync::Mutex<Vec<Vec<Short>>> = std::sync::Mutex::new(Vec::new());

impl Drop for NameTable {
    fn drop(&mut self) {
        // Only the chunks holding hits have bits to clear.
        if !self.bits.is_empty() {
            for (chunk, hits) in self.bits.chunks_mut(CHUNK_WORDS).zip(&self.hits) {
                if !hits.is_empty() {
                    chunk.fill(0);
                }
            }
            let mut pool = BITS_POOL.lock().unwrap();
            if pool.is_empty() {
                pool.push((std::mem::take(&mut self.bits), std::mem::take(&mut self.rank)));
            }
        }
        if let Some(d) = self.dense.take() {
            let mut pool = DENSE_POOL.lock().unwrap();
            if pool.is_empty() {
                pool.push(d);
            }
        }
        let mut pool = HIT_POOL.lock().unwrap();
        if pool.is_empty() {
            *pool = std::mem::take(&mut self.hits);
            pool.iter_mut().for_each(Vec::clear);
        }
    }
}

/// Scored names: which ones (`bits`), and their hits stored per chunk of
/// CHUNK_WORDS words in id order, `rank[w]` counting the chunk's hits
/// before word w. Lookups are O(1) and the table is as small as its hits.
struct NameTable {
    bits: Vec<u64>,
    rank: Vec<u16>,
    hits: Vec<Vec<NameHit>>,
    len: usize,
    /// Entries carrying a name that passes as a match (NF_OK).
    ok_entries: usize,
    /// Every name, unscored (no token or name filter): only `dense` works.
    all: bool,
    /// For a pass over every entry: each name's `Short` (zero if absent), a
    /// direct index with a quarter of a hit's bytes.
    dense: std::sync::OnceLock<Vec<Short>>,
}

/// What an entry's score needs of its name's hit.
#[derive(Clone, Copy, Default)]
struct Short {
    score: i16,
    bits: u8,
    flags: u8,
}

/// `n` default `Short`s, from the allocator's zeroed memory.
fn zeroed(n: usize) -> Vec<Short> {
    let layout = std::alloc::Layout::array::<Short>(n).expect("dense view size");
    if layout.size() == 0 {
        return Vec::new();
    }
    // Safety: allocated with Short's layout for `n` of them; a Short is
    // plain integers, and all zero bytes is its default.
    unsafe {
        let p = std::alloc::alloc_zeroed(layout) as *mut Short;
        if p.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Vec::from_raw_parts(p, n, n)
    }
}

/// `cell`'s value, built on first use outside its lock: `f` runs rayon jobs,
/// and a pool thread waiting on them inside `get_or_init` can take on another
/// search that then waits on that same init, parking every search thread.
/// Racing searches may each build it; the first one stored is kept.
fn lazy<T>(cell: &std::sync::OnceLock<T>, f: impl FnOnce() -> T) -> &T {
    if let Some(v) = cell.get() {
        return v;
    }
    let v = f();
    cell.get_or_init(|| v)
}

impl NameTable {
    fn new(bits: Vec<u64>, rank: Vec<u16>, hits: Vec<Vec<NameHit>>, ok_entries: usize, all: bool) -> NameTable {
        let len = hits.iter().map(Vec::len).sum();
        NameTable { bits, rank, hits, len, ok_entries, all, dense: std::sync::OnceLock::new() }
    }

    /// The `dense` view, built on first use.
    fn dense(&self, idx: &Index) -> &[Short] {
        lazy(&self.dense, || {
            let spare = DENSE_POOL.lock().unwrap().pop().filter(|d| d.len() == idx.words * 64);
            // A fresh one comes zeroed (all `Short::default()`) from the
            // allocator, which maps zero pages in without writing them.
            let fresh = spare.is_none();
            let mut d = spare.unwrap_or_else(|| zeroed(idx.words * 64));
            let flags = [idx.bitmap(crate::index::BM_DOT), idx.bitmap(crate::index::BM_APP)];
            d.par_chunks_mut(CHUNK_WORDS * 64).enumerate().for_each(|(c, out)| {
                if !fresh {
                    out.fill(Short::default());
                }
                let base = c * CHUNK_WORDS * 64;
                if self.all {
                    for (j, o) in out.iter_mut().enumerate() {
                        let (w, i) = ((base + j) / 64, j % 64);
                        let f = |b: &[u64], nf: u8| if b[w] >> i & 1 != 0 { nf } else { 0 };
                        o.flags = NF_OK | f(flags[0], NF_DOT) | f(flags[1], NF_APP);
                    }
                    return;
                }
                let hits = self.hits[c].iter();
                let words = self.bits[c * CHUNK_WORDS..].iter().take(CHUNK_WORDS);
                let ids = words.enumerate().flat_map(|(wi, &b)| {
                    let mut b = b;
                    std::iter::from_fn(move || {
                        (b != 0).then(|| {
                            let j = wi * 64 + b.trailing_zeros() as usize;
                            b &= b - 1;
                            j
                        })
                    })
                });
                for (j, h) in ids.zip(hits) {
                    out[j] = Short { score: h.score, bits: h.bits, flags: h.flags };
                }
            });
            d
        })
        .as_slice()
    }

    #[inline(always)]
    fn get(&self, id: u32) -> Option<NameHit> {
        let (w, i) = (id as usize >> 6, id & 63);
        let b = self.bits[w];
        if b >> i & 1 == 0 {
            return None;
        }
        let r = self.rank[w] as usize + (b & ((1 << i) - 1)).count_ones() as usize;
        Some(self.hits[w / CHUNK_WORDS][r])
    }

    /// Every name in the table, ascending.
    fn iter(&self) -> impl Iterator<Item = (u32, NameHit)> + '_ {
        self.hits.iter().enumerate().filter(|(_, hits)| !hits.is_empty()).flat_map(move |(c, hits)| {
            let words = self.bits[c * CHUNK_WORDS..].iter().take(CHUNK_WORDS);
            let ids = words.enumerate().flat_map(move |(wi, &b)| {
                let mut b = b;
                let base = ((c * CHUNK_WORDS + wi) * 64) as u32;
                std::iter::from_fn(move || {
                    (b != 0).then(|| {
                        let id = base + b.trailing_zeros();
                        b &= b - 1;
                        id
                    })
                })
            });
            ids.zip(hits.iter().copied())
        })
    }
}

/// A set of name ids, and which words of each chunk are not empty.
struct NameSet {
    bits: Vec<u64>,
    todo: Vec<Todo>,
    /// Non-zero words, and names.
    words: usize,
    names: usize,
    /// Most of its names will need scoring (not just their words'
    /// bitmaps): its names, not its words, say whether threads pay.
    busy: bool,
}

impl NameSet {
    fn new(bits: Vec<u64>) -> NameSet {
        let todo = bits.chunks(CHUNK_WORDS).map(nonzero).collect();
        let words = bits.iter().filter(|&&b| b != 0).count();
        let names = bits.iter().map(|b| b.count_ones() as usize).sum();
        NameSet { bits, todo, words, names, busy: false }
    }
}

/// One bit per word of a chunk (CHUNK_WORDS of them).
type Todo = [u64; CHUNK_WORDS / 64];

/// Which of a chunk's words are not zero.
fn nonzero(words: &[u64]) -> Todo {
    let mut out = Todo::default();
    for (o, g) in out.iter_mut().zip(words.chunks(64)) {
        *o = g.iter().enumerate().fold(0, |m, (b, &x)| m | ((x != 0) as u64) << b);
    }
    out
}

#[derive(Clone, Copy)]
struct NameHit {
    score: i16,
    /// Which positive tokens the name matched.
    bits: u8,
    flags: u8,
    /// Per-token score, first 4 tokens (for the folder memo).
    best: [i16; 4],
}

const NF_OK: u8 = 1;
const NF_DOT: u8 = 2;
const NF_NEG: u8 = 8;
const NF_APP: u8 = 4;

fn name_flags(name: &[u8]) -> u8 {
    let mut f = 0;
    if name.first() == Some(&b'.') {
        f |= NF_DOT;
    }
    if name.ends_with(b".app") {
        f |= NF_APP;
    }
    f
}

/// What a path query ("a/b") adds for an entry whose own name and parent
/// folder's name match the token bits `own` and `parent`: the last piece
/// names the entry (else it is a folder further up), and better still, the
/// piece before it its folder.
fn path_fit(own: u32, parent: u32, under: u32, leaf: u32) -> i32 {
    (if own & leaf == 0 { -PATH_MISS } else { 0 }) + if own & under & parent << 1 != 0 { PATH_HIT } else { 0 }
}

/// Several words that spell a name (`fido device discovery`,
/// `fido_device_discovery.cc` or `FidoDeviceDiscovery.java`): its stem or
/// whole name, delimiters left out, is the words run together (`joined`).
/// They score as one word matching it whole would.
fn spelled(name: &[u8], joined: &[u8]) -> i32 {
    let off = (name.len() > 1 && name[0] == b'.') as usize;
    let stem = name.iter().rposition(|&b| b == b'.').filter(|&p| p > off).unwrap_or(name.len());
    let squash = |s: &[u8]| s.iter().filter(|&&b| !is_delim(b)).map(|&b| fold(b)).eq(joined.iter().copied());
    if squash(&name[off..]) || squash(&name[off..stem]) { 100 } else { 0 }
}

fn is_delim(b: u8) -> bool {
    matches!(b, b'_' | b'-' | b'.' | b' ')
}

/// Does `name` hold `q` as typed from a word start (ASCII case aside)? What
/// `fuzzy_score`'s per-char bonuses can't tell of ".gitkeep" for ".gitkeep"
/// (a leading dot takes no word bonus) or of a word in another script.
fn at_word(name: &[u8], q: &[u8]) -> bool {
    !q.is_empty() && name.windows(q.len()).enumerate().any(|(i, w)| (i == 0 || is_delim(name[i - 1])) && w.iter().zip(q).all(|(&a, &b)| fold(a) == b))
}

const PATH_MISS: i32 = 40;
const PATH_HIT: i32 = 30;

/// Small per-entry nudges on top of match quality and the location prior.
#[inline]
fn rank_tweaks(flags: u8, kind: u8, mtime: u32, now: u32) -> i32 {
    let mut s = 0;
    if flags & NF_DOT != 0 {
        s -= 8;
    }
    if kind & FLAG_HIDDEN != 0 {
        s -= 8;
    }
    // Apps are dirs, or symlinks into the cryptex (/Applications/Safari.app).
    if matches!(kind & 3, KIND_DIR | KIND_LINK) && flags & NF_APP != 0 {
        s += 25;
    }
    let age = now.saturating_sub(mtime);
    s += match age {
        0..=86_400 => 10,
        86_401..=604_800 => 7,
        604_801..=2_592_000 => 4,
        2_592_001..=31_536_000 => 1,
        _ => 0,
    };
    s
}
