//! Name search: parse a query, scan the index in parallel, rank, top-k.

use crate::index::{char_bit, start_bit};
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
    /// Char classes a typo may leave out of a matching name: all but the
    /// first letter's, or none when the token takes no typos.
    pub loose: u64,
    /// `index::start_bit` of the first letter when the token takes typos.
    pub start: u64,
}

impl Token {
    /// Can a name with mask `m` (`index::name_mask`) match? Cleanly it has
    /// every char class; with a typo, a word in it starts with this token's
    /// first letter and at most one `loose` class is missing. Branchless, so
    /// the scan over every name stays vectorized.
    #[inline(always)]
    fn fits(&self, m: u64) -> bool {
        let miss = self.mask & !m;
        (miss == 0) | ((((miss & !self.loose) | (miss & miss.wrapping_sub(1))) == 0) & (m & self.start != 0))
    }
}

/// Fuzzy words this long forgive one typo (see `typo_score`).
const TYPO_MIN_LEN: usize = 5;
/// What a typo costs, so clean matches of the same quality rank first.
const TYPO_COST: i32 = 60;

fn takes_typos(text: &[u8], mode: Mode) -> bool {
    mode == Mode::Fuzzy && text.len() >= TYPO_MIN_LEN
}

#[derive(Clone, Default)]
pub struct Query {
    pub tokens: Vec<Token>,
    pub kind: Option<u8>,
    /// `type:app`: a folder kind also takes symlinks, since the system apps
    /// in /Applications link into the cryptex (/Applications/Safari.app).
    pub apps: bool,
    pub exts: Vec<Vec<u8>>,
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
    /// `'x` exact, `^x` prefix, `x$` suffix, `!x` negate; filters are
    /// `ext: type: kind: in: size: mtime: re: path: limit: grep: regex: sym:`.
    pub fn parse(s: &str, home: &str) -> Result<Query, String> {
        let mut q = Query { size: (0, u64::MAX), mtime: (0, u32::MAX), limit: 50, ..Default::default() };
        for word in split_words(s) {
            if let Some((k, v)) = word.split_once(':')
                && q.filter(k, v, home)?
            {
                continue;
            }
            for piece in word.split('/').filter(|p| !p.is_empty()) {
                q.push_token(piece);
            }
        }
        Ok(q)
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
        // Positive tokens are tracked in a u8 bitset.
        if t.is_empty() || (!negate && self.tokens.iter().filter(|t| !t.negate).count() >= 8) {
            return;
        }
        let text: Vec<u8> = t.bytes().map(|b| b.to_ascii_lowercase()).collect();
        let mask = text.iter().fold(0, |m, &b| m | char_bit(b));
        let (loose, start) = if takes_typos(&text, mode) { (mask & !char_bit(text[0]), start_bit(text[0])) } else { (0, 0) };
        self.tokens.push(Token { text, mask, mode, negate, loose, start });
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
                // The index holds real paths: /etc is /private/etc.
                let p = std::fs::canonicalize(&p).map_or(p, |c| c.to_string_lossy().into_owned());
                self.scope = Some(p.trim_end_matches('/').as_bytes().to_vec());
            }
            "size" => self.size = range(v, parse_size)?,
            "mtime" | "modified" => {
                // mtime:<7d means "modified within the last 7 days".
                let now = now_secs();
                let (lo, hi) = range(v, parse_age)?;
                self.mtime = (now.saturating_sub(hi.min(now as u64) as u32), now.saturating_sub(lo.min(now as u64) as u32));
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
        // A hit needs some token in its own name; most paths fail here,
        // before the folders are looked at.
        let mut pos = self.tokens.iter().filter(|t| !t.negate).peekable();
        let m = crate::index::name_mask(name);
        if pos.peek().is_some() && !pos.any(|t| t.fits(m) && token_score(name, m, t).is_some()) {
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
            if let Some(s) = token_score(name, m, tok) {
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
        if self.name_re.as_ref().is_some_and(|re| !re.is_match(name)) || self.path_re.as_ref().is_some_and(|re| !re.is_match(path)) {
            return None;
        }
        Some(score)
    }

    /// How the folders of a path (`/a/b` for `/a/b/name`) match the tokens:
    /// the best score per positive token, and whether a negated one hits.
    pub fn dir_match(&self, dirs: &[u8]) -> DirMatch {
        let comps: Vec<&[u8]> = dirs.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
        let mut d = DirMatch { negated: false, best: [None; 8] };
        d.negated = self.tokens.iter().any(|t| t.negate && comps.iter().any(|c| token_matches(c, t)));
        for (t, tok) in self.tokens.iter().filter(|t| !t.negate).enumerate() {
            d.best[t] = comps.iter().filter_map(|c| token_score(c, !0, tok)).max();
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

/// fzf-v1 style: leftmost-ending match, shrunk from the right, then scored
/// with boundary/camel/consecutive bonuses. Returns None when no match.
pub fn fuzzy_score(name: &[u8], q: &[u8]) -> Option<i32> {
    fuzzy_score_capped(name, q, 100)
}

/// `fuzzy_score` with the whole-name/stem/prefix bonus capped at `cap`.
fn fuzzy_score_capped(name: &[u8], q: &[u8], cap: i32) -> Option<i32> {
    // Leftmost-ending match: jump to each query byte in turn (memchr is
    // SIMD; most names fail on the first or second byte).
    let mut end = 0;
    let mut from = 0;
    for &c in q {
        end = from + find_folded(&name[from..], c)?;
        from = end + 1;
    }
    if q.len() == 1 {
        return Some(single_score(name, end, cap));
    }
    // Shrink from the right: the latest start that still ends at `end`.
    let mut start = end + 1;
    for &c in q.iter().rev() {
        start = rfind_folded(&name[..start], c)?;
    }
    // Score the greedy match from `start`, jumping between matched bytes:
    // each gap costs GAP_START then GAP_EXT per byte, a run of consecutive
    // matches carries its strongest boundary bonus along.
    let mut score = 0;
    let (mut at, mut first_bonus) = (start, 0);
    for (k, &c) in q.iter().enumerate() {
        let mut run = false;
        if k > 0 {
            let last = at;
            at = last + 1 + find_folded(&name[last + 1..=end], c)?;
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
    // leading dot doesn't count: "zshrc" means ~/.zshrc.
    let off = (name.len() > 1 && name[0] == b'.') as usize;
    let stem = name.iter().rposition(|&b| b == b'.').filter(|&p| p > off).unwrap_or(name.len());
    let contiguous = end + 1 - start == q.len();
    let placed = if start == off && contiguous && end + 1 == name.len() {
        100
    } else if start == off && contiguous && end + 1 == stem {
        80
    } else if start == off && contiguous {
        30
    } else {
        0
    };
    Some(score + placed.min(cap) - (name.len() as i32).min(80) / 3)
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
    if i == off {
        let stem = name.iter().rposition(|&b| b == b'.').filter(|&p| p > off).unwrap_or(name.len());
        score += cap.min(if i + 1 == name.len() {
            100
        } else if i + 1 == stem {
            80
        } else {
            30
        });
    }
    score - (name.len() as i32).min(80) / 3
}

/// Best score for `q` read with one typo (see `one_edit_prefix`) at the
/// start of `name` or of a space-separated word in it: scored as if the
/// right letters had been typed, minus TYPO_COST, and never placed above a
/// prefix: "manif" is "manifest" being typed, not a typo of "manic". `m` is
/// as for `token_score`. Other word starts (`_`, `-`, camelCase) would cost
/// a scan of every name per query, ~10x the price.
fn typo_score(name: &[u8], m: u64, q: &[u8]) -> Option<i32> {
    let mut best = typo_at(name, (name.len() > 1 && name[0] == b'.') as usize, q);
    if m & char_bit(b' ') != 0 {
        for sp in memchr::memchr_iter(b' ', name) {
            best = best.max(typo_at(name, sp + 1, q));
        }
    }
    best
}

fn typo_at(name: &[u8], s: usize, q: &[u8]) -> Option<i32> {
    if name.get(s).is_none_or(|&b| fold(b) != q[0]) {
        return None;
    }
    let mut fixed = [0u8; 128];
    let fixed = fixed.get_mut(..one_edit_prefix(&name[s..], q)?)?;
    for (f, &b) in fixed.iter_mut().zip(&name[s..]) {
        *f = fold(b);
    }
    Some(fuzzy_score_capped(name, fixed, 30)? - TYPO_COST)
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

/// Score a token against a name, honoring its mode. `m` is the name's
/// `index::name_mask`, or any superset of it (`!0` when unknown): it only
/// skips work.
#[inline]
fn token_score(name: &[u8], m: u64, t: &Token) -> Option<i32> {
    match t.mode {
        Mode::Fuzzy if takes_typos(&t.text, t.mode) => {
            let clean = if t.mask & !m == 0 { fuzzy_score(name, &t.text) } else { None };
            clean.max(if m & t.start != 0 { typo_score(name, m, &t.text) } else { None })
        }
        Mode::Fuzzy => fuzzy_score(name, &t.text),
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
        _ => token_score(name, !0, t).is_some(),
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

#[inline(always)]
fn key(score: i32, i: u32) -> u64 {
    (((score as i64 - i32::MIN as i64) as u64) << 32) | (!i) as u64
}

impl TopK {
    fn new(k: usize) -> TopK {
        TopK { k, buf: Vec::new(), floor: if k == 0 { u64::MAX } else { 0 } }
    }
    #[inline]
    fn push(&mut self, key: u64) {
        if key > self.floor {
            self.buf.push(key);
            if self.buf.len() >= self.k.saturating_mul(2).max(64) {
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

/// Top `k` over `0..n` items: a few contiguous pieces per thread, each with
/// its own heap, then one selection over their survivors (merging heaps
/// pairwise costs more than the scan when `k` is large).
fn top_k(n: usize, k: usize, visit: impl Fn(std::ops::Range<usize>, &mut TopK) + Sync) -> Vec<Hit> {
    let pieces = (rayon::current_num_threads() * 4).min(n.max(1));
    let step = n.div_ceil(pieces).max(1);
    let tops: Vec<TopK> = (0..pieces)
        .into_par_iter()
        .map(|p| {
            let mut top = TopK::new(k);
            visit((p * step).min(n)..((p + 1) * step).min(n), &mut top);
            top.cut();
            top
        })
        .collect();
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
    keys.into_iter().map(|x| Hit { score: ((x >> 32) as i64 + i32::MIN as i64) as i32, idx: !(x as u32), over: None }).collect()
}

fn ext_ok(name: &[u8], exts: &[Vec<u8>]) -> bool {
    let Some(dot) = name.iter().rposition(|&b| b == b'.') else { return false };
    let e = &name[dot + 1..];
    exts.iter().any(|x| x.len() == e.len() && x.iter().zip(e).all(|(&a, &b)| a == fold(b)))
}

/// Below this many entries carrying a matching name, a query visits just
/// those entries (via the name -> entries list) instead of every entry.
const SELECTIVE: usize = 60_000;
/// Name ids per parallel chunk when scoring names.
const NAME_CHUNK: usize = 1 << 15;

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
        Some((idx.dir_start()[d] as usize, idx.dir_end()[d] as usize))
    }

    pub fn search(&self, q: &Query) -> Vec<Hit> {
        let mut hits = self.search_base(q);
        hits.extend(self.search_overlay(q));
        hits.sort_by(|a, b| b.score.cmp(&a.score).then(a.idx.cmp(&b.idx)));
        hits.truncate(q.limit);
        hits
    }

    fn search_base(&self, q: &Query) -> Vec<Hit> {
        let Some((lo, hi)) = self.scope_range(q) else { return Vec::new() };
        let pos: Vec<&Token> = q.tokens.iter().filter(|t| !t.negate).collect();
        let neg: Vec<&Token> = q.tokens.iter().filter(|t| t.negate).collect();
        // Step 1: every name-only predicate, once per distinct name (~2M)
        // rather than once per entry (~7.5M); reused while you type.
        let scored = self.names(q, &pos, &neg);
        let s = Scan { q, live: self.live, names: &scored.names, npos: pos.len(), need_dirs: pos.len() > 1 || !neg.is_empty(), now: now_secs() };
        // Step 2: score entries. Few candidates: just the entries carrying a
        // matching name. Many: one sequential pass over every entry.
        if scored.names.ok_entries <= SELECTIVE && !FULL_PASS.load(std::sync::atomic::Ordering::Relaxed) {
            return s.selective(lo, hi);
        }
        let memo = if s.need_dirs { Some(scored.memo.get_or_init(|| self.dir_tokens(&scored.names))) } else { None };
        s.full(lo, hi, memo.map(|m| m.as_slice()))
    }

    /// The name table for this query: cached for a repeat of the last one
    /// (the second, longer page of results), narrowed from the last one when
    /// this query only extends it (typing), else scored from scratch.
    fn names(&self, q: &Query, pos: &[&Token], neg: &[&Token]) -> std::sync::Arc<Scored> {
        let key = NameKey::of(q);
        let prev = self.live.names_cache.0.lock().unwrap().clone();
        if let Some(p) = &prev
            && p.key == key
        {
            return p.clone();
        }
        let from = prev.as_ref().filter(|p| key.narrows(&p.key)).map(|p| &p.names);
        let scored = std::sync::Arc::new(Scored {
            at: std::time::Instant::now(),
            key,
            names: self.score_names(q, pos, neg, from),
            memo: std::sync::OnceLock::new(),
        });
        *self.live.names_cache.0.lock().unwrap() = Some(scored.clone());
        scored
    }

    /// Score distinct names against the query's name-only predicates: every
    /// name, or only the ones `from` matched. Matches come back sparse (plus
    /// a 256 KB membership bitset), so a selective query never touches a
    /// table the size of the name count.
    fn score_names(&self, q: &Query, pos: &[&Token], neg: &[&Token], from: Option<&NameTable>) -> NameTable {
        let idx = &self.live.base;
        let mask = idx.name_mask();
        let ne_off = idx.name_ents_off();
        let score_one = |k: usize, ok_entries: &mut usize| -> Option<NameHit> {
            let m = mask[k];
            // A name no token can match matters only when there are no positive
            // tokens (then every name passes).
            let fits = |t: &&Token| t.fits(m);
            if !pos.is_empty() && !pos.iter().any(fits) && !neg.iter().any(fits) {
                return None;
            }
            let name = idx.uname(k as u32);
            let mut h = NameHit { score: 0, bits: 0, flags: name_flags(name), best: [0; 4] };
            for (t, tok) in pos.iter().enumerate() {
                if tok.fits(m)
                    && let Some(s) = token_score(name, m, tok)
                {
                    h.bits |= 1 << t;
                    let s16 = s.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                    h.score = h.score.saturating_add(s16);
                    if t < 4 {
                        h.best[t] = s16.max(0);
                    }
                }
            }
            if neg.iter().any(|t| token_matches(name, t)) {
                h.flags |= NF_NEG;
            }
            // As a file match it must hit a token and pass name filters;
            // as a folder on someone's path, the raw token bits matter.
            let ok = (pos.is_empty() || h.bits != 0)
                && h.flags & NF_NEG == 0
                && (q.exts.is_empty() || ext_ok(name, &q.exts))
                && q.name_re.as_ref().is_none_or(|re| re.is_match(name));
            if ok {
                h.flags |= NF_OK;
                *ok_entries += (ne_off[k + 1] - ne_off[k]) as usize;
            }
            (ok || h.bits != 0 || h.flags & NF_NEG != 0).then_some(h)
        };
        // Each chunk of name ids writes its own slice of the bitset and of a
        // reused dense table. Slots without their bit set are never read, so
        // the table is never cleared (and never page-faulted in again).
        let mut bits = vec![0u64; idx.u.div_ceil(64)];
        let mut dense = DENSE_POOL.lock().unwrap().pop().filter(|d| d.len() == idx.u).unwrap_or_else(|| vec![NameHit::NONE; idx.u]);
        let counts: Vec<(usize, usize)> = dense
            .par_chunks_mut(NAME_CHUNK)
            .zip(bits.par_chunks_mut(NAME_CHUNK / 64))
            .enumerate()
            .map(|(c, (slots, words))| {
                let (a, b) = (c * NAME_CHUNK, ((c + 1) * NAME_CHUNK).min(idx.u));
                let (mut n, mut ok) = (0usize, 0usize);
                let mut put = |k: usize, h: NameHit| {
                    slots[k - a] = h;
                    words[(k - a) >> 6] |= 1 << (k & 63);
                    n += 1;
                };
                match from {
                    Some(f) => {
                        for w in a / 64..b.div_ceil(64) {
                            let mut m = f.bits[w];
                            while m != 0 {
                                let k = w * 64 + m.trailing_zeros() as usize;
                                if let Some(h) = score_one(k, &mut ok) {
                                    put(k, h);
                                }
                                m &= m - 1;
                            }
                        }
                    }
                    None => {
                        for k in a..b {
                            if let Some(h) = score_one(k, &mut ok) {
                                put(k, h);
                            }
                        }
                    }
                }
                (n, ok)
            })
            .collect();
        let ok_entries = counts.iter().map(|c| c.1).sum();
        let total: usize = counts.iter().map(|c| c.0).sum();
        let mut t = NameTable { bits, sparse: Vec::new(), dense: Some(dense), ok_entries };
        if total <= 1 << 16 {
            // Few matches: keep a compact copy and give the big table back.
            t.sparse = t.iter().collect();
            DENSE_POOL.lock().unwrap().push(t.dense.take().unwrap());
        }
        t
    }

    /// The overlay (entries added since the last compaction) has no dir
    /// memo: each candidate's path components stand in for it. Its top
    /// `limit` is all the merge can use.
    fn search_overlay(&self, q: &Query) -> Vec<Hit> {
        let now = now_secs();
        let pos: Vec<&Token> = q.tokens.iter().filter(|t| !t.negate).collect();
        // A hit needs some positive token in its own name.
        let cands: Vec<(&Vec<u8>, &crate::live::OEnt)> =
            self.live.over.iter().filter(|(_, o)| pos.is_empty() || pos.iter().any(|t| t.fits(o.mask))).collect();
        // Overlay entries cluster in a few busy folders: match each folder's
        // components once per folder, not per entry.
        let mut hits: Vec<Hit> = cands
            .par_iter()
            .fold(
                || (Vec::new(), HashMap::<&[u8], DirMatch, crate::index::Fx>::default()),
                |(mut out, mut memo), &(path, o)| {
                    let cut = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
                    let dir = &path[..cut];
                    if let Some(score) = q.match_path_with(path, o.kind, o.size, o.mtime, |_| *memo.entry(dir).or_insert_with(|| q.dir_match(dir))) {
                        let score = score + o.prior as i32 + rank_tweaks(name_flags(&path[cut + 1..]), o.kind, o.mtime, now);
                        out.push(Hit { score, idx: u32::MAX, over: Some(path.clone()) });
                    }
                    (out, memo)
                },
            )
            .map(|(out, _)| out)
            .flatten_iter()
            .collect();
        if hits.len() > q.limit {
            hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.over.cmp(&b.over)));
            hits.truncate(q.limit);
        }
        hits
    }

    /// For each dir: which tokens its name or an ancestor's matches, with the
    /// best score per token (first 4); bits == u32::MAX if a negated token does.
    fn dir_tokens(&self, names: &NameTable) -> Vec<DirMemo> {
        let idx = &self.live.base;
        let de = idx.dir_entry();
        let en = idx.ent_name();
        let mut out = MEMO_POOL.lock().unwrap().pop().unwrap_or_default();
        out.clear();
        out.resize(idx.d, DirMemo::default());
        out.par_iter_mut().enumerate().with_min_len(1 << 12).for_each(|(k, slot)| {
            if k > 0 {
                *slot = DirMemo::own(names, en[de[k] as usize]);
            }
        });
        // Fold ancestors in, parents first. A dir's descendants are one
        // contiguous id range, so the children of huge dirs go one by one,
        // then every small subtree in parallel.
        let dp = idx.dir_parent();
        let plan = idx.memo_plan();
        for &k in &plan.upper {
            out[k as usize] = out[k as usize].under(out[dp[k as usize] as usize]);
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
                let p = dp[k];
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
struct Scan<'a> {
    q: &'a Query,
    live: &'a Live,
    names: &'a NameTable,
    npos: usize,
    need_dirs: bool,
    now: u32,
}

impl Scan<'_> {
    /// Score entry `i` whose name scored `nh`, given its parent's memo.
    /// `None` if it fails a filter or cannot beat `floor`.
    #[inline(always)]
    fn score(&self, i: usize, nh: NameHit, memo: DirMemo, floor: u64, pbuf: &mut Vec<u8>) -> Option<u64> {
        let idx = &self.live.base;
        let q = self.q;
        let k = idx.kind()[i];
        if !q.kind_ok(k) {
            return None;
        }
        if q.size != (0, u64::MAX) {
            let sz = crate::index::dec_size(idx.size_raw()[i]);
            if sz < q.size.0 || sz > q.size.1 {
                return None;
            }
        }
        let mtime = idx.mtime()[i];
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
        }
        if self.live.is_dead(i as u32) {
            return None;
        }
        let p = idx.parent()[i] as usize;
        score += idx.dir_prior()[p] as i32 + rank_tweaks(nh.flags, k, mtime, self.now);
        let key = key(score, i as u32);
        if key <= floor {
            return None;
        }
        if let Some(re) = &q.path_re {
            idx.path(i, pbuf);
            if !re.is_match(pbuf) {
                return None;
            }
        }
        Some(key)
    }

    /// One sequential pass over every entry in `lo..hi`.
    fn full(&self, lo: usize, hi: usize, memo: Option<&[DirMemo]>) -> Vec<Hit> {
        let idx = &self.live.base;
        let (ent_name, parent) = (idx.ent_name(), idx.parent());
        top_k(hi - lo, self.q.limit, |r, top| {
            let mut pbuf = Vec::new();
            for i in lo + r.start..lo + r.end {
                let Some(nh) = self.names.get(ent_name[i]).filter(|h| h.flags & NF_OK != 0) else { continue };
                let m = memo.map_or(DirMemo::default(), |m| m[parent[i] as usize]);
                if let Some(k) = self.score(i, nh, m, top.floor, &mut pbuf) {
                    top.push(k);
                }
            }
        })
    }

    /// Visit only the entries carrying a matching name; folder tokens are
    /// checked by walking each candidate's ancestors (memoized per piece).
    fn selective(&self, lo: usize, hi: usize) -> Vec<Hit> {
        let idx = &self.live.base;
        let (ne_off, ne, parent) = (idx.name_ents_off(), idx.name_ents(), idx.parent());
        let ok: Vec<(u32, NameHit)> = self.names.iter().filter(|(_, h)| h.flags & NF_OK != 0).collect();
        top_k(ok.len(), self.q.limit, |r, top| {
            let (mut pbuf, mut memo) = (Vec::new(), HashMap::<u32, DirMemo, crate::index::Fx>::default());
            for &(id, nh) in &ok[r] {
                for &e in &ne[ne_off[id as usize] as usize..ne_off[id as usize + 1] as usize] {
                    let i = e as usize;
                    if i < lo || i >= hi {
                        continue;
                    }
                    let m = if self.need_dirs { self.memo_of(parent[i], &mut memo) } else { DirMemo::default() };
                    if let Some(k) = self.score(i, nh, m, top.floor, &mut pbuf) {
                        top.push(k);
                    }
                }
            }
        })
    }

    /// The dir memo of `d` (see `dir_tokens`), from its ancestor chain.
    fn memo_of(&self, d: u32, cache: &mut HashMap<u32, DirMemo, crate::index::Fx>) -> DirMemo {
        let idx = &self.live.base;
        let (de, en, dp) = (idx.dir_entry(), idx.ent_name(), idx.dir_parent());
        let mut chain = Vec::new();
        let mut k = d;
        let mut acc = loop {
            if k == 0 {
                break DirMemo::default();
            }
            if let Some(&m) = cache.get(&k) {
                break m;
            }
            chain.push(k);
            k = dp[k as usize];
        };
        for &k in chain.iter().rev() {
            acc = DirMemo::own(self.names, en[de[k as usize] as usize]).under(acc);
            cache.insert(k, acc);
        }
        acc
    }
}

/// The dir memo is ~13 MB; reusing it saves a page-fault storm per query.
static MEMO_POOL: std::sync::Mutex<Vec<Vec<DirMemo>>> = std::sync::Mutex::new(Vec::new());

/// What the name table depends on: two queries with the same key score
/// every name the same.
#[derive(PartialEq)]
struct NameKey {
    tokens: Vec<(Vec<u8>, Mode, bool)>,
    exts: Vec<Vec<u8>>,
    name_re: Option<String>,
}

impl NameKey {
    fn of(q: &Query) -> NameKey {
        NameKey {
            tokens: q.tokens.iter().map(|t| (t.text.clone(), t.mode, t.negate)).collect(),
            exts: q.exts.clone(),
            name_re: q.name_re.as_ref().map(|r| r.as_str().to_string()),
        }
    }

    /// Can only match names `prev` matched: same filters, same tokens, each
    /// positive token the same or longer in a way that only narrows it.
    fn narrows(&self, prev: &NameKey) -> bool {
        self.exts == prev.exts
            && self.name_re == prev.name_re
            && self.tokens.len() == prev.tokens.len()
            && self.tokens.iter().any(|t| !t.2)
            && self.tokens.iter().zip(&prev.tokens).all(|(a, b)| {
                a.1 == b.1
                    && a.2 == b.2
                    && if a.2 {
                        a.0 == b.0
                    } else if a.1 == Mode::Suffix {
                        a.0.ends_with(&b.0)
                    } else {
                        // Gaining a typo widens the match: score afresh.
                        a.0.starts_with(&b.0) && takes_typos(&a.0, a.1) == takes_typos(&b.0, b.1)
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
pub struct NameCache(std::sync::Mutex<Option<std::sync::Arc<Scored>>>);

impl NameCache {
    /// Drop the cached table and spare buffers once searching has stopped:
    /// tens of MB after a broad query, worth keeping only while typing.
    pub fn trim_if_idle(&self, idle: std::time::Duration) {
        let mut g = self.0.lock().unwrap();
        if g.as_ref().is_some_and(|s| s.at.elapsed() > idle) {
            *g = None;
            drop(g);
            trim_pools();
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct DirMemo {
    bits: u32,
    best: [i16; 4],
}

impl DirMemo {
    /// A dir's own name's contribution.
    #[inline]
    fn own(names: &NameTable, name: u32) -> DirMemo {
        match names.get(name) {
            Some(h) if h.flags & NF_NEG != 0 => DirMemo { bits: u32::MAX, best: [0; 4] },
            Some(h) => DirMemo { bits: h.bits as u32, best: h.best },
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
        DirMemo { bits: self.bits | p.bits, best }
    }
}

/// Spare dense name tables (24 MB each on this disk), so a broad query
/// doesn't page-fault a fresh one in.
static DENSE_POOL: std::sync::Mutex<Vec<Vec<NameHit>>> = std::sync::Mutex::new(Vec::new());

/// Free the spare buffers searches keep for speed (after a quiet spell).
pub fn trim_pools() {
    DENSE_POOL.lock().unwrap().clear();
    MEMO_POOL.lock().unwrap().clear();
}

impl Drop for NameTable {
    fn drop(&mut self) {
        if let Some(d) = self.dense.take() {
            let mut pool = DENSE_POOL.lock().unwrap();
            if pool.len() < 2 {
                pool.push(d);
            }
        }
    }
}

struct NameTable {
    bits: Vec<u64>,
    sparse: Vec<(u32, NameHit)>,
    dense: Option<Vec<NameHit>>,
    /// Entries carrying a name that passes as a match (NF_OK).
    ok_entries: usize,
}

impl NameTable {
    #[inline(always)]
    fn get(&self, id: u32) -> Option<NameHit> {
        if self.bits[id as usize >> 6] & (1 << (id & 63)) == 0 {
            return None;
        }
        match &self.dense {
            Some(d) => Some(d[id as usize]),
            None => self.sparse.binary_search_by_key(&id, |e| e.0).ok().map(|k| self.sparse[k].1),
        }
    }

    /// Every name in the table, ascending.
    fn iter(&self) -> Box<dyn Iterator<Item = (u32, NameHit)> + '_> {
        match &self.dense {
            None => Box::new(self.sparse.iter().copied()),
            Some(d) => Box::new(self.bits.iter().enumerate().flat_map(move |(w, &b)| {
                let mut b = b;
                std::iter::from_fn(move || {
                    (b != 0).then(|| {
                        let id = w as u32 * 64 + b.trailing_zeros();
                        b &= b - 1;
                        (id, d[id as usize])
                    })
                })
            })),
        }
    }
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

impl NameHit {
    const NONE: NameHit = NameHit { score: 0, bits: 0, flags: 0, best: [0; 4] };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{Index, name_mask};
    use crate::live::OEnt;
    use crate::walk::{KIND_OTHER, Listing, NONE, RawEnt};

    const HOME: &str = "/nonexistent-fsearch-home";

    fn q(s: &str) -> Query {
        Query::parse(s, HOME).unwrap()
    }

    fn tok(s: &str) -> Token {
        let mut q = Query::default();
        q.push_token(s);
        q.tokens.pop().unwrap()
    }

    /// An in-memory index of `(path, kind, size, mtime)`; every folder on a
    /// path must be listed itself, as a KIND_DIR entry.
    fn live(ents: &[(&str, u8, u64, u32)]) -> Live {
        let mut ids: HashMap<&str, u32> = HashMap::from([("", 0)]);
        for &(p, k, ..) in ents {
            if k & 3 == KIND_DIR {
                let n = ids.len() as u32;
                ids.entry(p).or_insert(n);
            }
        }
        let mut ls: Vec<Listing> = (0..ids.len() as u32).map(|id| Listing { id, names: Vec::new(), ents: Vec::new() }).collect();
        for &(p, kind, size, mtime) in ents {
            let cut = p.rfind('/').unwrap();
            let l = &mut ls[ids[&p[..cut]] as usize];
            let name = &p[cut + 1..];
            let child = if kind & 3 == KIND_DIR { ids[p] } else { NONE };
            l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, size, mtime, child });
            l.names.extend_from_slice(name.as_bytes());
        }
        Live::new(Index::build(ls, 0, 0, b"/Users/me"))
    }

    const D: u8 = KIND_DIR;
    const F: u8 = KIND_FILE;
    const OLD: u32 = 1_000_000_000;

    fn fixture() -> Live {
        let now = now_secs();
        live(&[
            ("/Users", D, 0, OLD),
            ("/Users/me", D, 0, OLD),
            ("/Users/me/Developer", D, 0, OLD),
            ("/Users/me/Developer/fsearch", D, 0, OLD),
            ("/Users/me/Developer/fsearch/src", D, 0, OLD),
            ("/Users/me/Developer/fsearch/src/main.rs", F, 1200, now),
            ("/Users/me/Developer/fsearch/src/query.rs", F, 40_000, OLD),
            ("/Users/me/Developer/fsearch/README.md", F, 3000, OLD),
            ("/Users/me/Developer/fsearch/target", D, 0, OLD),
            ("/Users/me/Developer/fsearch/target/main.o", F, 9000, OLD),
            ("/Users/me/Documents", D, 0, OLD),
            ("/Users/me/Documents/manifest.json", F, 100, OLD),
            ("/Users/me/Documents/Tax Return 2024.pdf", F, 5_000_000, OLD),
            ("/Users/me/Documents/photo.JPG", F, 2_000_000, OLD),
            ("/Users/me/.zshrc", F, 10, OLD),
            ("/Users/me/secret", D, 0, OLD),
            ("/Users/me/secret/main.rs", F, 10, OLD),
            ("/Applications", D, 0, OLD),
            ("/Applications/Safari.app", D, 0, OLD),
            ("/Applications/Notes.app", KIND_LINK, 0, OLD),
            ("/Applications/Hidden.app", D | FLAG_HIDDEN, 0, OLD),
        ])
    }

    fn paths(l: &Live, hits: &[Hit]) -> Vec<String> {
        let mut buf = Vec::new();
        hits.iter()
            .map(|h| match &h.over {
                Some(p) => String::from_utf8(p.clone()).unwrap(),
                None => {
                    l.base.path(h.idx as usize, &mut buf);
                    String::from_utf8(buf.clone()).unwrap()
                }
            })
            .collect()
    }

    fn find(l: &Live, s: &str) -> Vec<String> {
        paths(l, &Searcher { live: l }.search(&q(s)))
    }

    /// Same answer from a fresh name table (no cache to narrow from).
    fn fresh(s: &str) -> Vec<String> {
        find(&fixture(), s)
    }

    // ---- parsing ----

    #[test]
    fn split_words_quotes_and_spaces() {
        assert_eq!(split_words("  a  b "), ["a", "b"]);
        assert_eq!(split_words(r#"in:"~/My Stuff" x"#), ["in:~/My Stuff", "x"]);
        // An unclosed quote runs to the end.
        assert_eq!(split_words(r#""a b"#), ["a b"]);
        assert!(split_words("").is_empty());
        assert!(split_words(r#""""#).is_empty());
    }

    #[test]
    fn parse_defaults_and_empty() {
        let e = q("");
        assert!(e.tokens.is_empty() && e.kind.is_none() && e.scope.is_none() && e.grep.is_none());
        assert_eq!((e.size, e.mtime, e.limit), ((0, u64::MAX), (0, u32::MAX), 50));
        assert!(q("   ").tokens.is_empty());
    }

    #[test]
    fn token_modes() {
        let t = |s| {
            let t = tok(s);
            (String::from_utf8(t.text).unwrap(), t.mode, t.negate)
        };
        assert_eq!(t("Foo"), ("foo".into(), Mode::Fuzzy, false));
        assert_eq!(t("'foo"), ("foo".into(), Mode::Exact, false));
        assert_eq!(t("^foo"), ("foo".into(), Mode::Prefix, false));
        assert_eq!(t("foo$"), ("foo".into(), Mode::Suffix, false));
        assert_eq!(t("!foo"), ("foo".into(), Mode::Exact, true));
        assert_eq!(t("!^foo"), ("foo".into(), Mode::Prefix, true));
        assert_eq!(t("!foo$"), ("foo".into(), Mode::Suffix, true));
        // `'` wins over a trailing `$`: it stays part of the text.
        assert_eq!(t("'a$"), ("a$".into(), Mode::Exact, false));
        // Bare markers are no token at all.
        for s in ["!", "'", "^", "$", "!'"] {
            let mut q = Query::default();
            q.push_token(s);
            assert!(q.tokens.is_empty(), "{s}");
        }
    }

    #[test]
    fn slashes_split_tokens() {
        let p = q("src/main //x/");
        let texts: Vec<&[u8]> = p.tokens.iter().map(|t| &t.text[..]).collect();
        assert_eq!(texts, [&b"src"[..], b"main", b"x"]);
        assert!(q("/").tokens.is_empty());
    }

    #[test]
    fn at_most_eight_positive_tokens() {
        let p = q("a b c d e f g h i j !k !l");
        assert_eq!(p.tokens.iter().filter(|t| !t.negate).count(), 8);
        assert_eq!(p.tokens.iter().filter(|t| t.negate).count(), 2);
    }

    #[test]
    fn typo_fields() {
        let short = tok("main");
        assert_eq!((short.loose, short.start), (0, 0));
        let long = tok("Manifest");
        assert_eq!(long.start, start_bit(b'm'));
        assert_eq!(long.loose, long.mask & !char_bit(b'm'));
        // Exact tokens never take typos, whatever their length.
        assert_eq!(tok("'manifest").loose, 0);
    }

    #[test]
    fn filters() {
        let p = q("ext:.RS,md type:font");
        assert!(p.exts.starts_with(&[b"rs".to_vec(), b"md".to_vec()]) && p.exts.contains(&b"woff2".to_vec()));
        let app = q("type:app");
        assert_eq!((app.kind, app.exts.clone()), (Some(KIND_DIR), vec![b"app".to_vec()]));
        assert_eq!(q("type:image,video").exts.len(), TYPES[0].1.len() + TYPES[1].1.len());
        for (s, k) in [("f", F), ("file", F), ("d", D), ("dir", D), ("folder", D), ("l", KIND_LINK), ("link", KIND_LINK), ("symlink", KIND_LINK)] {
            assert_eq!(q(&format!("kind:{s}")).kind, Some(k));
        }
        assert_eq!(q("limit:7").limit, 7);
        assert_eq!(q("limit:0").limit, 0);
        let g = |s: &str| {
            let p = q(s);
            (p.grep, p.grep_mode)
        };
        assert_eq!(g("grep:foo"), (Some("foo".into()), GrepMode::Literal));
        assert_eq!(g("content:foo"), (Some("foo".into()), GrepMode::Literal));
        assert_eq!(g("regex:a.b"), (Some("a.b".into()), GrepMode::Regex));
        assert_eq!(g("sym:Foo"), (Some("Foo".into()), GrepMode::Symbol));
        assert_eq!(g("symbol:Foo"), (Some("Foo".into()), GrepMode::Symbol));
        let r = q("re:^ab path:CD");
        assert!(r.name_re.unwrap().is_match(b"ABx") && r.path_re.unwrap().is_match(b"/x/cd"));
        // Not a filter name: the whole word is a token.
        let t = q("http://x foo:bar");
        let texts: Vec<&[u8]> = t.tokens.iter().map(|t| &t.text[..]).collect();
        assert_eq!(texts, [&b"http:"[..], b"x", b"foo:bar"]);
        assert!(q("grep:x").clone_for_scan().grep.is_none());
    }

    #[test]
    fn filter_errors() {
        for s in [
            "type:nope",
            "type:",
            "kind:x",
            "kind:",
            "limit:x",
            "limit:-1",
            "limit:",
            "re:(",
            "path:[",
            "size:",
            "size:abc",
            "size:5q",
            "size:>x",
            "mtime:x",
            "mtime:5..",
            "size:1.2.3",
        ] {
            assert!(Query::parse(s, HOME).is_err(), "{s}");
        }
    }

    #[test]
    fn in_scope() {
        assert_eq!(q("in:/a/b/").scope.unwrap(), b"/a/b");
        assert_eq!(q("in:~").scope.unwrap(), HOME.as_bytes());
        assert_eq!(q("in:~/x/").scope.unwrap(), format!("{HOME}/x").as_bytes());
        // The root: everything is under it.
        assert_eq!(q("in:/").scope.unwrap(), b"");
        // Real folders resolve to their real path (/tmp is /private/tmp).
        let dir = std::env::temp_dir().join(format!("fsearch-query-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let real = std::fs::canonicalize(&dir).unwrap();
        let p = q(&format!("in:{}/./sub/", dir.display()));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(p.scope.unwrap(), real.join("sub").as_os_str().as_encoded_bytes());
    }

    #[test]
    fn ranges() {
        assert_eq!(range("5", parse_size), Ok((5, 5)));
        assert_eq!(range(">5", parse_size), Ok((5, u64::MAX)));
        assert_eq!(range(">=5", parse_size), Ok((5, u64::MAX)));
        assert_eq!(range("<5", parse_size), Ok((0, 5)));
        assert_eq!(range("<=5", parse_size), Ok((0, 5)));
        assert_eq!(range("1k..2k", parse_size), Ok((1000, 2000)));
        assert!(range("1k..", parse_size).is_err());
        assert!(range("..1k", parse_size).is_err());
    }

    #[test]
    fn sizes() {
        for (s, n) in [
            ("0", 0),
            ("12", 12),
            ("12b", 12),
            ("1k", 1000),
            ("1.5KB", 1500),
            ("2m", 2_000_000),
            ("2MB", 2_000_000),
            ("3g", 3_000_000_000),
            ("1gb", 1_000_000_000),
            ("1t", 1_000_000_000_000),
            ("1tb", 1_000_000_000_000),
            (".5k", 500),
        ] {
            assert_eq!(parse_size(s), Some(n), "{s}");
        }
        // Out of range saturates rather than wrapping.
        assert_eq!(parse_size("99999999999999999999999t"), Some(u64::MAX));
        for s in ["", "k", "-1", "1x", "inf", "nan", "1.2.3"] {
            assert_eq!(parse_size(s), None, "{s}");
        }
        let p = q("size:>1mb");
        assert_eq!(p.size, (1_000_000, u64::MAX));
    }

    #[test]
    fn ages() {
        for (s, n) in [
            ("5s", 5),
            ("2m", 120),
            ("2min", 120),
            ("1h", 3600),
            ("1", 86400),
            ("1d", 86400),
            ("1w", 604800),
            ("1mo", 2592000),
            ("1y", 31536000),
            ("1.5h", 5400),
        ] {
            assert_eq!(parse_age(s), Some(n), "{s}");
        }
        assert_eq!(parse_age("1x"), None);
        assert_eq!(parse_age("d"), None);
    }

    #[test]
    fn mtime_bounds() {
        let near = |a: u32, b: u32| a.abs_diff(b) <= 2;
        let now = now_secs();
        let p = q("mtime:<7d");
        assert!(near(p.mtime.0, now - 7 * 86400) && near(p.mtime.1, now));
        let p = q("modified:>7d");
        assert!(p.mtime.0 == 0 && near(p.mtime.1, now - 7 * 86400));
        let p = q("mtime:1d..2d");
        assert!(near(p.mtime.0, now - 2 * 86400) && near(p.mtime.1, now - 86400));
        // Older than the epoch: lower bound clamps to 0.
        assert_eq!(q("mtime:<200y").mtime.0, 0);
        assert_eq!(q("mtime:99999999999999999999999y").mtime, (0, 0));
    }

    #[test]
    fn mtime_older_than_u32_seconds_matches_nothing_recent() {
        // 140y is more seconds than a u32 holds; truncating it left a bound
        // of ~4 years ago instead of "before 1970 minus 84 years".
        let q = Query::parse("mtime:>140y", "/h").unwrap();
        assert_eq!(q.mtime, (0, 0));
    }

    #[test]
    fn huge_limit_does_not_overflow() {
        let mut t = TopK::new(usize::MAX);
        t.push(key(1, 1));
        assert_eq!(t.buf.len(), 1);
    }

    // ---- matching primitives ----

    #[test]
    fn folding_and_finding() {
        assert_eq!(fold(b'A'), b'a');
        assert_eq!(fold(b'z'), b'z');
        assert_eq!(fold(b'@'), b'@');
        assert_eq!(fold(b'['), b'[');
        assert_eq!(fold(0xC3), 0xC3);
        assert!(is_subseq(b"MyMainFile", b"mmf"));
        assert!(!is_subseq(b"abc", b"abcd"));
        assert!(!is_subseq(b"", b"a"));
        assert_eq!(find_ci(b"FooBar", b"bar"), Some(3));
        assert_eq!(find_ci(b"ab", b"abc"), None);
        assert_eq!(find_ci(b"abc", b"abc"), Some(0));
        assert_eq!(find_folded(b"xYz", b'y'), Some(1));
        assert_eq!(find_folded(b"a1b1", b'1'), Some(1));
        assert_eq!(rfind_folded(b"YxY", b'y'), Some(2));
        assert_eq!(rfind_folded(b"a1b1", b'1'), Some(3));
    }

    #[test]
    fn classes_and_bonuses() {
        assert!(class(b'a') == Class::Lower && class(b'Q') == Class::Upper && class(b'7') == Class::Digit);
        assert!(class(b'_') == Class::Delim && class(b'@') == Class::Delim && class(b'~') == Class::Other && class(0xE2) == Class::Other);
        assert_eq!(bonus(Class::Delim, Class::Lower), BONUS_BOUNDARY);
        assert_eq!(bonus(Class::Delim, Class::Delim), 0);
        assert_eq!(bonus(Class::Lower, Class::Upper), BONUS_CAMEL);
        assert_eq!(bonus(Class::Upper, Class::Digit), BONUS_CAMEL);
        assert_eq!(bonus(Class::Lower, Class::Lower), 0);
    }

    #[test]
    fn fuzzy_ranking() {
        let s = |n: &[u8], q: &[u8]| fuzzy_score(n, q);
        assert_eq!(s(b"abc", b"x"), None);
        assert_eq!(s(b"abc", b"abcd"), None);
        assert_eq!(s(b"", b"ab"), None);
        assert_eq!(s(b"acb", b"abc"), None);
        // Whole name > stem > prefix > inside > scattered.
        let whole = s(b"main", b"main").unwrap();
        let stem = s(b"main.rs", b"main").unwrap();
        let prefix = s(b"mainframe.rs", b"main").unwrap();
        let inside = s(b"domain.rs", b"main").unwrap();
        let scattered = s(b"mxaxixn.rs", b"main").unwrap();
        assert!(whole > stem && stem > prefix && prefix > inside && inside > scattered, "{whole} {stem} {prefix} {inside} {scattered}");
        // A leading dot doesn't count against a whole-name match.
        assert_eq!(s(b".zshrc", b"zshrc"), s(b"zshrc", b"zshrc").map(|x| x - 1));
        // A word boundary beats a mid-word hit; camelCase counts too.
        assert!(s(b"x_bar", b"bar") > s(b"xbar", b"bar"));
        assert!(s(b"fooBar", b"bar") > s(b"foobar", b"bar"));
        // A run carries the strongest boundary bonus met inside it.
        assert!(s(b"x-ab", b"-ab") > s(b"xyab", b"yab"));
        // Shrunk from the right: the tight match at the end is scored.
        assert!(s(b"a____ab", b"ab").unwrap() > s(b"a_____b", b"ab").unwrap());
        // Long names pay a capped length penalty.
        assert_eq!(s(&[b'x'; 300], b"xx"), s(&[b'x'; 240], b"xx"));
    }

    #[test]
    fn single_byte_query() {
        assert_eq!(fuzzy_score(b"a", b"a"), Some(SCORE_MATCH + BONUS_BOUNDARY * 2 + 100));
        assert_eq!(fuzzy_score(b"a.rs", b"a"), Some(SCORE_MATCH + BONUS_BOUNDARY * 2 + 80 - 1));
        assert_eq!(fuzzy_score(b"ab", b"a"), Some(SCORE_MATCH + BONUS_BOUNDARY * 2 + 30));
        assert_eq!(fuzzy_score(b"ba", b"a"), Some(SCORE_MATCH));
        assert_eq!(fuzzy_score(b".a", b"a"), Some(SCORE_MATCH + BONUS_BOUNDARY * 2 + 100));
        assert_eq!(fuzzy_score_capped(b"a", b"a", 30), Some(SCORE_MATCH + BONUS_BOUNDARY * 2 + 30));
    }

    #[test]
    fn one_edit() {
        let e = |w: &[u8], q: &[u8]| one_edit_prefix(w, q);
        assert_eq!(e(b"manifest", b"manfiest"), Some(8), "swapped");
        assert_eq!(e(b"manifest", b"manixest"), Some(8), "wrong");
        assert_eq!(e(b"manifest", b"manifst"), Some(8), "missing");
        assert_eq!(e(b"manifest", b"manifeest"), Some(8), "extra");
        assert_eq!(e(b"Manifest.json", b"manfiest"), Some(8), "folds case");
        assert_eq!(e(b"abc", b"abcd"), Some(3), "extra at the end");
        assert_eq!(e(b"manifest", b"manif"), None, "a clean prefix is no typo");
        assert_eq!(e(b"manifest", b"mxnixest"), None, "two edits");
        assert_eq!(e(b"hat_18", b"hat_19"), None, "digits are never edited");
        assert_eq!(e(b"hat_x8", b"hat_18"), None);
    }

    #[test]
    fn typos() {
        let ts = |n: &[u8], q: &[u8]| typo_score(n, name_mask(n), q);
        assert!(ts(b"manifest.json", b"manfiest").is_some());
        assert!(ts(b".manifest", b"manfiest").is_some());
        // At the start of a space-separated word, not elsewhere.
        assert!(ts(b"Tax Return 2024.pdf", b"retrun").is_some());
        assert!(ts(b"tax_return", b"retrun").is_none());
        assert!(ts(b"other", b"retrun").is_none());
        // Below the clean spelling, placed no higher than a prefix.
        let typo = ts(b"manifest", b"manifset").unwrap();
        assert!(typo < fuzzy_score(b"manifest", b"manifest").unwrap());
        assert_eq!(typo, fuzzy_score_capped(b"manifest", b"manifest", 30).unwrap() - TYPO_COST);
        // Words past the fixed buffer are skipped, not a panic.
        let long = [b'a'; 200];
        let mut q = vec![b'a'; 150];
        q[100] = b'b';
        assert!(typo_at(&long, 0, &q).is_none());
        q.truncate(127);
        assert!(typo_at(&long, 0, &q).is_some());
        assert!(typo_at(b"abc", 3, b"abcde").is_none());
    }

    #[test]
    fn token_scores_by_mode() {
        let s = |n: &[u8], t: &str| token_score(n, name_mask(n), &tok(t));
        assert!(s(b"main.rs", "main").is_some());
        assert!(s(b"manifest.json", "manfiest").is_some());
        assert!(s(b"manifest.json", "manifest").unwrap() > s(b"manifest.json", "manfiest").unwrap());
        // A typo token whose mask fits but whose start doesn't: no typo path.
        assert!(s(b"xmanifest", "manfiest").is_none());
        assert_eq!(s(b"main.rs", "'ain"), Some(40 - 7 / 3));
        assert_eq!(s(b"main.rs", "'MAIN"), Some(70 - 7 / 3));
        assert_eq!(s(b"main.rs", "'mian"), None);
        assert_eq!(s(b"main.rs", "^ma"), Some(60 - 7 / 3));
        assert_eq!(s(b"main.rs", "^ai"), None);
        assert_eq!(s(b"m", "^ma"), None);
        assert_eq!(s(b"main.RS", ".rs$"), Some(50 - 7 / 3));
        assert_eq!(s(b"main.rs", "main$"), None);
        assert_eq!(s(b"s", ".rs$"), None);
        // Negated tokens match by the same rules, fuzzy ones as subsequences.
        assert!(token_matches(b"secret", &tok("!secret")));
        assert!(!token_matches(b"secret", &tok("!sct")));
        assert!(token_matches(b"secret", &tok("sct")));
        let mut fz = tok("sct");
        fz.negate = true;
        assert!(token_matches(b"secret", &fz));
    }

    #[test]
    fn fits_prefilter() {
        let m = |n: &[u8]| name_mask(n);
        assert!(tok("main").fits(m(b"main.rs")));
        assert!(!tok("main").fits(m(b"mai.rs")));
        // One missing class is forgiven only when a word starts right.
        let t = tok("manixest");
        assert!(t.fits(m(b"manifest")));
        assert!(!t.fits(m(b"amanifest")));
        assert!(!tok("manizqst").fits(m(b"manifest")));
        // Never the first letter's class.
        assert!(!tok("xanifest").fits(m(b"manifest")));
    }

    #[test]
    fn extensions_and_flags() {
        let ex = |n: &[u8], e: &[&[u8]]| ext_ok(n, &e.iter().map(|x| x.to_vec()).collect::<Vec<_>>());
        assert!(ex(b"a.RS", &[b"rs"]));
        assert!(ex(b"a.tar.gz", &[b"md", b"gz"]));
        assert!(!ex(b"a.rsx", &[b"rs"]));
        assert!(!ex(b"Makefile", &[b"rs"]));
        assert!(ex(b".zshrc", &[b"zshrc"]));
        assert_eq!(name_flags(b".x.app"), NF_DOT | NF_APP);
        assert_eq!(name_flags(b"x"), 0);
        assert_eq!(name_flags(b""), 0);
    }

    #[test]
    fn tweaks() {
        let now = 100_000_000;
        assert_eq!(rank_tweaks(0, F, now, now), 10);
        assert_eq!(rank_tweaks(0, F, now + 50, now), 10);
        assert_eq!(rank_tweaks(0, F, now - 86_401, now), 7);
        assert_eq!(rank_tweaks(0, F, now - 604_801, now), 4);
        assert_eq!(rank_tweaks(0, F, now - 2_592_001, now), 1);
        assert_eq!(rank_tweaks(0, F, 0, now), 0);
        assert_eq!(rank_tweaks(NF_DOT, F | FLAG_HIDDEN, 0, now), -16);
        assert_eq!(rank_tweaks(NF_APP, D, 0, now), 25);
        assert_eq!(rank_tweaks(NF_APP, KIND_LINK, 0, now), 25);
        assert_eq!(rank_tweaks(NF_APP, F, 0, now), 0);
    }

    #[test]
    fn top_k_order_and_ties() {
        assert!(key(5, 0) > key(4, 0) && key(-1, 0) > key(i32::MIN, 0));
        // Equal scores: the lower index ranks first.
        assert!(key(5, 1) > key(5, 2));
        let scores: Vec<i32> = (0..1000).map(|i| i * 7919 % 1000 - 500).collect();
        let hits = top_k(scores.len(), 10, |r, top| {
            for i in r {
                top.push(key(scores[i], i as u32));
            }
        });
        let mut got: Vec<(i32, u32)> = hits.iter().map(|h| (h.score, h.idx)).collect();
        got.sort_by(|a, b| b.cmp(a));
        let mut want: Vec<(i32, u32)> = scores.iter().enumerate().map(|(i, &s)| (s, i as u32)).collect();
        want.sort_by(|a, b| b.cmp(a));
        assert_eq!(got, want[..10]);
        assert!(top_k(0, 10, |_, _| {}).is_empty());
        assert!(top_k(100, 0, |r, top| r.for_each(|i| top.push(key(1, i as u32)))).is_empty());
        // Many pushes into one TopK: cut back as it goes, floor rising.
        let mut t = TopK::new(3);
        for i in 0..200 {
            t.push(key(i, i as u32));
        }
        t.cut();
        t.buf.sort();
        assert_eq!(t.buf, [key(197, 197), key(198, 198), key(199, 199)]);
        assert_eq!(t.floor, key(197, 197));
        // Ties everywhere: still exactly k, lowest indices.
        let hits = top_k(500, 3, |r, top| r.for_each(|i| top.push(key(0, i as u32))));
        let mut idx: Vec<u32> = hits.iter().map(|h| h.idx).collect();
        idx.sort();
        assert_eq!(idx, [0, 1, 2]);
    }

    #[test]
    fn dir_memo_folding() {
        let a = DirMemo { bits: 0b01, best: [5, 0, 0, 0] };
        let b = DirMemo { bits: 0b10, best: [1, 9, 0, 0] };
        let m = a.under(b);
        assert_eq!((m.bits, m.best), (0b11, [5, 9, 0, 0]));
        let neg = DirMemo { bits: u32::MAX, best: [0; 4] };
        assert_eq!(a.under(neg).bits, u32::MAX);
        assert_eq!(neg.under(a).bits, u32::MAX);
    }

    #[test]
    fn name_key_narrowing() {
        let k = |s: &str| NameKey::of(&q(s));
        assert!(k("mai").narrows(&k("ma")));
        assert!(k("^mai").narrows(&k("^ma")));
        assert!(k("'mai").narrows(&k("'ma")));
        assert!(k("xrs$").narrows(&k("rs$")));
        assert!(!k("rsx$").narrows(&k("rs$")));
        assert!(k("manife").narrows(&k("manif")));
        assert!(k("main !foo").narrows(&k("mai !foo")));
        assert!(!k("ma").narrows(&k("mai")), "shorter widens");
        assert!(!k("manif").narrows(&k("mani")), "gaining typos widens");
        assert!(!k("main !foox").narrows(&k("main !foo")), "a longer negation widens");
        assert!(!k("main x").narrows(&k("main")), "token count");
        assert!(!k("^main").narrows(&k("main")), "mode");
        assert!(!k("main ext:rs").narrows(&k("mai")), "exts");
        assert!(!k("main re:x").narrows(&k("mai")), "name regex");
        assert!(!k("!main").narrows(&k("!main")), "negations only: every name is a candidate");
        assert!(k("main") == k("main kind:file size:>1 in:/x path:y"), "non-name filters are not in the key");
    }

    // ---- whole-path matching (overlay, content docs) ----

    #[test]
    fn match_path_filters() {
        let mp = |s: &str, p: &str, kind: u8, size: u64, mtime: u32| q(s).match_path(p.as_bytes(), kind, size, mtime);
        let now = now_secs();
        assert!(mp("main", "/a/main.rs", F, 1, now).is_some());
        assert!(mp("", "/a/main.rs", F, 1, now).is_some());
        assert!(mp("main", "/", D, 0, now).is_none());
        assert!(mp("main", "/a/", D, 0, now).is_none());
        assert!(mp("kind:dir", "/a/main", F, 1, now).is_none());
        assert!(mp("ext:md", "/a/main.rs", F, 1, now).is_none());
        assert!(mp("size:>5", "/a/main.rs", F, 1, now).is_none());
        assert!(mp("size:<5", "/a/main.rs", F, 9, now).is_none());
        assert!(mp("mtime:<1d", "/a/main.rs", F, 1, OLD).is_none());
        assert!(mp("mtime:>1d", "/a/main.rs", F, 1, now).is_none());
        assert!(mp("re:^x", "/a/main.rs", F, 1, now).is_none());
        assert!(mp("path:^/b", "/a/main.rs", F, 1, now).is_none());
        assert!(mp("re:^m path:^/a", "/a/main.rs", F, 1, now).is_some());
        // Scope: strictly below, on a component boundary.
        assert!(mp("in:/a", "/a/main.rs", F, 1, now).is_some());
        assert!(mp("in:/a", "/ab/main.rs", F, 1, now).is_none());
        assert!(mp("in:/a", "/a", D, 1, now).is_none());
        assert!(mp("in:/", "/a", D, 1, now).is_some());
    }

    #[test]
    fn match_path_tokens_and_folders() {
        let mp = |s: &str, p: &str| q(s).match_path(p.as_bytes(), F, 1, OLD);
        assert!(mp("zzz", "/a/main.rs").is_none());
        // Every token must match: the name some, its folders the rest.
        let src = fuzzy_score(b"src", b"src").unwrap();
        let main = fuzzy_score(b"main.rs", b"main").unwrap();
        assert_eq!(mp("src main", "/a/src/b/main.rs"), Some(main + src * 3 / 4), "folders count 3/4");
        assert!(mp("src main", "/x/main.rs").is_none());
        assert!(mp("src main", "/src/x.rs").is_none(), "folders alone are not a hit");
        // Negations hit the name or any folder.
        assert!(mp("main !secret", "/secret/main.rs").is_none());
        assert!(mp("main !secret", "/a/main_secret.rs").is_none());
        assert!(mp("main !secret", "/a/main.rs").is_some());
        assert!(mp("!secret", "/a/main.rs").is_some());
        let d = q("src !tmp main").dir_match(b"/a/src//b");
        assert!(!d.negated && d.best[0].is_some() && d.best[1].is_none());
        assert!(q("!tmp").dir_match(b"/tmp/x").negated);
    }

    // ---- the searcher over an in-memory index ----

    #[test]
    fn search_basics() {
        let l = fixture();
        let main = find(&l, "main");
        assert_eq!(main.len(), 4);
        assert!(main.contains(&"/Users/me/Developer/fsearch/target/main.o".into()));
        assert!(main.contains(&"/Users/me/Documents/manifest.json".into()), "m-a-i-n in order");
        assert_eq!(find(&l, "'main").len(), 3);
        assert_eq!(find(&l, "'main !secret").len(), 2);
        assert_eq!(find(&l, "'main !target !secret"), ["/Users/me/Developer/fsearch/src/main.rs"]);
        // "fsearch" holds s-r-c too.
        assert_eq!(find(&l, "src main"), ["/Users/me/Developer/fsearch/src/main.rs", "/Users/me/Developer/fsearch/target/main.o"]);
        assert_eq!(find(&l, "'src main"), ["/Users/me/Developer/fsearch/src/main.rs"]);
        assert_eq!(find(&l, "fsearch/'src/main"), ["/Users/me/Developer/fsearch/src/main.rs"]);
        assert_eq!(find(&l, "manfiest"), ["/Users/me/Documents/manifest.json"]);
        assert_eq!(find(&l, "retrun"), ["/Users/me/Documents/Tax Return 2024.pdf"]);
        assert_eq!(find(&l, "zshrc"), ["/Users/me/.zshrc"]);
        assert_eq!(find(&l, "PHOTO ext:jpg"), ["/Users/me/Documents/photo.JPG"]);
        assert_eq!(find(&l, "^read"), ["/Users/me/Developer/fsearch/README.md"]);
        assert_eq!(find(&l, ".rs$").len(), 3);
        assert!(find(&l, "nothing-like-this").is_empty());
        // A folder is a hit too.
        assert_eq!(find(&l, "'documents"), ["/Users/me/Documents"]);
        // Fresh-from-the-root results do not depend on the cache.
        assert_eq!(find(&l, "main"), fresh("main"));
    }

    #[test]
    fn search_filters() {
        let l = fixture();
        assert_eq!(find(&l, "ext:rs").len(), 3);
        assert_eq!(find(&l, "ext:rs kind:dir").len(), 0);
        assert_eq!(find(&l, "kind:dir in:/Applications"), ["/Applications/Safari.app", "/Applications/Hidden.app"]);
        assert_eq!(find(&l, "kind:link"), ["/Applications/Notes.app"]);
        assert_eq!(find(&l, "size:>1mb"), ["/Users/me/Documents/Tax Return 2024.pdf", "/Users/me/Documents/photo.JPG"]);
        assert_eq!(find(&l, "main mtime:<1d"), ["/Users/me/Developer/fsearch/src/main.rs"]);
        assert_eq!(find(&l, "main path:target"), ["/Users/me/Developer/fsearch/target/main.o"]);
        assert_eq!(find(&l, "re:^query"), ["/Users/me/Developer/fsearch/src/query.rs"]);
        assert_eq!(find(&l, "main limit:1").len(), 1);
        assert!(find(&l, "main limit:0").is_empty());
        assert_eq!(find(&l, "'main limit:18446744073709551615").len(), 3);
        // Symlinked apps count too (system apps link into the cryptex).
        assert_eq!(find(&l, "type:app").len(), 3);
        assert!(find(&l, "type:app").contains(&"/Applications/Notes.app".to_string()));
    }

    #[test]
    fn search_ranking() {
        let l = fixture();
        // A recent, exact stem match outranks an old one; hidden apps sink.
        assert_eq!(find(&l, "main.rs")[0], "/Users/me/Developer/fsearch/src/main.rs");
        let apps = find(&l, ".app$");
        assert_eq!(apps.last().unwrap(), "/Applications/Hidden.app");
        let hits = Searcher { live: &l }.search(&q("main"));
        assert!(hits.windows(2).all(|w| w[0].score >= w[1].score));
    }

    #[test]
    fn search_scope() {
        let l = fixture();
        let s = Searcher { live: &l };
        assert_eq!(s.scope_range(&q("x")), Some((1, l.base.n)));
        assert_eq!(s.scope_range(&q("in:/")), Some((1, l.base.n)));
        assert_eq!(find(&l, "'main in:/Users/me/Developer"), find(&l, "'main !secret"));
        assert_eq!(find(&l, "'main in:/users/ME/developer/"), find(&l, "'main !secret"), "lookup forgives case");
        assert!(find(&l, "main in:/Users/me/Developer/fsearch/src/main.rs").is_empty(), "a file is no scope");
        assert!(find(&l, "main in:/nowhere").is_empty());
        assert!(find(&l, "in:/Users/me/Documents/manifest.json").is_empty());
        assert_eq!(find(&l, "in:/Users/me/secret"), ["/Users/me/secret/main.rs"]);
    }

    #[test]
    fn negation_only_and_empty_queries() {
        let l = fixture();
        let all = find(&l, "limit:1000");
        assert_eq!(all.len(), l.base.n - 1);
        let some = find(&l, "!secret limit:1000");
        assert_eq!(some.len(), all.len() - 2);
        assert!(!some.iter().any(|p| p.contains("secret")));
    }

    /// FULL_PASS is process-wide; tests that flip it take turns.
    static PASS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn full_pass_agrees_with_selective() {
        let _g = PASS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let queries = [
            "main",
            "main !secret",
            "src main",
            "fsearch src main",
            "me fsearch src main README",
            "!secret limit:1000",
            "manfiest",
            "kind:dir",
            "size:>1mb",
            "main path:target",
            "a b c d e f",
            "in:/Users/me main",
            "rs$ !target",
        ];
        for s in queries {
            FULL_PASS.store(false, std::sync::atomic::Ordering::Relaxed);
            let sel = fresh(s);
            FULL_PASS.store(true, std::sync::atomic::Ordering::Relaxed);
            let full = fresh(s);
            FULL_PASS.store(false, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(sel, full, "{s}");
        }
    }

    #[test]
    fn name_cache_reuse_and_narrowing() {
        let l = fixture();
        let s = Searcher { live: &l };
        // Typing: each query narrows the last one's table.
        for typed in ["m", "ma", "mai", "main", "main.", "main.r", "main.rs"] {
            assert_eq!(find(&l, typed), fresh(typed), "{typed}");
        }
        for typed in ["manif", "manife", "manifes", "manifest"] {
            assert_eq!(find(&l, typed), fresh(typed), "{typed}");
        }
        // The same name key again (a filter that isn't in the key changed).
        let a = s.search(&q("main"));
        let b = s.search(&q("main limit:2"));
        assert_eq!(paths(&l, &a)[..2], paths(&l, &b)[..]);
        // Backspacing does not narrow.
        assert_eq!(find(&l, "mai"), fresh("mai"));
        l.names_cache.trim_if_idle(std::time::Duration::from_secs(3600));
        assert!(l.names_cache.0.lock().unwrap().is_some());
        l.names_cache.trim_if_idle(std::time::Duration::ZERO);
        assert!(l.names_cache.0.lock().unwrap().is_none());
    }

    #[test]
    fn overlay_entries() {
        let mut l = fixture();
        let now = now_secs();
        for (p, kind) in [
            ("/Users/me/Documents/mainframe.txt", F),
            ("/Users/me/Documents/new/main.c", F),
            ("/Users/me/secret/main.go", F),
            ("/Users/me/Documents/new", D),
            ("/Applications/New.app", D),
        ] {
            l.over.insert(p.as_bytes().to_vec(), OEnt::new(p.as_bytes(), kind, 5, now));
        }
        let main = find(&l, "main !secret limit:100");
        assert!(main.contains(&"/Users/me/Documents/mainframe.txt".into()));
        assert!(main.contains(&"/Users/me/Documents/new/main.c".into()));
        assert!(!main.iter().any(|p| p.contains("secret")));
        assert_eq!(find(&l, "new main"), ["/Users/me/Documents/new/main.c"]);
        // Apps rank up.
        assert_eq!(find(&l, "kind:dir new"), ["/Applications/New.app", "/Users/me/Documents/new"]);
        assert_eq!(find(&l, "in:/Users/me/Documents/new"), ["/Users/me/Documents/new/main.c"]);
        // More overlay hits than the limit: its own top-k is cut first.
        assert_eq!(find(&l, "main limit:2").len(), 2);
        assert_eq!(find(&l, "zzz").len(), 0);
    }

    /// Big enough for the dense name table (> 64k matched names), the full
    /// pass (> SELECTIVE entries) and a memo plan with an oversized folder.
    fn big() -> Live {
        let mut paths: Vec<(String, u8)> = vec![("/big".into(), D)];
        let mut f = 0;
        for d in 0..4200 {
            paths.push((format!("/big/d{d}"), D));
            for _ in 0..17 {
                paths.push((format!("/big/d{d}/f{f}.txt"), F));
                f += 1;
            }
            if d < 10 {
                paths.push((format!("/big/d{d}/n"), D));
                paths.push((format!("/big/d{d}/n/m"), D));
                paths.push((format!("/big/d{d}/n/m/deep{d}.txt"), F));
            }
        }
        let ents: Vec<(&str, u8, u64, u32)> = paths.iter().map(|(p, k)| (p.as_str(), *k, 1, OLD)).collect();
        live(&ents)
    }

    #[test]
    fn big_index_strategies() {
        let l = big();
        let files = 4200 * 17 + 10;
        let s = Searcher { live: &l };
        // Every name passes: dense table, full pass, dir memo for the negation.
        let lim = "limit:1000000";
        assert_eq!(s.search(&q(&format!("kind:file !zzz {lim}"))).len(), files);
        assert_eq!(s.search(&q(&format!("kind:file !d4199 {lim}"))).len(), files - 17);
        assert_eq!(s.search(&q(&format!("kind:file !m {lim}"))).len(), files - 10);
        assert_eq!(s.search(&q(&format!("!d4199 {lim}"))).len(), l.base.n - 1 - 18);
        assert_eq!(s.search(&q(&format!("kind:file txt n {lim}"))).len(), 10);
        // Every name scored but none passes: dense table, selective pass.
        assert!(s.search(&q("f ext:zzz")).is_empty());
        assert_eq!(paths(&l, &s.search(&q("deep3 d3 n m"))), ["/big/d3/n/m/deep3.txt"]);
        assert_eq!(s.search(&q("'f123.")).len(), 1);
    }

    #[test]
    fn dead_entries_are_skipped() {
        // A folder that isn't on disk: relisting it finds it gone.
        let root = format!("/fsearch-test-missing-{}", std::process::id());
        let gone = format!("{root}/gone.txt");
        let mut l = live(&[(&root, D, 0, OLD), (&gone, F, 1, OLD), ("/kept-gone.txt", F, 1, OLD)]);
        assert_eq!(find(&l, "gone").len(), 2);
        l.apply_dir(root.as_bytes(), false);
        assert_eq!(find(&l, "gone"), ["/kept-gone.txt"]);
    }

    #[test]
    fn odd_names() {
        let l = live(&[("/é", D, 0, OLD), ("/é/café.txt", F, 1, OLD), ("/é/CAFÉ.TXT", F, 1, OLD), ("/x", F, 1, OLD), ("/other", KIND_OTHER, 1, OLD)]);
        // Non-ASCII matches byte for byte (no Unicode case folding), though
        // as 5 bytes "café" forgives the one byte É differs by.
        assert_eq!(find(&l, "'café"), ["/é/café.txt"]);
        assert_eq!(find(&l, "café"), ["/é/café.txt", "/é/CAFÉ.TXT"]);
        assert_eq!(find(&l, "é caf").len(), 2);
        assert_eq!(find(&l, "x")[0], "/x");
        assert_eq!(find(&l, "other"), ["/other"]);
        let long = "y".repeat(10_000);
        assert!(find(&l, &long).is_empty());
        assert!(find(&l, &format!("'{long}")).is_empty());
    }
}
