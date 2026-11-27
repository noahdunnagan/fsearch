//! `fsearch mcp`: a Model Context Protocol server on stdin/stdout for coding
//! agents (Claude Code, Codex, ...): JSON-RPC 2.0, one message per line. The
//! tools are fff-mcp's (find_files, grep, multi_grep) so prompts written for
//! it work here. Each call is a request or two to the shared daemon (started
//! if need be), so every agent shares one live index; answers are terse
//! text: paths relative to the project, git status where it isn't clean,
//! definitions first.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Protocol versions spoken, newest first. A client asking for another one
/// gets the newest and decides for itself.
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// How long a call waits for a first index build before giving up.
const WAIT_INDEX: Duration = Duration::from_secs(30);

/// The most daemon requests one tool call makes (the most fallbacks of an
/// unlucky query; a definition lookup takes five).
const MAX_ASKS: usize = 16;

const INSTRUCTIONS: &str = "fsearch: indexed search over this project (or any folder, or the whole disk with path \"/\").
- grep: file contents; the default for any identifier or text. Definitions come first, with their first lines.
- find_files: file names (fuzzy, typo-tolerant), to locate a file or see what exists.
- multi_grep: several spellings at once (snake_case, CamelCase), OR'd.
Filters go inline: *.rs or *.{ts,tsx}, src/ (in a folder), src/**/*.rs (glob), !test/ or !*.md (exclude), \
git:modified|staged|untracked (git status); grep also takes a file name (main.rs foo). Results are best first: \
read the top file instead of searching again.";

pub fn run(dir: PathBuf) {
    let mut s = Session::new(dir);
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) if batch.is_empty() => Some(error(&Value::Null, -32600, "invalid request: an empty batch")),
            Ok(Value::Array(batch)) => {
                let r: Vec<Value> = batch.iter().filter_map(|m| s.message(m)).collect();
                (!r.is_empty()).then_some(Value::Array(r))
            }
            Ok(m) => s.message(&m),
            Err(e) => Some(error(&Value::Null, -32700, &format!("parse error: {e}"))),
        };
        for m in reply.into_iter().chain(s.outbox.drain(..)) {
            if writeln!(out, "{m}").and_then(|_| out.flush()).is_err() {
                return;
            }
        }
    }
}

struct Session {
    dir: PathBuf,
    home: String,
    /// The project: the first MCP root, else the git repo holding the
    /// working directory, else the working directory.
    root: String,
    /// Messages to send after the current reply (requests to the client).
    outbox: Vec<Value>,
    asked_roots: u32,
    /// Daemon requests made for the current tool call (see `spend`).
    asks: std::cell::Cell<usize>,
}

fn error(id: &Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

fn result(id: &Value, r: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": r})
}

impl Session {
    fn new(dir: PathBuf) -> Session {
        // Real paths, as the index holds them (/tmp is /private/tmp).
        let real = |p: String| std::fs::canonicalize(&p).map_or(p, |c| c.to_string_lossy().into_owned());
        let home = real(std::env::var("HOME").unwrap_or_else(|_| "/".into()));
        let cwd = real(std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|_| home.clone()));
        let root = real(repo_root(&cwd, &home).unwrap_or(cwd));
        Session { dir, home, root, outbox: Vec::new(), asked_roots: 0, asks: Default::default() }
    }

    /// The reply to one message, if it needs one.
    fn message(&mut self, m: &Value) -> Option<Value> {
        let id = m.get("id");
        let Some(method) = m.get("method").and_then(Value::as_str) else {
            if m.get("result").is_none() && m.get("error").is_none() {
                return Some(error(id.unwrap_or(&Value::Null), -32600, "invalid request: no method"));
            }
            // A reply to one of our requests (roots/list).
            if let Some(roots) = m.pointer("/result/roots").and_then(Value::as_array)
                && let Some(p) = roots.iter().find_map(|r| r["uri"].as_str().and_then(file_uri))
            {
                self.root = std::fs::canonicalize(&p).map_or(p, |c| c.to_string_lossy().into_owned());
            }
            return None;
        };
        let params = m.get("params").unwrap_or(&Value::Null);
        let Some(id) = id else {
            match method {
                "notifications/initialized" | "notifications/roots/list_changed" if self.asked_roots > 0 => self.ask_roots(),
                _ => {}
            }
            return None;
        };
        Some(match method {
            "initialize" => {
                let want = params["protocolVersion"].as_str().unwrap_or("");
                let version = VERSIONS.iter().find(|v| **v == want).unwrap_or(&VERSIONS[0]);
                if params.pointer("/capabilities/roots").is_some() {
                    // Asked once the client says it's ready (notifications/initialized).
                    self.asked_roots = 1;
                }
                self.warm();
                result(
                    id,
                    json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "fsearch", "version": env!("CARGO_PKG_VERSION")},
                        "instructions": INSTRUCTIONS,
                    }),
                )
            }
            "ping" => result(id, json!({})),
            "tools/list" => result(id, json!({ "tools": tools() })),
            "tools/call" => {
                let args = params.get("arguments").unwrap_or(&Value::Null);
                self.asks.set(0);
                let r = match params["name"].as_str().unwrap_or("") {
                    "find_files" => self.find_files(args),
                    "grep" => self.grep(args, false),
                    "multi_grep" => self.grep(args, true),
                    other => return Some(error(id, -32602, &format!("unknown tool {other}"))),
                };
                let (text, is_error) = match r {
                    Ok(t) => (t, false),
                    Err(e) => (e, true),
                };
                result(id, json!({"content": [{"type": "text", "text": text}], "isError": is_error}))
            }
            _ => error(id, -32601, &format!("method not found: {method}")),
        })
    }

    /// Have the daemon up and its index loading while the agent thinks.
    /// (The project's git status is read on the first search that uses it:
    /// many sessions never search.)
    fn warm(&self) {
        let dir = self.dir.clone();
        std::thread::spawn(move || ask_at(&dir, &json!({"op": "ping"})).ok());
    }

    fn ask_roots(&mut self) {
        self.asked_roots += 1;
        self.outbox.push(json!({"jsonrpc": "2.0", "id": format!("fsearch-roots-{}", self.asked_roots), "method": "roots/list"}));
    }

    fn ask(&self, req: &Value) -> Result<Value, String> {
        self.spend(1)?;
        ask_at(&self.dir, req)
    }

    /// Two requests, one after the other: two at once that share a names
    /// table can deadlock the daemon's search pool (query.rs
    /// `NameTable::dense` fills a `OnceLock` with a parallel loop; a worker
    /// waiting in it steals the other search, which waits on the same lock).
    fn ask2(&self, a: &Value, b: &Value) -> (Result<Value, String>, Result<Value, String>) {
        if let Err(e) = self.spend(2) {
            return (Err(e.clone()), Err(e));
        }
        (ask_at(&self.dir, a), ask_at(&self.dir, b))
    }

    /// Count `n` more daemon requests for this tool call: fallbacks and
    /// definition lookups stop when MAX_ASKS run out.
    fn spend(&self, n: usize) -> Result<(), String> {
        let used = self.asks.get() + n;
        if used > MAX_ASKS {
            return Err(format!("stopped after {MAX_ASKS} searches for one call"));
        }
        self.asks.set(used);
        Ok(())
    }

    /// The folder a call searches (None: the whole disk), from its `path`.
    fn scope(&self, a: &Value) -> Option<String> {
        let p = a["path"].as_str().map(str::trim).filter(|p| !p.is_empty() && *p != ".").unwrap_or(&self.root);
        if p.starts_with('/') && p.bytes().all(|b| b == b'/') {
            return None;
        }
        let raw = if p.starts_with('/') {
            p.to_string()
        } else if p == "~" || p.starts_with("~/") {
            format!("{}{}", self.home.trim_end_matches('/'), &p[1..])
        } else {
            format!("{}/{}", self.root.trim_end_matches('/'), p)
        };
        let norm = std::fs::canonicalize(&raw).map_or_else(
            |_| {
                let mut out = PathBuf::new();
                for c in Path::new(&raw).components() {
                    match c {
                        std::path::Component::RootDir => out.push("/"),
                        std::path::Component::CurDir => {}
                        std::path::Component::ParentDir => {
                            out.pop();
                        }
                        std::path::Component::Normal(s) => out.push(s),
                        std::path::Component::Prefix(_) => {}
                    }
                }
                out.to_string_lossy().into_owned()
            },
            |c| c.to_string_lossy().into_owned(),
        );
        (norm != "/" && !norm.is_empty()).then_some(norm)
    }

    /// How this call shows paths: relative to the project, or to the
    /// folder searched when that's elsewhere (said once, up top).
    fn view(&self, scope: &Option<String>) -> View {
        match scope {
            Some(s) if !within(s, &self.root) => View { base: s.clone(), head: Some(format!("in {s}/:")) },
            _ => View { base: self.root.clone(), head: None },
        }
    }

    fn find_files(&self, a: &Value) -> Result<String, String> {
        let query = arg_str(a, &["query", "pattern"]).unwrap_or_default();
        let max = arg_num(a, "maxResults", 20);
        let offset = cursor(a)?;
        let scope = self.scope(a);
        if query.trim().is_empty() || query.trim() == "*" {
            return self.worked_on(&scope, max);
        }
        let mut p = split(&query, false);
        let dirs = rewrite_lone_dir(&mut p);
        let req = |words: &[String], hide: bool| {
            let mut r = json!({
                "q": words.iter().chain(&p.filters).cloned().collect::<Vec<_>>().join(" "),
                "limit": max, "offset": offset, "git": true, "boost": true,
            });
            // What git ignores isn't the project's, unless asked for.
            if hide && !query.contains(".git") {
                r["ignored"] = false.into();
            }
            if !p.filters.iter().any(|f| f.starts_with("kind:")) {
                r["kind"] = (if dirs { "dir" } else { "file" }).into();
            }
            if let Some(s) = &scope {
                r["in"] = s.as_str().into();
            }
            // A repo's own files aren't the project's (unless asked for):
            // git status leaves them out of a repo, this out of a folder of repos.
            let mut globs = p.globs.clone();
            let in_repo = scope.as_deref().is_some_and(|s| Path::new(s).join(".git").exists());
            if !query.contains(".git") && (!hide || !in_repo) {
                globs.push("!.git/".into());
            }
            if !globs.is_empty() {
                r["glob"] = json!(globs);
            }
            r
        };
        let v = self.view(&scope);
        let r = self.ask(&req(&p.words, true))?;
        let hits = r["hits"].as_array().cloned().unwrap_or_default();
        if hits.is_empty() && offset > 0 {
            return Ok(format!("no more files past cursor {offset}"));
        }
        if !hits.is_empty() {
            return Ok(v.list_files(&hits, &p.words, r["next"].as_u64(), None));
        }
        // A short word with two letters swapped ("mian"): the index forgives
        // typos only from five letters.
        for (i, w) in p.words.iter().enumerate().filter(|(_, w)| (3..5).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_alphanumeric())) {
            for j in 0..w.len() - 1 {
                let mut t = w.clone().into_bytes();
                t.swap(j, j + 1);
                let mut words = p.words.clone();
                words[i] = String::from_utf8(t).unwrap_or_default();
                if words[i] == *w {
                    continue;
                }
                let Ok(r) = self.ask(&req(&words, true)) else { break };
                let hits = r["hits"].as_array().cloned().unwrap_or_default();
                if !hits.is_empty() {
                    return Ok(v.list_files(&hits, &words, r["next"].as_u64(), Some(format!("0 files match '{w}'; as '{}':", words[i]))));
                }
            }
        }
        // Nothing the project tracks: maybe in what git ignores (build output).
        let r = self.ask(&req(&p.words, false)).unwrap_or_default();
        let hits = r["hits"].as_array().cloned().unwrap_or_default();
        if !hits.is_empty() {
            return Ok(v.list_files(&hits, &p.words, r["next"].as_u64(), Some("0 matches outside git-ignored files; ignored:".into())));
        }
        // Nothing: drop one word at a time (the last first).
        if p.words.len() > 1 {
            for i in (0..p.words.len()).rev() {
                let fewer: Vec<String> = p.words.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, w)| w.clone()).collect();
                let Ok(r) = self.ask(&req(&fewer, true)) else { break };
                let hits = r["hits"].as_array().cloned().unwrap_or_default();
                if !hits.is_empty() {
                    let note = format!("0 files match all of '{}'; without '{}':", p.words.join(" "), p.words[i]);
                    return Ok(v.list_files(&hits, &fewer, r["next"].as_u64(), Some(note)));
                }
            }
        }
        // Then contents: an identifier is often a file's subject. Where it's
        // defined first (the symbol index, asked alongside).
        let text = p.words.join(" ");
        if !text.is_empty() {
            let mut g = json!({"op": "grep", "pattern": text, "limit": 5, "per_file": 1, "budget_ms": 500});
            if !p.filters.is_empty() {
                g["q"] = p.filters.join(" ").into();
            }
            if !p.globs.is_empty() {
                g["glob"] = json!(p.globs);
            }
            if let Some(s) = &scope {
                g["in"] = s.as_str().into();
            }
            let name = def_name(&text);
            let (r, d) = match name {
                Some(n) => {
                    let mut d = g.clone();
                    (d["pattern"], d["mode"], d["limit"]) = (n.into(), "symbol".into(), 2.into());
                    self.ask2(&g, &d)
                }
                None => (self.ask(&g), Err(String::new())),
            };
            let defs = d.map(|d| files(&d).to_vec()).unwrap_or_default();
            let mut fs: Vec<Value> = defs.into_iter().filter(|f| is_def(f["matches"][0]["text"].as_str().unwrap_or(""), name)).collect();
            for f in r.map(|r| files(&r).to_vec()).unwrap_or_default() {
                if fs.len() < 5 && !fs.iter().any(|o| o["path"] == f["path"]) {
                    fs.push(f);
                }
            }
            if !fs.is_empty() {
                let mut out: Vec<String> = v.head.iter().cloned().collect();
                out.push(format!("0 file names match '{text}'; files containing it:"));
                for f in fs {
                    let (path, m) = (f["path"].as_str().unwrap_or(""), &f["matches"][0]);
                    out.push(format!("{}:{}: {}", v.show(path), m["line"], clip(m["text"].as_str().unwrap_or(""), &text, 120)));
                }
                return Ok(out.join("\n"));
            }
        }
        Ok(format!("0 files match '{query}' in {}", scope.as_deref().unwrap_or("the whole disk")))
    }

    /// No query: what git says is changed, then what you worked on lately
    /// (opened, committed).
    fn worked_on(&self, scope: &Option<String>, max: usize) -> Result<String, String> {
        let mut changed = json!({"q": "git:modified", "kind": "file", "limit": max, "git": true, "boost": true});
        let mut recent = json!({"op": "recent", "kind": "file", "limit": max, "git": true});
        if let Some(s) = scope {
            (changed["in"], recent["in"]) = (s.as_str().into(), s.as_str().into());
        }
        let mut hits = self.ask(&changed).ok().and_then(|r| r["hits"].as_array().cloned()).unwrap_or_default();
        hits.truncate(max);
        for h in self.ask(&recent)?["hits"].as_array().cloned().unwrap_or_default() {
            if hits.len() < max && !hits.iter().any(|o| o["path"] == h["path"]) {
                hits.push(h);
            }
        }
        if hits.is_empty() {
            return Ok("nothing changed in git or worked on lately here; give a query".into());
        }
        Ok(self.view(scope).list_files(&hits, &[], None, Some("changed, then worked on lately:".into())))
    }

    fn grep(&self, a: &Value, multi: bool) -> Result<String, String> {
        let max = arg_num(a, "maxResults", 20);
        let offset = cursor(a)?;
        let context = arg_num(a, "context", 0).min(20);
        let mode = Out::of(a["output_mode"].as_str());
        let scope = self.scope(a);
        let (p, pattern, regex) = if multi {
            let pats = patterns(&a["patterns"]);
            if pats.is_empty() {
                return Err("multi_grep needs patterns".into());
            }
            let p = split(a["constraints"].as_str().unwrap_or(""), true);
            let alt = pats.iter().map(|s| regex::escape(s)).collect::<Vec<_>>().join("|");
            (p, if pats.len() == 1 { pats[0].clone() } else { alt }, pats.len() > 1)
        } else {
            let query = arg_str(a, &["query", "pattern"]).filter(|q| !q.trim().is_empty()).ok_or("grep needs a query")?;
            let mut p = split(&query, true);
            // Constraints alone: they were the text after all ("src/", "main.rs").
            if p.words.is_empty() {
                p = Parts { words: vec![query.trim().to_string()], ..Default::default() };
            }
            let text = p.words.join(" ");
            if text.trim().is_empty() {
                return Err("grep needs a query".into());
            }
            let regex = a["regex"].as_bool().unwrap_or_else(|| looks_like_regex(&text));
            (p, text, regex)
        };
        let req = |pattern: &str, regex: bool, globs: &[String], offset: usize| {
            let mut r = json!({
                "op": "grep", "pattern": pattern, "mode": if regex { "regex" } else { "literal" },
                "q": p.filters.join(" "), "offset": offset, "budget_ms": 2000, "git": true, "ignored": false,
                // Pages hold `max` lines, several a file: about half as many files do.
                "limit": if matches!(mode, Out::Content) { max / 2 + 1 } else { max },
                "per_file": match mode { Out::Count => 1000, Out::Files => 1, Out::Content => if globs.iter().any(|g| is_file_glob(g)) { max } else { 5 } },
            });
            if let Some(s) = &scope {
                r["in"] = s.as_str().into();
            }
            if !globs.is_empty() {
                r["glob"] = json!(globs);
            }
            r
        };
        let v = self.view(&scope);
        // An identifier's definitions lead the first page even when the
        // ranking (newest first) has them further down: the symbol index
        // has them, asked alongside the search.
        let name = def_name(&pattern).filter(|_| offset == 0 && matches!(mode, Out::Content) && !regex && !multi);
        let def_req = |pat: &str, regex: bool, mode: &str, limit: usize, budget: u64| {
            let mut d = req(pat, regex, &p.globs, 0);
            (d["mode"], d["limit"], d["per_file"], d["budget_ms"]) = (mode.into(), limit.into(), 2.into(), budget.into());
            d
        };
        let both = |a: Value, b: Value| self.ask2(&a, &b);
        let (main, sym) = match name {
            Some(n) => both(req(&pattern, regex, &p.globs, offset), def_req(n, false, "symbol", 3, 2000)),
            None => (self.ask(&req(&pattern, regex, &p.globs, offset)), Err(String::new())),
        };
        let mut r = match main {
            // Not a regex after all (an unbalanced paren): as text.
            Err(e) if regex && !multi && a["regex"].as_bool().is_none() && e.contains("regex") => {
                self.ask(&req(&pattern, false, &p.globs, offset))?
            }
            r => r?,
        };
        let mut note = None;
        if offset > 0 && files(&r).is_empty() {
            return Ok(format!("no more matches past cursor {offset}"));
        }
        if offset == 0 && files(&r).is_empty() {
            // Nothing: loosen one way at a time, and say how.
            let ident = !regex && is_ident(&pattern);
            let tries: Vec<(String, bool, Vec<String>, String)> = [
                p.globs.iter().any(|g| is_file_glob(g)).then(|| {
                    let globs = p.globs.iter().filter(|g| !is_file_glob(g)).cloned().collect();
                    (pattern.clone(), regex, globs, format!("0 matches for '{pattern}' in the named file; everywhere:"))
                }),
                (!regex && looks_like_regex(&pattern))
                    .then(|| (pattern.clone(), true, p.globs.clone(), format!("0 matches for '{pattern}' as text; as a regex:"))),
                ident.then(|| (variants(&pattern), true, p.globs.clone(), format!("0 matches for '{pattern}'; other spellings:"))),
                (!regex && pattern.contains(' ')).then(|| {
                    let w = pattern.split_whitespace().max_by_key(|w| w.len()).unwrap_or("").to_string();
                    (w.clone(), false, p.globs.clone(), format!("0 matches for '{pattern}'; for '{w}':"))
                }),
            ]
            .into_iter()
            .flatten()
            .collect();
            for (pat, re, globs, why) in tries {
                if let Ok(r2) = self.ask(&req(&pat, re, &globs, 0))
                    && !files(&r2).is_empty()
                {
                    // Another spelling found (kthread_create_on_node): searched
                    // for as itself, so its definition leads.
                    if ident
                        && !multi
                        && pat == variants(&pattern)
                        && let Some(w) = spelling(&r2, &pat).filter(|w| *w != pattern)
                    {
                        let mut a2 = a.clone();
                        a2["query"] = arg_str(a, &["query", "pattern"]).unwrap_or_default().replacen(&pattern, &w, 1).into();
                        return Ok(format!("0 matches for '{pattern}'; as '{w}':\n{}", self.grep(&a2, false)?));
                    }
                    (r, note) = (r2, Some(why));
                    break;
                }
            }
            if note.is_none() {
                // Maybe it names a file rather than something in one.
                let mut f = json!({"q": pattern, "kind": "file", "limit": 3});
                if let Some(s) = &scope {
                    f["in"] = s.as_str().into();
                }
                let names = self.ask(&f).ok().and_then(|r| r["hits"].as_array().cloned()).unwrap_or_default();
                let mut out = format!("0 matches for '{pattern}' in {}", scope.as_deref().unwrap_or("the whole disk"));
                if r["indexing"].as_u64().is_some_and(|n| n > 0) {
                    out += " (the content index is still being built)";
                }
                if !names.is_empty() {
                    out += "; files named like it:";
                    for h in names {
                        out += &format!("\n{}", v.show(h["path"].as_str().unwrap_or("")));
                    }
                }
                return Ok(out);
            }
        }
        if let Some(name) = name {
            let only_defs = |r: &Result<Value, String>| {
                let mut fs = r.as_ref().map(|d| files(d).to_vec()).unwrap_or_default();
                for f in &mut fs {
                    let keep: Vec<Value> = f["matches"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|m| is_def(m["text"].as_str().unwrap_or(""), Some(name)))
                        .cloned()
                        .collect();
                    f["matches"] = keep.into();
                }
                fs.retain(|f| f["matches"].as_array().is_some_and(|m| !m.is_empty()));
                fs
            };
            let mut defs = only_defs(&sym);
            // C, when nothing better turned up: the symbol index misses it (no
            // keyword before a function; `struct x *p` taken for a
            // definition). So: every `struct name {` (a literal: the index
            // finds them at once) and `name(` from column 0 after a type, or
            // none (the type on the line before), first in files whose path
            // has a word of the name (sched/sleep_timeout.c for
            // schedule_timeout), then in all; not in tools, tests or docs.
            let c = |f: &Value| {
                f["path"].as_str().and_then(|p| p.rsplit_once('.')).is_some_and(|(_, e)| ["c", "h", "cc", "cpp", "hpp", "m", "mm"].contains(&e))
            };
            let good = |f: &Value| c(f) && !aux(v.show(f["path"].as_str().unwrap_or("")));
            if files(&r).iter().any(c) && !defs.iter().any(good) {
                let fun = format!(r"(?m-i)^(?:[A-Za-z_][A-Za-z0-9_ \t*]*[ \t*])?{}\(", regex::escape(name));
                let code = |mut d: Value| {
                    d["glob"] = json!(p.globs.iter().cloned().chain(AUX.iter().map(|a| format!("!{a}/"))).collect::<Vec<_>>());
                    d
                };
                let mut near = code(def_req(&fun, true, "regex", 4, 10));
                let words: Vec<String> = name.split('_').filter(|w| w.len() >= 3).map(regex::escape).collect();
                near["path"] = format!(
                    "^{}/.*(?:{})",
                    regex::escape(scope.as_deref().unwrap_or("")),
                    if words.is_empty() { regex::escape(name) } else { words.join("|") }
                )
                .into();
                let (st, nr) = both(def_req(&format!("struct {name} {{"), false, "literal", 8, 2000), near);
                // Before any of another language (a Rust binding of a C function).
                let mut cs: Vec<Value> = only_defs(&st).into_iter().chain(only_defs(&nr)).collect();
                if !cs.iter().any(good) {
                    cs.extend(only_defs(&self.ask(&code(def_req(&fun, true, "regex", 8, 25)))));
                }
                defs.splice(0..0, cs);
            }
            // The page's own count too (the only one may be in tests/), but
            // not a C prototype spanning lines (`int f(int a,` ... `);`).
            defs.extend(only_defs(&Ok(r.clone())));
            filter_prototypes(&mut defs);
            let rank = |f: &Value| def_rank(v.show(f["path"].as_str().unwrap_or("")), f["matches"][0]["text"].as_str().unwrap_or(""), name);
            defs.sort_by_key(rank);
            let mut seen = std::collections::HashSet::new();
            defs.retain(|f| seen.insert(f["path"].as_str().unwrap_or("").to_string()));
            // The best, and a second as good (not a copy in tools/).
            let best = defs.first().map(|f| rank(f).0);
            defs.retain(|f| Some(rank(f).0) == best);
            defs.truncate(2);
            lead(&mut r, &defs);
        }
        Ok(v.list_matches(&r, &pattern, regex, if regex { None } else { def_name(&pattern) }, mode, max, context, offset, note))
    }
}

/// Put `defs` (files with definitions) first in `r`'s files, merging lines
/// into a file already there, marked `lead` to stay first; files new to the
/// page are marked `extra` so the cursor doesn't count them, the others
/// `at` their place in the daemon's order.
fn lead(r: &mut Value, defs: &[Value]) {
    let Some(fs) = r["files"].as_array_mut() else { return };
    // Where each was in the daemon's order: pages count by it.
    for (i, f) in fs.iter_mut().enumerate() {
        f["at"] = i.into();
    }
    for d in defs.iter().rev() {
        let mut f = match fs.iter().position(|f| f["path"] == d["path"]) {
            Some(i) => fs.remove(i),
            None => json!({"path": d["path"], "matches": [], "extra": true}),
        };
        let mut ls: Vec<Value> = f["matches"].as_array().cloned().unwrap_or_default();
        ls.extend(d["matches"].as_array().cloned().unwrap_or_default());
        ls.sort_by_key(|m| m["line"].as_u64());
        ls.dedup_by_key(|m| m["line"].as_u64());
        f["matches"] = ls.into();
        if f.get("git").is_none() && d.get("git").is_some() {
            f["git"] = d["git"].clone();
        }
        f["lead"] = true.into();
        fs.insert(0, f);
    }
}

/// How a call shows paths (see `Session::view`).
struct View {
    base: String,
    head: Option<String>,
}

impl View {
    fn show<'a>(&self, path: &'a str) -> &'a str {
        match path.strip_prefix(self.base.as_str()) {
            Some(rest) if rest.starts_with('/') => &rest[1..],
            _ => path,
        }
    }

    fn list_files(&self, hits: &[Value], words: &[String], next: Option<u64>, note: Option<String>) -> String {
        // A path given (`include/linux/sched.h`): the file at it first.
        let at = |h: &&Value| {
            let p = self.show(h["path"].as_str().unwrap_or(""));
            words.iter().any(|w| w.contains('/') && (p == w.trim_start_matches("./") || p.ends_with(&format!("/{}", w.trim_start_matches("./")))))
        };
        let mut hits: Vec<&Value> = hits.iter().collect();
        hits.sort_by_key(|h| !at(h));
        // Weak: the best hit doesn't spell every word out (typos, scattered letters).
        let spelled = |h: &Value| {
            let p = h["path"].as_str().unwrap_or("").to_lowercase();
            words.iter().all(|w| p.contains(&w.to_lowercase()))
        };
        let weak = note.is_none() && !words.is_empty() && hits.first().is_some_and(|h| !spelled(h));
        let mut out: Vec<String> = self.head.iter().cloned().chain(note).collect();
        if weak {
            out.push(format!("no exact match for '{}'; closest:", words.join(" ")));
        }
        for h in hits {
            let path = self.show(h["path"].as_str().unwrap_or(""));
            let dir = if h["kind"] == "dir" { "/" } else { "" };
            let git = h["git"].as_str().map_or(String::new(), |g| format!(" ({g})"));
            out.push(format!("{path}{dir}{git}"));
        }
        if let Some(n) = next {
            out.push(format!("cursor: {n}"));
        }
        out.join("\n")
    }

    #[allow(clippy::too_many_arguments)]
    fn list_matches(
        &self,
        r: &Value,
        pattern: &str,
        regex: bool,
        name: Option<&str>,
        mode: Out,
        max: usize,
        context: usize,
        offset: usize,
        note: Option<String>,
    ) -> String {
        let mut out: Vec<String> = self.head.iter().cloned().chain(note).collect();
        let fs: Vec<&Value> = files(r).iter().collect();
        let head = |f: &Value| {
            let git = f["git"].as_str().map_or(String::new(), |g| format!(" ({g})"));
            format!("{}{git}", self.show(f["path"].as_str().unwrap_or("")))
        };
        let lines = |f: &Value| f["matches"].as_array().cloned().unwrap_or_default();
        // The daemon's files (not definitions put first from elsewhere) in
        // its order: a page shows a run of them from the cursor, and the
        // next starts past exactly those, whatever order they're shown in.
        let mut ranked: Vec<(usize, &Value)> =
            fs.iter().enumerate().filter(|(_, f)| f.get("extra").is_none()).map(|(i, f)| (f["at"].as_u64().map_or(i, |a| a as usize), *f)).collect();
        ranked.sort_by_key(|&(at, _)| at);
        let mut taken = ranked.len();
        match mode {
            Out::Files => out.extend(fs.iter().map(|f| head(f))),
            Out::Count => out.extend(fs.iter().map(|f| {
                let n = lines(f).len();
                format!("{}: {n}{}", head(f), if n >= 1000 { "+" } else { "" })
            })),
            Out::Content => {
                let text = |m: &Value| m["text"].as_str().unwrap_or("").to_string();
                let def = |f: &Value, m: &Value| is_def(&text(m), name) && !prototype(f["path"].as_str().unwrap_or(""), m);
                // Definitions in the code itself first, then the code, then
                // tools, tests and docs (theirs first), then files that only
                // import it.
                let rank = |f: &&Value| {
                    let ls = lines(f);
                    if f.get("lead").is_some() {
                        return 0;
                    }
                    if ls.iter().all(|m| is_import(&text(m))) {
                        return 4;
                    }
                    2 * aux(self.show(f["path"].as_str().unwrap_or(""))) as u8 + !ls.iter().any(|m| def(f, m)) as u8
                };
                // The definitions put first, then the daemon's files, at least
                // one, until `max` lines. (A definition from further down
                // shows again in its place on a later page.)
                let lead = |f: &Value| f.get("lead").is_some();
                let mut n: usize = fs.iter().filter(|f| lead(f)).map(|f| lines(f).len()).sum();
                taken = 0;
                while taken < ranked.len() && (taken == 0 || n < max) {
                    n += if lead(ranked[taken].1) { 0 } else { lines(ranked[taken].1).len() };
                    taken += 1;
                }
                let mut page: Vec<&Value> = ranked[..taken].iter().map(|&(_, f)| f).filter(|f| !lead(f)).collect();
                page.sort_by_cached_key(rank);
                let mut expanded = 0;
                for f in fs.iter().copied().filter(|f| lead(f)).chain(page) {
                    out.push(head(f));
                    let ls = lines(f);
                    let path = f["path"].as_str().unwrap_or("");
                    // A definition's body, shown for the first two (a second
                    // only in the code itself: not a copy in tools/).
                    let body_of = |m: &Value, done: usize| done < 2 && (done == 0 || !aux(self.show(path))) && def(f, m) && opens_body(&text(m));
                    // Context and definition bodies come from the file itself.
                    let text = if context > 0 || ls.iter().any(|m| body_of(m, expanded)) { read_text(path) } else { String::new() };
                    let body: Vec<&str> = text.lines().collect();
                    let mut last = 0;
                    for m in &ls {
                        let (ln, text) = (m["line"].as_u64().unwrap_or(0) as usize, m["text"].as_str().unwrap_or(""));
                        if ln <= last {
                            continue;
                        }
                        if context > 0 && !body.is_empty() {
                            // Not past its end: the file may have shrunk since.
                            for c in ln.saturating_sub(context).max(last + 1)..ln.min(body.len() + 1) {
                                out.push(format!("{c}-{}", clip(body[c - 1], "", 160)));
                            }
                        }
                        let col = regex.then(|| m["col"].as_u64().map(|c| c as usize)).flatten();
                        out.push(format!("{ln}:{}", clip_at(text, if regex { "" } else { pattern }, col, 160)));
                        last = ln;
                        let after = if context > 0 {
                            context
                        } else if body_of(m, expanded) {
                            expanded += 1;
                            6
                        } else {
                            0
                        };
                        for c in ln + 1..=(ln + after).min(body.len()) {
                            // A definition's body ends at a blank line; context doesn't.
                            if context == 0 && body[c - 1].trim().is_empty() {
                                break;
                            }
                            if ls.iter().any(|m| m["line"].as_u64() == Some(c as u64)) {
                                break;
                            }
                            out.push(format!("{c}-{}", clip(body[c - 1], "", 160)));
                            last = c;
                        }
                    }
                }
            }
        }
        if r["next"].as_u64().is_some() || taken < ranked.len() {
            out.push(format!("cursor: {}", offset + taken));
        }
        if r["complete"] == false {
            out.push("(stopped early: more files may match; narrow it down)".into());
        }
        if r["indexing"].as_u64().is_some_and(|n| n > 0) {
            out.push("(the content index is still being built: results may be incomplete)".into());
        }
        out.join("\n")
    }
}

/// One request to the daemon. A connection each, its write side closed once
/// the request is out: the daemon then knows no keystroke follows and
/// doesn't keep the cores spinning for one (agents think for seconds).
fn ask_at(dir: &Path, req: &Value) -> Result<Value, String> {
    let t = Instant::now();
    loop {
        let mut s = crate::server::connect(dir).map_err(|e| format!("cannot reach the fsearch daemon: {e}"))?;
        s.write_all(format!("{req}\n").as_bytes()).map_err(|e| e.to_string())?;
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&line).map_err(|e| format!("daemon: {e}"))?;
        if v["ok"] == true {
            return Ok(v);
        }
        let e = v["error"].as_str().unwrap_or("error");
        if !e.starts_with("indexing") || t.elapsed() > WAIT_INDEX {
            return Err(e.to_string());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn files(r: &Value) -> &[Value] {
    r["files"].as_array().map_or(&[], Vec::as_slice)
}

#[derive(Clone, Copy)]
enum Out {
    Content,
    Files,
    Count,
}

impl Out {
    fn of(s: Option<&str>) -> Out {
        match s {
            Some("files_with_matches" | "files") => Out::Files,
            Some("count") => Out::Count,
            _ => Out::Content,
        }
    }
}

fn tools() -> Value {
    let common = |extra: Value| {
        let mut p = json!({
            "path": {"type": "string", "description": "Folder to search: relative to the project, absolute, or \"/\" for the whole disk. Default: the project."},
            "maxResults": {"type": "number", "description": "Default 20."},
            "cursor": {"type": "string", "description": "From the previous result, for the next page."},
        });
        p.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        p
    };
    let grep_extra = json!({
        "context": {"type": "number", "description": "Lines to show around each match."},
        "output_mode": {"type": "string", "enum": ["content", "files_with_matches", "count"], "description": "Default content."},
    });
    let ro = json!({"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false});
    json!([
        {
            "name": "find_files",
            "description": "Find files by name: fuzzy and typo-tolerant, over the whole path. Use it to locate a file or see which files exist; use grep for contents. All words must match. Inline filters: *.rs, src/, src/**/*.rs, !test/, git:modified. A lone 'name/' finds folders; an empty query lists files changed in git, then those worked on lately.",
            "inputSchema": {"type": "object", "properties": common(json!({
                "query": {"type": "string", "description": "Name words and filters, e.g. 'config *.ts !test/'."},
            })), "required": ["query"]},
            "annotations": ro,
        },
        {
            "name": "grep",
            "description": "Search file contents (indexed). Give a bare identifier or literal text from one line, not code syntax; a regex is detected (\\b, .*, a|b, [a-z]) or set with regex. Smart case. Prefix filters: *.rs, src/, !test/, or a file name to search one file ('main.rs parse'). Definitions come first, with their first lines.",
            "inputSchema": {"type": "object", "properties": common({
                let mut g = json!({
                    "query": {"type": "string", "description": "Filters, then the text, e.g. '*.rs fn parse'."},
                    "regex": {"type": "boolean", "description": "Treat the text as a regex (default: detected)."},
                });
                g.as_object_mut().unwrap().extend(grep_extra.as_object().unwrap().clone());
                g
            }), "required": ["query"]},
            "annotations": ro,
        },
        {
            "name": "multi_grep",
            "description": "Search file contents for lines matching ANY of several literal patterns (OR), e.g. every spelling of a name: ['PrepareUpload', 'prepare_upload']. Patterns are literal: never escape them. Filters go in constraints.",
            "inputSchema": {"type": "object", "properties": common({
                let mut g = json!({
                    "patterns": {"type": "array", "items": {"type": "string"}, "description": "Literal patterns, any of which may match."},
                    "constraints": {"type": "string", "description": "File filters, e.g. '*.{ts,tsx} !test/'."},
                });
                g.as_object_mut().unwrap().extend(grep_extra.as_object().unwrap().clone());
                g
            }), "required": ["patterns"]},
            "annotations": ro,
        },
    ])
}

/// The first of `keys` given as a string.
fn arg_str(a: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| a[*k].as_str()).map(str::to_string)
}

/// A count argument (models send 20, 20.0 or "20"); `default` when absent or not positive.
fn arg_num(a: &Value, key: &str, default: usize) -> usize {
    let v = &a[key];
    let n = v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).unwrap_or(-1.0);
    if n.is_finite() && n >= 0.5 { (n.round() as usize).min(1000) } else { default }
}

/// The page offset a cursor carries (cursors are offsets: no state to lose).
fn cursor(a: &Value) -> Result<usize, String> {
    match &a["cursor"] {
        Value::Null => Ok(0),
        Value::Number(n) => Ok(n.as_u64().unwrap_or(0) as usize),
        Value::String(s) if s.trim().is_empty() => Ok(0),
        Value::String(s) => s.trim().parse().map_err(|_| format!("bad cursor {s}")),
        other => Err(format!("bad cursor {other}")),
    }
}

/// multi_grep's patterns: a list, or a string holding a JSON list or one pattern.
fn patterns(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string).collect(),
        Value::String(s) if s.trim_start().starts_with('[') => serde_json::from_str(s).unwrap_or_else(|_| vec![s.clone()]),
        Value::String(s) if !s.is_empty() => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// A tool query taken apart: name words (find_files) or the text (grep),
/// fsearch filters, and path globs for the daemon.
#[derive(Default)]
struct Parts {
    words: Vec<String>,
    filters: Vec<String>,
    globs: Vec<String>,
}

/// fsearch filters a query may carry as they are. Grep text is code, so
/// there only the ones code rarely spells take effect.
const FILTERS: &[&str] = &["ext", "type", "kind", "in", "size", "mtime", "modified", "re", "path", "git", "limit"];
const GREP_FILTERS: &[&str] = &["ext", "in", "git", "size", "mtime"];

fn split(query: &str, grep: bool) -> Parts {
    let mut p = Parts::default();
    let words = words(query);
    let texts = words.iter().filter(|w| !is_constraint(w, grep)).count();
    for w in words {
        let (neg, body) = match w.strip_prefix('!') {
            Some(b) if !b.is_empty() => (true, b),
            _ => (false, w.as_str()),
        };
        if let Some((k, v)) = body.split_once(':')
            && !v.is_empty()
            && (if grep { GREP_FILTERS } else { FILTERS }).contains(&k)
        {
            p.filters.push(w.clone());
        } else if let Some(exts) = ext_glob(body) {
            if neg { p.globs.push(w.clone()) } else { p.filters.push(format!("ext:{exts}")) }
        } else if is_glob(body) || (body.len() > 1 && body.ends_with('/')) {
            p.globs.push(w.clone());
        } else if neg {
            // `!word`: leave out paths below the project with it in a name.
            p.globs.push(format!("!*{body}*/"));
        } else if grep && texts > 0 && is_file(body) {
            p.globs.push(body.to_string());
        } else {
            p.words.push(w);
        }
    }
    p
}

fn is_constraint(w: &str, grep: bool) -> bool {
    let b = w.strip_prefix('!').unwrap_or(w);
    w.starts_with('!')
        || b.split_once(':').is_some_and(|(k, v)| !v.is_empty() && (if grep { GREP_FILTERS } else { FILTERS }).contains(&k))
        || ext_glob(b).is_some()
        || is_glob(b)
        || (b.len() > 1 && b.ends_with('/'))
        || (grep && is_file(b))
}

/// Words, with "double quoted" runs kept whole.
fn words(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quoted) = (Vec::new(), String::new(), false);
    for c in s.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `*.rs`, `**/*.rs`, `*.{ts,tsx}`: the extensions, as `ext:` takes them.
fn ext_glob(w: &str) -> Option<String> {
    let rest = w.strip_prefix("**/").unwrap_or(w).strip_prefix("*.")?;
    let list = rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')).unwrap_or(rest);
    let ok = !list.is_empty() && list.split(',').all(|e| !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    ok.then(|| list.to_string())
}

/// A path glob (rather than code that happens to hold a `*`): wildcards
/// with a `/` or braces, or `*word*`.
fn is_glob(w: &str) -> bool {
    let wild = w.contains(['*', '?', '[']) || (w.contains('{') && w.contains(','));
    wild && (w.contains('/')
        || (w.contains('{') && w.contains('}'))
        || (w.len() > 2 && w.starts_with('*') && w.ends_with('*') && !w[1..w.len() - 1].contains('*')))
}

/// `main.rs`, `src/lib.rs`: a file to search in.
fn is_file(w: &str) -> bool {
    let name = w.rsplit('/').next().unwrap_or(w);
    match name.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && (1..=10).contains(&ext.len())
                && ext.starts_with(|c: char| c.is_ascii_alphabetic())
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
                && w.chars().all(|c| c.is_alphanumeric() || "._-/@+".contains(c))
        }
        None => false,
    }
}

/// A glob naming one file (see `is_file`) rather than a pattern.
fn is_file_glob(g: &str) -> bool {
    !g.starts_with('!') && !is_glob(g) && is_file(g)
}

/// Text that only makes sense as a regex.
fn looks_like_regex(p: &str) -> bool {
    let escapes = ["\\b", "\\s", "\\d", "\\w", "\\S", "\\W", "\\D", "\\(", "\\[", "\\.", "\\{", "(?"];
    let alternation = p.contains('|') && !p.contains("||") && p.split('|').all(|a| !a.is_empty() && !a.starts_with(' ') && !a.ends_with(' '));
    let class = p.find('[').is_some_and(|i| p[i..].find(']').is_some_and(|j| p[i..i + j].contains('-')));
    escapes.iter().any(|e| p.contains(e))
        || [".*", ".+", ".?"].iter().any(|e| p.contains(e))
        || alternation
        || class
        || (p.len() > 1 && p.starts_with('^'))
        || (p.len() > 1 && p.ends_with('$') && !p.ends_with("\\$"))
}

/// The name a grep for a definition is after: an identifier, or the one
/// after a declaring keyword ("struct task_struct", "fn parse").
fn def_name(p: &str) -> Option<&str> {
    if is_ident(p) {
        return Some(p);
    }
    let (kw, name) = p.split_once(' ')?;
    (DEF_WORDS.contains(&kw) && is_ident(name)).then_some(name)
}

fn is_ident(p: &str) -> bool {
    p.len() >= 3 && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') && p.chars().any(|c| c.is_ascii_alphabetic())
}

/// The spelling of `re` most of `r`'s matching lines use, if one does.
fn spelling(r: &Value, re: &str) -> Option<String> {
    let re = regex::Regex::new(re).ok()?;
    let mut n: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for m in files(r).iter().flat_map(|f| f["matches"].as_array().into_iter().flatten()) {
        for w in re.find_iter(m["text"].as_str().unwrap_or("")) {
            *n.entry(w.as_str()).or_default() += 1;
        }
    }
    n.into_iter().max_by_key(|&(w, c)| (c, std::cmp::Reverse(w))).map(|(w, _)| w.to_string()).filter(|w| is_ident(w))
}

/// An identifier's other spellings: its words with or without `_`/`-`
/// between them, any case (`prepareUpload` finds `prepare_upload`, `PREPARE-UPLOAD`).
fn variants(id: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut prev = '_';
    for c in id.chars() {
        if c == '_' || c == '-' {
            prev = '_';
            continue;
        }
        let boundary = prev == '_' || (c.is_ascii_uppercase() && !prev.is_ascii_uppercase()) || (c.is_ascii_digit() != prev.is_ascii_digit());
        if boundary || parts.is_empty() {
            parts.push(String::new());
        }
        parts.last_mut().unwrap().push(c);
        prev = c;
    }
    format!("(?i){}", parts.iter().map(|p| regex::escape(p)).collect::<Vec<_>>().join("[_-]?"))
}

const DEF_WORDS: &[&str] = &[
    "fn",
    "func",
    "function",
    "def",
    "class",
    "struct",
    "enum",
    "trait",
    "interface",
    "type",
    "impl",
    "module",
    "mod",
    "object",
    "protocol",
    "extension",
    "union",
    "typedef",
    "namespace",
    "record",
    "actor",
    "macro_rules!",
    "#define",
];
const MODIFIERS: &[&str] =
    &["pub", "export", "default", "async", "abstract", "unsafe", "static", "protected", "private", "public", "final", "inline", "extern", "const"];

/// Does `line` define something (`name`, if given)? A declaring keyword
/// after any modifiers, then the name; or C style (`c_fn`).
fn is_def(line: &str, name: Option<&str>) -> bool {
    let mut s = line.trim_start();
    loop {
        if let Some(r) = s.strip_prefix("pub(").and_then(|r| r.split_once(')')) {
            s = r.1.trim_start();
            continue;
        }
        match MODIFIERS.iter().find(|m| s.strip_prefix(**m).is_some_and(|r| r.starts_with([' ', '\t']))) {
            Some(m) => s = s[m.len()..].trim_start(),
            None => break,
        }
    }
    let kw = DEF_WORDS.iter().find(|k| s.strip_prefix(**k).is_some_and(|r| r.starts_with([' ', '\t', '<', '(']) || r.is_empty()));
    match (kw, name) {
        (Some(k), Some(n)) => {
            let rest = s[k.len()..].trim_start_matches(|c: char| c.is_whitespace() || c == '*' || c == '&');
            let rest = rest.strip_prefix("mut ").unwrap_or(rest);
            let Some(tail) = rest.strip_prefix(n).filter(|t| !t.starts_with(|c: char| c.is_alphanumeric() || c == '_')) else {
                // `struct page *alloc_page(...)`: a function returning one.
                return matches!(*k, "struct" | "union" | "enum") && c_fn(line, n);
            };
            let tail = tail.trim();
            // `struct x *p;`, `class X;`: a use or a forward declaration.
            match *k {
                "struct" | "union" | "enum" | "class" => {
                    // Past type parameters (`struct Searcher<'a> {`).
                    let tail = tail.strip_prefix('<').map_or(tail, |t| {
                        let mut depth = 1;
                        let end = t.find(|c| {
                            depth += (c == '<') as i32 - (c == '>') as i32;
                            depth == 0
                        });
                        end.map_or("", |e| t[e + 1..].trim_start())
                    });
                    tail.is_empty() || tail.starts_with(['{', ':', '(']) || ["where", "extends", "implements"].iter().any(|w| tail.starts_with(w))
                }
                _ => !tail.ends_with(';') || tail.contains(['=', '{']),
            }
        }
        (Some(_), None) => true,
        (None, Some(n)) => c_fn(line, n),
        (None, None) => false,
    }
}

/// A C function definition's first line: from column 0, `name(` after a
/// type or alone, no `;` at the end (not a call or a one-line prototype).
fn c_fn(line: &str, n: &str) -> bool {
    let t = line.trim_end();
    !line.starts_with([' ', '\t'])
        && !t.ends_with(';')
        && !t.starts_with("extern")
        && t.find(n).is_some_and(|i| {
            let (before, after) = (&t[..i], t[i + n.len()..].trim_start());
            after.starts_with('(') && !before.contains(['=', '(']) && (before.is_empty() || before.ends_with([' ', '*']))
        })
}

/// Does a definition's first line open a body to show: `{`, a macro going
/// on (`\`), a Python block (`:`), or a signature going on (`(`, `,`,
/// `)`: the body is below). Not `#define X 1` or `type X = Y;`.
fn opens_body(line: &str) -> bool {
    line.trim_end().ends_with(['{', '\\', ':', '(', ',', ')'])
}

/// A path in tools, tests, samples or docs rather than the code itself.
fn aux(path: &str) -> bool {
    path.split('/').any(|c| AUX.contains(&c))
}

/// Folders of tools, tests, samples and docs rather than the code itself.
const AUX: &[&str] = &[
    "tools",
    "test",
    "tests",
    "testing",
    "selftests",
    "testdata",
    "fixtures",
    "samples",
    "examples",
    "Documentation",
    "docs",
    "scripts",
    "benches",
    "vendor",
    "third_party",
];

/// How good a definition is to lead with, best first: in the code (not
/// tools, tests, docs), the thing itself (not an `impl` of it, not
/// file-local: `static`, a header's inline stub or another function of the
/// same name), in a path naming more words of the name (lib/find_bit.c for
/// _find_first_bit), not a stub (`{}`).
fn def_rank(path: &str, line: &str, name: &str) -> (bool, bool, usize, bool) {
    let missing = name.split('_').filter(|w| w.len() >= 3 && !path.contains(w)).count();
    (aux(path), ["static ", "impl"].iter().any(|w| line.trim_start().starts_with(w)), missing, line.contains("{}"))
}

/// Is match `m` in `path` the start of a C prototype spanning lines, not a
/// definition: its declaration ends with `;` before any `{`.
fn prototype(path: &str, m: &Value) -> bool {
    let text = m["text"].as_str().unwrap_or("").trim_end();
    if !text.ends_with([',', '(']) || !path.rsplit_once('.').is_some_and(|(_, e)| ["c", "h", "cc", "cpp", "hpp", "m", "mm"].contains(&e)) {
        return false;
    }
    let n = m["line"].as_u64().unwrap_or(0) as usize;
    for l in read_text(path).lines().skip(n).take(16) {
        if l.contains('{') {
            return false;
        }
        if l.trim_end().ends_with(';') {
            return true;
        }
    }
    false
}

fn is_import(line: &str) -> bool {
    let s = line.trim_start();
    ["import ", "use ", "from ", "#include", "require(", "@import"].iter().any(|p| s.starts_with(p))
}

/// A line for display: trimmed, and if long, a window around `pat` (or `col`).
fn clip(line: &str, pat: &str, max: usize) -> String {
    clip_at(line, pat, None, max)
}

fn clip_at(line: &str, pat: &str, col: Option<usize>, max: usize) -> String {
    let lead = line.len() - line.trim_start().len();
    let t = line.trim();
    if t.chars().count() <= max {
        return t.to_string();
    }
    let at = if !pat.is_empty() { t.to_lowercase().find(&pat.to_lowercase()) } else { col.map(|c| c.saturating_sub(lead).min(t.len())) };
    let start = at.map_or(0, |i| i.saturating_sub(max / 3));
    let start = (0..=start).rev().find(|&i| t.is_char_boundary(i)).unwrap_or(0);
    let end = t[start..].char_indices().nth(max).map_or(t.len(), |(i, _)| start + i);
    format!("{}{}{}", if start > 0 { "…" } else { "" }, &t[start..end], if end < t.len() { "…" } else { "" })
}

/// A file's text (for context lines), if it reads as text.
fn read_text(path: &str) -> String {
    match std::fs::read(path) {
        Ok(b) if b.len() <= 8 << 20 => String::from_utf8(b).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
        _ => String::new(),
    }
}

/// Is `path` `dir` or inside it?
fn within(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir).is_some_and(|r| r.is_empty() || r.starts_with('/'))
}

/// The repo holding `dir` (its top folder), unless that's the home folder
/// itself or `/` (a dotfiles repo isn't a project).
fn repo_root(dir: &str, home: &str) -> Option<String> {
    let mut d = Path::new(dir);
    loop {
        if d.join(".git").exists() {
            let s = d.to_string_lossy();
            return (s != home && s != "/").then(|| s.into_owned());
        }
        d = d.parent()?;
    }
}

/// The path of a `file://` URI.
fn file_uri(u: &str) -> Option<String> {
    let p = u.strip_prefix("file://")?;
    let p = p.strip_prefix("localhost").unwrap_or(p);
    let b = p.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(h) = p.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(h);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    let s = String::from_utf8(out).ok()?;
    Some(s.trim_end_matches('/').to_string()).filter(|s| s.starts_with('/'))
}

fn rewrite_lone_dir(p: &mut Parts) -> bool {
    let dirs = p.words.is_empty()
        && p.globs.len() == 1
        && !p.globs[0].starts_with('!')
        && p.globs[0].strip_suffix('/').is_some_and(|b| !b.is_empty() && !b.contains('/') && !is_glob(b) && !b.contains(['*', '?', '[', '{']));
    if dirs {
        let d = p.globs.pop().unwrap();
        p.words.push(d.trim_end_matches('/').to_string());
    }
    dirs
}

fn filter_prototypes(defs: &mut Vec<Value>) {
    for f in defs.iter_mut() {
        let path = f["path"].as_str().unwrap_or("").to_string();
        if let Some(ms) = f["matches"].as_array_mut() {
            ms.retain(|m| !prototype(&path, m));
        }
    }
    defs.retain(|f| f["matches"].as_array().is_some_and(|m| !m.is_empty()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_queries() {
        let p = split("*.rs src/ !test/ parse config", true);
        assert_eq!(p.filters, ["ext:rs"]);
        assert_eq!(p.globs, ["src/", "!test/"]);
        assert_eq!(p.words, ["parse", "config"]);
        let p = split("main.rs fn main", true);
        assert_eq!(p.globs, ["main.rs"]);
        assert_eq!(p.words, ["fn", "main"]);
        assert_eq!(split("self.query", true).words, ["self.query"]);
        assert_eq!(split("*.{ts,tsx} git:modified button", false).filters, ["ext:ts,tsx", "git:modified"]);
    }

    #[test]
    fn spots_definitions() {
        assert!(is_def("pub fn search(&self) {", Some("search")));
        assert!(is_def("pub(crate) struct Query {", Some("Query")));
        assert!(is_def("static int foo_bar(struct x *y)", Some("foo_bar")));
        assert!(is_def("foo_bar(struct x *y)", Some("foo_bar")) && !is_def("foo_bar(x);", Some("foo_bar")));
        assert!(!is_def("\tfoo_bar(x);", Some("foo_bar")));
        assert!(!is_def("int foo_bar(int);", Some("foo_bar")));
        assert!(!is_def("fn other() -> Query {", Some("Query")));
        assert!(is_def("#define FOO 1", Some("FOO")));
        assert!(is_def("struct task_struct {", Some("task_struct")) && !is_def("struct task_struct *p;", Some("task_struct")));
        assert!(!is_def("extern long foo(int a,", Some("foo")) && !is_def("class Foo;", Some("Foo")));
        assert_eq!(def_name("struct task_struct"), Some("task_struct"));
        // C functions returning a struct or an enum.
        assert!(is_def("const struct cpumask *housekeeping_cpumask(enum hk_type type)", Some("housekeeping_cpumask")));
        assert!(is_def("enum dlm_status dlmlock(struct dlm_ctxt *dlm, int mode,", Some("dlmlock")));
        assert!(!is_def("struct page *p = alloc_page(gfp);", Some("alloc_page")));
        assert!(opens_body("struct x {") && opens_body("int f(int a)") && !opens_body("#define FOO 1") && !opens_body("type X = Y;"));
        assert!(is_def("pub struct Searcher<'a> {", Some("Searcher")) && is_def("class Foo extends Bar<T> {", Some("Foo")));
        assert!(is_def("struct Meters(u32);", Some("Meters")) && !is_def("struct Foo<T> *p;", Some("Foo")));
        // Code before tools/ copies, global before static.
        assert!(
            def_rank("lib/rbtree.c", "struct rb_node *rb_prev(", "rb_prev") < def_rank("tools/lib/rbtree.c", "struct rb_node *rb_prev(", "rb_prev")
        );
        assert!(def_rank("a/b.c", "int f(void)", "f") < def_rank("a/b.c", "static int f(void)", "f"));
        assert!(def_rank("b.rs", "pub trait Store {", "Store") < def_rank("a.rs", "impl Store for X {", "Store"));
    }

    #[test]
    fn context_past_the_end() {
        // The file shrank since it was grepped: its line is past the end.
        let path = std::env::temp_dir().join(format!("fsearch-mcp-{}.txt", std::process::id()));
        std::fs::write(&path, "a\nb\n").unwrap();
        let r = json!({"files": [{"path": path.to_str().unwrap(), "matches": [{"line": 50, "text": "x"}]}]});
        let out = View { base: "/".into(), head: None }.list_matches(&r, "x", false, None, Out::Content, 20, 2, 0, None);
        std::fs::remove_file(&path).unwrap();
        assert!(out.contains("50:x"));
    }

    #[test]
    fn cursor_counts_what_was_shown() {
        // Daemon order: a test file, the code, a definition; 3 lines each, 4 a
        // page. However they're shown, the cursor must not skip one or show
        // one twice.
        let f = |p: &str, t: &str| json!({"path": p, "matches": [{"line": 1, "text": t}, {"line": 2, "text": t}, {"line": 3, "text": t}]});
        let r = json!({"files": [f("/p/tests/a.rs", "parse"), f("/p/src/b.rs", "parse"), f("/p/src/c.rs", "fn parse() {")], "next": 3});
        let v = View { base: "/p".into(), head: None };
        let out = v.list_matches(&r, "parse", false, Some("parse"), Out::Content, 4, 0, 0, None);
        let shown: Vec<&str> = out.lines().filter(|l| l.ends_with(".rs")).collect();
        let n: usize = out.lines().find_map(|l| l.strip_prefix("cursor: ")).unwrap().parse().unwrap();
        let order = ["tests/a.rs", "src/b.rs", "src/c.rs"];
        assert!(order[..n].iter().all(|p| shown.contains(p)), "skipped: {shown:?} cursor {n}");
        assert!(order[n..].iter().all(|p| !shown.contains(p)), "shown again next page: {shown:?} cursor {n}");
        // A definition put first from elsewhere (extra) must not keep the cursor at 0.
        let mut d = f("/p/src/d.rs", "fn parse() {");
        (d["extra"], d["lead"]) = (true.into(), true.into());
        let r = json!({"files": [d, f("/p/src/b.rs", "parse")], "next": 1});
        let out = v.list_matches(&r, "parse", false, Some("parse"), Out::Content, 2, 0, 0, None);
        assert_ne!(out.lines().find_map(|l| l.strip_prefix("cursor: ")), Some("0"));
    }

    #[test]
    fn spellings() {
        let re = regex::Regex::new(&variants("prepareUpload")).unwrap();
        assert!(re.is_match("prepare_upload") && re.is_match("PrepareUpload") && re.is_match("PREPARE-UPLOAD"));
        assert!(looks_like_regex("foo|bar") && looks_like_regex("\\bfoo") && !looks_like_regex("|x| x + 1") && !looks_like_regex("a || b"));
        assert!(!looks_like_regex("arr[0]") && looks_like_regex("[a-z]+"));
    }

    #[test]
    fn scope_normalizes_slashes_parents_and_symlinks() {
        let s = Session {
            dir: PathBuf::new(),
            home: "/Users/me".into(),
            root: "/p".into(),
            outbox: Vec::new(),
            asked_roots: 0,
            asks: Default::default(),
        };
        assert_eq!(s.scope(&json!({"path": "///"})), None);
        let other = s.scope(&json!({"path": "../other"})).unwrap();
        assert_eq!(other, "/other");
        assert!(!within(&other, &s.root));

        let root_sess =
            Session { dir: PathBuf::new(), home: "/Users/me".into(), root: "/".into(), outbox: Vec::new(), asked_roots: 0, asks: Default::default() };
        assert_eq!(root_sess.scope(&json!({"path": "src"})), Some("/src".into()));

        let base = std::env::temp_dir().join(format!("fsearch-scope-{}", std::process::id()));
        let target = base.join("real");
        let link = base.join("link");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let got = s.scope(&json!({"path": link.to_str().unwrap()})).unwrap();
        let want = std::fs::canonicalize(&target).unwrap().to_string_lossy().into_owned();
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(got, want);
    }

    #[test]
    fn find_files_keeps_nested_and_wildcard_dir_globs() {
        let mut p = split("src/ui/", false);
        assert!(!rewrite_lone_dir(&mut p));
        assert_eq!(p.globs, ["src/ui/"]);

        let mut p = split("*/", false);
        assert!(!rewrite_lone_dir(&mut p));
        assert_eq!(p.globs, ["*/"]);

        let mut p = split("tests/", false);
        assert!(rewrite_lone_dir(&mut p));
        assert_eq!(p.words, ["tests"]);
        assert!(p.globs.is_empty());
    }

    #[test]
    fn defs_prototype_filter_keeps_later_matches() {
        let path = std::env::temp_dir().join(format!("fsearch-proto-{}.c", std::process::id()));
        std::fs::write(&path, "int foo(int a,\n  int b);\nint foo(int a,\n  int b) { return a; }\n").unwrap();
        let mut defs = vec![json!({
            "path": path.to_str().unwrap(),
            "matches": [
                {"line": 1, "text": "int foo(int a,"},
                {"line": 3, "text": "int foo(int a,"},
            ]
        })];
        filter_prototypes(&mut defs);
        let _ = std::fs::remove_file(&path);
        assert_eq!(defs.len(), 1);
        let ms = defs[0]["matches"].as_array().unwrap();
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0]["line"], 3);
    }

    #[test]
    fn clip_centers_regex_match_on_col() {
        let line = format!("    {}TARGET_MATCH{}", "a".repeat(200), "b".repeat(20));
        let r = json!({"files": [{"path": "/p/a.rs", "matches": [{"line": 1, "text": line, "col": 204}]}]});
        let out = View { base: "/p".into(), head: None }.list_matches(&r, "TARGET_\\w+", true, None, Out::Content, 20, 0, 0, None);
        assert!(out.contains("TARGET_MATCH"), "clipped output missed match: {out}");
    }

    #[test]
    fn grep_rejects_blank_query() {
        let s = Session {
            dir: PathBuf::new(),
            home: "/Users/me".into(),
            root: "/p".into(),
            outbox: Vec::new(),
            asked_roots: 0,
            asks: Default::default(),
        };
        assert_eq!(s.grep(&json!({"query": "   "}), false).unwrap_err(), "grep needs a query");
    }
}
