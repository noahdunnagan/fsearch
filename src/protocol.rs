//! Shared JSON-lines request/response protocol.
use fsearch::walk::{KIND_DIR, KIND_FILE, KIND_LINK};
use fsearch::{Engine, Found, GrepMode, Query};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// The answer to one request line, as one line of JSON.
pub(crate) fn respond(line: &str, engine: &Engine, out: &mut Vec<u8>) {
    respond_with(line, out, |v| run(v, engine));
}

/// One-shot Windows name searches do not need the content index. Stdio uses
/// a complete Engine so all its requests share one mapped generation.
#[cfg(windows)]
pub(crate) fn respond_once(line: &str, opts: fsearch::Options, out: &mut Vec<u8>) {
    respond_with(line, out, |v| {
        let op = v.get("op").and_then(Value::as_str).unwrap_or("search");
        if op == "search" && !is_grep(v) {
            let q = parse_request(v, &opts.home)?;
            // Includes opening the saved name index for this one-shot call.
            let t = Instant::now();
            let found = Engine::search_saved(opts, &q)?;
            Ok(Reply::Hits(found, t.elapsed().as_micros() as u64))
        } else {
            run(v, &Engine::start(opts)?)
        }
    });
}

fn respond_with(line: &str, out: &mut Vec<u8>, run: impl FnOnce(&Value) -> Result<Reply, String>) {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return put(out, &json!({"ok": false, "error": format!("bad json: {e}")})),
    };
    let id = v.get("id").unwrap_or(&Value::Null);
    match run(&v) {
        Ok(Reply::Hits(found, took_us)) => {
            let hits = found
                .iter()
                .map(|f| Hit { kind: kind_name(f.kind), mtime: f.mtime, path: fsearch::paths::display_native(&f.path), score: f.score, size: f.size })
                .collect();
            put(out, &Hits { hits, id, ok: true, took_us })
        }
        Ok(Reply::Value(mut r)) => {
            r["id"] = id.clone();
            put(out, &r)
        }
        Err(e) => put(out, &json!({"ok": false, "error": e, "id": id})),
    }
}

fn put(out: &mut Vec<u8>, v: &impl serde::Serialize) {
    serde_json::to_writer(&mut *out, v).expect("json");
    out.push(b'\n');
}

enum Reply {
    Value(Value),
    /// Name-search results and the search's own time (µs): the hot path,
    /// written straight from the results.
    Hits(Vec<Found>, u64),
}

/// The JSON of a name-search answer. Keys in sorted order, the order every
/// other answer (a `Value` object) prints in.
#[derive(serde::Serialize)]
struct Hits<'a> {
    hits: Vec<Hit<'a>>,
    id: &'a Value,
    ok: bool,
    took_us: u64,
}

#[derive(serde::Serialize)]
struct Hit<'a> {
    kind: &'static str,
    mtime: u32,
    path: std::borrow::Cow<'a, str>,
    score: i32,
    size: u64,
}

fn run(v: &Value, engine: &Engine) -> Result<Reply, String> {
    let op = v.get("op").and_then(Value::as_str).unwrap_or("search");
    match op {
        "ping" => Ok(Reply::Value(json!({"ok": true}))),
        #[cfg(target_os = "macos")]
        "save" => {
            engine.save();
            Ok(Reply::Value(json!({"ok": true, "scheduled": true})))
        }
        #[cfg(windows)]
        "save" => Err("Windows snapshots are saved by fsearch index; reopen stdio after rebuilding".into()),
        _ if is_grep(v) => grep(v, engine).map(Reply::Value),
        "status" => {
            let s = engine.status();
            if !s.ready {
                return Err(engine.indexing());
            }
            let mut v = serde_json::to_value(s).map_err(|e| e.to_string())?;
            v["ok"] = true.into();
            Ok(Reply::Value(v))
        }
        "search" => {
            let q = parse_request(v, engine.home())?;
            let t = Instant::now();
            let found = engine.search(&q)?;
            Ok(Reply::Hits(found, t.elapsed().as_micros() as u64))
        }
        _ => Err(format!("unknown op {op}")),
    }
}

fn is_grep(v: &Value) -> bool {
    let op = v.get("op").and_then(Value::as_str).unwrap_or("search");
    op == "grep"
        || (op == "search"
            && v.get("q").and_then(Value::as_str).is_some_and(|q| ["grep:", "regex:", "sym:", "content:", "symbol:"].iter().any(|k| q.contains(k))))
}

/// Content search. The pattern comes from `pattern` (+ `mode`) or from a
/// `grep:`/`regex:`/`sym:` filter in `q`; the rest of the query narrows
/// which files are read.
fn grep(v: &Value, engine: &Engine) -> Result<Value, String> {
    let mut q = parse_request(v, engine.home())?;
    let mode = match v.get("mode").and_then(Value::as_str) {
        Some("regex") => GrepMode::Regex,
        Some("symbol") => GrepMode::Symbol,
        Some("literal") => GrepMode::Literal,
        Some(m) => return Err(format!("unknown mode {m}")),
        None => q.grep_mode,
    };
    let pattern = v.get("pattern").and_then(Value::as_str).map(str::to_string).or(q.grep.take()).ok_or("grep needs a pattern")?;
    let mut g = fsearch::Grep::new(&pattern, mode)?;
    if let Some(n) = v.get("per_file").and_then(Value::as_u64) {
        g.max_per_file = n as usize;
    }
    if let Some(ms) = v.get("budget_ms").and_then(Value::as_u64) {
        g.budget = (ms > 0).then(|| Duration::from_millis(ms));
    }
    let t = Instant::now();
    let (r, indexed) = engine.grep(&q, &g)?;
    let files: Vec<Value> = r
        .files
        .iter()
        .map(|f| {
            json!({
                "path": fsearch::paths::display(&f.path),
                "matches": f.lines.iter().map(|(n, t)| json!({"line": n, "text": t})).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "ok": true,
        "took_us": t.elapsed().as_micros() as u64,
        "source": if indexed { "index" } else { "scan" },
        "candidates": r.candidates,
        "read": r.read,
        "complete": r.complete,
        "indexing": engine.status().content_pending,
        "files": files,
    }))
}

/// `q` is the query language; any filter key may also be given as its own
/// JSON field (`{"q": "main", "ext": "rs", "in": "~/Developer"}`).
fn parse_request(v: &Value, home: &str) -> Result<Query, String> {
    let mut q = Query::parse(v.get("q").and_then(Value::as_str).unwrap_or(""), home)?;
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if k == "limit" {
                q.limit = val.as_u64().ok_or("limit must be a number")? as usize;
            } else {
                let s = match val {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                q.filter(k, &s, home)?;
            }
        }
    }
    Ok(q)
}

fn kind_name(k: u8) -> &'static str {
    match k & 3 {
        KIND_FILE => "file",
        KIND_DIR => "dir",
        KIND_LINK => "link",
        _ => "other",
    }
}
