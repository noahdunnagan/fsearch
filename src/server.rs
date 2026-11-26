//! The daemon: one `Engine`, answering JSON lines over a unix socket.
//! `fsearch stdio`, `fsearch mcp` and the CLI are thin clients.

use crate::frecency::{self, Frecency};
use crate::git::{self, Git};
use fsearch::walk::{KIND_DIR, KIND_FILE, KIND_LINK, KIND_OTHER};
use fsearch::{Engine, Found, GrepMode, Options, Query};
use regex::bytes::Regex;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("fsearch.sock")
}

/// The socket lock, or None if another daemon holds it. The login agent's
/// daemon stops a stray one (say, started on first use mid-install) and
/// takes over: if it gave way, launchd (KeepAlive) would respawn it forever.
fn take_socket_lock(dir: &Path, as_agent: bool) -> Option<std::fs::File> {
    // Opened without truncating: a loser must not wipe the owner's pid.
    let lock = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(dir.join("socket.lock")).ok()?;
    (try_lock(&lock) || (as_agent && stop(dir).is_ok() && try_lock(&lock))).then_some(lock)
}

pub fn serve(dir: PathBuf, home: String) {
    // One daemon per socket. (The engine's own lock decides who writes the
    // index: an app embedding fsearch may own it while the daemon follows.)
    std::fs::create_dir_all(&dir).ok();
    // launchd names the job it started in XPC_SERVICE_NAME: the login agent's.
    let as_agent = std::env::var("XPC_SERVICE_NAME").is_ok_and(|n| n == super::LABEL);
    let Some(mut lock) = take_socket_lock(&dir, as_agent) else {
        eprintln!("{} another fsearch daemon is running", fsearch::query::now_secs());
        return;
    };
    // The pid lets `stop` find us.
    let _ = lock.set_len(0).and_then(|_| write!(lock, "{}", std::process::id()));
    let git = Git::new(&home);
    git::kill_on_term();
    let engine = match Engine::start(Options { dir: dir.clone(), home, skip: None }) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", fsearch::query::now_secs());
            return;
        }
    };
    let g = git.clone();
    engine.on_change(move |dirs| g.changed(dirs));
    let cx = Arc::new(Ctx { engine, git, frecency: Frecency::load(dir.join("frecency")) });
    let sock = socket_path(&dir);
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{} {}: {e}", fsearch::query::now_secs(), sock.display());
            return;
        }
    };
    for conn in listener.incoming().flatten() {
        let cx = cx.clone();
        std::thread::spawn(move || handle(conn, &cx));
    }
}

/// What requests reach: the engine, the git status of what it finds, and
/// what you opened lately.
struct Ctx {
    engine: Engine,
    git: Arc<Git>,
    frecency: Arc<Frecency>,
}

fn try_lock(f: &std::fs::File) -> bool {
    unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(f), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Stop the daemon serving `dir`, if one is running, and wait until it has
/// let go of the socket lock. One already on its way out (say, after a
/// launchd bootout) is just waited for.
pub fn stop(dir: &Path) -> Result<(), String> {
    stop_within(dir, Duration::from_secs(30))
}

fn stop_within(dir: &Path, timeout: Duration) -> Result<(), String> {
    let path = dir.join("socket.lock");
    let Ok(lock) = std::fs::File::open(&path) else { return Ok(()) };
    let me = std::process::id() as i32;
    let (mut killed, mut named) = (None, None);
    for _ in 0..timeout.as_millis().div_ceil(100) {
        if try_lock(&lock) {
            return Ok(());
        }
        // Read every pass: a client may have started a new daemon once the
        // old one let go (mid-install), and a pid that isn't a daemon's (a
        // crashed one's, reused) is never signalled.
        let pid = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse::<i32>().ok()).filter(|&p| p > 1);
        named = pid.or(named);
        if let Some(p) = pid.filter(|&p| p != me && killed != Some(p) && is_daemon(p)) {
            unsafe { libc::kill(p, libc::SIGTERM) };
            killed = Some(p);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(match (killed, named) {
        (Some(pid), _) => format!("daemon {pid} did not exit"),
        (None, Some(p)) => format!("socket.lock names pid {p}, not an fsearch daemon; stop the daemon holding the lock by hand"),
        (None, None) => "a daemon is running but did not record its pid; stop it by hand".into(),
    })
}

/// Whether `pid` is a daemon: an fsearch binary (or its test harness) run
/// as `serve`.
fn is_daemon(pid: i32) -> bool {
    let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    let exe = n > 0 && Path::new(std::ffi::OsStr::from_bytes(&buf[..n as usize])).file_name().is_some_and(|f| f.as_bytes().starts_with(b"fsearch"));
    exe && args(pid).get(1).is_some_and(|a| a == b"serve")
}

/// `pid`'s argv, empty if it can't be read (KERN_PROCARGS2: argc, the exec
/// path and its NUL padding, then argv).
fn args(pid: i32) -> Vec<Vec<u8>> {
    let mut max: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    if unsafe { libc::sysctl(mib.as_mut_ptr(), 2, (&raw mut max).cast(), &mut len, std::ptr::null_mut(), 0) } != 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; max.max(0) as usize];
    let mut len = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    if unsafe { libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) } != 0 || len < 4 {
        return Vec::new();
    }
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]).max(0) as usize;
    let rest = &buf[4..len];
    let path_end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let start = rest[path_end..].iter().position(|&b| b != 0).map_or(rest.len(), |i| path_end + i);
    rest[start..].split(|&b| b == 0).take(argc).map(<[u8]>::to_vec).collect()
}

/// How long the cores stay clocked up after an answer to a client that is
/// still connected (typing): most gaps between keystrokes are shorter.
const WARM: Duration = Duration::from_millis(250);

fn handle(mut conn: UnixStream, cx: &Ctx) {
    // Content searches run on this thread: keep them on performance cores.
    unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0) };
    let Ok(r) = conn.try_clone() else { return };
    let mut out = Vec::new();
    for line in BufReader::new(r).lines() {
        let Ok(line) = line else { return };
        if line.trim().is_empty() {
            continue;
        }
        out.clear();
        respond(&line, cx, &mut out);
        if conn.write_all(&out).is_err() {
            return;
        }
        if waiting(&conn) {
            cx.engine.keep_warm(WARM);
        }
    }
}

/// The client is still connected with nothing more to ask yet: a session
/// whose next request is a keystroke away. (One-shot clients like the CLI
/// close their side as soon as the request is out.)
fn waiting(conn: &UnixStream) -> bool {
    let mut b = 0u8;
    let n = unsafe { libc::recv(std::os::fd::AsRawFd::as_raw_fd(conn), (&raw mut b).cast(), 1, libc::MSG_PEEK | libc::MSG_DONTWAIT) };
    n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock
}

/// The answer to one request line, as one line of JSON.
fn respond(line: &str, cx: &Ctx, out: &mut Vec<u8>) {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return put(out, &json!({"ok": false, "error": format!("bad json: {e}")})),
    };
    let id = v.get("id").unwrap_or(&Value::Null);
    match run(&v, cx) {
        Ok(Reply::Hits(found, took_us, next, annotate)) => {
            let hits = found
                .iter()
                .map(|f| Hit {
                    git: annotate.then(|| cx.git.status(f.path.as_os_str().as_bytes()).and_then(git::word)).flatten(),
                    kind: kind_name(f.kind),
                    mtime: f.mtime,
                    path: f.path.to_string_lossy(),
                    score: f.score,
                    size: f.size,
                })
                .collect();
            put(out, &Hits { hits, id, next, ok: true, took_us })
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
    /// Name-search results, the search's own time (µs), for a paged request
    /// where the next page starts, and whether to give each hit's git
    /// status: the hot path, written straight from the results.
    Hits(Vec<Found>, u64, Option<usize>, bool),
}

/// The JSON of a name-search answer. Keys in sorted order, the order every
/// other answer (a `Value` object) prints in.
#[derive(serde::Serialize)]
struct Hits<'a> {
    hits: Vec<Hit<'a>>,
    id: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<usize>,
    ok: bool,
    took_us: u64,
}

#[derive(serde::Serialize)]
struct Hit<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    git: Option<&'static str>,
    kind: &'static str,
    mtime: u32,
    path: std::borrow::Cow<'a, str>,
    score: i32,
    size: u64,
}

fn run(v: &Value, cx: &Ctx) -> Result<Reply, String> {
    let engine = &cx.engine;
    let op = v.get("op").and_then(Value::as_str).unwrap_or("search");
    let is_grep = op == "grep"
        || (op == "search"
            && v.get("q").and_then(Value::as_str).is_some_and(|q| ["grep:", "regex:", "sym:", "content:", "symbol:"].iter().any(|k| q.contains(k))));
    match op {
        "ping" => Ok(Reply::Value(json!({"ok": true}))),
        "save" => {
            engine.save();
            Ok(Reply::Value(json!({"ok": true, "scheduled": true})))
        }
        _ if is_grep => grep(v, cx).map(Reply::Value),
        "open" => {
            // An editor or agent opened these: they rank higher for a while.
            let paths: Vec<&str> = match (v.get("path"), v.get("paths")) {
                (Some(Value::String(p)), _) => vec![p],
                (_, Some(Value::Array(a))) => a.iter().filter_map(Value::as_str).collect(),
                _ => return Err("open needs a path (or paths)".into()),
            };
            let now = fsearch::query::now_secs();
            let scores: Vec<f32> = paths.iter().map(|p| cx.frecency.open(&real(p), now)).collect();
            Ok(Reply::Value(json!({"ok": true, "scores": scores})))
        }
        "recent" => {
            // What you worked on lately (under `in:`, passing the query),
            // best first: opens and your commits (see `frecent`).
            let (q, _) = parse_request(v, engine.home())?;
            let top = frecent(cx, q.scope.as_deref(), fsearch::query::now_secs());
            let hits = top.into_iter().filter_map(|(p, s)| Some(Found { score: (s * 100.0) as i32, ..found(&q, &p)? }));
            Ok(Reply::Hits(hits.take(q.limit).collect(), 0, None, v.get("git") == Some(&Value::Bool(true))))
        }
        "git" => {
            // The repo holding a folder, its status read in the background
            // (`fsearch mcp` asks at start, so the first search has it).
            let p = v.get("path").and_then(Value::as_str).ok_or("git needs a path")?;
            let r = cx.git.load(&[&real(p)[..], b"/."].concat());
            let snap = r.as_ref().and_then(|r| r.snap(Duration::ZERO));
            Ok(Reply::Value(json!({
                "ok": true,
                "root": r.as_ref().map(|r| String::from_utf8_lossy(&r.root).into_owned()),
                "read": snap.is_some(),
                "changed": snap.map(|s| s.files.values().chain(s.dirs.values()).filter(|&&b| b & git::IGNORED == 0).count()),
            })))
        }
        "status" => {
            let s = engine.status();
            if !s.ready {
                return Err(engine.indexing());
            }
            let mut v = serde_json::to_value(s).map_err(|e| e.to_string())?;
            v["ok"] = true.into();
            Ok(Reply::Value(v))
        }
        "search" | "glob" => {
            let (mut q, sels) = parse_request(v, engine.home())?;
            let x = Extras::parse(v, &mut q, sels, op == "glob", false)?;
            let t = Instant::now();
            if x.plain() {
                let found = engine.search(&q)?;
                return Ok(Reply::Hits(found, t.elapsed().as_micros() as u64, None, false));
            }
            x.ready(cx, &q)?;
            let path = |f: &Found| f.path.as_os_str().as_bytes().to_vec();
            // Boosts reorder a fixed window, whatever the page.
            let reranks = x.boost || x.near.is_some();
            let (limit, want) = (q.limit, if reranks { x.offset.saturating_add(q.limit).max(RERANK) } else { x.offset.saturating_add(q.limit) });
            let (mut found, cut) = if x.listed() {
                let mut all = from_git(cx, &q, &x, want.saturating_add(1));
                all.retain(|f| x.keep(&cx.git, &path(f)));
                (all, false)
            } else {
                fetch_kept(
                    &x,
                    want,
                    MAX_FETCH,
                    |f| x.keep(&cx.git, &path(f)),
                    |n| {
                        q.limit = n;
                        Ok((engine.search(&q)?, false))
                    },
                )?
            };
            if reranks {
                rerank(cx, &mut found, x.boost, x.near.as_deref());
            }
            let next = x.cut(&mut found, limit).or(cut.then_some(x.offset + found.len()));
            Ok(Reply::Hits(found, t.elapsed().as_micros() as u64, next, x.annotate))
        }
        _ => Err(format!("unknown op {op}")),
    }
}

/// What a request may add to the query language: a page offset (`offset`;
/// answers then say where the next page starts); globs a path must
/// (`src/**/*.rs`) or must not (`!test/`) match, relative to the `in:`
/// folder, else `cwd`, else `/`; `git:` filters in `q` (`git:modified`,
/// `!git:ignored`; without `in:`, within `cwd`); each hit's git status
/// (`"git": true`); and leaving out what git ignores where its status is
/// known (`"ignored": false`); and, for a name search, reordering the best
/// hits by frecency (`"boost": true`) and nearness to the file you're in
/// (`"near": path`), see `rerank`. The `glob` op lists what its `pattern`
/// matches.
#[derive(Default)]
struct Extras {
    offset: usize,
    paged: bool,
    /// Checked on each hit: the negative globs, and positive ones past the
    /// first (which the query applies itself, as its `path:` regex).
    globs: Vec<(Regex, bool)>,
    /// `git:` filters, true if negated.
    sels: Vec<(git::Sel, bool)>,
    annotate: bool,
    hide_ignored: bool,
    cwd: Option<Vec<u8>>,
    boost: bool,
    near: Option<Vec<u8>>,
}

/// Request fields `Extras` reads, not query filters.
const EXTRAS: &[&str] = &["offset", "cursor", "glob", "cwd", "git", "ignored", "boost", "near"];
/// Frecency reorders this many of the best hits (a fixed window, so pages
/// agree). Replays did as well with 32-200: a file needs to be among them.
const RERANK: usize = 256;

/// How long a `git:` filter waits for a repo's first `git status`.
const GIT_WAIT: Duration = Duration::from_secs(5);
/// The most repos below its folder a `git:` filter reads...
const MAX_REPOS: usize = 16;
/// ...and folders git lists whole (untracked, ignored) it searches.
const MAX_DIRS: usize = 64;

impl Extras {
    fn parse(v: &Value, q: &mut Query, sels: Vec<(git::Sel, bool)>, glob_op: bool, grep: bool) -> Result<Extras, String> {
        let cwd = v.get("cwd").and_then(Value::as_str).map(real);
        // `cursor` too, except in a grep: there it is where the content
        // index's ranking resumes (see `grep`), not a count of files shown.
        let at = v.get("offset").or(v.get("cursor").filter(|_| !grep));
        let mut x = Extras {
            offset: 0,
            paged: glob_op || at.is_some(),
            globs: Vec::new(),
            annotate: v.get("git") == Some(&Value::Bool(true)),
            hide_ignored: v.get("ignored") == Some(&Value::Bool(false)) && !sels.contains(&(git::Sel::Ignored, false)),
            sels,
            cwd,
            boost: v.get("boost") == Some(&Value::Bool(true)),
            near: v.get("near").and_then(Value::as_str).map(real),
        };
        if let Some(o) = at {
            // Past what a page can be fetched from, every page is empty.
            x.offset = (o.as_u64().or_else(|| o.as_str()?.parse().ok()).ok_or("offset must be a number")?).min(MAX_FETCH as u64) as usize;
        }
        let mut globs: Vec<&str> = match v.get("glob") {
            None => Vec::new(),
            Some(Value::String(g)) => vec![g],
            Some(Value::Array(a)) => a.iter().map(|g| g.as_str().ok_or("glob must be a string or a list of them")).collect::<Result<_, _>>()?,
            Some(_) => return Err("glob must be a string or a list of them".into()),
        };
        if glob_op {
            globs.insert(0, v.get("pattern").and_then(Value::as_str).ok_or("glob needs a pattern")?);
            q.kind = q.kind.or(Some(KIND_FILE));
        }
        // `git:` filters are about one repo: without `in:`, the one holding `cwd`.
        if !x.sels.is_empty()
            && q.scope.is_none()
            && let Some(c) = &x.cwd
        {
            q.scope = Some(git_root(c).unwrap_or_else(|| c.clone()));
        }
        let base = q.scope.clone().or(x.cwd.clone()).unwrap_or_default();
        for g in globs {
            let (neg, g) = g.strip_prefix('!').map_or((false, g), |g| (true, g));
            let re = glob_regex(g, &base)?;
            if neg || q.path_re.is_some() {
                x.globs.push((re, neg));
                continue;
            }
            // The first positive glob narrows the search itself: to the
            // folder its leading literal part names, to its extensions,
            // and as the query's path regex.
            if let Some(dir) = glob_dir(g, &base)
                && q.scope.as_ref().is_none_or(|s| within(&dir, s))
            {
                q.scope = Some(dir);
            }
            if q.exts.is_empty() {
                q.exts = glob_exts(g);
            }
            q.path_re = Some(re);
        }
        Ok(x)
    }

    /// Nothing beyond the query language: answered exactly as before.
    fn plain(&self) -> bool {
        !self.paged && self.globs.is_empty() && self.sels.is_empty() && !self.annotate && !self.hide_ignored && !self.boost && self.near.is_none()
    }

    /// A positive `git:` filter for statuses git lists (modified...): its
    /// hits come from the repos' status, not a search.
    fn listed(&self) -> bool {
        self.sels.iter().any(|&(s, neg)| !neg && s.listed())
    }

    /// The folder the git parts are about: the scope, else `cwd`.
    fn base<'a>(&'a self, q: &'a Query) -> Option<&'a [u8]> {
        q.scope.as_deref().or(self.cwd.as_deref())
    }

    /// Have the status of the repo in question read: waited for by `git:`
    /// filters (an error if it takes too long), started for the rest.
    fn ready(&self, cx: &Ctx, q: &Query) -> Result<(), String> {
        let Some(base) = self.base(q).filter(|_| !self.sels.is_empty() || self.annotate || self.hide_ignored || self.boost) else { return Ok(()) };
        if self.sels.is_empty() {
            cx.git.load(&[base, b"/."].concat());
            return Ok(());
        }
        // A `git:` filter is about the repo holding the folder and those below it.
        let deadline = Instant::now() + GIT_WAIT;
        for r in repos_at(cx, Some(base)) {
            if r.snap(deadline.saturating_duration_since(Instant::now())).is_none() {
                return Err(format!("still reading the git status of {}: try again in a few seconds", String::from_utf8_lossy(&r.root)));
            }
        }
        Ok(())
    }

    fn keep(&self, git: &Git, path: &[u8]) -> bool {
        if !self.globs.iter().all(|(re, neg)| re.is_match(path) != *neg) {
            return false;
        }
        if self.sels.is_empty() && !self.hide_ignored {
            return true;
        }
        let s = git.status(path);
        self.sels.iter().all(|&(sel, neg)| sel.test(s) != neg) && !(self.hide_ignored && s.is_some_and(|s| s & git::IGNORED != 0))
    }

    /// Cut `v` (every result so far, best first) to the page at the
    /// offset; where the next page starts, if one does.
    fn cut<T>(&self, v: &mut Vec<T>, limit: usize) -> Option<usize> {
        let want = self.offset.saturating_add(limit);
        let more = v.len() > want;
        v.truncate(want);
        v.drain(..self.offset.min(v.len()));
        more.then_some(self.offset + v.len())
    }
}

/// The hits of a query with a positive `git:` filter for listed statuses:
/// the files that status lists in the repos at or under the scope (else
/// `cwd`; else every repo searched so far), as the rest of the query
/// matches them, best first. A folder git lists whole (untracked, ignored)
/// is searched within the scope, at most MAX_DIRS of them, and at most
/// `want` hits from each.
fn from_git(cx: &Ctx, q: &Query, x: &Extras, want: usize) -> Vec<Found> {
    let deadline = Instant::now() + GIT_WAIT;
    let pass = |bits: u8| x.sels.iter().filter(|(s, neg)| !neg && s.listed()).all(|(s, _)| s.test(Some(bits)));
    let (mut out, mut dirs) = (Vec::new(), Vec::new());
    for r in repos_at(cx, x.base(q)) {
        let Some(snap) = r.snap(deadline.saturating_duration_since(Instant::now())) else { continue };
        for (rel, _) in snap.files.iter().chain(&snap.dirs).filter(|(_, b)| pass(**b)) {
            let path = [&r.root[..], b"/", rel].concat();
            if let Some(f) = found(q, &path) {
                out.push(f);
            }
            if snap.dirs.contains_key(rel) {
                dirs.push(path);
            }
        }
    }
    dirs.sort();
    // Within the scope: the folder, or the scope itself if it's inside one.
    let inside = dirs.into_iter().filter_map(|d| match &q.scope {
        Some(s) if !within(&d, s) => within(s, &d).then(|| s.clone()),
        _ => Some(d),
    });
    for d in inside.take(MAX_DIRS) {
        let mut sub = q.clone();
        (sub.scope, sub.limit) = (Some(d), want);
        out.extend(cx.engine.search(&sub).unwrap_or_default());
    }
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));
    out.dedup_by(|a, b| a.path == b.path);
    out
}

/// The repos a `git:` filter is about: the one holding `base` and those
/// below it (by their `.git` in the index, at most MAX_REPOS), their status
/// read if it isn't yet; without `base`, every repo searched so far.
fn repos_at(cx: &Ctx, base: Option<&[u8]>) -> Vec<Arc<git::Repo>> {
    let Some(base) = base else { return cx.git.known_under(b"/") };
    let mut repos: Vec<Arc<git::Repo>> = cx.git.load(&[base, b"/."].concat()).into_iter().collect();
    let mut dq = Query::parse("", cx.engine.home()).unwrap_or_default();
    (dq.name_re, dq.scope, dq.limit) = (Regex::new(r"^\.git$").ok(), Some(base.to_vec()), MAX_REPOS);
    for f in cx.engine.search(&dq).unwrap_or_default() {
        if let Some(r) = cx.git.load(f.path.as_os_str().as_bytes())
            && !repos.iter().any(|o| Arc::ptr_eq(o, &r))
        {
            repos.push(r);
        }
    }
    repos
}

/// Is `path` `dir` or inside it (by whole folder names: /p/abc isn't in /p/a)?
fn within(path: &[u8], dir: &[u8]) -> bool {
    path.starts_with(dir) && (path.len() == dir.len() || dir.ends_with(b"/") || path[dir.len()] == b'/')
}

/// A path as a hit, if it exists and the query matches it.
fn found(q: &Query, path: &[u8]) -> Option<Found> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(std::ffi::OsStr::from_bytes(path)).ok()?;
    let t = m.file_type();
    let kind = if t.is_dir() {
        KIND_DIR
    } else if t.is_symlink() {
        KIND_LINK
    } else if t.is_file() {
        KIND_FILE
    } else {
        KIND_OTHER
    };
    let (size, mtime) = (m.size(), m.mtime().clamp(0, u32::MAX as i64) as u32);
    let score = q.match_path(path, kind, size, mtime)?;
    Some(Found { path: PathBuf::from(std::ffi::OsStr::from_bytes(path)), kind, size, mtime, score })
}

/// The top folder of the repo holding `dir`, if any.
fn git_root(dir: &[u8]) -> Option<Vec<u8>> {
    let mut d = dir;
    loop {
        if std::fs::symlink_metadata(std::ffi::OsStr::from_bytes(&[d, b"/.git"].concat())).is_ok() {
            return Some(d.to_vec());
        }
        d = &d[..d.iter().rposition(|&b| b == b'/').filter(|&i| i > 0)?];
    }
}

/// A path as the index has it: `~` expanded, symlinks resolved.
fn real(p: &str) -> Vec<u8> {
    let p = match p.strip_prefix('~') {
        Some(rest) => format!("{}{rest}", std::env::var("HOME").unwrap_or_default()),
        None => p.to_string(),
    };
    std::fs::canonicalize(&p).map_or_else(|_| p.into_bytes(), |c| c.as_os_str().as_bytes().to_vec())
}

/// The most hits a search looks through for a page that passes its globs.
const MAX_FETCH: usize = 20_000;
/// The most files a grep looks through for a page that passes its globs.
const MAX_GREP: usize = 2_000;

/// Results passing `keep`, best first, more than `want` of them unless
/// the search runs dry, stops early (out of time: then true) or reaches
/// `cap`. `search(n)` gives the best `n` (and whether it stopped early);
/// it's asked for more and more until enough pass.
fn fetch_kept<T>(
    x: &Extras,
    want: usize,
    cap: usize,
    keep: impl Fn(&T) -> bool,
    mut search: impl FnMut(usize) -> Result<(Vec<T>, bool), String>,
) -> Result<(Vec<T>, bool), String> {
    // Room for some to fail the filters (not for ignored files: few name
    // or content hits are); more if too many do.
    let mut fetch = if x.globs.is_empty() && x.sels.is_empty() { want.saturating_add(1) } else { want.saturating_mul(2).saturating_add(16) };
    loop {
        let n = fetch.min(cap);
        let (mut got, cut) = search(n)?;
        let full = got.len() == n;
        got.retain(&keep);
        if got.len() > want || !full || n == cap || cut {
            return Ok((got, cut));
        }
        fetch = fetch.saturating_mul(8);
    }
}

/// The files under `dir` (None: anywhere) you worked on lately, most
/// first, with their frecency: opens, and your commits in the repo holding
/// `dir`. (Recent mtimes count for hits, but listing them takes a scan.)
fn frecent(cx: &Ctx, dir: Option<&[u8]>, now: u32) -> Vec<(Vec<u8>, f32)> {
    let mut m: std::collections::HashMap<Vec<u8>, f32> = std::collections::HashMap::new();
    let commits = dir.map(|d| cx.git.history_under(d, now)).unwrap_or_default();
    for (p, s) in cx.frecency.under(dir.unwrap_or(b"/"), now).into_iter().chain(commits) {
        *m.entry(p).or_default() += s;
    }
    let mut v: Vec<(Vec<u8>, f32)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

/// Reorder the best RERANK of `hits` (all kept so far, best first) by
/// score plus frecency (`boost`: opens, your commits, and the file's mtime
/// as one more open, see `frecency::boost`) and nearness to the `near` file
/// (`nearness`). What it can't do: lift a file the query ranks below them
/// (the ranking in `query.rs` knows nothing of either).
fn rerank(cx: &Ctx, hits: &mut [Found], boost: bool, near: Option<&[u8]>) {
    let now = fsearch::query::now_secs();
    let n = hits.len().min(RERANK);
    for f in &mut hits[..n] {
        let p = f.path.as_os_str().as_bytes();
        if boost {
            f.score += frecency::boost(cx.frecency.score(p, now) + cx.git.history(p, now) + frecency::decay(now.saturating_sub(f.mtime)));
        }
        if let Some(near) = near {
            f.score += nearness(near, p);
        }
    }
    // Stable: equals keep their order.
    hits[..n].sort_by_key(|f| std::cmp::Reverse(f.score));
}

/// How near `path` is to `near` (the file you're in): +12 in its folder,
/// 3 less per folder between them; the file itself -20 (it isn't what you
/// are looking for). Replaying Linux history (`near`: another file of the
/// commit), the file searched for ranks first for its name 84% -> 89%
/// on top of frecency, and an unrelated `near` costs nothing measurable.
fn nearness(near: &[u8], path: &[u8]) -> i32 {
    if path == near {
        return -20;
    }
    fn dirs(p: &[u8]) -> std::slice::Split<'_, u8, impl FnMut(&u8) -> bool> {
        p[..p.iter().rposition(|&b| b == b'/').unwrap_or(0)].split(|&b| b == b'/')
    }
    let common = dirs(near).zip(dirs(path)).take_while(|(x, y)| x == y).count();
    (12 - 3 * (dirs(near).count() + dirs(path).count() - 2 * common) as i32).max(0)
}

/// A glob as a case-insensitive regex over whole paths, relative to `base`
/// (empty: `/`). With a `/` in it, it is anchored there (`src/**/*.rs`;
/// `/etc/*.conf`); without one, it matches a name at any depth below
/// (`*.rs`); a trailing `/` matches a folder at any depth below and all
/// that's in it (`tests/`). `**` spans folders, `*` and `?` stay within one,
/// `[...]` and `{a,b}` as in a shell.
fn glob_regex(glob: &str, base: &[u8]) -> Result<Regex, String> {
    let g = glob.strip_prefix("./").unwrap_or(glob);
    let (body, dir) = g.strip_suffix('/').map_or((g, false), |b| (b, true));
    let mut re = String::from("(?is)^");
    match body.strip_prefix('/') {
        Some(abs) => {
            re.push('/');
            translate(abs, &mut re)?;
        }
        None => {
            re += &regex::escape(&String::from_utf8_lossy(base));
            re.push('/');
            if dir || !body.contains('/') {
                re += "(?:.*/)?";
            }
            translate(body, &mut re)?;
        }
    }
    re += if dir { "(?:/|$)" } else { "$" };
    Regex::new(&re).map_err(|e| format!("bad glob {glob}: {e}"))
}

fn translate(g: &str, re: &mut String) -> Result<(), String> {
    let mut cs = g.chars().peekable();
    let mut braces = 0;
    while let Some(c) = cs.next() {
        match c {
            '*' if cs.peek() == Some(&'*') => {
                cs.next();
                if cs.peek() == Some(&'/') {
                    cs.next();
                    *re += "(?:.*/)?";
                } else {
                    *re += ".*";
                }
            }
            '*' => *re += "[^/]*",
            '?' => *re += "[^/]",
            '[' => {
                re.push('[');
                if cs.peek().is_some_and(|&c| c == '!' || c == '^') {
                    cs.next();
                    re.push('^');
                }
                let mut first = true;
                loop {
                    match cs.next() {
                        None => return Err(format!("unclosed [ in glob {g}")),
                        Some(']') if !first => break,
                        Some(c @ ('[' | ']' | '\\' | '&' | '~' | '-')) if c != '-' || first => {
                            re.push('\\');
                            re.push(c);
                        }
                        Some(c) => re.push(c),
                    }
                    first = false;
                }
                re.push(']');
            }
            '{' => {
                braces += 1;
                *re += "(?:";
            }
            '}' if braces > 0 => {
                braces -= 1;
                re.push(')');
            }
            ',' if braces > 0 => re.push('|'),
            '\\' => *re += &regex::escape(&cs.next().map_or(String::new(), String::from)),
            c => *re += &regex::escape(c.encode_utf8(&mut [0; 4])),
        }
    }
    if braces > 0 { Err(format!("unclosed {{ in glob {g}")) } else { Ok(()) }
}

/// The folder an anchored glob's leading literal part names, as a real path
/// (`src/ui/**/*.rs` in /p: /p/src/ui): nothing it matches is outside it.
fn glob_dir(g: &str, base: &[u8]) -> Option<Vec<u8>> {
    let g = g.strip_prefix("./").unwrap_or(g);
    if g.ends_with('/') || !g.contains('/') {
        return None;
    }
    let (abs, body) = g.strip_prefix('/').map_or((false, g), |b| (true, b));
    let parts: Vec<&str> = body.split('/').collect();
    let lit: Vec<&str> = parts[..parts.len() - 1].iter().take_while(|p| !p.contains(['*', '?', '[', '{', '\\'])).copied().collect();
    let mut dir = if abs { Vec::new() } else { base.to_vec() };
    for p in lit {
        dir.push(b'/');
        dir.extend_from_slice(p.as_bytes());
    }
    if dir.is_empty() {
        return None;
    }
    let real = std::fs::canonicalize(std::ffi::OsStr::from_bytes(&dir)).map_or(dir, |p| p.as_os_str().as_bytes().to_vec());
    Some(real)
}

/// The extensions a glob's name part allows, if it names them all (`*.rs`,
/// `*.{ts,tsx}`): they narrow the search before any path is built.
fn glob_exts(g: &str) -> Vec<Vec<u8>> {
    let name = g.rsplit('/').next().unwrap_or(g);
    let Some(rest) = name.strip_prefix("*.") else { return Vec::new() };
    let list = rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')).unwrap_or(rest);
    let exts: Vec<Vec<u8>> = list.split(',').map(|e| e.to_ascii_lowercase().into_bytes()).collect();
    let plain = exts.iter().all(|e| !e.is_empty() && e.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    if plain { exts } else { Vec::new() }
}

/// Content search. The pattern comes from `pattern` (+ `mode`), `patterns`
/// (any of these literals) or from a `grep:`/`regex:`/`sym:` filter in `q`;
/// the rest of the query narrows which files are read, or `file` names the
/// one to read. Also: `case`, `context` / `before` / `after` (lines around
/// matches), `defs` (mark definitions),
/// `cursor` (the `next` of the page before; with `offset`, globs or `git:`
/// the `next` is an offset instead).
fn grep(v: &Value, cx: &Ctx) -> Result<Value, String> {
    let engine = &cx.engine;
    let (mut q, sels) = parse_request(v, engine.home())?;
    let x = Extras::parse(v, &mut q, sels, false, true)?;
    let mode = match v.get("mode").and_then(Value::as_str) {
        Some("regex") => GrepMode::Regex,
        Some("symbol") => GrepMode::Symbol,
        Some("literal") => GrepMode::Literal,
        Some(m) => return Err(format!("unknown mode {m}")),
        None => q.grep_mode,
    };
    let case = match v.get("case").and_then(Value::as_str) {
        None | Some("smart") => fsearch::Case::Smart,
        Some("sensitive") => fsearch::Case::Sensitive,
        Some("insensitive") => fsearch::Case::Insensitive,
        Some(c) => return Err(format!("unknown case {c}")),
    };
    let pattern = v.get("pattern").and_then(Value::as_str).map(str::to_string).or(q.grep.take());
    let mut g = match (v.get("patterns").and_then(Value::as_array), pattern) {
        (Some(ps), _) => fsearch::Grep::any_of(&ps.iter().filter_map(Value::as_str).collect::<Vec<_>>(), case)?,
        (None, Some(p)) => fsearch::Grep::with_case(&p, mode, case)?,
        (None, None) => return Err("grep needs a pattern".into()),
    };
    let file = v.get("file").and_then(Value::as_str).map(|f| match f.strip_prefix('~') {
        Some(r) => format!("{}{r}", engine.home()),
        None if !f.starts_with('/') => format!("{}/{f}", engine.home()),
        None => f.to_string(),
    });
    let num = |k: &str| v.get(k).and_then(Value::as_u64).map(|n| n as usize);
    // One file: its matching lines, up to 200 unless told.
    g.max_per_file = num("per_file").unwrap_or(if file.is_some() { 200 } else { g.max_per_file });
    if let Some(ms) = v.get("budget_ms").and_then(Value::as_u64) {
        g.budget = (ms > 0).then(|| Duration::from_millis(ms));
    }
    (g.before, g.after) = (num("before").or(num("context")).unwrap_or(0), num("after").or(num("context")).unwrap_or(0));
    g.defs = v.get("defs").and_then(Value::as_bool).unwrap_or(false);
    g.skip = num("cursor").unwrap_or(0);
    let t = Instant::now();
    let source = |indexed| if indexed { "index" } else { "scan" };
    let (r, source, next) = if let Some(f) = &file {
        let r = fsearch::content::grep_file(&g, f.as_bytes());
        let next = r.next;
        (r, "file", next)
    } else if x.plain() {
        let (r, indexed) = engine.grep(&q, &g)?;
        let next = r.next;
        (r, source(indexed), next)
    } else if x.listed() {
        // Only the files git lists (modified...), newest first: read them.
        x.ready(cx, &q)?;
        let mut paths = from_git(cx, &q.clone_for_scan(), &x, MAX_GREP);
        paths.retain(|f| f.kind & 3 == KIND_FILE && f.size <= fsearch::content::MAX_FILE && x.keep(&cx.git, f.path.as_os_str().as_bytes()));
        paths.sort_by_key(|f| std::cmp::Reverse(f.mtime));
        let paths: Vec<Vec<u8>> = paths.into_iter().map(|f| f.path.as_os_str().as_bytes().to_vec()).collect();
        let mut r = fsearch::content::verify(&g, &paths, x.offset.saturating_add(q.limit).saturating_add(1));
        let next = x.cut(&mut r.files, q.limit).or((!r.complete).then_some(x.offset + r.files.len()));
        (r, "scan", next)
    } else {
        x.ready(cx, &q)?;
        let limit = q.limit;
        let mut last = None;
        let (mut files, cut) = fetch_kept(
            &x,
            x.offset.saturating_add(limit),
            MAX_GREP,
            |f: &fsearch::FileMatches| x.keep(&cx.git, &f.path),
            |n| {
                q.limit = n;
                let (mut r, indexed) = engine.grep(&q, &g)?;
                let (files, cut) = (std::mem::take(&mut r.files), !r.complete);
                last = Some((r, indexed));
                Ok((files, cut))
            },
        )?;
        let next = x.cut(&mut files, limit).or(cut.then_some(x.offset + files.len()));
        let (mut r, indexed) = last.expect("page searched");
        r.files = files;
        (r, source(indexed), next)
    };
    let files: Vec<Value> = r
        .files
        .iter()
        .map(|f| {
            let matches = f.lines.iter().zip(&f.hits).map(|((n, t), h)| {
                let mut m = json!({"line": n, "text": t, "col": h.col, "ranges": h.ranges});
                if h.def {
                    m["def"] = true.into();
                }
                if g.before > 0 {
                    m["before"] = json!(h.before);
                }
                if g.after > 0 {
                    m["after"] = json!(h.after);
                }
                m
            });
            let mut j = json!({"path": String::from_utf8_lossy(&f.path), "matches": matches.collect::<Vec<_>>()});
            if let Some(w) = x.annotate.then(|| cx.git.status(&f.path).and_then(git::word)).flatten() {
                j["git"] = w.into();
            }
            j
        })
        .collect();
    let mut out = json!({
        "ok": true,
        "took_us": t.elapsed().as_micros() as u64,
        "source": source,
        "candidates": r.candidates,
        "read": r.read,
        "complete": r.complete,
        "indexing": engine.status().content_pending,
        "files": files,
    });
    if let Some(n) = next {
        out["next"] = n.into();
    }
    Ok(out)
}

/// `q` is the query language; any filter key may also be given as its own
/// JSON field (`{"q": "main", "ext": "rs", "in": "~/Developer"}`). Its
/// `git:` filters come back apart (see `Extras`).
fn parse_request(v: &Value, home: &str) -> Result<(Query, Vec<(git::Sel, bool)>), String> {
    let (rest, sels) = take_git(v.get("q").and_then(Value::as_str).unwrap_or(""))?;
    let mut q = Query::parse(&rest, home)?;
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if EXTRAS.contains(&k.as_str()) {
                continue;
            }
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
    Ok((q, sels))
}

/// A query's `git:` words (`git:modified`, `!git:ignored`), and the rest.
#[allow(clippy::type_complexity)]
fn take_git(q: &str) -> Result<(std::borrow::Cow<'_, str>, Vec<(git::Sel, bool)>), String> {
    if !q.contains("git:") {
        return Ok((q.into(), Vec::new()));
    }
    let (mut rest, mut sels) = (Vec::new(), Vec::new());
    for w in q.split(' ') {
        let (neg, b) = w.strip_prefix('!').map_or((false, w), |b| (true, b));
        match b.strip_prefix("git:") {
            Some(v) => {
                let sel =
                    git::Sel::parse(v).ok_or(format!("unknown git status {v}: modified, untracked, staged, clean, ignored, tracked or conflict"))?;
                sels.push((sel, neg));
            }
            None => rest.push(w),
        }
    }
    Ok((rest.join(" ").into(), sels))
}

fn kind_name(k: u8) -> &'static str {
    match k & 3 {
        KIND_FILE => "file",
        KIND_DIR => "dir",
        KIND_LINK => "link",
        _ => "other",
    }
}

/// Connect to the daemon, starting it if it isn't running.
pub fn connect(dir: &Path) -> std::io::Result<UnixStream> {
    let sock = socket_path(dir);
    match UnixStream::connect(&sock) {
        Ok(s) => return Ok(s),
        // Too long for a socket (a long HOME): no daemon could listen there.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => return Err(std::io::Error::new(e.kind(), format!("{}: {e}", sock.display()))),
        Err(_) => {}
    }
    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("daemon.log"))?;
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    // Own session: closing the terminal that started it doesn't kill it.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    // Set here too, so the daemon a search starts needn't restart itself
    // in it (main.rs `space_efficient`): 4 ms off that first answer.
    cmd.env("MallocSpaceEfficient", "1");
    cmd.arg("serve").stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log).spawn()?;
    for _ in 0..1500 {
        std::thread::sleep(Duration::from_millis(2));
        if let Ok(s) = UnixStream::connect(&sock) {
            return Ok(s);
        }
    }
    UnixStream::connect(&sock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Child, Command, Stdio};

    /// A folder for one test's lock file, next to the test binary (in the
    /// target dir, never the real data dir).
    fn test_dir(name: &str) -> PathBuf {
        let exe = std::env::current_exe().unwrap();
        let d = exe.parent().unwrap().join(format!("server-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// What `fake` runs: idle until signalled.
    #[test]
    #[ignore]
    fn idle() {
        if std::env::var_os("FSEARCH_TEST_IDLE").is_some() {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    /// This test binary (named fsearch-…), idling; as `<exe> serve …` when
    /// `serve`, like a daemon. It shares `lock` (and its flock) if given.
    fn fake(serve: bool, lock: Option<&std::fs::File>) -> Child {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        if serve {
            // An extra test filter that matches nothing.
            cmd.arg("serve");
        }
        cmd.args(["--exact", "server::tests::idle", "--ignored"]).env("FSEARCH_TEST_IDLE", "1").stdout(Stdio::null()).stderr(Stdio::null());
        if let Some(fd) = lock.map(AsRawFd::as_raw_fd) {
            unsafe {
                cmd.pre_exec(move || if libc::fcntl(fd, libc::F_SETFD, 0) == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) });
            }
        }
        cmd.spawn().unwrap()
    }

    /// socket.lock in `dir`, locked as a daemon's.
    fn locked(dir: &Path) -> std::fs::File {
        let f = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(dir.join("socket.lock")).unwrap();
        assert!(try_lock(&f));
        f
    }

    #[test]
    fn only_fsearch_serve_is_a_daemon() {
        // Our own argv, read back; we're no daemon (unless run as `… serve`).
        let ours: Vec<Vec<u8>> = std::env::args_os().map(|a| a.as_bytes().to_vec()).collect();
        let me = std::process::id() as i32;
        assert_eq!(args(me), ours);
        assert_eq!(is_daemon(me), ours.get(1).is_some_and(|a| a == b"serve"));

        let (mut d, mut client) = (fake(true, None), fake(false, None));
        // Not fsearch, though `serve` is its first argument.
        let dir = test_dir("is-daemon");
        std::fs::write(dir.join("serve"), "sleep 60\nexit 0\n").unwrap();
        let mut sh = Command::new("/bin/sh").arg("serve").current_dir(&dir).spawn().unwrap();
        let got = (is_daemon(d.id() as i32), is_daemon(client.id() as i32), is_daemon(sh.id() as i32));
        for c in [&mut d, &mut client, &mut sh] {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, (true, false, false));
    }

    /// The daemon stop signalled exits, and a client starts a new one that
    /// takes the lock (mid-install): stop signals that one too.
    #[test]
    fn stop_signals_a_daemon_started_after_the_first() {
        let dir = test_dir("restarted");
        let lock = locked(&dir);
        // Both share the locked file: it stays locked until both are gone.
        let (mut a, mut b) = (fake(true, Some(&lock)), fake(true, Some(&lock)));
        drop(lock);
        std::fs::write(dir.join("socket.lock"), a.id().to_string()).unwrap();
        let d = dir.clone();
        let stopping = std::thread::spawn(move || stop_within(&d, Duration::from_secs(20)));
        assert_eq!(a.wait().unwrap().signal(), Some(libc::SIGTERM));
        std::fs::write(dir.join("socket.lock"), b.id().to_string()).unwrap();
        let r = stopping.join().unwrap();
        let _ = b.kill();
        assert_eq!(b.wait().unwrap().signal(), Some(libc::SIGTERM));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(r, Ok(()));
    }

    /// A recorded pid that isn't a daemon's (a crashed daemon's, reused by
    /// a client) is never signalled.
    #[test]
    fn stop_never_signals_a_non_daemon() {
        let dir = test_dir("non-daemon");
        let lock = locked(&dir);
        let mut client = fake(false, Some(&lock));
        drop(lock);
        std::fs::write(dir.join("socket.lock"), client.id().to_string()).unwrap();
        let r = stop_within(&dir, Duration::from_millis(300));
        let alive = client.try_wait().unwrap().is_none();
        let _ = client.kill();
        let _ = client.wait();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(r.is_err_and(|e| e.contains("not an fsearch daemon")));
        assert!(alive, "signalled a process that isn't a daemon");
    }

    /// A stray daemon holds the lock: a plain daemon gives way, but the
    /// login agent's stops it and takes over.
    #[test]
    fn the_agents_daemon_takes_over_from_a_stray() {
        let dir = test_dir("agent");
        let lock = locked(&dir);
        let mut stray = fake(true, Some(&lock));
        drop(lock);
        std::fs::write(dir.join("socket.lock"), stray.id().to_string()).unwrap();
        assert!(take_socket_lock(&dir, false).is_none());
        assert!(stray.try_wait().unwrap().is_none(), "a plain daemon leaves it running");
        let got = take_socket_lock(&dir, true);
        let _ = stray.kill();
        let status = stray.wait().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(got.is_some(), "the agent's daemon takes the lock");
        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }

    #[test]
    fn near() {
        let n = |a: &str, b: &str| nearness(a.as_bytes(), b.as_bytes());
        assert_eq!((n("/p/src/a.rs", "/p/src/b.rs"), n("/p/src/a.rs", "/p/src/a.rs")), (12, -20));
        assert_eq!((n("/p/src/a.rs", "/p/src/ui/c.rs"), n("/p/src/a.rs", "/p/docs/x.md"), n("/p/a/b/c/d.rs", "/q/e.rs")), (9, 6, 0));
    }
}
