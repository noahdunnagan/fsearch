//! The daemon: one `Engine`, answering JSON lines over a unix socket.
//! `fsearch stdio` and the CLI are thin clients.

use fsearch::walk::{KIND_DIR, KIND_FILE, KIND_LINK};
use fsearch::{Engine, GrepMode, Options, Query, try_lock};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("fsearch.sock")
}

/// sockaddr_un holds 104 bytes, NUL included: a longer path (a long HOME)
/// can't be bound or connected to at all.
pub fn check_socket(dir: &Path) -> Result<(), String> {
    let sock = socket_path(dir);
    let n = sock.as_os_str().len();
    if n > 103 { Err(format!("socket path too long ({n} bytes, at most 103): {}", sock.display())) } else { Ok(()) }
}

pub fn serve(dir: PathBuf, home: String) {
    // One daemon per socket. (The engine's own lock decides who writes the
    // index: an app embedding fsearch may own it while the daemon follows.)
    std::fs::create_dir_all(&dir).ok();
    // Opened without truncating: a loser must not wipe the owner's pid.
    let Ok(mut lock) = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(dir.join("socket.lock")) else { return };
    if !try_lock(&lock) {
        eprintln!("{} another fsearch daemon is running", fsearch::query::now_secs());
        return;
    }
    // The pid lets `stop` find us.
    let _ = lock.set_len(0).and_then(|_| write!(lock, "{}", std::process::id()));
    let engine = match Engine::start(Options { dir: dir.clone(), home, skip: None }) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{} {e}", fsearch::query::now_secs());
            return;
        }
    };
    let sock = socket_path(&dir);
    let _ = std::fs::remove_file(&sock);
    let listener = match UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{} bind {}: {e}", fsearch::query::now_secs(), sock.display());
            return;
        }
    };
    for conn in listener.incoming().flatten() {
        let e = engine.clone();
        std::thread::spawn(move || handle(conn, &e));
    }
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
    for tick in 0..timeout.as_millis().div_ceil(100) {
        if try_lock(&lock) {
            return Ok(());
        }
        // Read every time: a new holder writes its pid only after taking the
        // lock, so until then the file may name a crashed daemon's pid, now
        // ours or a stranger's. Only a daemon (`fsearch serve`) is signalled.
        let pid = std::fs::read_to_string(&path).ok().and_then(|s| s.trim().parse::<i32>().ok()).filter(|&p| p > 1);
        named = pid.or(named);
        if let Some(p) = pid.filter(|&p| p != me && killed != Some(p) && is_fsearch(p) && is_daemon(p)) {
            unsafe { libc::kill(p, libc::SIGTERM) };
            killed = Some(p);
        }
        // No pid at all: a daemon from before they were recorded (the first
        // upgrade). Find it among the processes with the file open (another
        // install may have it open too); look again every second or so.
        if pid.is_none()
            && killed.is_none()
            && tick % 10 == 0
            && let Some(p) = holders(&path).into_iter().find(|&p| p != me && is_fsearch(p) && is_daemon(p))
        {
            unsafe { libc::kill(p, libc::SIGTERM) };
            killed = Some(p);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(match (killed, named) {
        (Some(pid), _) => format!("daemon {pid} did not exit"),
        (None, Some(p)) if p == me => {
            format!("socket.lock holds a stale pid ({me}, this process); the daemon holding the lock never recorded its own: stop it by hand")
        }
        (None, Some(p)) => {
            format!("socket.lock holds a stale pid ({p}, not an fsearch daemon); the daemon holding the lock never recorded its own: stop it by hand")
        }
        (None, None) => "a daemon is running but did not record its pid; stop it by hand".into(),
    })
}

/// Processes that have `path` open (lsof).
fn holders(path: &Path) -> Vec<i32> {
    let out = std::process::Command::new("/usr/sbin/lsof").arg("-t").arg("--").arg(path).stderr(std::process::Stdio::null()).output();
    out.map(|o| String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| l.trim().parse().ok()).collect()).unwrap_or_default()
}

/// Whether `pid` is a daemon: `fsearch serve` (`serve` on its command line).
fn is_daemon(pid: i32) -> bool {
    let out = std::process::Command::new("/bin/ps").args(["-o", "args=", "-p", &pid.to_string()]).output();
    out.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).split_whitespace().any(|a| a == "serve"))
}

/// Whether `pid` runs an fsearch binary (the daemon, or its test harness).
fn is_fsearch(pid: i32) -> bool {
    let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
    n > 0 && Path::new(std::ffi::OsStr::from_bytes(&buf[..n as usize])).file_name().is_some_and(|f| f.as_bytes().starts_with(b"fsearch"))
}

fn handle(conn: UnixStream, engine: &Engine) {
    let Ok(r) = conn.try_clone() else { return };
    let mut w = std::io::BufWriter::new(conn);
    for line in BufReader::new(r).lines() {
        let Ok(line) = line else { return };
        if line.trim().is_empty() {
            continue;
        }
        let resp = respond(&line, engine);
        if writeln!(w, "{resp}").and_then(|_| w.flush()).is_err() {
            return;
        }
    }
}

fn respond(line: &str, engine: &Engine) -> Value {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return json!({"ok": false, "error": format!("bad json: {e}")}),
    };
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let mut out = match run(&v, engine) {
        Ok(r) => r,
        Err(e) => json!({"ok": false, "error": e}),
    };
    out["id"] = id;
    out
}

fn run(v: &Value, engine: &Engine) -> Result<Value, String> {
    let op = v.get("op").and_then(Value::as_str).unwrap_or("search");
    match op {
        "ping" => Ok(json!({"ok": true})),
        "save" => {
            engine.save();
            Ok(json!({"ok": true, "scheduled": true}))
        }
        "status" => {
            let s = engine.status();
            if !s.ready {
                return Err("indexing (first run scans the whole disk, ~20s)".into());
            }
            let mut v = serde_json::to_value(s).map_err(|e| e.to_string())?;
            v["ok"] = true.into();
            Ok(v)
        }
        "search" | "grep" => {
            let q = parse_request(v, engine.home())?;
            // Content search when asked for, or when the query names a
            // pattern (`grep:` in `q`, or a `"grep"` field).
            if op == "grep" || q.grep.is_some() {
                return grep(v, q, engine);
            }
            let t = Instant::now();
            let found = engine.search(&q)?;
            let took = t.elapsed().as_micros() as u64;
            let hits: Vec<Value> = found
                .iter()
                .map(|f| {
                    json!({
                        "path": f.path.to_string_lossy(),
                        "kind": kind_name(f.kind),
                        "size": f.size,
                        "mtime": f.mtime,
                        "score": f.score,
                    })
                })
                .collect();
            Ok(json!({"ok": true, "took_us": took, "hits": hits}))
        }
        _ => Err(format!("unknown op {op}")),
    }
}

/// Content search. The pattern comes from `pattern` (+ `mode`) or from a
/// `grep:`/`regex:`/`sym:` filter in `q`; the rest of the query narrows
/// which files are read.
fn grep(v: &Value, mut q: Query, engine: &Engine) -> Result<Value, String> {
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
                "path": String::from_utf8_lossy(&f.path),
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

/// Connect to the daemon, starting it if it isn't running.
pub fn connect(dir: &Path) -> std::io::Result<UnixStream> {
    // Not worth starting a daemon that can never listen.
    check_socket(dir).map_err(std::io::Error::other)?;
    let sock = socket_path(dir);
    if let Ok(s) = UnixStream::connect(&sock) {
        return Ok(s);
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
    cmd.arg("serve").stdin(std::process::Stdio::null()).stdout(log.try_clone()?).stderr(log).spawn()?;
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(30));
        if let Ok(s) = UnixStream::connect(&sock) {
            return Ok(s);
        }
    }
    UnixStream::connect(&sock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// Runs before main, while the process has one thread: `env::set_var`
    /// with other threads running is unsound.
    #[used]
    #[unsafe(link_section = "__DATA,__mod_init_func")]
    static SET_ROOT: extern "C" fn() = {
        extern "C" fn init() {
            // Not in the helper children (lock holder, file opener): they are
            // killed, never exit cleanly.
            if std::env::var_os("FSEARCH_TEST_HOLD").is_none() && std::env::var_os("FSEARCH_TEST_OPEN").is_none() {
                root();
            }
        }
        init
    };

    /// The root is in the environment before any test thread starts.
    #[test]
    fn the_root_is_set_before_any_test_runs() {
        assert!(std::env::var_os("FSEARCH_ROOT").is_some());
    }

    /// Engines here index this temp folder, never `/`.
    fn root() -> &'static Path {
        static ROOT: OnceLock<PathBuf> = OnceLock::new();
        ROOT.get_or_init(|| {
            let r = std::env::temp_dir().join(format!("fss-{}", std::process::id()));
            assert!(r.parent().is_some_and(|p| p != Path::new("/")));
            let _ = std::fs::remove_dir_all(&r);
            std::fs::create_dir_all(&r).unwrap();
            unsafe { std::env::set_var("FSEARCH_ROOT", &r) };
            // Statics are never dropped: remove the folder when the process exits.
            extern "C" fn clean() {
                if let Some(r) = ROOT.get() {
                    let _ = std::fs::remove_dir_all(r);
                }
            }
            unsafe { libc::atexit(clean) };
            std::fs::canonicalize(r).unwrap()
        })
    }

    fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
        let t = Instant::now();
        while !f() {
            assert!(t.elapsed() < Duration::from_secs(20), "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// One engine over a small tree, shared by the request tests.
    fn engine() -> &'static Engine {
        static E: OnceLock<Engine> = OnceLock::new();
        E.get_or_init(|| {
            let r = root();
            let home = r.join("home");
            std::fs::create_dir_all(home.join("proj")).unwrap();
            std::fs::write(home.join("proj/walrus.txt"), "fn walrus() {}\nthe walrus needle\n").unwrap();
            std::fs::create_dir_all(r.join("out")).unwrap();
            std::fs::write(r.join("out/walrus_out.txt"), "outside needle\n").unwrap();
            std::os::unix::fs::symlink("walrus.txt", home.join("proj/walrus_link")).unwrap();
            let fifo = std::ffi::CString::new(home.join("proj/walrus_fifo").as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            let e = Engine::start(Options { dir: r.join("data"), home: home.to_string_lossy().into(), skip: Some(vec![]) }).unwrap();
            wait_for("the index", || e.status().ready);
            wait_for("content indexing", || e.status().content_docs > 0 && e.status().content_pending == 0);
            e
        })
    }

    fn ask(req: Value) -> Value {
        respond(&req.to_string(), engine())
    }

    fn err(req: Value) -> String {
        let v = ask(req);
        assert_eq!(v["ok"], false, "{v}");
        v["error"].as_str().unwrap().to_string()
    }

    #[test]
    fn requests() {
        assert!(respond("{nope", engine())["error"].as_str().unwrap().starts_with("bad json"));
        assert_eq!(ask(json!({"op": "ping", "id": 7})), json!({"ok": true, "id": 7}));
        // The id comes back whatever its type, also on errors.
        assert_eq!(ask(json!({"op": "nope", "id": {"a": [1]}}))["id"], json!({"a": [1]}));
        assert_eq!(err(json!({"op": "nope"})), "unknown op nope");
        assert_eq!(ask(json!({"op": "ping"}))["id"], Value::Null);
        assert_eq!(ask(json!({"op": "save"}))["scheduled"], true);
        let st = ask(json!({"op": "status"}));
        assert!(st["ok"] == true && st["entries"].as_u64().unwrap() > 0 && st["owner"] == true, "{st}");

        // Name search; filters may be JSON fields too.
        let v = ask(json!({"q": "walrus", "id": "a"}));
        assert_eq!(v["id"], "a");
        let kinds: Vec<(&str, &str)> = v["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| (h["path"].as_str().unwrap().rsplit('/').next().unwrap(), h["kind"].as_str().unwrap()))
            .collect();
        for k in [("walrus.txt", "file"), ("walrus_link", "link"), ("walrus_fifo", "other"), ("walrus_out.txt", "file")] {
            assert!(kinds.contains(&k), "{kinds:?}");
        }
        let v = ask(json!({"q": "walrus", "kind": "link", "limit": 5}));
        assert_eq!(v["hits"].as_array().unwrap().len(), 1);
        assert_eq!(ask(json!({"q": "proj", "kind": "dir"}))["hits"][0]["kind"], "dir");
        assert_eq!(ask(json!({"q": "walrus", "limit": 0}))["hits"], json!([]));
        assert_eq!(err(json!({"q": "walrus", "limit": "3"})), "limit must be a number");
        assert_eq!(err(json!({"q": "walrus", "kind": "nope"})), "unknown kind nope");
        assert!(err(json!({"q": "re:("})).contains("regex"));
        // Non-string filter values are used as their JSON text.
        assert_eq!(ask(json!({"q": "walrus", "ext": 7}))["hits"], json!([]));
        // Not an object: an empty search.
        assert_eq!(ask(json!([1, 2]))["ok"], true);
    }

    /// A follower still waiting for its owner's first index.
    #[test]
    fn status_before_ready() {
        let dir = root().join("unready");
        std::fs::create_dir_all(&dir).unwrap();
        let f = std::fs::File::create(dir.join("daemon.lock")).unwrap();
        assert!(try_lock(&f));
        let home = root().join("home").to_string_lossy().into_owned();
        let e = Engine::start(Options { dir, home, skip: Some(vec![]) }).unwrap();
        let v = respond(r#"{"op":"status"}"#, &e);
        assert!(v["error"].as_str().unwrap().starts_with("indexing"), "{v}");
        assert!(respond(r#"{"q":"x"}"#, &e)["error"].as_str().unwrap().starts_with("indexing"));
    }

    #[test]
    fn huge_limit() {
        let v = ask(json!({"q": "walrus", "limit": u64::MAX}));
        assert_eq!(v["ok"], true, "{v}");
    }

    #[test]
    fn grep_requests() {
        let files = |v: &Value| -> Vec<String> {
            assert_eq!(v["ok"], true, "{v}");
            v["files"].as_array().unwrap().iter().map(|f| f["path"].as_str().unwrap().rsplit('/').next().unwrap().to_string()).collect()
        };
        let v = ask(json!({"op": "grep", "pattern": "needle"}));
        assert_eq!((v["source"].as_str(), files(&v)), (Some("index"), vec!["walrus.txt".to_string()]));
        assert_eq!(v["files"][0]["matches"][0], json!({"line": 2, "text": "the walrus needle"}));
        assert_eq!(files(&ask(json!({"op": "grep", "pattern": "need.e", "mode": "regex"}))), ["walrus.txt"]);
        assert_eq!(files(&ask(json!({"op": "grep", "pattern": "walrus", "mode": "symbol"}))), ["walrus.txt"]);
        assert_eq!(files(&ask(json!({"op": "grep", "pattern": "need.e", "mode": "literal"}))), Vec::<String>::new());
        assert_eq!(err(json!({"op": "grep", "pattern": "x", "mode": "fuzzy"})), "unknown mode fuzzy");
        assert_eq!(err(json!({"op": "grep"})), "grep needs a pattern");
        assert!(err(json!({"op": "grep", "pattern": "(", "mode": "regex"})).contains("regex"));
        // From the query language, in a search.
        assert_eq!(files(&ask(json!({"q": "grep:needle"}))), ["walrus.txt"]);
        assert_eq!(files(&ask(json!({"q": "regex:ne+dle", "per_file": 1, "budget_ms": 0}))), ["walrus.txt"]);
        // Outside home: a scan of the files the name index picks.
        let out = root().join("out");
        let v = ask(json!({"op": "grep", "pattern": "needle", "in": out.to_str().unwrap(), "budget_ms": 5000}));
        assert_eq!((v["source"].as_str(), files(&v)), (Some("scan"), vec!["walrus_out.txt".to_string()]));
    }

    /// Every filter key may be a JSON field, `grep` included: a search
    /// that names a pattern is a content search.
    #[test]
    fn grep_as_a_json_field() {
        let v = ask(json!({"q": "walrus", "grep": "needle"}));
        assert_eq!(v["source"], "index", "{v}");
        assert_eq!(v["files"][0]["matches"][0]["line"], 2);
    }

    /// A filter keyword inside another value is not a content search: the
    /// parsed query decides, not a substring of `q`.
    #[test]
    fn keyword_inside_a_value_is_a_name_search() {
        let v = ask(json!({"q": "walrus path:a/regex:b"}));
        assert!(v["hits"].is_array(), "{v}");
        let v = ask(json!({"q": "walrus re:content:"}));
        assert!(v["hits"].is_array(), "{v}");
    }

    #[test]
    fn serves_a_socket() {
        let dir = root().join("srv");
        let home = root().join("home").to_string_lossy().into_owned();
        {
            let (dir, home) = (dir.clone(), home.clone());
            std::thread::spawn(move || serve(dir, home));
        }
        wait_for("the socket", || UnixStream::connect(socket_path(&dir)).is_ok());
        assert_eq!(std::fs::read_to_string(dir.join("socket.lock")).unwrap(), std::process::id().to_string());
        // A second daemon on the same dir gives way, leaving the pid alone.
        serve(dir.clone(), home);
        assert_eq!(std::fs::read_to_string(dir.join("socket.lock")).unwrap(), std::process::id().to_string());

        let s = connect(&dir).unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        write!(w, "\n  \n{}\n{}\n", json!({"op": "ping", "id": 1}), json!({"op": "status", "id": 2})).unwrap();
        r.read_line(&mut line).unwrap();
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap(), json!({"ok": true, "id": 1}));
        line.clear();
        r.read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], 2);
        // Not ready yet, or ready: either way an answer, not a hang.
        assert!(v["ok"] == true || v["error"].as_str().unwrap().starts_with("indexing"), "{v}");
        // Closing the write side ends the connection.
        w.shutdown(std::net::Shutdown::Write).unwrap();
        line.clear();
        assert_eq!(r.read_line(&mut line).unwrap(), 0);
        // Bad UTF-8 drops the connection.
        let mut s = UnixStream::connect(socket_path(&dir)).unwrap();
        s.write_all(b"\xff\xfe\n").unwrap();
        line.clear();
        assert_eq!(BufReader::new(s).read_line(&mut line).unwrap(), 0);
    }

    #[test]
    fn serve_gives_up_without_a_usable_dir() {
        let f = root().join("not-a-dir");
        std::fs::write(&f, "").unwrap();
        serve(f.join("x"), String::new());
        // The engine can't take its lock file.
        let d = root().join("bad-engine");
        std::fs::create_dir_all(d.join("daemon.lock")).unwrap();
        serve(d.clone(), String::new());
        assert!(!socket_path(&d).exists());
    }

    /// Run alone by `holder`: lock `FSEARCH_TEST_HOLD` like a daemon, with
    /// our pid in it, and wait to be killed.
    #[test]
    #[ignore]
    fn lock_holder() {
        let Some(p) = std::env::var_os("FSEARCH_TEST_HOLD") else { return };
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(p).unwrap();
        assert!(try_lock(&f));
        // Like a daemon between taking the lock and recording its pid.
        let delay = std::env::var("FSEARCH_TEST_HOLD_DELAY").ok().and_then(|d| d.parse().ok()).unwrap_or(0);
        std::thread::sleep(Duration::from_millis(delay));
        f.set_len(0).unwrap();
        write!(f, "{}", std::process::id()).unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }

    fn holder(lock: &Path) -> std::process::Child {
        let c = spawn_holder(lock, 0);
        let pid = c.id().to_string();
        wait_for("the holder", || std::fs::read_to_string(lock).is_ok_and(|s| s == pid));
        c
    }

    /// Not a daemon: only has the file open (another `fsearch install`).
    #[test]
    #[ignore]
    fn file_opener() {
        let Some(p) = std::env::var_os("FSEARCH_TEST_OPEN") else { return };
        let _f = std::fs::File::open(p).unwrap();
        std::thread::sleep(Duration::from_secs(60));
    }

    fn spawn_holder(lock: &Path, delay_ms: u64) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap())
            // "serve" on its command line, like a daemon's (an extra test
            // filter that matches nothing else).
            .args(["--exact", "server::tests::lock_holder", "serve", "--ignored", "--nocapture"])
            .env("FSEARCH_TEST_HOLD", lock)
            .env("FSEARCH_TEST_HOLD_DELAY", delay_ms.to_string())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    #[test]
    fn stop_kills_the_lock_holder() {
        let dir = root().join("stop1");
        std::fs::create_dir_all(&dir).unwrap();
        // Nothing there, or nothing holding it: nothing to do.
        assert_eq!(stop(&dir), Ok(()));
        std::fs::write(dir.join("socket.lock"), "1").unwrap();
        assert_eq!(stop(&dir), Ok(()));

        let mut c = holder(&dir.join("socket.lock"));
        let t = Instant::now();
        let r = stop(&dir);
        let _ = c.kill();
        assert_eq!(r, Ok(()));
        assert!(t.elapsed() < Duration::from_secs(5));
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(c.wait().unwrap().signal(), Some(libc::SIGTERM));
    }

    /// A stale pid that is now ours, with someone else still holding the
    /// lock: say so, rather than claim no pid was recorded.
    #[test]
    fn stop_names_a_stale_pid_that_is_ours() {
        let dir = root().join("stop3");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket.lock");
        std::fs::write(&path, std::process::id().to_string()).unwrap();
        let held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(try_lock(&held));
        let err = stop_within(&dir, Duration::from_millis(300)).unwrap_err();
        assert!(err.contains("stale") && err.contains(&std::process::id().to_string()), "{err}");
        drop(held);
    }

    /// A crashed daemon's pid, since reused by an unrelated process, while
    /// the new holder hasn't written its own: never signal the stranger.
    #[test]
    fn stop_never_signals_a_stranger() {
        let dir = root().join("stop4");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket.lock");
        let mut stranger = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        std::fs::write(&path, stranger.id().to_string()).unwrap();
        let held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(try_lock(&held));
        let r = stop_within(&dir, Duration::from_millis(300));
        let alive = stranger.try_wait().unwrap().is_none();
        let _ = stranger.kill();
        let _ = stranger.wait();
        drop(held);
        assert!(r.is_err());
        assert!(alive, "signalled an unrelated process");
    }

    /// The file names a stranger until the holder records its own pid:
    /// keep reading, and stop the holder once it does.
    #[test]
    fn stop_waits_for_the_holder_to_record_its_pid() {
        let dir = root().join("stop5");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket.lock");
        let mut stranger = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        std::fs::write(&path, stranger.id().to_string()).unwrap();
        let mut c = spawn_holder(&path, 400);
        wait_for("the holder's lock", || !try_lock(&std::fs::File::open(&path).unwrap()));
        let r = stop_within(&dir, Duration::from_secs(5));
        let _ = c.kill();
        let _ = stranger.kill();
        let _ = stranger.wait();
        assert_eq!(r, Ok(()));
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(c.wait().unwrap().signal(), Some(libc::SIGTERM));
    }

    /// A daemon from before pids were recorded holds the lock with an empty
    /// file (the first upgrade): find it by who has the file open.
    #[test]
    fn stop_finds_a_holder_that_never_recorded_its_pid() {
        let dir = root().join("stop6");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket.lock");
        std::fs::write(&path, "").unwrap();
        let mut c = spawn_holder(&path, 60_000);
        wait_for("the holder's lock", || !try_lock(&std::fs::File::open(&path).unwrap()));
        let r = stop_within(&dir, Duration::from_secs(5));
        let _ = c.kill();
        assert_eq!(r, Ok(()));
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(c.wait().unwrap().signal(), Some(libc::SIGTERM));
    }

    /// Without a pid, the daemon is found among the processes with the
    /// file open, not taken to be the first of them (another install).
    #[test]
    fn stop_signals_the_daemon_not_another_opener() {
        let dir = root().join("stop7");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket.lock");
        std::fs::write(&path, "").unwrap();
        let mut opener = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "server::tests::file_opener", "--ignored"])
            .env("FSEARCH_TEST_OPEN", &path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        wait_for("the opener", || holders(&path).contains(&(opener.id() as i32)));
        let mut c = spawn_holder(&path, 60_000);
        wait_for("the holder's lock", || !try_lock(&std::fs::File::open(&path).unwrap()));
        let r = stop_within(&dir, Duration::from_secs(5));
        let opener_alive = opener.try_wait().unwrap().is_none();
        let _ = opener.kill();
        let _ = opener.wait();
        let _ = c.kill();
        assert_eq!(r, Ok(()));
        assert!(opener_alive, "signalled the other opener");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(c.wait().unwrap().signal(), Some(libc::SIGTERM));
    }

    /// install renames the new binary over the running one before stopping
    /// it: the old daemon must still be recognised and stopped.
    #[test]
    fn stop_finds_a_daemon_whose_binary_was_replaced() {
        let dir = root().join("stop8");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket.lock");
        let bin = dir.join("fsearch");
        std::fs::copy(std::env::current_exe().unwrap(), &bin).unwrap();
        let mut c = std::process::Command::new(&bin)
            .args(["--exact", "server::tests::lock_holder", "serve", "--ignored", "--nocapture"])
            .env("FSEARCH_TEST_HOLD", &path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = c.id().to_string();
        wait_for("the holder", || std::fs::read_to_string(&path).is_ok_and(|s| s == pid));
        // What install does: a new copy renamed over the running one.
        let new = dir.join("fsearch.new");
        std::fs::copy(std::env::current_exe().unwrap(), &new).unwrap();
        std::fs::rename(&new, &bin).unwrap();
        let r = stop_within(&dir, Duration::from_secs(5));
        let _ = c.kill();
        assert_eq!(r, Ok(()));
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(c.wait().unwrap().signal(), Some(libc::SIGTERM));
    }

    /// A recorded pid reused by another fsearch process that isn't a daemon
    /// (an `fsearch stdio` client) is never signalled.
    #[test]
    fn stop_never_signals_a_non_daemon_fsearch() {
        let dir = root().join("stop9");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket.lock");
        std::fs::write(&path, "").unwrap();
        let mut client = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "server::tests::file_opener", "--ignored"])
            .env("FSEARCH_TEST_OPEN", &path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::fs::write(&path, client.id().to_string()).unwrap();
        let held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(try_lock(&held));
        let r = stop_within(&dir, Duration::from_millis(300));
        let alive = client.try_wait().unwrap().is_none();
        let _ = client.kill();
        let _ = client.wait();
        drop(held);
        assert!(r.is_err());
        assert!(alive, "signalled a non-daemon fsearch process");
    }

    /// The lock's holder hasn't written its pid yet, and the file still
    /// names a stale pid that is now ours: never signal ourselves.
    #[test]
    fn stop_never_signals_itself() {
        let dir = root().join("stop2");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("socket.lock");
        std::fs::write(&path, std::process::id().to_string()).unwrap();
        let held = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        assert!(try_lock(&held));
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            drop(held);
        });
        assert_eq!(stop(&dir), Ok(()));
    }
}
