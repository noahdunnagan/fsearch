//! The daemon: one `Engine`, answering JSON lines over a unix socket.
//! `fsearch stdio` and the CLI are thin clients.

use fsearch::walk::{KIND_DIR, KIND_FILE, KIND_LINK};
use fsearch::{Engine, GrepMode, Options, Query};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("fsearch.sock")
}

pub fn private_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let file = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(dir)?;
    let metadata = file.metadata()?;
    if metadata.uid() != unsafe { libc::getuid() } {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "data directory belongs to another user"));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn serve(dir: PathBuf, home: String) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if unsafe { libc::getuid() } == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "run as an ordinary user with CAP_SYS_ADMIN and CAP_DAC_READ_SEARCH, not root"));
    }
    unsafe { libc::umask(0o077) };
    // One daemon per socket. (The engine's own lock decides who writes the
    // index: an app embedding fsearch may own it while the daemon follows.)
    private_dir(&dir)?;
    let lock = std::fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(dir.join("socket.lock"))?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        eprintln!("{} another fsearch daemon is running", fsearch::query::now_secs());
        return Ok(());
    }
    let engine = Engine::start(Options { dir: dir.clone(), home, skip: None }).map_err(std::io::Error::other)?;
    let sock = socket_path(&dir);
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o700))?;
    for conn in listener.incoming() {
        let conn = conn?;
        let e = engine.clone();
        std::thread::spawn(move || handle(conn, &e));
    }
    Ok(())
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
    let is_grep = op == "grep"
        || (op == "search"
            && v.get("q").and_then(Value::as_str).is_some_and(|q| ["grep:", "regex:", "sym:", "content:", "symbol:"].iter().any(|k| q.contains(k))));
    match op {
        "ping" => Ok(json!({"ok": true})),
        "save" => {
            engine.save();
            Ok(json!({"ok": true, "scheduled": true}))
        }
        _ if is_grep => grep(v, engine),
        "status" => {
            let s = engine.status();
            if !s.ready {
                return Err("indexing (building the whole-disk name index)".into());
            }
            let mut v = serde_json::to_value(s).map_err(|e| e.to_string())?;
            v["ok"] = true.into();
            Ok(v)
        }
        "search" => {
            let q = parse_request(v, engine.home())?;
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
    private_dir(dir)?;
    let sock = socket_path(dir);
    if let Ok(s) = UnixStream::connect(&sock) {
        return Ok(s);
    }
    #[cfg(target_os = "linux")]
    {
        let unit = service_name();
        let status = std::process::Command::new("sudo").args(["-n", "systemctl", "start", &unit]).status()?;
        if !status.success() {
            return Err(std::io::Error::other(format!("could not start {unit}; install with `sudo -v && fsearch install --login`, or start it with `sudo systemctl start {unit}`")));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let log = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(dir.join("daemon.log"))?;
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
    }
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(30));
        if let Ok(s) = UnixStream::connect(&sock) {
            return Ok(s);
        }
    }
    UnixStream::connect(&sock).map_err(|e| std::io::Error::new(e.kind(), format!("daemon socket {} is unavailable: {e}; check the service log", sock.display())))
}

#[cfg(target_os = "linux")]
pub fn service_name() -> String {
    format!("fsearch-{}.service", unsafe { libc::getuid() })
}
