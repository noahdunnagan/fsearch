//! The daemon: one `Engine`, answering JSON lines over a unix socket.
//! `fsearch stdio` and the CLI are thin clients.

use fsearch::walk::{KIND_DIR, KIND_FILE, KIND_LINK};
use fsearch::{Engine, GrepMode, Options, Query};
use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PER_FILE: usize = 20;
const MAX_BUDGET_MS: usize = 1000;
const MAX_CONNECTIONS: usize = 8;
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join("fsearch.sock")
}

pub fn serve(dir: PathBuf, home: String) -> Result<(), String> {
    // One daemon per socket. (The engine's own lock decides who writes the
    // index: an app embedding fsearch may own it while the daemon follows.)
    fsearch::storage::ensure_private_dir(&dir).map_err(|e| e.to_string())?;
    let lock = fsearch::storage::open_private_file(&dir.join("socket.lock")).map_err(|e| e.to_string())?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another fsearch daemon is running".into());
    }
    let sock = socket_path(&dir);
    if owned_socket(&sock).map_err(|e| e.to_string())?.is_some() {
        std::fs::remove_file(&sock).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&sock).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let engine = Engine::start(Options { dir: dir.clone(), home, skip: None })?;
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let conn = conn.map_err(|e| e.to_string())?;
        if check_peer(&conn).is_err() {
            continue;
        }
        let Some(slot) = ConnectionSlot::acquire(&active) else { continue };
        let e = engine.clone();
        let _ = std::thread::Builder::new().name("fsearch-client".into()).spawn(move || {
            let _slot = slot;
            handle(conn, &e);
        });
    }
    Ok(())
}

fn handle(conn: UnixStream, engine: &Engine) {
    if set_timeouts(&conn, IDLE_TIMEOUT).is_err() {
        return;
    }
    let Ok(r) = conn.try_clone() else { return };
    let mut w = std::io::BufWriter::new(conn);
    let mut reader = BufReader::new(r);
    loop {
        let line = match read_line(&mut reader, MAX_REQUEST_BYTES) {
            Ok(Some(line)) => line,
            Ok(None) => return,
            Err(error) => {
                let _ = write_response(&mut w, &json!({"ok": false, "error": error.to_string(), "id": null}));
                return;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let resp = respond(&line, engine);
        if write_response(&mut w, &resp).is_err() {
            return;
        }
    }
}

struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn acquire(active: &Arc<AtomicUsize>) -> Option<Self> {
        active.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |count| (count < MAX_CONNECTIONS).then_some(count + 1)).ok()?;
        Some(Self(active.clone()))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

fn set_timeouts(stream: &UnixStream, timeout: Duration) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}

/// Read only a bounded prefix, including the newline when present.
pub fn read_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let size = reader.take((max_bytes + 1) as u64).read_until(b'\n', &mut bytes)?;
    if size > max_bytes {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("line exceeds {max_bytes} bytes")));
    }
    if size == 0 {
        return Ok(None);
    }
    String::from_utf8(bytes).map(Some).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line must contain UTF-8 text"))
}

fn write_response<W: Write>(writer: &mut W, response: &Value) -> io::Result<()> {
    let mut encoded = ResponseBuffer(Vec::new());
    if serde_json::to_writer(&mut encoded, response).is_err() {
        writeln!(writer, "{}", json!({"ok": false, "error": "response exceeds the byte limit", "id": response["id"]}))?;
    } else {
        writer.write_all(&encoded.0)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()
}

struct ResponseBuffer(Vec<u8>);

impl Write for ResponseBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE_BYTES - 1 - self.0.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response exceeds the byte limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn respond(line: &str, engine: &Engine) -> Value {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return json!({"ok": false, "error": format!("bad json: {e}")}),
    };
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let mut out = match parse_operation(&v, engine.home()).and_then(|request| run(request, engine)) {
        Ok(r) => r,
        Err(e) => json!({"ok": false, "error": e}),
    };
    out["id"] = id;
    out
}

enum Request {
    Ping,
    Save,
    Status,
    Search(Query),
    Grep(Query, fsearch::Grep),
}

fn run(request: Request, engine: &Engine) -> Result<Value, String> {
    match request {
        Request::Ping => Ok(json!({"ok": true})),
        Request::Save => {
            engine.save();
            Ok(json!({"ok": true, "scheduled": true}))
        }
        Request::Grep(q, g) => grep(&q, &g, engine),
        Request::Status => {
            let s = engine.status();
            if !s.ready {
                return Err("indexing (first run scans the whole disk, ~20s)".into());
            }
            let mut v = serde_json::to_value(s).map_err(|e| e.to_string())?;
            v["ok"] = true.into();
            Ok(v)
        }
        Request::Search(q) => {
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
    }
}

/// Content search. The pattern comes from `pattern` (+ `mode`) or from a
/// `grep:`/`regex:`/`sym:` filter in `q`; the rest of the query narrows
/// which files are read.
fn grep(q: &Query, g: &fsearch::Grep, engine: &Engine) -> Result<Value, String> {
    let t = Instant::now();
    let (r, indexed) = engine.grep(q, g)?;
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
    let obj = v.as_object().ok_or("request must be a JSON object")?;
    let mut q = Query::parse(string_field(v, "q")?.unwrap_or(""), home)?;
    for (k, val) in obj {
        match k.as_str() {
            "id" | "op" | "q" | "pattern" | "mode" | "per_file" | "budget_ms" => {}
            "limit" => q.limit = bounded_number(v, "limit", q.limit, fsearch::query::MAX_RESULTS)?,
            _ => {
                let text = val.as_str().ok_or_else(|| format!("{k} must be a string"))?;
                if !q.filter(k, text, home)? {
                    return Err(format!("unknown request field {k}"));
                }
            }
        }
    }
    q.validate_limits()?;
    Ok(q)
}

fn string_field<'a>(v: &'a Value, key: &str) -> Result<Option<&'a str>, String> {
    v.get(key).map(|value| value.as_str().ok_or_else(|| format!("{key} must be a string"))).transpose()
}

fn bounded_number(v: &Value, key: &str, default: usize, maximum: usize) -> Result<usize, String> {
    let Some(value) = v.get(key) else { return Ok(default) };
    let number = value.as_u64().ok_or_else(|| format!("{key} must be a positive integer"))?;
    if number == 0 || number > maximum as u64 {
        return Err(format!("{key} must be between 1 and {maximum}"));
    }
    Ok(number as usize)
}

fn parse_operation(v: &Value, home: &str) -> Result<Request, String> {
    let mut q = parse_request(v, home)?;
    let per_file = bounded_number(v, "per_file", 5, MAX_PER_FILE)?;
    let budget_ms = bounded_number(v, "budget_ms", 250, MAX_BUDGET_MS)?;
    let op = string_field(v, "op")?.unwrap_or("search");
    match op {
        "ping" => Ok(Request::Ping),
        "save" => Ok(Request::Save),
        "status" => Ok(Request::Status),
        "search" | "grep" => {
            if op == "search" && q.grep.is_none() {
                return Ok(Request::Search(q));
            }
            let mode = match string_field(v, "mode")? {
                Some("regex") => GrepMode::Regex,
                Some("symbol") => GrepMode::Symbol,
                Some("literal") => GrepMode::Literal,
                Some(mode) => return Err(format!("unknown mode {mode}")),
                None => q.grep_mode,
            };
            let pattern = string_field(v, "pattern")?.map(str::to_string).or(q.grep.take()).ok_or("grep needs a pattern")?;
            let mut grep = fsearch::Grep::new(&pattern, mode)?;
            grep.max_per_file = per_file;
            grep.budget = Some(Duration::from_millis(budget_ms as u64));
            Ok(Request::Grep(q, grep))
        }
        _ => Err(format!("unknown op {op}")),
    }
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
    fsearch::storage::ensure_private_dir(dir)?;
    let sock = socket_path(dir);
    match connect_existing(&sock) {
        Ok(stream) => return Ok(stream),
        Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused) => {}
        Err(error) => return Err(error),
    }
    let log = fsearch::storage::open_private_log(&dir.join("daemon.log"))?;
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
        if let Ok(s) = connect_existing(&sock) {
            return Ok(s);
        }
    }
    connect_existing(&sock)
}

fn owned_socket(path: &Path) -> io::Result<Option<std::fs::Metadata>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "daemon path must be a socket owned by this user"));
    }
    Ok(Some(metadata))
}

fn connect_existing(path: &Path) -> io::Result<UnixStream> {
    let metadata = owned_socket(path)?.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "daemon socket does not exist"))?;
    if metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "daemon socket must have private permissions"));
    }
    let stream = UnixStream::connect(path)?;
    check_peer(&stream)?;
    set_timeouts(&stream, IDLE_TIMEOUT)?;
    Ok(stream)
}

fn check_peer(stream: &UnixStream) -> io::Result<()> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // This identifies the Unix user, not the calling app or its TCC grant.
    if uid != unsafe { libc::geteuid() } {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "daemon peer belongs to another user"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn invalid_json_result_limits_are_rejected() {
        // Given requests with result counts outside the permitted range.
        for limit in [json!(0), json!(201), json!(u64::MAX), json!(-1), json!(1.5), json!("50")] {
            let request = json!({"q": "report", "limit": limit});

            // When the JSON request is converted to a query.
            let result = parse_request(&request, "/fixture");

            // Then the request is rejected before it can reach search.
            assert!(result.is_err(), "unsafe result limit was accepted: {limit}");
        }
    }

    #[test]
    fn invalid_query_limits_cannot_be_hidden_by_json_overrides() {
        // Given invalid limits in query text and a valid JSON override.
        for query in ["limit:0", "limit:201", "limit:18446744073709551615"] {
            let request = json!({"q": query, "limit": 50});

            // When the whole request is converted to a search operation.
            let result = parse_operation(&request, "/fixture");

            // Then the invalid query fails before the override is applied.
            assert!(result.is_err(), "invalid query limit was hidden by JSON: {query}");
        }
    }

    #[test]
    fn content_search_limits_reject_zero_huge_and_wrong_types() {
        // Given invalid per-file and time-budget values.
        for key in ["per_file", "budget_ms"] {
            let maximum = if key == "per_file" { MAX_PER_FILE } else { MAX_BUDGET_MS };
            for value in [json!(0), json!(u64::MAX), json!(-1), json!(1.5), json!("5"), json!(maximum + 1)] {
                let mut request = json!({"op": "grep", "pattern": "report"});
                request[key] = value.clone();

                // When the JSON request is converted to an operation.
                let result = parse_operation(&request, "/fixture");

                // Then every invalid value is rejected.
                assert!(result.is_err(), "unsafe {key} value was accepted: {value}");
            }
        }
    }

    #[test]
    fn valid_content_search_uses_explicit_bounded_values() {
        // Given a valid content request at each permitted upper boundary.
        let request = json!({"q": "grep:report limit:200", "per_file": 20, "budget_ms": 1000});

        // When the request is converted to an operation.
        let result = parse_operation(&request, "/fixture").unwrap();

        // Then it is a content search with the exact requested limits.
        let Request::Grep(query, grep) = result else { panic!("content query selected name search") };
        assert_eq!(query.limit, 200);
        assert_eq!(grep.max_per_file, 20);
        assert_eq!(grep.budget, Some(Duration::from_millis(1000)));
    }

    #[test]
    fn name_search_and_content_defaults_are_preserved() {
        // Given ordinary name and content requests with no limits.
        let name_request = json!({"q": "report"});
        let content_request = json!({"op": "grep", "pattern": "report"});

        // When both requests are converted to operations.
        let name = parse_operation(&name_request, "/fixture").unwrap();
        let content = parse_operation(&content_request, "/fixture").unwrap();

        // Then name and content searches retain the documented defaults.
        let Request::Search(query) = name else { panic!("name query selected another operation") };
        assert_eq!(query.limit, 50);
        let Request::Grep(query, grep) = content else { panic!("grep request selected another operation") };
        assert_eq!(query.limit, 50);
        assert_eq!(grep.max_per_file, 5);
        assert_eq!(grep.budget, Some(Duration::from_millis(250)));
    }

    #[test]
    fn content_filter_text_inside_a_filename_does_not_change_the_operation() {
        // Given a filename token that contains the text of a content filter.
        let request = json!({"q": "project-grep:report"});

        // When the request is converted to an operation.
        let result = parse_operation(&request, "/fixture").unwrap();

        // Then the parsed query selects a normal name search.
        let Request::Search(query) = result else { panic!("filename text selected content search") };
        assert_eq!(query.tokens.len(), 1);
        assert_eq!(query.tokens[0].text, b"project-grep:report");
    }

    #[test]
    fn oversized_lines_consume_only_the_bounded_prefix() {
        // Given an oversized frame followed by more input.
        let mut input = Cursor::new(vec![b'x'; MAX_REQUEST_BYTES * 4]);
        assert_eq!(input.position(), 0);

        // When the frame is read through the request boundary.
        let result = read_line(&mut input, MAX_REQUEST_BYTES);

        // Then it fails after at most the maximum plus one byte.
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(input.position(), (MAX_REQUEST_BYTES + 1) as u64);
    }

    #[test]
    fn a_socket_frame_roundtrips_and_identifies_its_user() {
        // Given a connected local socket pair and one complete JSON line.
        let (mut client, server) = UnixStream::pair().unwrap();
        let frame = b"{\"op\":\"ping\",\"id\":7}\n";
        client.write_all(frame).unwrap();
        check_peer(&server).unwrap();

        // When the request frame is read from the verified peer.
        let line = read_line(&mut BufReader::new(server), MAX_REQUEST_BYTES).unwrap();

        // Then the complete request is preserved.
        assert_eq!(line.as_deref(), Some(std::str::from_utf8(frame).unwrap()));
    }

    #[test]
    fn idle_socket_reads_time_out() {
        // Given a socket pair with no available input and a short test timeout.
        let (_client, server) = UnixStream::pair().unwrap();
        set_timeouts(&server, Duration::from_millis(20)).unwrap();

        // When a request read waits for data.
        let started = Instant::now();
        let error = read_line(&mut BufReader::new(server), MAX_REQUEST_BYTES).unwrap_err();

        // Then the idle connection stops instead of holding a worker forever.
        assert!(matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut), "unexpected idle error: {error}");
        assert!(started.elapsed() < Duration::from_secs(1), "idle read exceeded its test timeout");
    }

    #[test]
    fn connection_admission_is_bounded_and_releases_slots() {
        // Given all available connection slots in use.
        let active = Arc::new(AtomicUsize::new(0));
        let _slots: Vec<_> = (0..MAX_CONNECTIONS).map(|_| ConnectionSlot::acquire(&active).unwrap()).collect();
        assert_eq!(active.load(Ordering::Relaxed), MAX_CONNECTIONS);

        // When another connection tries to enter.
        let excess = ConnectionSlot::acquire(&active);

        // Then excess admission fails without changing the active count.
        assert!(excess.is_none(), "more than eight connections were admitted");
        assert_eq!(active.load(Ordering::Relaxed), MAX_CONNECTIONS);
    }

    #[test]
    fn a_released_connection_slot_can_be_used_again() {
        // Given a full connection set with one slot released.
        let active = Arc::new(AtomicUsize::new(0));
        let mut slots: Vec<_> = (0..MAX_CONNECTIONS).map(|_| ConnectionSlot::acquire(&active).unwrap()).collect();
        slots.pop();
        assert_eq!(active.load(Ordering::Relaxed), MAX_CONNECTIONS - 1);

        // When a replacement connection tries to enter.
        let replacement = ConnectionSlot::acquire(&active);

        // Then the released slot is available exactly once.
        assert!(replacement.is_some(), "a released connection slot was not restored");
        assert_eq!(active.load(Ordering::Relaxed), MAX_CONNECTIONS);
    }

    #[test]
    fn oversized_responses_return_the_complete_error_contract() {
        // Given a response larger than the wire byte limit.
        let response = json!({"ok": true, "id": 7, "text": "x".repeat(MAX_RESPONSE_BYTES)});
        let mut wire = Vec::new();
        assert!(wire.is_empty());

        // When the response is sent through the output boundary.
        write_response(&mut wire, &response).unwrap();

        // Then the whole response is replaced by the documented error shape.
        assert_eq!(serde_json::from_slice::<Value>(&wire).unwrap(), json!({"ok": false, "error": "response exceeds the byte limit", "id": 7}));
    }
}
