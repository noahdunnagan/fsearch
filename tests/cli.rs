//! The `fsearch` binary, run with HOME (so its data dir) and FSEARCH_ROOT
//! in a temp folder. Never `install`/`uninstall`: those drive launchctl.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A temp HOME. Under /tmp, not the per-user temp dir: the socket path
/// (HOME/Library/Application Support/FSearch/fsearch.sock) must fit in
/// sockaddr_un's 104 bytes. Drop stops the daemon started for it.
struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Home {
        let h = PathBuf::from(format!("/tmp/fsearch-cli-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&h);
        std::fs::create_dir_all(h.join("root")).unwrap();
        Home(std::fs::canonicalize(h).unwrap())
    }
    fn data(&self) -> PathBuf {
        self.0.join("Library/Application Support/FSearch")
    }
    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_fsearch"));
        c.args(args).env("HOME", &self.0).env("FSEARCH_ROOT", self.0.join("root")).env_remove("FSEARCH_RESTRICT");
        c
    }
    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args).stdin(Stdio::null()).output().unwrap()
    }
    fn write(&self, rel: &str, body: &str) -> PathBuf {
        assert!(!rel.starts_with('/'));
        let p = self.0.join("root").join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }
}

fn locked(path: &Path) -> bool {
    let Ok(f) = std::fs::File::open(path) else { return false };
    unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX | libc::LOCK_NB) != 0 }
}

impl Drop for Home {
    fn drop(&mut self) {
        // Only the daemon that holds this temp dir's lock, i.e. ours.
        let lock = self.data().join("socket.lock");
        if locked(&lock)
            && let Some(pid) = std::fs::read_to_string(&lock).ok().and_then(|s| s.trim().parse::<i32>().ok()).filter(|&p| p > 1)
        {
            unsafe { libc::kill(pid, libc::SIGTERM) };
            let t = Instant::now();
            while locked(&lock) && t.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn usage() {
    let h = Home::new("usage");
    // `--json` alone is no query either.
    for args in [&[][..], &["-h"], &["--help"], &["--json"]] {
        let o = h.run(args);
        assert!(o.status.success() && err(&o).contains("usage:"), "{args:?}");
    }
}

/// A HOME long enough that the socket path can't fit sockaddr_un: a
/// clear error, at once, from the client and from `serve`; no panic.
#[test]
fn socket_path_too_long() {
    let h = Home::new(&"x".repeat(60));
    assert!(h.data().join("fsearch.sock").as_os_str().len() > 103);
    let t = Instant::now();
    let o = h.run(&["status"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("socket path too long"), "{}", err(&o));
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    let o = h.run(&["serve"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("socket path too long") && !err(&o).contains("panicked"), "{}", err(&o));
}

#[test]
fn bench_needs_an_index() {
    let h = Home::new("bench");
    let o = h.run(&["bench", "x"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("no index yet"));
}

#[test]
fn searches_through_the_daemon() {
    let h = Home::new("daemon");
    let heron = h.write("proj/heronfile.txt", "one\n  a heron needle  \n");
    let heron = heron.to_string_lossy();

    // The first request starts the daemon; poll until it has indexed.
    let t = Instant::now();
    let status = loop {
        let o = h.run(&["status"]);
        let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        if v["ok"] == true {
            break v;
        }
        assert!(v["error"].as_str().unwrap().starts_with("indexing"), "{v}");
        assert!(t.elapsed() < Duration::from_secs(20), "daemon never got ready");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status["entries"].as_u64().unwrap() > 0);
    // A flag before the command doesn't turn it into a search for "status".
    let v: serde_json::Value = serde_json::from_slice(&h.run(&["--json", "status"]).stdout).unwrap();
    assert!(v["entries"].as_u64().is_some_and(|n| n > 0), "{v}");
    let pid = std::fs::read_to_string(h.data().join("socket.lock")).unwrap();
    assert!(pid.parse::<u32>().is_ok());

    let o = h.run(&["heronfile"]);
    assert!(o.status.success());
    assert_eq!(out(&o), format!("{heron}\n"));
    // `--json` anywhere: the raw response.
    for args in [&["heronfile", "--json"][..], &["--json", "heronfile"]] {
        let v: serde_json::Value = serde_json::from_slice(&h.run(args).stdout).unwrap();
        assert_eq!(v["hits"][0]["path"], *heron, "{args:?}");
    }
    // Several words make one query.
    assert_eq!(out(&h.run(&["proj", "heron"])), format!("{heron}\n"));
    // Content search prints file:line: text.
    let want = format!("{heron}:2: a heron needle\n");
    let t = Instant::now();
    while out(&h.run(&["regex:heron.needle"])) != want {
        assert!(t.elapsed() < Duration::from_secs(20), "content never indexed");
        std::thread::sleep(Duration::from_millis(100));
    }
    let o = h.run(&["re:("]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).starts_with("fsearch: "), "{}", err(&o));

    // stdio: JSON lines both ways, until stdin closes.
    let mut c = h.cmd(&["stdio"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    writeln!(c.stdin.take().unwrap(), "{{\"op\":\"ping\",\"id\":1}}\n{{\"q\":\"heronfile\",\"id\":2}}").unwrap();
    let o = c.wait_with_output().unwrap();
    let lines: Vec<serde_json::Value> = out(&o).lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), 2);
    assert_eq!((lines[0]["id"].as_i64(), lines[1]["id"].as_i64()), (Some(1), Some(2)));

    // One daemon per data dir: a second `serve` gives way.
    let o = h.run(&["serve"]);
    assert!(err(&o).contains("another fsearch daemon is running"));
    assert_eq!(std::fs::read_to_string(h.data().join("socket.lock")).unwrap(), pid);

    // bench reads the saved index in-process.
    let o = h.run(&["bench", "heronfile"]);
    assert!(o.status.success());
    assert!(out(&o).ends_with(&format!(" {heron}\n")), "{}", out(&o));
    assert!(err(&o).contains("median"));
    let o = h.run(&["bench", "re:("]);
    assert_eq!(o.status.code(), Some(1));
}
