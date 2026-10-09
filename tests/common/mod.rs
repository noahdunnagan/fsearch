//! Shared by the integration tests: each `tests/*.rs` is its own process,
//! with its own `FSEARCH_ROOT` (the folder engines index instead of `/`).
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// This process's index root, set as `FSEARCH_ROOT` before any engine starts.
pub fn root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let r = std::env::temp_dir().join(format!("fsearch-test-{}", std::process::id()));
        assert!(r.starts_with(std::env::temp_dir()) && r != std::env::temp_dir());
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(&r).unwrap();
        // Set once, before any engine (or other env reader) runs.
        unsafe { std::env::set_var("FSEARCH_ROOT", &r) };
        r
    })
}

/// A fresh folder under the root, removed on drop.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new() -> Scratch {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = root().join(format!("t{}", N.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
    pub fn path(&self, rel: &str) -> PathBuf {
        // An absolute `rel` would replace the base: never `/` by accident.
        assert!(!rel.starts_with('/'), "stay inside the temp dir");
        self.0.join(rel)
    }
    /// Write `rel` (creating its folders).
    pub fn write(&self, rel: &str, body: &str) -> PathBuf {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }
    pub fn mkdir(&self, rel: &str) -> PathBuf {
        let p = self.path(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Poll `f` until it holds; panics with `what` after `secs`.
pub fn wait_for(secs: u64, what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(secs), "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Hold `path` exclusively with flock, as an owning engine or daemon would.
pub fn hold_lock(path: &Path) -> std::fs::File {
    let f = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(path).unwrap();
    assert_eq!(unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), libc::LOCK_EX | libc::LOCK_NB) }, 0);
    f
}

/// Run `save` and wait until `dir/index.bin` is rewritten. (Not "overlay
/// empty": the data dir is under the root, so the save's own writes come
/// back as events.)
pub fn saved(dir: &Path, save: impl FnOnce()) {
    let mtime = || std::fs::metadata(dir.join("index.bin")).and_then(|m| m.modified()).ok();
    let before = mtime();
    save();
    wait_for(10, "a save", || mtime() != before);
}

pub fn real(p: &Path) -> String {
    std::fs::canonicalize(p).unwrap().to_string_lossy().into_owned()
}
