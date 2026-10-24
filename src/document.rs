//! Document text shared by the index builder and every grep read path.
//! PDF integration follows ATS-aerothermal-solutions/fsearch's 6bcfdba;
//! bounded parsing and metadata-keyed caching follow joshwhiteley/fsearch.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const MAX_SOURCE: u64 = 64 << 20;
pub const MAX_TEXT: usize = 8 << 20;
const TIMEOUT: Duration = Duration::from_secs(10);
const CACHE_BYTES: u64 = 256 << 20;
const CACHE_FILES: usize = 4096;
static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CONFIG_DIR: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

pub fn enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Acquire)
}
pub(crate) fn configure(dir: &Path) {
    let mut config = CONFIG_DIR.lock().unwrap();
    *config = Some(dir.to_path_buf());
    ENABLED.store(std::fs::read(dir.join("document-indexing")).is_ok_and(|b| b == b"1\n"), std::sync::atomic::Ordering::Release);
}
/// Configure document extraction for library users that build their own
/// segments. Engine clients use `Engine::set_document_indexing` to resync too.
pub fn set_enabled(dir: &Path, value: bool) -> std::io::Result<()> {
    let mut config = CONFIG_DIR.lock().unwrap();
    let temp = dir.join(format!("document-indexing.{}.tmp", std::process::id()));
    let result = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        f.write_all(if value { b"1\n" } else { b"0\n" })?;
        std::fs::rename(&temp, dir.join("document-indexing"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result?;
    *config = Some(dir.to_path_buf());
    ENABLED.store(value, std::sync::atomic::Ordering::Release);
    Ok(())
}

pub fn kind(path: &[u8]) -> Option<&'static str> {
    let ext = path.rsplit(|&b| b == b'.').next()?;
    ["doc", "docx", "pdf", "xls", "xlsx"].into_iter().find(|k| ext.eq_ignore_ascii_case(k.as_bytes()))
}

// Nanosecond change times and inode also invalidate same-size rewrites and
// replacements within the name index's one-second mtime resolution.
fn stamp(m: &std::fs::Metadata) -> [u64; 7] {
    [m.dev(), m.ino(), m.len(), m.mtime() as u64, m.mtime_nsec() as u64, m.ctime() as u64, m.ctime_nsec() as u64]
}

fn cache_key(path: &[u8], meta: &std::fs::Metadata) -> String {
    use std::hash::{Hash, Hasher};
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    (1u32, path, stamp(meta)).hash(&mut hash);
    format!("{:016x}.txt", hash.finish())
}

fn cache_dir() -> Option<PathBuf> {
    let dir = CONFIG_DIR.lock().unwrap().as_ref()?.join("document-text-v1");
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700).create(&dir).ok()?;
    let m = std::fs::symlink_metadata(&dir).ok()?;
    (m.is_dir() && !m.file_type().is_symlink() && m.uid() == unsafe { libc::getuid() } && m.mode() & 0o077 == 0).then_some(dir)
}

fn cached(path: &Path) -> Option<Vec<u8>> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_TEXT as u64 || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_TEXT as u64 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= MAX_TEXT && std::str::from_utf8(&bytes).is_ok()).then_some(bytes)
}

fn store(dir: &Path, key: &str, bytes: &[u8]) {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temp = dir.join(format!("{}.{}.tmp", std::process::id(), SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        file.write_all(bytes)?;
        std::fs::rename(&temp, dir.join(key))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    prune(dir, bytes.len() as u64);
}

fn prune(dir: &Path, written: u64) {
    static WRITTEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let force = WRITTEN.fetch_add(written, std::sync::atomic::Ordering::Relaxed) + written >= 32 << 20;
    static LAST: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let mut last = LAST.lock().unwrap();
    if !force && last.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
        return;
    }
    *last = Some(Instant::now());
    WRITTEN.store(0, std::sync::atomic::Ordering::Relaxed);
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<_> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            (m.is_file() && e.path().extension().is_some_and(|e| e == "txt")).then(|| (m.modified().ok(), m.len(), e.path()))
        })
        .collect();
    let mut bytes: u64 = files.iter().map(|f| f.1).sum();
    let mut count = files.len();
    files.sort_by_key(|f| f.0);
    for (_, size, path) in files {
        if bytes <= CACHE_BYTES && count <= CACHE_FILES {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            bytes = bytes.saturating_sub(size);
            count -= 1;
        }
    }
}

/// Uses an already-open regular file, like the upstream PDF patch: parsing
/// never bypasses the engine's no-follow / no-iCloud-download open policy.
pub fn read(path: &[u8], file: File) -> Option<Vec<u8>> {
    if !enabled() {
        return None;
    }
    let kind = kind(path)?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > MAX_SOURCE {
        return None;
    }
    let dir = cache_dir();
    let key = cache_key(path, &meta);
    let valid = || enabled() && crate::content::open_regular(path).and_then(|f| f.metadata().ok()).is_some_and(|m| stamp(&m) == stamp(&meta));
    if let Some(bytes) = dir.as_ref().and_then(|d| cached(&d.join(&key))) {
        return valid().then_some(bytes);
    }
    let mut command = if kind == "doc" || kind == "docx" {
        let mut c = Command::new("/usr/bin/textutil");
        c.args(["-convert", "txt", "-format", kind, "-encoding", "UTF-8", "-stdin", "-stdout"]);
        c
    } else {
        let exe = std::env::current_exe().ok()?;
        let beside = exe.with_file_name("fsearch-extract");
        let helper = if beside.is_file() { beside } else { exe.parent()?.parent()?.join("fsearch-extract") };
        let mut c = Command::new(helper);
        c.arg(kind).env("RAYON_NUM_THREADS", "1");
        c
    };
    let child = command.stdin(Stdio::from(file)).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let bytes = collect(child, TIMEOUT, MAX_TEXT)?;
    if !valid() || std::str::from_utf8(&bytes).is_err() {
        return None;
    }
    if let Some(dir) = dir {
        store(&dir, &key, &bytes);
    }
    Some(bytes)
}

// Nonblocking pipe + kill/reap, adapted from joshwhiteley/fsearch's PDF
// process collector. No watchdog thread or parser survives a failed read.
fn collect(mut child: std::process::Child, timeout: Duration, cap: usize) -> Option<Vec<u8>> {
    let result = (|| {
        let mut pipe = child.stdout.take()?;
        let fd = pipe.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return None;
            }
        }
        let start = Instant::now();
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            if start.elapsed() >= timeout {
                return None;
            }
            match pipe.read(&mut buffer) {
                Ok(0) => {
                    if let Some(status) = child.try_wait().ok()? {
                        return status.success().then_some(bytes);
                    }
                }
                Ok(n) => {
                    if bytes.len().saturating_add(n) > cap {
                        return None;
                    }
                    bytes.extend_from_slice(&buffer[..n]);
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    let _ = child.kill();
    let _ = child.wait();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_subprocess_time_and_output() {
        let mut sleep = Command::new("/bin/sleep");
        sleep.arg("5").stdout(Stdio::piped());
        assert!(collect(sleep.spawn().unwrap(), Duration::from_millis(30), 64).is_none());
        let mut echo = Command::new("/usr/bin/printf");
        echo.arg("123456789").stdout(Stdio::piped());
        assert!(collect(echo.spawn().unwrap(), Duration::from_secs(1), 4).is_none());
    }
    #[test]
    fn only_supported_document_extensions() {
        for ext in ["DOC", "docx", "pdf", "XLS", "xlsx"] {
            assert!(kind(format!("/a/report.{ext}").as_bytes()).is_some());
        }
        assert!(kind(b"/a/report.pptx").is_none());
    }
}
