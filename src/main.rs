mod server;

use fsearch::{index, live, query};

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Instant;

/// Big buffers (index builds, content batches) come straight from mmap and
/// go straight back with munmap. macOS's malloc keeps freed large blocks
/// mapped and dirty, which left the daemon at ~1 GB footprint after a build
/// while only ~2 MB was live.
struct Alloc;
const BIG: usize = 1 << 20;

unsafe impl GlobalAlloc for Alloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if l.size() < BIG || l.align() > 16384 {
            return unsafe { System.alloc(l) };
        }
        let p = unsafe { libc::mmap(std::ptr::null_mut(), l.size(), libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0) };
        if p == libc::MAP_FAILED { std::ptr::null_mut() } else { p as *mut u8 }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        // Fresh anonymous pages are already zero.
        if l.size() < BIG || l.align() > 16384 { unsafe { System.alloc_zeroed(l) } } else { unsafe { self.alloc(l) } }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if l.size() < BIG || l.align() > 16384 {
            unsafe { System.dealloc(p, l) }
        } else {
            unsafe { libc::munmap(p as *mut libc::c_void, l.size()) };
        }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        if (l.size() < BIG && new_size < BIG) || l.align() > 16384 {
            return unsafe { System.realloc(p, l, new_size) };
        }
        let q = unsafe { self.alloc(Layout::from_size_align_unchecked(new_size, l.align())) };
        if !q.is_null() {
            unsafe {
                std::ptr::copy_nonoverlapping(p, q, l.size().min(new_size));
                self.dealloc(p, l);
            }
        }
        q
    }
}

#[global_allocator]
static GLOBAL: Alloc = Alloc;

const USAGE: &str = "usage:
  fsearch <query...> [--json]   search (starts the daemon if needed)
  fsearch stdio                 JSON lines on stdin/stdout
  fsearch serve                 run the daemon in the foreground
  fsearch status
  fsearch install [--login]      copy to ~/.local/bin; --login also starts the daemon at login
                                (needs Full Disk Access granted to ~/.local/bin/fsearch)
  fsearch uninstall             remove the login agent (keeps the index)
  fsearch bench <query...>      time a query in-process against the saved index";

const LABEL: &str = "mt.nd.fsearch";

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".into())
}

fn data_dir() -> PathBuf {
    let d = PathBuf::from(home()).join("Library/Application Support/FSearch");
    std::fs::create_dir_all(&d).ok();
    d
}

unsafe extern "C" {
    fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
}

fn main() {
    // Never let a search download iCloud placeholders: opening or listing a
    // dataless file/dir fails fast instead of materializing it.
    // (IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_PROCESS, OFF)
    unsafe { setiopolicy_np(3, 0, 1) };
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("-h" | "--help") => eprintln!("{USAGE}"),
        Some("serve") => server::serve(data_dir(), home()),
        Some("stdio") => stdio(),
        Some("status") => print_one(&serde_json::json!({"op": "status"}), true),
        Some("bench") => bench(&args[1..].join(" ")),
        Some("install") => install(args.iter().any(|a| a == "--login")),
        Some("uninstall") => uninstall(),
        Some(_) => {
            let json = args.iter().any(|a| a == "--json");
            let q: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "--json").collect();
            print_one(&serde_json::json!({"q": q.join(" ")}), json);
        }
    }
}

fn print_one(req: &serde_json::Value, raw: bool) {
    let mut s = server::connect(&data_dir()).unwrap_or_else(|e| die(&format!("cannot reach daemon: {e}")));
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).unwrap();
    if raw {
        print!("{line}");
        return;
    }
    let v: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
    if v["ok"] != true {
        die(v["error"].as_str().unwrap_or("error"));
    }
    let mut out = std::io::stdout().lock();
    for h in v["hits"].as_array().into_iter().flatten() {
        let _ = writeln!(out, "{}", h["path"].as_str().unwrap_or(""));
    }
    for f in v["files"].as_array().into_iter().flatten() {
        for m in f["matches"].as_array().into_iter().flatten() {
            let _ = writeln!(out, "{}:{}: {}", f["path"].as_str().unwrap_or(""), m["line"], m["text"].as_str().unwrap_or("").trim());
        }
    }
}

fn stdio() {
    let s = server::connect(&data_dir()).unwrap_or_else(|e| die(&format!("cannot reach daemon: {e}")));
    let mut up = s.try_clone().unwrap();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if writeln!(up, "{line}").is_err() {
                break;
            }
        }
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let mut out = std::io::stdout().lock();
    for line in BufReader::new(s).lines() {
        let Ok(line) = line else { break };
        if writeln!(out, "{line}").and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}

fn bench(qs: &str) {
    let idx = index::Index::load(&data_dir().join("index.bin")).unwrap_or_else(|| die("no index yet; run fsearch serve"));
    let live = live::Live::new(idx);
    let q = query::Query::parse(qs, &home()).unwrap_or_else(|e| die(&e));
    let s = query::Searcher { live: &live };
    let mut times = Vec::new();
    let mut hits = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        hits = s.search(&q);
        times.push(t.elapsed());
    }
    let mut p = Vec::new();
    for h in hits.iter().take(10) {
        live.base.path(h.idx as usize, &mut p);
        println!("{:5} {}", h.score, String::from_utf8_lossy(&p));
    }
    times.sort();
    eprintln!("first {:.2?}  median {:.2?}  min {:.2?}", times[0].max(times[times.len() - 1]), times[times.len() / 2], times[0]);
}

fn plist_path() -> PathBuf {
    PathBuf::from(home()).join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

fn launchctl(args: &[&str]) -> bool {
    std::process::Command::new("launchctl").args(args).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
}

fn domain() -> String {
    format!("gui/{}", unsafe { libc::getuid() })
}

fn install(login: bool) {
    // A plain reinstall keeps an existing login agent.
    let login = login || plist_path().exists();
    let bin = PathBuf::from(home()).join(".local/bin/fsearch");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    // Replace, never overwrite in place: a rewritten signed binary at the same
    // path can be SIGKILLed by the code-signing cache. Copy then rename, so
    // reinstalling from the installed copy works too. First, so a failure
    // leaves the running daemon alone.
    let tmp = bin.with_extension("new");
    std::fs::copy(std::env::current_exe().unwrap(), &tmp).and_then(|_| std::fs::rename(&tmp, &bin)).unwrap_or_else(|e| die(&format!("copy: {e}")));
    // Stop the old daemon so the next one runs the new binary. Unload the
    // login agent first, or KeepAlive would restart it straight away; if the
    // daemon won't stop, load the agent again rather than leave none.
    let target = format!("{}/{LABEL}", domain());
    let had_agent = launchctl(&["bootout", &target]);
    if let Err(e) = server::stop(&data_dir()) {
        if had_agent {
            launchctl(&["bootstrap", &domain(), plist_path().to_str().unwrap()]);
        }
        die(&e);
    }
    if !login {
        println!("installed {}; the daemon starts on first use", bin.display());
        return;
    }
    let log = data_dir().join("daemon.log");
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{}</string><string>serve</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{}</string>
  <key>StandardErrorPath</key><string>{}</string>
</dict>
</plist>
"#,
        bin.display(),
        log.display(),
        log.display()
    );
    std::fs::write(plist_path(), plist).unwrap();
    // bootout returns before the old job is fully gone; bootstrap fails
    // until it is.
    let bootstrap = || launchctl(&["bootstrap", &domain(), plist_path().to_str().unwrap()]);
    let retry = || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        false
    };
    if !(0..50).any(|_| bootstrap() || retry()) {
        die("launchctl bootstrap failed");
    }
    println!("installed {} (LaunchAgent {LABEL})", bin.display());
}

fn uninstall() {
    launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
    let _ = std::fs::remove_file(plist_path());
    println!("removed LaunchAgent {LABEL}; index kept in {}", data_dir().display());
}

fn die(msg: &str) -> ! {
    eprintln!("fsearch: {msg}");
    std::process::exit(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe fn check(p: *mut u8, n: usize, fill: u8) {
        assert!(!p.is_null());
        for i in [0, n / 2, n - 1] {
            assert_eq!(unsafe { *p.add(i) }, fill, "byte {i} of {n}");
        }
    }

    /// Blocks on either side of the mmap threshold, and moves across it.
    #[test]
    fn alloc_round_trips() {
        let a = Alloc;
        for (from, to) in [(100, 200), (100, BIG + 5), (BIG + 5, 100), (BIG, 3 * BIG), (3 * BIG, BIG + 1), (BIG - 1, BIG)] {
            let l = Layout::from_size_align(from, 16).unwrap();
            unsafe {
                let p = a.alloc(l);
                std::ptr::write_bytes(p, 0xab, from);
                let q = a.realloc(p, l, to);
                check(q, from.min(to), 0xab);
                std::ptr::write_bytes(q, 0xcd, to);
                a.dealloc(q, Layout::from_size_align(to, 16).unwrap());
            }
        }
    }

    #[test]
    fn alloc_zeroed_and_aligned() {
        let a = Alloc;
        for (size, align) in [(64, 8), (BIG, 8), (BIG * 2, 4096), (BIG, 16384), (BIG, 1 << 16), (100, 1 << 16)] {
            let l = Layout::from_size_align(size, align).unwrap();
            unsafe {
                let p = a.alloc_zeroed(l);
                assert_eq!(p as usize % align, 0, "{size} aligned to {align}");
                check(p, size, 0);
                // Big, over-aligned blocks stay with the system allocator,
                // also when resized.
                std::ptr::write_bytes(p, 1, size);
                let q = a.realloc(p, l, size * 2);
                assert_eq!(q as usize % align, 0);
                check(q, size, 1);
                a.dealloc(q, Layout::from_size_align(size * 2, align).unwrap());
            }
        }
    }

    #[test]
    fn huge_alloc_fails_cleanly() {
        let l = Layout::from_size_align(1 << 62, 8).unwrap();
        unsafe {
            assert!(Alloc.alloc(l).is_null());
            let small = Layout::from_size_align(BIG, 8).unwrap();
            let p = Alloc.alloc(small);
            // A failed grow leaves the old block alone.
            assert!(Alloc.realloc(p, small, 1 << 62).is_null());
            Alloc.dealloc(p, small);
        }
    }
}
