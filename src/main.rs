mod server;

use fsearch::{default_dir, index, live, query};

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

#[cfg(target_os = "macos")]
const LABEL: &str = "mt.nd.fsearch";

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".into())
}

fn data_dir() -> PathBuf {
    let d = default_dir(&home());
    std::fs::create_dir_all(&d).ok();
    d
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
}

fn main() {
    // Never let a search download iCloud placeholders: opening or listing a
    // dataless file/dir fails fast instead of materializing it.
    #[cfg(target_os = "macos")]
    unsafe {
        setiopolicy_np(3, 0, 1)
    };
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

#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    PathBuf::from(home()).join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

#[cfg(target_os = "macos")]
fn launchctl(args: &[&str]) -> bool {
    std::process::Command::new("launchctl").args(args).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
}

#[cfg(target_os = "macos")]
fn domain() -> String {
    format!("gui/{}", unsafe { libc::getuid() })
}

fn install(login: bool) {
    // A plain reinstall keeps an existing login agent.
    #[cfg(target_os = "macos")]
    let login = login || plist_path().exists();
    let bin = PathBuf::from(home()).join(".local/bin/fsearch");
    // Stop the old daemon so the next one runs the new binary.
    server::stop(&data_dir()).unwrap_or_else(|e| die(&e));
    #[cfg(target_os = "macos")]
    {
        // Unload the login agent first, or KeepAlive would restart it
        // straight away.
        let target = format!("{}/{LABEL}", domain());
        launchctl(&["bootout", &target]);
    }
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap_or_else(|e| die(&format!("install: cannot create {:?}: {e}", bin.parent().unwrap())));
    // Replace, never overwrite in place: a rewritten signed binary at the same
    // path can be SIGKILLed by the code-signing cache. Copy then rename, so
    // reinstalling from the installed copy works too.
    let tmp = bin.with_extension("new");
    std::fs::copy(std::env::current_exe().unwrap(), &tmp).and_then(|_| std::fs::rename(&tmp, &bin)).unwrap_or_else(|e| die(&format!("copy: {e}")));
    if !login {
        println!("installed {}; the daemon starts on first use", bin.display());
        return;
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let service_dir = PathBuf::from(home()).join(".config/systemd/user");
        std::fs::create_dir_all(&service_dir).unwrap_or_else(|e| die(&format!("install: cannot create {service_dir:?}: {e}")));
        let service_path = service_dir.join("fsearch.service");
        let service = format!(
            r#"[Unit]
Description=FSearch file search daemon
After=default.target

[Service]
Type=simple
ExecStart="{}" serve
Restart=on-failure
RestartSec=1

[Install]
WantedBy=default.target
"#,
            bin.display()
        );
        std::fs::write(&service_path, &service).unwrap_or_else(|e| die(&format!("cannot write {service_path:?}: {e}")));
        let reload = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        let enable = Command::new("systemctl").args(["--user", "enable", "--now", "fsearch.service"]).status();
        if !reload.is_ok_and(|s| s.success()) || !enable.is_ok_and(|s| s.success()) {
            eprintln!("fsearch: installed {service_path:?} but systemctl failed (non-systemd host? run `fsearch serve` directly)");
            return;
        }
        println!("installed {} (systemd user service)", bin.display());
    }
    #[cfg(target_os = "macos")]
    {
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
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    println!("installed {}", bin.display());
}

fn uninstall() {
    #[cfg(target_os = "macos")]
    {
        launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
        let _ = std::fs::remove_file(plist_path());
        println!("removed LaunchAgent {LABEL}; index kept in {}", data_dir().display());
    }
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let disable = Command::new("systemctl").args(["--user", "disable", "--now", "fsearch.service"]).status();
        let service_path = PathBuf::from(home()).join(".config/systemd/user/fsearch.service");
        let _ = std::fs::remove_file(&service_path);
        let reload = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        if !disable.is_ok_and(|s| s.success()) || !reload.is_ok_and(|s| s.success()) {
            eprintln!("fsearch: removed {service_path:?} but systemctl reported failure");
            return;
        }
        println!("removed systemd user service; index kept in {}", data_dir().display());
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    eprintln!("fsearch: uninstall is not supported on this platform; index kept in {}", data_dir().display());
}

fn die(msg: &str) -> ! {
    eprintln!("fsearch: {msg}");
    std::process::exit(1)
}
