mod server;

use fsearch::{index, live, query};

#[cfg(target_os = "macos")]
use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Instant;

/// Big buffers (index builds, content batches) come straight from mmap and
/// go straight back with munmap. macOS's malloc keeps freed large blocks
/// mapped and dirty, which left the daemon at ~1 GB footprint after a build
/// while only ~2 MB was live.
#[cfg(target_os = "macos")]
struct Alloc;
#[cfg(target_os = "macos")]
const BIG: usize = 1 << 20;

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
#[global_allocator]
static GLOBAL: Alloc = Alloc;

#[cfg(target_os = "macos")]
const USAGE: &str = "usage:
  fsearch <query...> [--json]   search (starts the daemon if needed)
  fsearch stdio                 JSON lines on stdin/stdout
  fsearch serve                 run the daemon in the foreground
  fsearch status
  fsearch install [--login]      copy to ~/.local/bin; --login also starts the daemon at login
                                (needs Full Disk Access granted to ~/.local/bin/fsearch)
  fsearch uninstall             remove the login agent (keeps the index)
  fsearch bench <query...>      time a query in-process against the saved index";

#[cfg(target_os = "linux")]
const USAGE: &str = "usage:
  fsearch <query...> [--json]   search (starts the installed system service if needed)
  fsearch stdio                 JSON lines on stdin/stdout
  fsearch serve                 run the daemon (requires fanotify capabilities)
  fsearch status
  fsearch install [--login]      copy to ~/.local/bin; --login installs and starts
                                a system service (run sudo -v first)
  fsearch uninstall             remove the system service and root binary (keeps the index)
  fsearch bench <query...>      time a query in-process against the saved index";

#[cfg(target_os = "macos")]
const LABEL: &str = "mt.nd.fsearch";

fn home() -> String {
    #[cfg(target_os = "macos")]
    { std::env::var("HOME").unwrap_or_else(|_| "/".into()) }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| die("HOME must be set"));
        if !std::path::Path::new(&home).is_absolute() || home == "/" || home.chars().any(char::is_control) {
            die("HOME must be an absolute user home directory without control characters");
        }
        home
    }
}

fn data_dir() -> PathBuf {
    let d = fsearch::default_dir(&home());
    server::private_dir(&d).unwrap_or_else(|e| die(&format!("data directory {}: {e}", d.display())));
    d
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
}

fn main() {
    #[cfg(target_os = "macos")]
    // Never materialize iCloud placeholders (process VFS policy).
    unsafe { setiopolicy_np(3, 0, 1) };
    #[cfg(target_os = "linux")]
    unsafe { libc::umask(0o077) };
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("-h" | "--help") => eprintln!("{USAGE}"),
        Some("serve") => server::serve(data_dir(), home()).unwrap_or_else(|e| die(&format!("daemon: {e}"))),
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

#[cfg(target_os = "macos")]
fn install(login: bool) {
    let bin = PathBuf::from(home()).join(".local/bin/fsearch");
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    // Replace, never overwrite in place: a rewritten signed binary at the same
    // path can be SIGKILLed by the code-signing cache.
    let _ = std::fs::remove_file(&bin);
    std::fs::copy(std::env::current_exe().unwrap(), &bin).unwrap_or_else(|e| die(&format!("copy: {e}")));
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
    let target = format!("{}/{LABEL}", domain());
    launchctl(&["bootout", &target]);
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

#[cfg(target_os = "macos")]
fn uninstall() {
    launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
    let _ = std::fs::remove_file(plist_path());
    println!("removed LaunchAgent {LABEL}; index kept in {}", data_dir().display());
}

#[cfg(target_os = "linux")]
fn sudo_script(script: &str, args: &[&std::ffi::OsStr], input: &[u8]) -> std::io::Result<()> {
    let mut child = std::process::Command::new("sudo")
        .args(["-n", "sh", "-eu", "-c", script, "--"])
        .args(args).stdin(std::process::Stdio::piped()).spawn()?;
    let written = child.stdin.take().unwrap().write_all(input);
    let status = child.wait()?;
    written?;
    if !status.success() {
        return Err(std::io::Error::other("privileged service operation failed; run `sudo -v` before install/uninstall and check the systemctl error above"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemd_value(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%")
}

#[cfg(target_os = "linux")]
fn install(login: bool) {
    if unsafe { libc::getuid() } == 0 {
        die("install as your ordinary user; authorize sudo first with `sudo -v`");
    }
    let bin = PathBuf::from(home()).join(".local/bin/fsearch");
    let copy = || -> std::io::Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::create_dir_all(bin.parent().unwrap())?;
        let tmp = bin.with_file_name(format!(".fsearch-{}", std::process::id()));
        let mut dest = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o700).open(&tmp)?;
        let result = (|| {
            let mut source = std::fs::File::open(std::env::current_exe()?)?;
            std::io::copy(&mut source, &mut dest)?;
            dest.set_permissions(std::fs::Permissions::from_mode(0o755))?;
            std::fs::rename(&tmp, &bin)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    };
    copy().unwrap_or_else(|e| die(&format!("install {}: {e}", bin.display())));
    if !login {
        println!("installed {}; run `sudo -v && fsearch install --login` to install the required Linux service", bin.display());
        return;
    }
    let _ = data_dir();
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let mut environment = format!("Environment=\"HOME={}\"\n", systemd_value(&home()));
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|p| std::path::Path::new(p).is_absolute()) {
        let xdg = xdg.to_str().unwrap_or_else(|| die("XDG_DATA_HOME must be UTF-8 for systemd installation"));
        if xdg.chars().any(char::is_control) {
            die("XDG_DATA_HOME must not contain control characters");
        }
        environment.push_str(&format!("Environment=\"XDG_DATA_HOME={}\"\n", systemd_value(xdg)));
    }
    let unit = format!("[Unit]\nDescription=FSearch file index for user {uid}\nAfter=local-fs.target\n\n[Service]\nType=simple\nUser={uid}\nGroup={gid}\n{environment}ExecStart=/usr/local/bin/fsearch serve\nAmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH\nNoNewPrivileges=true\nUMask=0077\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n");
    let name = server::service_name();
    // Both staging files are root-owned in root-owned directories. Rename the
    // executable instead of overwriting a running inode (ETXTBSY).
    let script = r#"install -d -o root -g root -m 0755 /usr/local/bin /etc/systemd/system
binary=$(mktemp /usr/local/bin/.fsearch.XXXXXX)
unit=
trap 'rm -f "$binary" "$unit"' EXIT
install -o root -g root -m 0755 -- "$1" "$binary"
mv -f -- "$binary" /usr/local/bin/fsearch
unit=$(mktemp /etc/systemd/system/.fsearch.XXXXXX)
cat > "$unit"
chown root:root "$unit"
chmod 0644 "$unit"
mv -f -- "$unit" "/etc/systemd/system/$2"
systemctl daemon-reload
systemctl enable "$2"
systemctl restart "$2"
"#;
    sudo_script(script, &[bin.as_os_str(), std::ffi::OsStr::new(&name)], unit.as_bytes())
        .unwrap_or_else(|e| die(&format!("install {name}: {e}")));
    server::connect(&data_dir()).unwrap_or_else(|e| die(&format!("{name} did not start: {e}; inspect `journalctl -u {name}`")));
    println!("installed {} and /usr/local/bin/fsearch (system service {name})", bin.display());
}

#[cfg(target_os = "linux")]
fn uninstall() {
    if unsafe { libc::getuid() } == 0 {
        die("uninstall as the ordinary user who installed the service");
    }
    let name = server::service_name();
    let script = r#"if [ -f "/etc/systemd/system/$1" ]; then
    systemctl disable --now "$1"
    rm -f -- "/etc/systemd/system/$1"
fi
rm -f -- /usr/local/bin/fsearch
systemctl daemon-reload
"#;
    sudo_script(script, &[std::ffi::OsStr::new(&name)], b"")
        .unwrap_or_else(|e| die(&format!("uninstall {name}: {e}")));
    println!("removed system service {name} and /usr/local/bin/fsearch; index kept in {}", data_dir().display());
}

fn die(msg: &str) -> ! {
    eprintln!("fsearch: {msg}");
    std::process::exit(1)
}
