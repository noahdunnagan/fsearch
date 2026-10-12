#[cfg(not(windows))]
mod frecency;
#[cfg(not(windows))]
mod git;
#[cfg(not(windows))]
mod mcp;
#[cfg(not(windows))]
mod server;
#[cfg(windows)]
#[path = "win_server.rs"]
mod server;

use fsearch::{index, live, query};

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Instant;

#[global_allocator]
static GLOBAL: fsearch::alloc::Alloc = fsearch::alloc::Alloc;

const USAGE: &str = "usage:
  fsearch <query...> [--json]   search (starts the daemon if needed)
  fsearch stdio                 JSON lines on stdin/stdout
  fsearch mcp                   MCP server on stdin/stdout, for coding agents
  fsearch serve                 run the daemon in the foreground
  fsearch status
  fsearch install [--login]     install the binary and optional login/startup entry
  fsearch uninstall             remove the login/startup entry (keeps the index)
  fsearch bench <query...>      time a query in-process against the saved index";

#[cfg(not(windows))]
const LABEL: &str = "mt.nd.fsearch";

fn home() -> String {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".into())
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").unwrap_or_else(|_| "/".into())
    }
}

fn data_dir() -> PathBuf {
    let d = fsearch::default_dir(&home());
    std::fs::create_dir_all(&d).ok();
    d
}

fn main() {
    #[cfg(target_os = "macos")]
    unsafe {
        unsafe extern "C" {
            fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
        }
        setiopolicy_np(3, 0, 1);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("-h" | "--help") => eprintln!("{USAGE}"),
        Some("serve") => {
            space_efficient();
            server::serve(data_dir(), home())
        }
        Some("stdio") => stdio(),
        Some("mcp") => {
            #[cfg(not(windows))]
            mcp::run(data_dir());
            #[cfg(windows)]
            die("mcp is not yet wired on Windows; use fsearch stdio");
        }
        Some("status") => print_one(&serde_json::json!({"op": "status"}), true),
        Some("bench") => bench(&args[1..].join(" ")),
        Some("install") => install(args.iter().any(|a| a == "--login")),
        Some("uninstall") => uninstall(),
        Some(_) => {
            let json = args.iter().any(|a| a == "--json");
            let q: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "--json").collect();
            let cwd = std::env::current_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
            print_one(&serde_json::json!({"q": q.join(" "), "cwd": cwd}), json);
        }
    }
}

fn space_efficient() {
    #[cfg(target_os = "macos")]
    if std::env::var_os("MallocSpaceEfficient").is_none()
        && let Ok(exe) = std::env::current_exe()
    {
        use std::os::unix::process::CommandExt;
        let e = std::process::Command::new(exe).args(std::env::args_os().skip(1)).env("MallocSpaceEfficient", "1").exec();
        eprintln!("{} re-exec failed: {e}", query::now_secs());
    }
}


fn print_one(req: &serde_json::Value, raw: bool) {
    let mut s = server::connect(&data_dir()).unwrap_or_else(|e| die(&format!("cannot reach daemon: {e}")));
    s.write_all(format!("{req}\n").as_bytes()).unwrap();
    #[cfg(unix)]
    let _ = s.shutdown(std::net::Shutdown::Write);
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
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for h in v["hits"].as_array().into_iter().flatten() {
        let _ = writeln!(out, "{}", h["path"].as_str().unwrap_or(""));
    }
    for f in v["files"].as_array().into_iter().flatten() {
        for m in f["matches"].as_array().into_iter().flatten() {
            let _ = writeln!(out, "{}:{}: {}", f["path"].as_str().unwrap_or(""), m["line"], m["text"].as_str().unwrap_or("").trim());
        }
    }
    let _ = out.flush();
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
        #[cfg(unix)]
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
    let dir = data_dir();
    let idx = index::Index::load(&dir.join("index.bin")).unwrap_or_else(|| die("no index yet; run fsearch serve"));
    let live = live::Live::new(idx);
    let home = home();
    let mut q = query::Query::parse(qs, &home).unwrap_or_else(|e| die(&e));
    // Like the daemon: a content search when the query has a pattern, on
    // user-interactive threads, paths included.
    let grep = q.grep.take().map(|p| fsearch::Grep::new(&p, q.grep_mode).unwrap_or_else(|e| die(&e)));
    let content = grep.as_ref().map(|_| fsearch::content::Content::open_shared(dir.join("content")));
    let pool = rayon::ThreadPoolBuilder::new()
        .start_handler(|_| {
            fsearch::alloc::keep_on_this_thread();
        })
        .build()
        .unwrap();
    let run = || -> Vec<String> {
        let (Some(g), Some(c)) = (&grep, &content) else {
            let mut p = Vec::new();
            let hits = pool.install(|| query::Searcher { live: &live }.search(&q));
            return hits
                .iter()
                .map(|h| {
                    live.base.path(h.idx as usize, &mut p);
                    format!("{:5} {}", h.score, String::from_utf8_lossy(&p))
                })
                .collect();
        };
        let r = if q.scope.as_ref().is_none_or(|s| fsearch::content::in_scope(s, home.as_bytes())) {
            pool.install(|| c.search(g, &q))
        } else {
            let paths = pool.install(|| fsearch::content::scan_paths(&live, q.clone_for_scan()));
            fsearch::content::verify(g, &paths, q.limit)
        };
        let first = |f: &fsearch::FileMatches| f.lines.first().map_or(String::new(), |(n, t)| format!("{n}: {}", t.trim()));
        r.files.iter().map(|f| format!("{}:{}", String::from_utf8_lossy(&f.path), first(f))).collect()
    };
    // Between runs, another name search: a repeat would be answered from
    // the names cache, which only a repeat of the last query hits.
    let other = query::Query::parse("zzzzzz", &home).unwrap();
    let mut times = Vec::new();
    let mut out = Vec::new();
    for _ in 0..20 {
        pool.install(|| query::Searcher { live: &live }.search(&other));
        let t = Instant::now();
        out = run();
        times.push(t.elapsed());
    }
    for l in out.iter().take(10) {
        println!("{l}");
    }
    let first = times[0];
    times.sort();
    eprintln!("first {first:.2?}  median {:.2?}  min {:.2?}", times[times.len() / 2], times[0]);
}

#[cfg(not(windows))]
fn plist_path() -> PathBuf {
    PathBuf::from(home()).join(format!("Library/LaunchAgents/{LABEL}.plist"))
}

#[cfg(not(windows))]
fn launchctl(args: &[&str]) -> bool {
    std::process::Command::new("launchctl").args(args).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
}

#[cfg(not(windows))]
fn domain() -> String {
    format!("gui/{}", unsafe { libc::getuid() })
}

#[cfg(windows)]
fn install(login: bool) {
    let dest = data_dir().join("fsearch.exe");
    let _ = std::fs::remove_file(&dest);
    std::fs::copy(std::env::current_exe().unwrap(), &dest).unwrap_or_else(|e| die(&format!("copy: {e}")));
    if login {
        println!("installed {}; add a startup entry with: fsearch serve", dest.display());
    } else {
        println!("installed {}; daemon starts on first search", dest.display());
    }
}

#[cfg(windows)]
fn uninstall() {
    println!("index kept in {}", data_dir().display());
}

#[cfg(not(windows))]
fn install(login: bool) {
    let login = login || plist_path().exists();
    let bin = PathBuf::from(home()).join(".local/bin/fsearch");
    let target = format!("{}/{LABEL}", domain());
    launchctl(&["bootout", &target]);
    server::stop(&data_dir()).unwrap_or_else(|e| die(&e));
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    let tmp = bin.with_extension("new");
    std::fs::copy(std::env::current_exe().unwrap(), &tmp).and_then(|_| std::fs::rename(&tmp, &bin)).unwrap_or_else(|e| die(&format!("copy: {e}")));
    let agents =
        format!("for coding agents: claude mcp add -s user fsearch -- {0} mcp\n                   codex mcp add fsearch -- {0} mcp", bin.display());
    if !login {
        println!("installed {}; the daemon starts on first use\n{agents}", bin.display());
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
    let bootstrap = || launchctl(&["bootstrap", &domain(), plist_path().to_str().unwrap()]);
    let retry = || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        false
    };
    if !(0..50).any(|_| bootstrap() || retry()) {
        die("launchctl bootstrap failed");
    }
    println!("installed {} (LaunchAgent {LABEL})\n{agents}", bin.display());
}

#[cfg(not(windows))]
fn uninstall() {
    launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
    let _ = std::fs::remove_file(plist_path());
    println!("removed LaunchAgent {LABEL}; index kept in {}", data_dir().display());
}


fn die(msg: &str) -> ! {
    eprintln!("fsearch: {msg}");
    std::process::exit(1)
}
