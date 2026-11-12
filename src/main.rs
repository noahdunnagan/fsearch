mod frecency;
mod git;
mod mcp;
mod server;

use fsearch::{index, live, query};

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Instant;

/// See `fsearch::alloc`.
#[global_allocator]
static GLOBAL: fsearch::alloc::Alloc = fsearch::alloc::Alloc;

const USAGE: &str = "usage:
  fsearch <query...> [--json]   search (starts the daemon if needed)
  fsearch stdio                 JSON lines on stdin/stdout
  fsearch mcp                   MCP server on stdin/stdout, for coding agents
  fsearch serve                 run the daemon in the foreground
  fsearch status
  fsearch install [--login]      copy to ~/.local/bin; --login also starts the daemon at login
                                (needs Full Disk Access granted to ~/.local/bin/fsearch)
  fsearch uninstall             remove the login agent (keeps the index)
  fsearch version               print the version
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
        Some("serve") => {
            space_efficient();
            server::serve(data_dir(), home())
        }
        Some("stdio") => stdio(),
        Some("mcp") => mcp::run(data_dir()),
        Some("status") => print_one(&serde_json::json!({"op": "status"}), true),
        Some("version" | "--version") => println!("fsearch {}", env!("CARGO_PKG_VERSION")),
        Some("bench") => bench(&args[1..].join(" ")),
        Some("install") => install(args.iter().any(|a| a == "--login")),
        Some("uninstall") => uninstall(),
        Some(_) => {
            let json = args.iter().any(|a| a == "--json");
            let q: Vec<&str> = args.iter().map(String::as_str).filter(|a| *a != "--json").collect();
            // The folder `git:` filters and globs are about, unless `in:` says.
            let cwd = std::env::current_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
            print_one(&serde_json::json!({"q": q.join(" "), "cwd": cwd}), json);
        }
    }
}

/// macOS's malloc (27, xzone) keeps freed small blocks dirty and its
/// pressure relief does nothing, so after the first run or a compaction the
/// daemon held 150-290 MB it no longer used, until restarted. In
/// space-efficient mode, read only at launch, it hands them back: the daemon
/// idles at 5-15 MB on the M6, for searches ~8% slower. So `serve` restarts
/// itself in it.
fn space_efficient() {
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
    // One request only: the daemon needn't keep the cores warm for a next one.
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
            unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0) };
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
    // Stop the old daemon so the next one runs the new binary. Unload the
    // login agent first, or KeepAlive would restart it straight away.
    let target = format!("{}/{LABEL}", domain());
    launchctl(&["bootout", &target]);
    server::stop(&data_dir()).unwrap_or_else(|e| die(&e));
    std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
    // Replace, never overwrite in place: a rewritten signed binary at the same
    // path can be SIGKILLed by the code-signing cache. Copy then rename, so
    // reinstalling from the installed copy works too.
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
    println!("installed {} (LaunchAgent {LABEL})\n{agents}", bin.display());
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
