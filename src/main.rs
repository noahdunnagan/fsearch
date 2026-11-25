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

#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    Help,
    Serve,
    Stdio,
    Mcp,
    Status,
    Version,
    Bench(String),
    Install { login: bool },
    Uninstall,
    Search { query: String, json: bool },
}

fn dispatch(args: &[String]) -> Cmd {
    let strs: Vec<&str> = args.iter().map(String::as_str).collect();
    match strs.as_slice() {
        [] | ["-h" | "--help", ..] => Cmd::Help,
        ["serve"] => Cmd::Serve,
        ["stdio"] => Cmd::Stdio,
        ["mcp"] => Cmd::Mcp,
        ["status"] => Cmd::Status,
        ["version" | "--version"] => Cmd::Version,
        ["bench", rest @ ..] => Cmd::Bench(rest.join(" ")),
        ["install"] => Cmd::Install { login: false },
        ["install", "--login"] => Cmd::Install { login: true },
        ["uninstall"] => Cmd::Uninstall,
        _ => {
            let json = strs.contains(&"--json");
            let q: Vec<&str> = strs.into_iter().filter(|&a| a != "--json").collect();
            Cmd::Search { query: q.join(" "), json }
        }
    }
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn main() {
    // Never let a search download iCloud placeholders: opening or listing a
    // dataless file/dir fails fast instead of materializing it.
    // (IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_PROCESS, OFF)
    unsafe { setiopolicy_np(3, 0, 1) };
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Cmd::Help => eprintln!("{USAGE}"),
        Cmd::Serve => {
            space_efficient();
            server::serve(data_dir(), home())
        }
        Cmd::Stdio => stdio(),
        Cmd::Mcp => mcp::run(data_dir()),
        Cmd::Status => print_one(&serde_json::json!({"op": "status"}), true),
        Cmd::Version => println!("fsearch {}", env!("CARGO_PKG_VERSION")),
        Cmd::Bench(q) => bench(&q),
        Cmd::Install { login } => install(login),
        Cmd::Uninstall => uninstall(),
        Cmd::Search { query, json } => {
            // The folder `git:` filters and globs are about, unless `in:` says.
            let cwd = std::env::current_dir().map(|d| d.to_string_lossy().into_owned()).unwrap_or_default();
            print_one(&serde_json::json!({"q": query, "cwd": cwd}), json);
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
    s.write_all(format!("{req}\n").as_bytes()).unwrap_or_else(|e| die(&format!("daemon error: {e}")));
    // One request only: the daemon needn't keep the cores warm for a next one.
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut line = String::new();
    BufReader::new(&s).read_line(&mut line).unwrap_or_else(|e| die(&format!("daemon error: {e}")));
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
        let r = if q.scope.as_ref().is_none_or(|s| fsearch::content::in_scope(s, home.as_bytes()) && c.holds(s)) {
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
    let bin_xml = xml_escape(&bin.display().to_string());
    let log_xml = xml_escape(&log.display().to_string());
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{bin_xml}</string><string>serve</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log_xml}</string>
  <key>StandardErrorPath</key><string>{log_xml}</string>
</dict>
</plist>
"#
    );
    let plist_file = plist_path();
    std::fs::create_dir_all(plist_file.parent().unwrap()).unwrap();
    std::fs::write(&plist_file, plist).unwrap();
    // bootout returns before the old job is fully gone; bootstrap fails
    // until it is.
    let bootstrap = || launchctl(&["bootstrap", &domain(), plist_file.to_str().unwrap()]);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_string()).collect()
    }

    #[test]
    fn xml_escape_escapes_special_chars() {
        assert_eq!(xml_escape(r#"a&b<c>d"e'f"#), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(xml_escape("/Users/alice/Library/Application Support/FSearch"), "/Users/alice/Library/Application Support/FSearch");
    }

    #[test]
    fn dispatch_zero_arg_subcommands_require_exact_arity() {
        assert_eq!(dispatch(&s(&[])), Cmd::Help);
        assert_eq!(dispatch(&s(&["-h"])), Cmd::Help);
        assert_eq!(dispatch(&s(&["--help", "extra"])), Cmd::Help);
        assert_eq!(dispatch(&s(&["serve"])), Cmd::Serve);
        assert_eq!(dispatch(&s(&["stdio"])), Cmd::Stdio);
        assert_eq!(dispatch(&s(&["mcp"])), Cmd::Mcp);
        assert_eq!(dispatch(&s(&["status"])), Cmd::Status);
        assert_eq!(dispatch(&s(&["version"])), Cmd::Version);
        assert_eq!(dispatch(&s(&["--version"])), Cmd::Version);
        assert_eq!(dispatch(&s(&["uninstall"])), Cmd::Uninstall);
        assert_eq!(dispatch(&s(&["install"])), Cmd::Install { login: false });
        assert_eq!(dispatch(&s(&["install", "--login"])), Cmd::Install { login: true });
        assert_eq!(dispatch(&s(&["bench", "foo", "bar"])), Cmd::Bench("foo bar".into()));

        // Multi-word queries starting with subcommand names must search, not run the subcommand.
        assert_eq!(dispatch(&s(&["status", "foo"])), Cmd::Search { query: "status foo".into(), json: false });
        assert_eq!(dispatch(&s(&["version", "check"])), Cmd::Search { query: "version check".into(), json: false });
        assert_eq!(dispatch(&s(&["serve", "http"])), Cmd::Search { query: "serve http".into(), json: false });
        assert_eq!(dispatch(&s(&["install", "script"])), Cmd::Search { query: "install script".into(), json: false });
        assert_eq!(dispatch(&s(&["foo", "--json"])), Cmd::Search { query: "foo".into(), json: true });
    }
}
