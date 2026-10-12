use fsearch::{Engine, Options};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::PathBuf;

const USAGE: &str = r#"usage:
  fsearch index [folder ...]    build or refresh the saved index
                               no folders: reuse the previous roots, or all drives on first use
  fsearch <query...> [--json]  search the saved index
  fsearch stdio               JSON lines on stdin/stdout, using one snapshot
  fsearch status              show saved index statistics

Windows uses explicit snapshots. Run index again after files change.
Named pipes, live updates, install --login, and Windows Service support are not available yet.
Data: %LOCALAPPDATA%\FSearch. Set FSEARCH_DATA_DIR to use a separate index."#;

fn options() -> Options {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| die("USERPROFILE is not set"));
    let dir = std::env::var_os("FSEARCH_DATA_DIR").map(PathBuf::from).unwrap_or_else(|| fsearch::default_dir(&home));
    Options { dir, home, skip: None }
}

pub fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.first().map(|a| a.to_str().unwrap_or_else(|| die("commands and search queries must be valid Unicode"))) {
        None | Some("-h" | "--help") => println!("{USAGE}"),
        Some("index") => rebuild(&args[1..]),
        Some("serve" | "install" | "uninstall" | "bench") => die("this command is not supported on Windows yet; use index, stdio, or a search query"),
        Some(command) => {
            if command == "stdio" {
                let engine = Engine::start(options()).unwrap_or_else(|e| die(&e));
                stdio(&engine);
            } else {
                let raw = command == "status" || args.iter().any(|a| a == "--json");
                let query: Vec<_> = args
                    .iter()
                    .filter(|a| *a != "--json")
                    .map(|a| a.to_str().unwrap_or_else(|| die("search queries must be valid Unicode")))
                    .collect();
                let request = if command == "status" { json!({"op": "status"}) } else { json!({"q": query.join(" ")}) };
                print_one(&request, raw);
            }
        }
    }
}

fn rebuild(args: &[OsString]) {
    let opts = options();
    let roots: Vec<PathBuf> =
        if args.is_empty() { Engine::saved_roots(&opts.dir).unwrap_or_else(|e| die(&e)) } else { args.iter().map(PathBuf::from).collect() };
    eprintln!("Indexing. Inaccessible folders and reparse points are skipped.");
    let engine = Engine::rebuild(opts, &roots).unwrap_or_else(|e| die(&e));
    let status = engine.status();
    println!("Indexed {} entries and {} text files. Run fsearch index to refresh.", status.entries, status.content_docs);
}

fn stdio(engine: &Engine) {
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let mut response = Vec::new();
        crate::protocol::respond(&line, engine, &mut response);
        if out.write_all(&response).and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}

fn print_one(request: &Value, raw: bool) {
    let mut response = Vec::new();
    crate::protocol::respond_once(&request.to_string(), options(), &mut response);
    let value: Value = serde_json::from_slice(&response).unwrap();
    if raw {
        let _ = std::io::stdout().write_all(&response);
    } else if value["ok"] != true {
        die(value["error"].as_str().unwrap_or("search failed"));
    } else {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        for hit in value["hits"].as_array().into_iter().flatten() {
            let _ = writeln!(out, "{}", hit["path"].as_str().unwrap_or(""));
        }
        for file in value["files"].as_array().into_iter().flatten() {
            for m in file["matches"].as_array().into_iter().flatten() {
                let _ = writeln!(out, "{}:{}: {}", file["path"].as_str().unwrap_or(""), m["line"], m["text"].as_str().unwrap_or("").trim());
            }
        }
    }
    if value["ok"] != true {
        std::process::exit(1);
    }
}

fn die(message: &str) -> ! {
    eprintln!("fsearch: {message}");
    std::process::exit(1)
}
