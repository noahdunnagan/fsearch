//! End-to-end latency rig: the daemon as its clients use it, from outside.
//! (examples/rig.rs times searches in-process; this adds everything between
//! a keystroke or a command and its answer.)
//!
//!   e2e <transport> <corpus.json> <out.json> <plan...>    one daemon
//!   e2e dual <transport A> <transport B> <corpus.json> <out.json> <plan...>
//!       two daemons side by side, every request asked of both in turn
//!   e2e cli <bin A> <bin B> <HOME A> <HOME B> <corpus.json> <out.json> <rounds> [cats]
//!       `fsearch <query>` as a shell runs it, A and B in turn
//!   e2e launch <rounds> <command>...    process launch to exit, in turn
//!
//! transport: `stdio:<bin>[@<HOME>][#arg#arg]` spawns `<bin> stdio [args]`
//! like an app; `sock:<path>` talks to the daemon's socket directly.
//! plan (in order): `name:R` every name query, R rounds back to back;
//! `typing:R:GAP` every typing run, one request per keystroke GAP ms apart;
//! `grep:R`; `ping:N`; `connping:N` (a fresh connection each, sock only);
//! `idle:GAPS:N` N exact-name queries after each of the comma-separated
//! pauses (s). dual takes name, grep, ping and typing (back to back).
//!
//! Per request it records the wall time, the daemon's own search time
//! (took_us), and a digest of the answer without its timing fields, so
//! two builds can be checked for identical answers.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

enum Conn {
    Stdio { child: std::process::Child, w: std::process::ChildStdin, r: BufReader<std::process::ChildStdout> },
    Sock { w: UnixStream, r: BufReader<UnixStream> },
}

impl Conn {
    fn open(t: &str) -> Conn {
        if let Some(spec) = t.strip_prefix("stdio:") {
            // stdio:<bin>[@<HOME>][#extra#args]
            let mut parts = spec.split('#');
            let bin = parts.next().unwrap();
            let (bin, home) = bin.split_once('@').map_or((bin, None), |(b, h)| (b, Some(h)));
            let mut cmd = std::process::Command::new(bin);
            if let Some(h) = home {
                cmd.env("HOME", h);
            }
            let mut child =
                cmd.arg("stdio").args(parts).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().expect("spawn stdio");
            let w = child.stdin.take().unwrap();
            let r = BufReader::new(child.stdout.take().unwrap());
            Conn::Stdio { child, w, r }
        } else if let Some(p) = t.strip_prefix("sock:") {
            let s = UnixStream::connect(p).expect("connect");
            Conn::Sock { w: s.try_clone().unwrap(), r: BufReader::new(s) }
        } else {
            panic!("transport must be stdio:<bin> or sock:<path>")
        }
    }

    /// One request, one response line. Returns (wall, line).
    fn ask(&mut self, req: &str, line: &mut String) -> Duration {
        line.clear();
        let t = Instant::now();
        match self {
            Conn::Stdio { w, r, .. } => {
                w.write_all(req.as_bytes()).unwrap();
                w.flush().unwrap();
                r.read_line(line).unwrap();
            }
            Conn::Sock { w, r } => {
                w.write_all(req.as_bytes()).unwrap();
                r.read_line(line).unwrap();
            }
        }
        t.elapsed()
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let Conn::Stdio { child, .. } = self {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn fnv(h: &mut u64, b: &[u8]) {
    for &x in b {
        *h = (*h ^ x as u64).wrapping_mul(0x100_0000_01b3);
    }
}

/// took_us, and a digest of the line with timing/progress fields removed.
fn digest(line: &str) -> (Option<u64>, u64) {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let mut took = None;
    let mut rest = line.trim_end();
    for key in ["\"took_us\":", "\"indexing\":"] {
        if let Some(p) = rest.find(key) {
            let after = &rest[p + key.len()..];
            let n = after.bytes().take_while(u8::is_ascii_digit).count();
            if key.starts_with("\"took") {
                took = after[..n].parse().ok();
            }
            fnv(&mut h, &rest.as_bytes()[..p]);
            rest = &after[n..];
        }
    }
    fnv(&mut h, rest.as_bytes());
    // Another tool's daemon may report it as "ms":1.234 instead.
    if took.is_none()
        && let Some(p) = line.find("\"ms\":")
    {
        let after = &line[p + 5..];
        let n = after.bytes().take_while(|b| b.is_ascii_digit() || *b == b'.').count();
        took = after[..n].parse::<f64>().ok().map(|ms| (ms * 1e3) as u64);
    }
    (took, h)
}

#[derive(Default)]
struct Rec {
    res: serde_json::Map<String, Value>,
}

impl Rec {
    fn add(&mut self, kind: &str, cat: &str, q: &str, wall: Duration, line: &str) {
        let (took, d) = digest(line);
        let ok = line.contains("\"ok\":true");
        let e = self
            .res
            .entry(format!("{kind} {q}"))
            .or_insert_with(|| json!({"kind": kind, "cat": cat, "ms": [], "took_ms": [], "digest": format!("{d:016x}"), "ok": ok}));
        e["ms"].as_array_mut().unwrap().push((wall.as_secs_f64() * 1e3).into());
        if let Some(t) = took {
            e["took_ms"].as_array_mut().unwrap().push((t as f64 / 1e3).into());
        }
        if e["digest"] != format!("{d:016x}") {
            e["unstable"] = true.into();
        }
    }
}

fn req(q: &str) -> String {
    let mut s = json!({"q": q}).to_string();
    s.push('\n');
    s
}

/// Two daemons side by side, every request asked of both (alternating who
/// goes first), so drift on the machine hits both alike.
fn dual(a: &[String]) {
    let corpus: Value = serde_json::from_str(&std::fs::read_to_string(&a[2]).unwrap()).unwrap();
    let list = |k: &str| -> Vec<(String, String)> {
        corpus[k]
            .as_array()
            .map(|v| v.iter().map(|v| (v["cat"].as_str().unwrap().into(), v["q"].as_str().unwrap().into())).collect())
            .unwrap_or_default()
    };
    let (names, greps) = (list("names"), list("grep"));
    let mut conns = [Conn::open(&a[0]), Conn::open(&a[1])];
    let mut recs = [Rec::default(), Rec::default()];
    let mut line = String::new();
    for c in conns.iter_mut() {
        for _ in 0..3 {
            c.ask("{\"op\":\"ping\"}\n", &mut line);
        }
        for (_, q) in names.iter().chain(&greps) {
            c.ask(&req(q), &mut line);
        }
    }
    let mut turn = 0usize;
    for item in &a[4..] {
        let parts: Vec<&str> = item.split(':').collect();
        let n: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
        let (kind, set): (&str, Vec<(String, String)>) = match parts[0] {
            "name" => ("name", names.clone()),
            "grep" => ("grep", greps.clone()),
            "ping" => ("ping", vec![("ping".into(), String::new())]),
            "typing" => {
                // Back to back keystrokes, the run taking turns on A and B.
                for _ in 0..n {
                    for run in corpus["typing"].as_array().unwrap() {
                        let keys: Vec<&str> = run.as_array().unwrap().iter().map(|k| k.as_str().unwrap()).collect();
                        turn += 1;
                        for k in [turn % 2, 1 - turn % 2] {
                            conns[k].ask(&req("zzzz qqqq"), &mut line);
                            for (i, key) in keys.iter().enumerate() {
                                let w = conns[k].ask(&req(key), &mut line);
                                recs[k].add("key", if i == 0 { "first" } else { "next" }, key, w, &line);
                            }
                        }
                    }
                }
                continue;
            }
            other => panic!("unknown plan item {other}"),
        };
        for _ in 0..n {
            for (cat, q) in &set {
                let r = if kind == "ping" { "{\"op\":\"ping\"}\n".to_string() } else { req(q) };
                turn += 1;
                for k in [turn % 2, 1 - turn % 2] {
                    let w = conns[k].ask(&r, &mut line);
                    recs[k].add(kind, cat, q, w, &line);
                }
            }
        }
    }
    let mut out = serde_json::Map::new();
    out.insert("A".into(), Value::Object(recs[0].res.clone()));
    out.insert("B".into(), Value::Object(recs[1].res.clone()));
    std::fs::write(&a[3], serde_json::to_string(&out).unwrap()).unwrap();
    compare(&recs[0].res, &recs[1].res);
}

/// The CLI as a shell runs it: spawn, read all its output, wait. A and B
/// alternate per query.
fn cli(a: &[String]) {
    let (bins, homes) = ([&a[0], &a[1]], [&a[2], &a[3]]);
    let corpus: Value = serde_json::from_str(&std::fs::read_to_string(&a[4]).unwrap()).unwrap();
    let rounds: usize = a[6].parse().unwrap();
    let cats: Vec<&str> = a.get(7).map(|s| s.split(',').collect()).unwrap_or_default();
    let names: Vec<(String, String)> = corpus["names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["cat"].as_str().unwrap().to_string(), v["q"].as_str().unwrap().to_string()))
        .filter(|(c, _)| cats.is_empty() || cats.contains(&c.as_str()))
        .collect();
    let mut recs = [Rec::default(), Rec::default()];
    let run = |k: usize, q: &str| -> (Duration, String) {
        let t = Instant::now();
        let out = std::process::Command::new(bins[k])
            .arg(q)
            .env("HOME", homes[k])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .unwrap();
        (t.elapsed(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    for k in 0..2 {
        for (_, q) in &names {
            run(k, q);
        }
    }
    let mut turn = 0usize;
    for _ in 0..rounds {
        for (cat, q) in &names {
            turn += 1;
            for k in [turn % 2, 1 - turn % 2] {
                let (w, out) = run(k, q);
                recs[k].add("cli", cat, q, w, &out);
            }
        }
    }
    let mut out = serde_json::Map::new();
    out.insert("A".into(), Value::Object(recs[0].res.clone()));
    out.insert("B".into(), Value::Object(recs[1].res.clone()));
    std::fs::write(&a[5], serde_json::to_string(&out).unwrap()).unwrap();
    compare(&recs[0].res, &recs[1].res);
}

fn compare(ra: &serde_json::Map<String, Value>, rb: &serde_json::Map<String, Value>) {
    let med = |v: &Value| {
        let mut t: Vec<f64> = v["ms"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect();
        t.sort_by(f64::total_cmp);
        t[t.len() / 2]
    };
    let mut cats: std::collections::BTreeMap<(String, String), Vec<(f64, f64)>> = Default::default();
    let mut diff = Vec::new();
    for (k, va) in ra {
        let Some(vb) = rb.get(k) else { continue };
        cats.entry((va["kind"].as_str().unwrap().into(), va["cat"].as_str().unwrap().into())).or_default().push((med(va), med(vb)));
        if va["digest"] != vb["digest"] {
            diff.push(k.clone());
        }
    }
    let geo = |v: &[f64]| (v.iter().map(|m| m.max(1e-3).ln()).sum::<f64>() / v.len() as f64).exp();
    println!("{:9} {:8} {:>3}  {:>8} {:>8}  {:>6}", "kind", "cat", "n", "A ms", "B ms", "B/A");
    for ((kind, cat), p) in cats {
        let (ga, gb) = (geo(&p.iter().map(|x| x.0).collect::<Vec<_>>()), geo(&p.iter().map(|x| x.1).collect::<Vec<_>>()));
        println!("{kind:9} {cat:8} {:3}  {ga:8.3} {gb:8.3}  {:6.3}", p.len(), gb / ga);
    }
    println!("{} requests with different responses", diff.len());
    for k in diff.iter().take(10) {
        println!("  {k}");
    }
}

/// Process launch to exit, commands taking turns (rotating who goes first).
///   e2e launch <rounds> <cmd> <cmd>...   (each cmd: words split on spaces)
fn launch(a: &[String]) {
    let rounds: usize = a[0].parse().unwrap();
    let cmds: Vec<Vec<&str>> = a[1..].iter().map(|c| c.split(' ').collect()).collect();
    let mut t: Vec<Vec<f64>> = vec![Vec::new(); cmds.len()];
    let run = |c: &[&str]| {
        let t0 = Instant::now();
        std::process::Command::new(c[0])
            .args(&c[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        t0.elapsed().as_secs_f64() * 1e6
    };
    for c in &cmds {
        for _ in 0..20 {
            run(c);
        }
    }
    for r in 0..rounds {
        for k in 0..cmds.len() {
            let i = (k + r) % cmds.len();
            t[i].push(run(&cmds[i]));
        }
    }
    for (c, mut v) in a[1..].iter().zip(t) {
        v.sort_by(f64::total_cmp);
        let n = v.len();
        println!("{:>8.1} us p50 {:>8.1} p10 {:>8.1} p90  {c}", v[n / 2], v[n / 10], v[n * 9 / 10]);
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("launch") => return launch(&a[1..]),
        Some("dual") => return dual(&a[1..]),
        Some("cli") => return cli(&a[1..]),
        _ => {}
    }
    if a.len() < 4 {
        eprintln!("usage: e2e <stdio:BIN|sock:PATH> <corpus.json> <out.json> <plan...>");
        std::process::exit(2);
    }
    let transport = &a[0];
    let corpus: Value = serde_json::from_str(&std::fs::read_to_string(&a[1]).unwrap()).unwrap();
    let names: Vec<(String, String)> =
        corpus["names"].as_array().unwrap().iter().map(|v| (v["cat"].as_str().unwrap().into(), v["q"].as_str().unwrap().into())).collect();
    let greps: Vec<(String, String)> =
        corpus["grep"].as_array().unwrap().iter().map(|v| (v["cat"].as_str().unwrap().into(), v["q"].as_str().unwrap().into())).collect();
    let typing: Vec<Vec<String>> = corpus["typing"]
        .as_array()
        .map(|t| t.iter().map(|r| r.as_array().unwrap().iter().map(|k| k.as_str().unwrap().to_string()).collect()).collect())
        .unwrap_or_default();
    let mut conn = Conn::open(transport);
    let mut rec = Rec::default();
    let mut line = String::new();
    // Connected and answering (also faults in whatever the first query needs).
    for _ in 0..3 {
        conn.ask("{\"op\":\"ping\"}\n", &mut line);
    }
    for (_, q) in &names {
        conn.ask(&req(q), &mut line);
    }
    for item in &a[3..] {
        let parts: Vec<&str> = item.split(':').collect();
        let num = |i: usize, d: u64| parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);
        let t0 = Instant::now();
        match parts[0] {
            "name" => {
                for _ in 0..num(1, 3) {
                    for (cat, q) in &names {
                        let w = conn.ask(&req(q), &mut line);
                        rec.add("name", cat, q, w, &line);
                    }
                }
            }
            "typing" => {
                let gap = Duration::from_millis(num(2, 0));
                for _ in 0..num(1, 3) {
                    for run in &typing {
                        // Something else first, so the name cache can't answer the first key.
                        conn.ask(&req("zzzz qqqq"), &mut line);
                        let mut total = Duration::ZERO;
                        let mut first = Duration::ZERO;
                        for (i, k) in run.iter().enumerate() {
                            std::thread::sleep(gap);
                            let w = conn.ask(&req(k), &mut line);
                            if i == 0 {
                                first = w;
                            }
                            total += w;
                            rec.add(&format!("key{}", gap.as_millis()), if i == 0 { "first" } else { "next" }, k, w, &line);
                        }
                        let key = format!("typing{} {}", gap.as_millis(), run.last().unwrap());
                        rec.res.entry(key.clone()).or_insert_with(
                            || json!({"kind": "typing", "cat": format!("gap{}", gap.as_millis()), "ms": [], "first_ms": [], "digest": ""}),
                        );
                        let e = rec.res.get_mut(&key).unwrap();
                        e["ms"].as_array_mut().unwrap().push((total.as_secs_f64() * 1e3).into());
                        e["first_ms"].as_array_mut().unwrap().push((first.as_secs_f64() * 1e3).into());
                    }
                }
            }
            "grep" => {
                for _ in 0..num(1, 3) {
                    for (cat, q) in &greps {
                        let w = conn.ask(&req(q), &mut line);
                        rec.add("grep", cat, q, w, &line);
                    }
                }
            }
            "ping" => {
                for _ in 0..num(1, 1000) {
                    let w = conn.ask("{\"op\":\"ping\"}\n", &mut line);
                    rec.add("ping", "ping", "ping", w, &line);
                }
            }
            "connping" => {
                let p = transport.strip_prefix("sock:").expect("connping needs sock:");
                for _ in 0..num(1, 200) {
                    let t = Instant::now();
                    let mut s = UnixStream::connect(p).unwrap();
                    s.write_all(b"{\"op\":\"ping\"}\n").unwrap();
                    line.clear();
                    BufReader::new(&s).read_line(&mut line).unwrap();
                    drop(s);
                    rec.add("connping", "connping", "connping", t.elapsed(), &line);
                }
            }
            "idle" => {
                let n = num(2, 10) as usize;
                for g in parts[1].split(',') {
                    let gap = Duration::from_secs_f64(g.parse().unwrap());
                    for (cat, q) in names.iter().filter(|(c, _)| c == "exact").take(n) {
                        std::thread::sleep(gap);
                        let w = conn.ask(&req(q), &mut line);
                        rec.add(&format!("idle{g}"), cat, q, w, &line);
                    }
                }
            }
            other => panic!("unknown plan item {other}"),
        }
        eprintln!("{item}: {:.1?}", t0.elapsed());
    }
    std::fs::write(&a[2], serde_json::to_string(&rec.res).unwrap()).unwrap();
    summarize(&rec.res);
}

fn summarize(res: &serde_json::Map<String, Value>) {
    let mut cats: std::collections::BTreeMap<(String, String), (Vec<f64>, Vec<f64>)> = Default::default();
    for v in res.values() {
        let med = |k: &str| {
            let mut t: Vec<f64> = v[k].as_array().map(|a| a.iter().map(|x| x.as_f64().unwrap()).collect()).unwrap_or_default();
            t.sort_by(f64::total_cmp);
            t.get(t.len() / 2).copied()
        };
        let e = cats.entry((v["kind"].as_str().unwrap().into(), v["cat"].as_str().unwrap().into())).or_default();
        if let Some(m) = med("ms") {
            e.0.push(m);
        }
        if let Some(m) = med("took_ms") {
            e.1.push(m);
        }
    }
    let geo = |v: &[f64]| if v.is_empty() { f64::NAN } else { (v.iter().map(|m| m.max(1e-3).ln()).sum::<f64>() / v.len() as f64).exp() };
    for ((kind, cat), (wall, took)) in cats {
        println!("{kind:9} {cat:8} n={:3}  wall {:8.3} ms  daemon {:8.3} ms", wall.len(), geo(&wall), geo(&took));
    }
}
