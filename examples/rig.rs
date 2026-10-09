//! Speed rig: times every kind of search against a frozen copy of an index,
//! in-process, and fingerprints the results so a speedup can be checked for
//! identical output.
//!
//!   rig gen <snap dir> <corpus.json>            sample queries from the index
//!   rig run <snap dir> <corpus.json> <out.json> time them
//!
//! `<snap dir>` holds `index.bin` and `content/` (APFS clones of the live
//! ones, so the daemon keeps running untouched). Compare builds with
//! `demo/abba.py`.

use fsearch::Grep;
use fsearch::content::{self, Content};
use fsearch::index::Index;
use fsearch::live::Live;
use fsearch::query::{Query, Searcher};
use serde_json::{Value, json};
use std::path::Path;
use std::time::{Duration, Instant};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("gen") => gen_corpus(Path::new(&a[1]), &a[2]),
        Some("run") => run(Path::new(&a[1]), &a[2], &a[3]),
        _ => eprintln!("usage: rig gen <snap> <corpus.json> | rig run <snap> <corpus.json> <out.json>"),
    }
}

fn home() -> String {
    std::env::var("HOME").unwrap()
}

/// Deterministic xorshift, so every build samples the same corpus.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn gen_corpus(snap: &Path, out: &str) {
    let idx = Index::load(&snap.join("index.bin")).expect("index");
    let ne = idx.name_ents_off();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let text = |k: usize| String::from_utf8_lossy(idx.uname(k as u32)).into_owned();
    let mut names: Vec<(String, String)> = Vec::new();
    let mut push = |cat: &str, q: String| names.push((cat.into(), q));

    // Unique names people would type: the exact name, then one typo of it.
    let mut targets = Vec::new();
    while targets.len() < 60 {
        let k = rng.below(idx.u);
        let n = text(k);
        // Words, not cache hashes: mostly letters, no long hex runs.
        let letters = n.chars().filter(char::is_ascii_alphabetic).count();
        let hexy = n.as_bytes().windows(8).any(|w| w.iter().all(u8::is_ascii_hexdigit));
        if ne[k + 1] - ne[k] == 1 && (6..=32).contains(&n.len()) && n.is_ascii() && !n.contains(' ') && letters * 10 >= n.len() * 7 && !hexy {
            targets.push((k, n));
        }
    }
    for (_, t) in &targets {
        push("exact", t.clone());
    }
    for (i, (_, t)) in targets.iter().enumerate() {
        let mut s: Vec<char> = t.chars().collect();
        let letters: Vec<usize> = (1..s.len()).filter(|&i| s[i].is_ascii_alphabetic()).collect();
        let p = letters[rng.below(letters.len())];
        match i % 4 {
            0 if p + 1 < s.len() && s[p + 1].is_ascii_alphabetic() && s[p] != s[p + 1] => s.swap(p, p + 1),
            1 => {
                s.remove(p);
            }
            2 => s.insert(p, (b'a' + rng.below(26) as u8) as char),
            _ => s[p] = if s[p].eq_ignore_ascii_case(&'x') { 'q' } else { 'x' },
        }
        push("typo", s.into_iter().collect());
    }
    // Common short words (names many entries share), and folder + name pairs.
    let mut words = std::collections::BTreeSet::new();
    while words.len() < 30 {
        let k = rng.below(idx.u);
        let stem = text(k).split('.').next().unwrap_or("").to_ascii_lowercase();
        if ne[k + 1] - ne[k] >= 20 && (3..=10).contains(&stem.len()) && stem.chars().all(|c| c.is_ascii_lowercase()) {
            words.insert(stem);
        }
    }
    for w in words {
        push("word", w);
    }
    for (k, t) in targets.iter().take(30) {
        let e = idx.name_ents()[ne[*k] as usize] as usize;
        let dir = idx.dir_entry()[idx.parent()[e] as usize] as usize;
        let folder = String::from_utf8_lossy(idx.name(dir)).into_owned();
        let stem = t.split('.').next().unwrap_or(t);
        push("multi", format!("{} {stem}", folder.split(['.', ' ']).next().unwrap_or("")));
    }
    #[rustfmt::skip]
    let filters = [
        "ext:rs engine", "type:image screenshot", "kind:dir node_modules", "type:app safari", "in:~/Developer main",
        "size:>100mb", "mtime:<1d", "re:^IMG_[0-9]+", "path:Developer.*swift$ view", "main !test", "'main.rs", "^Cargo",
        "toml$", "ext:pdf", "a", "e s", "in:~/Developer ext:md readme", "type:code mtime:<7d", "kind:file size:>1gb", "Developer/Tools fsearch",
    ];
    for f in filters {
        push("filter", f.into());
    }
    let typing: Vec<Vec<String>> = targets.iter().take(10).map(|(_, t)| (1..=t.len()).map(|n| t[..n].to_string()).collect()).collect();

    // Content: rare identifiers from random indexed files, then common words,
    // regexes, definitions, scoped and unindexed-folder searches.
    let content = Content::open_shared(snap.join("content"));
    let ident = regex::Regex::new(r"\b[a-z][a-z0-9_]{9,30}\b").unwrap();
    let mut rare = std::collections::BTreeSet::new();
    let docs: Vec<(usize, u32)> = content
        .segs
        .iter()
        .enumerate()
        .flat_map(|(si, s)| (0..s.ndocs as u32).filter(move |&d| !s.is_dead(d) && s.rank()[d as usize] >= 0).map(move |d| (si, d)))
        .collect();
    while rare.len() < 40 {
        let (si, d) = docs[rng.below(docs.len())];
        let Ok(body) = std::fs::read_to_string(std::str::from_utf8(content.segs[si].path(d)).unwrap_or("")) else { continue };
        let found: Vec<&str> = ident.find_iter(&body).map(|m| m.as_str()).collect();
        if !found.is_empty() {
            rare.insert(format!("grep:{}", found[rng.below(found.len())]));
        }
    }
    let mut grep: Vec<(String, String)> = rare.into_iter().map(|q| ("rare".to_string(), q)).collect();
    #[rustfmt::skip]
    let fixed = [
        ("common", "grep:TODO"), ("common", "grep:import"), ("common", "\"grep:fn main\""), ("common", "grep:return"), ("common", "\"grep:use std\""),
        ("common", "grep:struct"), ("common", "\"grep:async fn\""), ("common", "grep:localhost"),
        ("regex", r"regex:fn\s+\w+_score"), ("regex", "regex:TODO|FIXME"), ("regex", r"regex:impl\s+\w+\s+for"), ("regex", "regex:[A-Z]{3,}_[A-Z]{3,}"),
        ("sym", "sym:Engine"), ("sym", "sym:main"), ("sym", "sym:Searcher"), ("sym", "sym:render"), ("sym", "sym:Config"),
        ("scoped", "ext:rs grep:unsafe"), ("scoped", "in:~/Developer grep:TODO"), ("scoped", "ext:md grep:install"), ("scoped", "in:~/Developer/Tools/FSearch grep:fold"),
        ("scan", "in:/etc grep:localhost"), ("scan", "in:/usr/share/doc grep:license"),
    ];
    grep.extend(fixed.iter().map(|(c, q)| (c.to_string(), q.to_string())));
    let corpus = json!({
        "names": names.iter().map(|(c, q)| json!({"cat": c, "q": q})).collect::<Vec<_>>(),
        "typing": typing,
        "grep": grep.iter().map(|(c, q)| json!({"cat": c, "q": q})).collect::<Vec<_>>(),
    });
    std::fs::write(out, serde_json::to_string_pretty(&corpus).unwrap()).unwrap();
    eprintln!("{} name queries, {} typing runs, {} content queries", names.len(), typing.len(), grep.len());
}

fn fnv(h: &mut u64, b: &[u8]) {
    for &x in b {
        *h = (*h ^ x as u64).wrapping_mul(0x100_0000_01b3);
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// A name search as the daemon answers it: parse, search, then each hit's
/// path. Returns the result fingerprint.
fn name_search(live: &Live, pool: &rayon::ThreadPool, q: &str, home: &str) -> u64 {
    let q = Query::parse(q, home).unwrap();
    let hits = pool.install(|| Searcher { live }.search(&q));
    let (mut h, mut p) = (0xcbf2_9ce4_8422_2325u64, Vec::new());
    for hit in hits {
        live.base.path(hit.idx as usize, &mut p);
        fnv(&mut h, &p);
        fnv(&mut h, &hit.score.to_le_bytes());
    }
    h
}

/// A content search as the daemon answers it (see `Engine::grep`).
fn grep_search(live: &Live, content: &Content, pool: &rayon::ThreadPool, q: &str, home: &str, budget: Option<Duration>) -> (u64, usize) {
    let mut q = Query::parse(q, home).unwrap();
    let mode = q.grep_mode;
    let mut g = Grep::new(&q.grep.take().unwrap(), mode).unwrap();
    g.budget = budget;
    let indexed = q.scope.as_ref().is_none_or(|s| content::in_scope(s, home.as_bytes()));
    let r = if indexed {
        pool.install(|| content.search(&g, &q))
    } else {
        let paths = pool.install(|| content::scan_paths(live, q.clone_for_scan()));
        content::verify(&g, &paths, q.limit)
    };
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for f in &r.files {
        fnv(&mut h, &f.path);
        for (n, t) in &f.lines {
            fnv(&mut h, &n.to_le_bytes());
            fnv(&mut h, t.as_bytes());
        }
    }
    (h, r.read)
}

fn run(snap: &Path, corpus: &str, out: &str) {
    let corpus: Value = serde_json::from_str(&std::fs::read_to_string(corpus).unwrap()).unwrap();
    let home = home();
    let t = Instant::now();
    let live = Live::new(Index::load(&snap.join("index.bin")).expect("index"));
    let content = Content::open_shared(snap.join("content"));
    let load = ms(t.elapsed());
    let pool = rayon::ThreadPoolBuilder::new()
        .start_handler(|_| unsafe {
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0);
        })
        .build()
        .unwrap();
    let mut res = serde_json::Map::new();
    let mut record = |kind: &str, cat: &str, q: &str, t: f64, digest: u64| {
        let e = res.entry(format!("{kind} {q}")).or_insert_with(|| json!({"kind": kind, "cat": cat, "ms": [], "digest": format!("{digest:016x}")}));
        e["ms"].as_array_mut().unwrap().push(t.into());
        if e["digest"] != format!("{digest:016x}") {
            e["unstable"] = true.into();
        }
    };
    let names: Vec<(String, String)> =
        corpus["names"].as_array().unwrap().iter().map(|v| (v["cat"].as_str().unwrap().into(), v["q"].as_str().unwrap().into())).collect();
    // Warm: one pass to fault things in, then rounds where every query
    // follows a different one (so the name cache never answers).
    for (_, q) in &names {
        name_search(&live, &pool, q, &home);
    }
    for _ in 0..7 {
        for (cat, q) in &names {
            let t = Instant::now();
            let d = name_search(&live, &pool, q, &home);
            record("name", cat, q, ms(t.elapsed()), d);
        }
    }
    // After an idle spell the daemon has dropped its cache and spare buffers.
    for _ in 0..3 {
        for (cat, q) in &names {
            live.names_cache.trim_if_idle(Duration::ZERO);
            let t = Instant::now();
            let d = name_search(&live, &pool, q, &home);
            record("idle", cat, q, ms(t.elapsed()), d);
        }
    }
    // Typing: each keystroke is a query; the run's total is what you wait.
    for _ in 0..5 {
        for run in corpus["typing"].as_array().unwrap() {
            live.names_cache.trim_if_idle(Duration::ZERO);
            let keys: Vec<&str> = run.as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
            let (t, mut d) = (Instant::now(), 0u64);
            for k in &keys {
                d ^= name_search(&live, &pool, k, &home);
            }
            record("typing", "typing", keys.last().unwrap(), ms(t.elapsed()), d);
        }
    }
    let greps: Vec<(String, String)> =
        corpus["grep"].as_array().unwrap().iter().map(|v| (v["cat"].as_str().unwrap().into(), v["q"].as_str().unwrap().into())).collect();
    for (_, q) in &greps {
        grep_search(&live, &content, &pool, q, &home, None);
    }
    for _ in 0..5 {
        for (cat, q) in &greps {
            let t = Instant::now();
            let (d, _) = grep_search(&live, &content, &pool, q, &home, None);
            record("grep", cat, q, ms(t.elapsed()), d);
        }
    }
    res.insert("load_ms".into(), load.into());
    std::fs::write(out, serde_json::to_string(&res).unwrap()).unwrap();
    summarize(&res);
}

fn summarize(res: &serde_json::Map<String, Value>) {
    let mut cats: std::collections::BTreeMap<(String, String), Vec<f64>> = Default::default();
    for v in res.values().filter(|v| v.is_object()) {
        let mut t: Vec<f64> = v["ms"].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect();
        t.sort_by(f64::total_cmp);
        cats.entry((v["kind"].as_str().unwrap().into(), v["cat"].as_str().unwrap().into())).or_default().push(t[t.len() / 2]);
    }
    for ((kind, cat), meds) in cats {
        let geo = (meds.iter().map(|m| m.max(1e-3).ln()).sum::<f64>() / meds.len() as f64).exp();
        let max = meds.iter().cloned().fold(0.0, f64::max);
        println!("{kind:7} {cat:8} n={:3}  geomean {geo:8.3} ms  worst {max:8.2} ms", meds.len());
    }
}
