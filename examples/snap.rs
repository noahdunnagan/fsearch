//! Content lab: index one folder tree (no whole-disk crawl), list what the
//! content index holds, and grep it the way the daemon does.
//!
//!   snap build <home> <dir>                 name index of <home> (and its ancestors) in
//!                                           <dir>/index.bin, content index in <dir>/content
//!   snap wants <home> <dir>                 the files a sync of <home> would index (reads
//!                                           <dir>/index.bin, building it if missing)
//!   snap measure <home> <tmp dir>           a first content build of <home>, a segment at a time,
//!                                           each deleted once measured (peak disk: one segment)
//!   snap docs <dir> <home>                  the indexed text files, one per line
//!   snap try <dir> <home> <request.json>    a grep request (as the daemon's JSON op takes
//!                                           it) against the index, answered as JSON
//!   snap grep <dir> <home> <patterns.txt>   per pattern (one a line; `regex:` for a regex),
//!                                           every file holding it, as JSON lines (smart case)

use fsearch::content::{self, Content};
use fsearch::index::Index;
use fsearch::live::Live;
use fsearch::walk::{self, KIND_DIR, Listing, RawEnt};
use fsearch::{Grep, GrepMode, Query};
use std::path::Path;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("build") => build(&a[1], Path::new(&a[2])),
        Some("docs") => docs(Path::new(&a[1])),
        Some("wants") => wants(&a[1], Path::new(&a[2])),
        Some("measure") => measure(&a[1], Path::new(&a[2])),
        Some("try") => try_grep(Path::new(&a[1]), &a[2], &a[3]),
        Some("grep") => grep(Path::new(&a[1]), &a[2], &a[3]),
        _ => eprintln!("usage: snap build <home> <dir> | snap docs <dir> <home> | snap grep <dir> <home> <patterns.txt>"),
    }
}

/// `home`'s tree, under listings for each of its ancestors (listing 0 is "/").
fn scan_home(home: &[u8]) -> Vec<Listing> {
    let mut ls = walk::scan(home, 8);
    let comps: Vec<&[u8]> = home.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
    let k = comps.len() as u32;
    for l in &mut ls {
        l.id += k;
        for e in &mut l.ents {
            if e.child != walk::NONE {
                e.child += k;
            }
        }
    }
    for (i, c) in comps.iter().enumerate() {
        let ent = RawEnt { name_off: 0, name_len: c.len() as u16, kind: KIND_DIR, size: 0, mtime: 0, child: i as u32 + 1 };
        ls.push(Listing { id: i as u32, names: c.to_vec(), ents: vec![ent] });
    }
    ls
}

fn build(home: &str, dir: &Path) {
    assert!(!dir.join("index.bin").exists(), "{} already holds an index", dir.display());
    std::fs::create_dir_all(dir).unwrap();
    let t = Instant::now();
    let idx = Index::build(scan_home(home.as_bytes()), 0, fsearch::query::now_secs(), home.as_bytes());
    idx.save(&dir.join("index.bin")).unwrap();
    let live = Live::new(Index::load(&dir.join("index.bin")).unwrap());
    let names_s = t.elapsed().as_secs_f64();
    // As the engine's first content build: 8 threads at user-initiated QoS
    // (one batch at a time).
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .start_handler(|_| unsafe {
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0);
        })
        .build()
        .unwrap();
    let t = Instant::now();
    let mut c = Content::open(dir.join("content"));
    let wants = content::wants(&live, home.as_bytes(), &[], &[home.as_bytes().to_vec()]);
    let wants_s = t.elapsed().as_secs_f64();
    let todo = c.diff(wants);
    let cdir = c.dir.clone();
    for range in todo.batches() {
        let id = c.alloc_id();
        if let Some(seg) = pool.install(|| content::build_segment(&cdir, id, &todo, range)) {
            c.push(seg);
        }
    }
    let built_s = t.elapsed().as_secs_f64();
    while let Some(ids) = c.merge_plan() {
        let id = c.alloc_id();
        let Some(seg) = pool.install(|| content::merge(&cdir, id, &c.segments(&ids))) else { break };
        c.replace(&ids, seg);
    }
    let text: usize = c.segs.iter().map(|s| (0..s.ndocs as u32).filter(|&d| !s.is_dead(d) && s.rank()[d as usize] > i8::MIN + 1).count()).sum();
    #[rustfmt::skip]
    println!(
        "{}",
        serde_json::json!({"names_s": names_s, "wants_s": wants_s, "content_s": built_s, "merged_s": t.elapsed().as_secs_f64(), "listed": todo.len(),
            "docs": c.docs(), "text_docs": text, "segments": c.segs.len(), "content_bytes": c.bytes()})
    );
}

fn wants(home: &str, dir: &Path) {
    if !dir.join("index.bin").exists() {
        std::fs::create_dir_all(dir).unwrap();
        Index::build(scan_home(home.as_bytes()), 0, fsearch::query::now_secs(), home.as_bytes()).save(&dir.join("index.bin")).unwrap();
    }
    let live = Live::new(Index::load(&dir.join("index.bin")).unwrap());
    let t = Instant::now();
    let w = content::wants(&live, home.as_bytes(), &[], &[home.as_bytes().to_vec()]);
    eprintln!("wants {:.3} s", t.elapsed().as_secs_f64());
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for (_, _, docs) in &w {
        for i in 0..docs.len() {
            use std::io::Write;
            out.write_all(docs.path(i)).unwrap();
            out.write_all(b"\n").unwrap();
        }
    }
}

fn measure(home: &str, dir: &Path) {
    let live = Live::new(Index::build(scan_home(home.as_bytes()), 0, fsearch::query::now_secs(), home.as_bytes()));
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .start_handler(|_| unsafe {
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INITIATED, 0);
        })
        .build()
        .unwrap();
    let t = Instant::now();
    let mut c = Content::open(dir.to_path_buf());
    let todo = c.diff(content::wants(&live, home.as_bytes(), &[], &[home.as_bytes().to_vec()]));
    let (mut bytes, mut docs, mut text, mut segs) = (0, 0, 0, 0);
    for range in todo.batches() {
        let id = c.alloc_id();
        if let Some(seg) = pool.install(|| content::build_segment(dir, id, &todo, range)) {
            bytes += std::fs::metadata(dir.join(format!("seg-{id:06}.fsc"))).unwrap().len();
            docs += seg.ndocs;
            text += (0..seg.ndocs).filter(|&d| seg.rank()[d] > i8::MIN + 1).count();
            segs += 1;
            drop(seg);
            std::fs::remove_file(dir.join(format!("seg-{id:06}.fsc"))).unwrap();
        }
    }
    #[rustfmt::skip]
    println!("{}", serde_json::json!({"content_s": t.elapsed().as_secs_f64(), "docs": docs, "text_docs": text, "segments": segs, "unmerged_bytes": bytes}));
}

/// The content side of the daemon's grep op (see server.rs), for testing.
fn try_grep(dir: &Path, home: &str, req: &str) {
    use serde_json::{Value, json};
    let v: Value = serde_json::from_str(req).unwrap();
    let c = Content::open_shared(dir.join("content"));
    let mut q = Query::parse(v["q"].as_str().unwrap_or(""), home).unwrap();
    q.limit = v["limit"].as_u64().map_or(q.limit, |n| n as usize);
    let case = match v["case"].as_str() {
        Some("sensitive") => fsearch::Case::Sensitive,
        Some("insensitive") => fsearch::Case::Insensitive,
        _ => fsearch::Case::Smart,
    };
    let mode = match v["mode"].as_str() {
        Some("regex") => GrepMode::Regex,
        Some("symbol") => GrepMode::Symbol,
        _ => q.grep_mode,
    };
    let mut g = match v["patterns"].as_array() {
        Some(ps) => Grep::any_of(&ps.iter().filter_map(Value::as_str).collect::<Vec<_>>(), case).unwrap(),
        None => Grep::with_case(&v["pattern"].as_str().map(str::to_string).or(q.grep.take()).unwrap(), mode, case).unwrap(),
    };
    g.budget = None;
    let num = |k: &str| v[k].as_u64().map(|n| n as usize);
    g.max_per_file = num("per_file").unwrap_or(g.max_per_file);
    (g.before, g.after) = (num("before").or(num("context")).unwrap_or(0), num("after").or(num("context")).unwrap_or(0));
    g.defs = v["defs"].as_bool().unwrap_or(false);
    g.skip = num("cursor").unwrap_or(0);
    let fresh: Vec<Vec<u8>> = v["fresh"].as_array().into_iter().flatten().filter_map(Value::as_str).map(|s| s.as_bytes().to_vec()).collect();
    let r = match v["file"].as_str() {
        Some(f) => content::verify(&g, &[f.as_bytes()], 1),
        None => c.search_with(&g, &q, &fresh),
    };
    let files: Vec<Value> = (r.files.iter())
        .map(|f| {
            let hit = |((n, t), h): (&(usize, String), &fsearch::Hit)| {
                json!({"line": n, "text": t, "col": h.col, "ranges": h.ranges, "def": h.def, "before": h.before, "after": h.after})
            };
            let m: Vec<Value> = f.lines.iter().zip(&f.hits).map(hit).collect();
            json!({"path": String::from_utf8_lossy(&f.path), "matches": m})
        })
        .collect();
    let out = json!({"pattern": g.pattern, "candidates": r.candidates, "read": r.read, "complete": r.complete, "next": r.next, "files": files});
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn docs(dir: &Path) {
    let c = Content::open_shared(dir.join("content"));
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for s in &c.segs {
        for d in (0..s.ndocs as u32).filter(|&d| !s.is_dead(d) && s.rank()[d as usize] > i8::MIN + 1) {
            use std::io::Write;
            out.write_all(&s.path(d)).unwrap();
            out.write_all(b"\n").unwrap();
        }
    }
}

fn grep(dir: &Path, home: &str, patterns: &str) {
    let c = Content::open_shared(dir.join("content"));
    for p in std::fs::read_to_string(patterns).unwrap().lines().filter(|l| !l.is_empty()) {
        let mut g = match p.strip_prefix("regex:") {
            Some(re) => Grep::new(re, GrepMode::Regex).unwrap(),
            None => Grep::new(p, GrepMode::Literal).unwrap(),
        };
        g.budget = None;
        g.max_per_file = 1;
        let mut q = Query::parse("", home).unwrap();
        q.limit = usize::MAX;
        let t = Instant::now();
        let r = c.search(&g, &q);
        let files: Vec<String> = r.files.iter().map(|f| String::from_utf8_lossy(&f.path).into_owned()).collect();
        println!("{}", serde_json::json!({"pattern": p, "ms": t.elapsed().as_secs_f64() * 1e3, "read": r.read, "files": files}));
    }
}
