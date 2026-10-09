//! Engine end to end over a temp folder: build, search, live FSEvents
//! updates, content search, saving, and owner/follower handoff.

mod common;

use common::{Outside, Scratch, hold_lock, real, root, saved, wait_for};
use fsearch::{Engine, Grep, GrepMode, Options, Query};
use std::path::{Path, PathBuf};

fn start(dir: &Path, home: &Path) -> Engine {
    Engine::start(Options { dir: dir.into(), home: real(home), skip: Some(vec![]) }).unwrap()
}

fn ready(e: &Engine) {
    wait_for(30, "the index", || e.status().ready);
}

fn names(e: &Engine, q: &str) -> Vec<PathBuf> {
    let q = Query::parse(q, e.home()).unwrap();
    e.search(&q).unwrap().into_iter().map(|f| f.path).collect()
}

fn finds(e: &Engine, q: &str, p: &Path) -> bool {
    let p = std::fs::canonicalize(p).unwrap_or(p.into());
    names(e, q).contains(&p)
}

#[test]
fn indexes_follows_changes_and_saves() {
    let s = Scratch::new();
    let a = s.write("home/proj/zebrafile.txt", "hello needle world\n");
    s.write("home/proj/other.rs", "fn main() {}\n");
    let e = start(&s.path("data"), &s.mkdir("home"));
    ready(&e);
    let st = e.status();
    assert!(st.owner && st.entries > 0 && st.dirs > 0 && st.index_bytes > 0 && st.full_disk_access);
    assert!(finds(&e, "zebrafile", &a));
    let f = e.search(&Query::parse("zebrafile", e.home()).unwrap()).unwrap();
    assert_eq!((f[0].size, f[0].kind), (19, fsearch::walk::KIND_FILE));
    assert!(s.path("data/index.bin").exists());
    // An empty `skipped`: nothing was out of reach.
    assert_eq!(std::fs::read(s.path("data/skipped")).unwrap(), b"");

    // Live: create, then delete, through FSEvents.
    let b = s.write("home/proj/new/quaggafile.md", "another needle\n");
    wait_for(10, "a new file", || finds(&e, "quaggafile", &b));
    assert!(e.status().overlay > 0);
    std::fs::remove_file(&a).unwrap();
    wait_for(10, "a removed file", || !finds(&e, "zebrafile", &a));
    assert!(e.status().removed > 0);

    // Saving folds the overlay into a new base.
    saved(&s.path("data"), || e.save());
    wait_for(10, "the new base", || e.status().removed == 0);
    assert!(finds(&e, "quaggafile", &b));
    assert!(!finds(&e, "zebrafile", &a));

    // Content: home is indexed, so grep answers from the index.
    wait_for(20, "content indexing", || e.status().content_docs >= 2 && e.status().content_pending == 0);
    let g = Grep::new("needle", GrepMode::Literal).unwrap();
    let q = Query::parse("", e.home()).unwrap();
    let (r, indexed) = e.grep(&q, &g).unwrap();
    assert!(indexed);
    let hits: Vec<String> = r.files.iter().map(|f| String::from_utf8_lossy(&f.path).into_owned()).collect();
    assert_eq!(hits, vec![real(&b)]);
    assert!(e.status().content_segments > 0 && e.status().content_bytes > 0);

    // Outside home: files are picked from the name index and read.
    let c = s.write("elsewhere/notes.txt", "a needle outside home\n");
    wait_for(10, "a file outside home", || finds(&e, "notes", &c));
    let q = Query::parse(&format!("in:{}", s.path("elsewhere").display()), e.home()).unwrap();
    let (r, indexed) = e.grep(&q, &g).unwrap();
    assert!(!indexed);
    assert_eq!(r.files.len(), 1);
}

#[test]
fn a_new_folder_is_scanned_whole() {
    let s = Scratch::new();
    let e = start(&s.path("data"), &s.mkdir("home"));
    ready(&e);
    // Built elsewhere and moved in: one event for the parent only.
    let tmp = Scratch::new();
    tmp.write("deep/a/b/c/okapifile", "");
    std::fs::rename(tmp.path("deep"), s.path("home/deep")).unwrap();
    wait_for(10, "a moved-in subtree", || finds(&e, "okapifile", &s.path("home/deep/a/b/c/okapifile")));
    std::fs::remove_dir_all(s.path("home/deep")).unwrap();
    wait_for(10, "a removed subtree", || names(&e, "okapifile").is_empty());
}

#[test]
fn restart_loads_the_saved_index_and_replays() {
    let s = Scratch::new();
    let home = s.mkdir("home");
    let data = s.path("data");
    let a = s.write("home/ibexfile", "");
    {
        let e = start(&data, &home);
        ready(&e);
    }
    // Same process, so the first engine still holds the lock: copy its
    // index to a fresh dir to start an owner from a saved index.
    let data2 = s.mkdir("data2");
    std::fs::copy(data.join("index.bin"), data2.join("index.bin")).unwrap();
    std::fs::copy(data.join("skipped"), data2.join("skipped")).unwrap();
    // Changed after the save: the replay of history brings it in.
    let b = s.write("home/yakfile", "");
    let e = start(&data2, &home);
    ready(&e);
    assert!(e.status().owner);
    assert!(finds(&e, "ibexfile", &a));
    wait_for(10, "a replayed change", || finds(&e, "yakfile", &b));
}

/// A follower reads the owner's index, picks up its saves promptly (even
/// when its dir is given through a symlink, as temp dirs are), and takes
/// over when the owner lets go.
/// A data dir outside the indexed root still gets events: a follower sees
/// the owner's save there without waiting for its fallback check.
#[test]
fn follower_follows_a_data_dir_outside_the_root() {
    let s = Scratch::new();
    let home = s.mkdir("home");
    s.write("home/yakfile", "");
    let owner = start(&s.path("data"), &home);
    ready(&owner);

    let out = Outside::new("follower-data");
    assert!(!out.0.starts_with(root()));
    std::fs::copy(s.path("data/index.bin"), out.0.join("index.bin")).unwrap();
    let _held = hold_lock(&out.0.join("daemon.lock"));
    let f = start(&out.0, &home);
    ready(&f);
    assert!(!f.status().owner);

    let b = s.write("home/elkfile", "");
    wait_for(10, "the owner's update", || finds(&owner, "elkfile", &b));
    saved(&s.path("data"), || owner.save());
    let want = fsearch::index::Index::load(&s.path("data/index.bin")).unwrap().n;
    let tmp = out.0.join("index.tmp");
    std::fs::copy(s.path("data/index.bin"), &tmp).unwrap();
    std::fs::rename(&tmp, out.0.join("index.bin")).unwrap();
    wait_for(5, "the follower to reload", || f.status().entries == want);
}

#[test]
fn follower_follows_then_takes_over() {
    let s = Scratch::new();
    let home = s.mkdir("home");
    s.write("home/emufile", "");
    let owner = start(&s.path("data"), &home);
    ready(&owner);

    // `std::env::temp_dir()` is under /var, a symlink to /private/var.
    let fdir = s.mkdir("fdata");
    assert_ne!(real(&fdir), fdir.to_string_lossy());
    std::fs::copy(s.path("data/index.bin"), fdir.join("index.bin")).unwrap();
    std::fs::copy(s.path("data/skipped"), fdir.join("skipped")).unwrap();
    let held = hold_lock(&fdir.join("daemon.lock"));
    let f = start(&fdir, &home);
    ready(&f);
    assert!(!f.status().owner);
    assert!(finds(&f, "emufile", &s.path("home/emufile")));
    // A follower tracks changes itself, in its overlay.
    let b = s.write("home/gnufile", "");
    wait_for(10, "the follower's own update", || finds(&f, "gnufile", &b));
    assert!(f.status().overlay > 0);

    // The owner saves; the follower reloads that save (well before its
    // 10 s fallback check).
    wait_for(10, "the owner's update", || finds(&owner, "gnufile", &b));
    saved(&s.path("data"), || owner.save());
    let want = fsearch::index::Index::load(&s.path("data/index.bin")).unwrap().n;
    let tmp = fdir.join("index.tmp");
    std::fs::copy(s.path("data/index.bin"), &tmp).unwrap();
    std::fs::rename(&tmp, fdir.join("index.bin")).unwrap();
    wait_for(5, "the follower to reload", || f.status().entries == want);
    // The owner's content changes are reopened too.
    s.write("fdata/content/poke", "");
    assert!(finds(&f, "gnufile", &b));

    // The owner goes away; the next event lets the follower take over.
    drop(held);
    s.write("fdata/poke", "");
    wait_for(10, "the takeover", || f.status().owner);
    s.write("home/kudufile.txt", "kudu needle\n");
    wait_for(20, "content indexing by the new owner", || f.status().content_docs > 0);
}

/// A follower started before any index exists waits for the owner's first
/// build, and builds it itself if the owner quits first.
#[test]
fn follower_builds_when_the_owner_quits_before_saving() {
    let s = Scratch::new();
    let home = s.mkdir("home");
    let a = s.write("home/tapirfile", "");
    let dir = s.mkdir("data");
    let held = hold_lock(&dir.join("daemon.lock"));
    let f = start(&dir, &home);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(!f.status().ready);
    assert!(f.search(&Query::parse("x", f.home()).unwrap()).is_err());
    let g = Grep::new("x", GrepMode::Literal).unwrap();
    assert!(f.grep(&Query::parse("in:/private/tmp", f.home()).unwrap(), &g).is_err());
    drop(held);
    wait_for(10, "the follower to build", || f.status().ready);
    assert!(f.status().owner);
    assert!(finds(&f, "tapirfile", &a));
    assert!(dir.join("index.bin").exists());
}

/// A follower whose owner builds the first index picks it up.
#[test]
fn follower_waits_for_the_first_index() {
    let s = Scratch::new();
    let home = s.mkdir("home");
    let a = s.write("home/lemurfile", "");
    let dir = s.mkdir("data");
    let held = hold_lock(&dir.join("daemon.lock"));
    let f = start(&dir, &home);
    // Stand in for the owner: build an index elsewhere and save it here.
    let other = start(&s.path("data2"), &home);
    ready(&other);
    std::fs::copy(s.path("data2/index.bin"), dir.join("index.bin")).unwrap();
    wait_for(10, "the follower to load", || f.status().ready);
    assert!(!f.status().owner);
    assert!(finds(&f, "lemurfile", &a));
    drop(held);
}

/// Folders the saved index lacked (listed in `skipped`, or the gated ones
/// when there is no such file) are rescanned at startup once readable.
#[test]
fn rescans_what_the_saved_index_lacked() {
    use std::os::unix::fs::PermissionsExt;
    let s = Scratch::new();
    let home = s.mkdir("home");
    let shut = s.write("home/shut/hidden/okapi_inner", "");
    let docs = s.write("home/Documents/gatedfile", "");
    let set = |p: &str, mode| std::fs::set_permissions(s.path(p), std::fs::Permissions::from_mode(mode)).unwrap();
    // Unreadable during the build: their entries are there, their
    // contents not, and no later event brings them back.
    set("home/shut", 0o000);
    set("home/Documents", 0o000);
    let e = start(&s.path("data"), &home);
    ready(&e);
    set("home/shut", 0o755);
    set("home/Documents", 0o755);
    // Saved past those changes, so a restart doesn't replay them.
    std::thread::sleep(std::time::Duration::from_millis(500));
    saved(&s.path("data"), || e.save());
    assert!(names(&e, "okapi_inner").is_empty());
    assert!(names(&e, "gatedfile").is_empty());

    // `skipped` names one folder (and one that is gone).
    let d1 = s.mkdir("d1");
    std::fs::copy(s.path("data/index.bin"), d1.join("index.bin")).unwrap();
    std::fs::write(d1.join("skipped"), format!("{}\n\n{}/gone\n", real(&s.path("home/shut")), real(&home))).unwrap();
    let e1 = start(&d1, &home);
    ready(&e1);
    wait_for(10, "the rescan", || finds(&e1, "okapi_inner", &shut));
    assert!(names(&e1, "gatedfile").is_empty());
    // Saved straight after, with nothing left out.
    wait_for(10, "the save after a rescan", || std::fs::read(d1.join("skipped")).unwrap().is_empty());

    // No `skipped` (a save from before it existed): the gated folders.
    let d2 = s.mkdir("d2");
    std::fs::copy(s.path("data/index.bin"), d2.join("index.bin")).unwrap();
    let e2 = start(&d2, &home);
    ready(&e2);
    wait_for(10, "the gated rescan", || finds(&e2, "gatedfile", &docs));
    wait_for(10, "the save after a rescan", || d2.join("skipped").exists());
}

#[test]
fn start_fails_when_the_dir_cannot_be_made() {
    let s = Scratch::new();
    s.write("file", "");
    let r = Engine::start(Options { dir: s.path("file/data"), home: real(&s.0), skip: Some(vec![]) });
    assert!(r.is_err());
    s.mkdir("d/daemon.lock");
    assert!(Engine::start(Options { dir: s.path("d"), home: real(&s.0), skip: Some(vec![]) }).is_err());
}

#[test]
fn helpers() {
    common::root();
    let g = fsearch::gated("/Users/x");
    assert!(g.contains(&b"/Users/x/Desktop".to_vec()) && g.contains(&b"/Volumes".to_vec()));
    assert_eq!(fsearch::default_dir("/Users/x"), PathBuf::from("/Users/x/Library/Application Support/FSearch"));
    // Either answer is fine; it must not prompt or hang.
    let _ = fsearch::has_full_disk_access();
    fsearch::no_materialize();
}
