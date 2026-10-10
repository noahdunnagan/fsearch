//! Without Full Disk Access (forced with FSEARCH_RESTRICT) the consent-gated
//! folders are never opened. `walk::SKIP` is process-wide, hence its own file.

mod common;

use common::{Scratch, real, wait_for};
use fsearch::{Engine, Options, Query};

/// Runs before main, while the process has one thread: `env::set_var`
/// with other threads running is unsound.
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static RESTRICT: extern "C" fn() = {
    extern "C" fn init() {
        unsafe { std::env::set_var("FSEARCH_RESTRICT", "1") };
    }
    init
};

/// Set before any test thread starts: setting it from a test is unsound.
#[test]
fn restrict_is_set_before_any_test_runs() {
    assert!(std::env::var_os("FSEARCH_RESTRICT").is_some());
}

#[test]
fn gated_folders_are_skipped_and_recorded() {
    let s = Scratch::new();
    let home = s.mkdir("home");
    s.write("home/Documents/secretfile", "");
    let open = s.write("home/openfile", "");
    let start = |dir| Engine::start(Options { dir, home: real(&home), skip: None }).unwrap();
    let find = |e: &Engine, q: &str| e.search(&Query::parse(q, e.home()).unwrap()).unwrap().len();
    let e = start(s.path("data"));
    wait_for(30, "the index", || e.status().ready);
    assert!(!e.status().full_disk_access);
    assert_eq!(find(&e, "openfile"), 1);
    assert_eq!(find(&e, "secretfile"), 0);
    let skipped = String::from_utf8(std::fs::read(s.path("data/skipped")).unwrap()).unwrap();
    assert!(skipped.lines().any(|l| l == format!("{}/Documents", real(&home))));
    assert!(skipped.lines().any(|l| l == "/Volumes"));

    // Changes inside stay unseen; outside they show up.
    s.write("home/Documents/secret2file", "");
    let b = s.write("home/open2file", "");
    wait_for(10, "a change outside the gated folders", || find(&e, "open2file") == 1);
    assert_eq!(find(&e, "secret2file"), 0);

    // On restart the recorded folders are still blocked: no rescan, and
    // the next save records them again.
    let d2 = s.mkdir("data2");
    std::fs::copy(s.path("data/index.bin"), d2.join("index.bin")).unwrap();
    std::fs::copy(s.path("data/skipped"), d2.join("skipped")).unwrap();
    let e2 = start(d2.clone());
    wait_for(10, "the index", || e2.status().ready);
    assert_eq!(find(&e2, "secretfile"), 0);
    common::saved(&d2, || e2.save());
    assert_eq!(std::fs::read_to_string(d2.join("skipped")).unwrap(), skipped);
    assert!(open.exists() && b.exists());
}
