//! A bad FSEARCH_ROOT fails `Engine::start` before it touches process-wide
//! state. Its own binary: the variable and `walk::SKIP` are global.

use fsearch::{Engine, Options, walk};

fn missing() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("fsearch-badroot-{}-missing", std::process::id()))
}

/// Runs before main, while the process has one thread: `env::set_var`
/// with other threads running is unsound.
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static SET_ROOT: extern "C" fn() = {
    extern "C" fn init() {
        unsafe { std::env::set_var("FSEARCH_ROOT", missing()) };
    }
    init
};

#[test]
fn a_bad_root_fails_before_setting_skip() {
    let data = std::env::temp_dir().join(format!("fsearch-badroot-{}-data", std::process::id()));
    let r = Engine::start(Options { dir: data.clone(), home: "/nowhere".into(), skip: Some(vec!["/nowhere/skip".into()]) });
    let _ = std::fs::remove_dir_all(&data);
    let err = r.err().expect("a missing root is an error");
    assert!(err.contains("FSEARCH_ROOT"), "{err}");
    assert!(walk::SKIP.get().is_none(), "SKIP set by a start that failed");
    assert!(!missing().exists());
}
