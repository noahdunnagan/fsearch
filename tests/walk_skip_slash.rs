//! A skip entry written with a trailing slash still covers its folder.
//! `walk::SKIP` is process-global, so this is its own test binary.

use fsearch::walk;

#[test]
fn a_trailing_slash_still_skips_the_folder() {
    let r = std::env::temp_dir().canonicalize().unwrap().join(format!("fsearch-skipslash-{}", std::process::id()));
    let root = r.to_string_lossy().into_owned();
    // An empty entry names no folder, so it blocks nothing.
    assert!(walk::set_skip(vec![format!("{root}/skip/").into_bytes(), format!("{root}/two//").into_bytes(), Vec::new()]));
    assert!(walk::blocked(format!("{root}/two").as_bytes()));
    assert!(walk::blocked(format!("{root}/two/x").as_bytes()));
    assert!(walk::blocked(format!("{root}/skip").as_bytes()));
    assert!(walk::blocked(format!("{root}/skip/inner").as_bytes()));
    assert!(!walk::blocked(format!("{root}/skipper").as_bytes()));
    assert!(!walk::blocked(root.as_bytes()));
}
