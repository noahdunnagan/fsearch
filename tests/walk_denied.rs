//! `walk::DENIED` is process-global, so its tests get a binary of their own.

use fsearch::walk;
use std::os::unix::ffi::OsStrExt;

/// Only folders that are gone are forgotten. One that reads now still lacks
/// its contents in the index until the next start rescans it, so it stays
/// listed until then.
#[test]
fn denied_forgets_only_folders_that_are_gone() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!("fsearch-prune-{}", std::process::id()));
    std::fs::create_dir_all(root.join("open")).unwrap();
    let open = root.join("open").as_os_str().as_bytes().to_vec();
    let gone = root.join("gone").as_os_str().as_bytes().to_vec();
    walk::DENIED.lock().unwrap().extend([open.clone(), gone.clone()]);
    walk::prune_denied();
    let left = walk::DENIED.lock().unwrap().clone();
    let _ = std::fs::remove_dir_all(&root);
    assert!(left.contains(&open), "readable now, but not rescanned yet: {left:?}");
    assert!(!left.contains(&gone), "{left:?}");
}
