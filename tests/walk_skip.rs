//! `walk::SKIP` is process-global, so it gets a test binary of its own.

use fsearch::index::Index;
use fsearch::live::Live;
use fsearch::walk::{self, Listing, NONE};
use std::os::unix::ffi::OsStrExt;

fn names(l: &Listing) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = l.ents.iter().map(|e| &l.names[e.name_off as usize..][..e.name_len as usize]).collect();
    v.sort();
    v
}

/// Removes the tree on drop, even after a failed assertion (and first
/// makes a mode-000 folder deletable again).
struct Cleanup(std::path::PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(self.0.join("locked"), std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn skipped_folders_are_never_opened() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!("fsearch-skip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let _cleanup = Cleanup(root.clone());
    for d in ["skip/in", "skipx", "ok"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("skip/f"), b"x").unwrap();
    std::fs::write(root.join("ok/f"), b"x").unwrap();
    let r = root.as_os_str().as_bytes().to_vec();
    let skip = [r.as_slice(), b"/skip"].concat();
    walk::SKIP.set(vec![skip.clone()]).unwrap();

    assert!(walk::blocked(&skip));
    assert!(walk::blocked(&[skip.as_slice(), b"/in"].concat()));
    assert!(!walk::blocked(&[r.as_slice(), b"/skipx"].concat()), "a prefix of a name is not its parent");
    assert!(!walk::blocked(&r));

    // DENIED is for EPERM (privacy-refused) folders. Mode 000 is EACCES, a
    // plain permission problem: listed empty, not recorded. A real EPERM
    // needs a TCC-protected folder, which depends on this process's grants.
    // Root reads mode 000 anyway, so the case is moot there.
    if unsafe { libc::geteuid() } != 0 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(root.join("locked/in")).unwrap();
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let ls = walk::scan(&r, 2);
        std::fs::set_permissions(root.join("locked"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(ls.len(), 4, "root, locked (empty), ok, skipx");
        assert!(walk::DENIED.lock().unwrap().is_empty());
        std::fs::remove_dir_all(root.join("locked")).unwrap();
    }

    // The folder is an entry, but never listed.
    let ls = walk::scan(&r, 2);
    let top = ls.iter().find(|l| l.id == 0).unwrap();
    assert_eq!(names(top), [&b"ok"[..], b"skip", b"skipx"]);
    let e = top.ents.iter().find(|e| &top.names[e.name_off as usize..][..e.name_len as usize] == b"skip").unwrap();
    assert_eq!(e.child, NONE);
    assert_eq!(ls.len(), 3, "root, ok, skipx");
    assert!(walk::list_one(&skip).is_none());
    assert_eq!(walk::scan(&skip, 1)[0].ents.len(), 0);

    // Live updates leave it alone too, even once it's gone.
    let mut live = Live::new(Index::build(walk::scan_rooted(&r, 2), 0, 0, b""));
    std::fs::write(root.join("skip/new"), b"x").unwrap();
    live.apply_dir(&skip, false);
    live.apply_dir(&skip, true);
    assert!(live.over.is_empty() && live.dead_count == 0);
    std::fs::remove_dir_all(root.join("skip")).unwrap();
    live.apply_dir(&skip, false);
    assert!(live.over.is_empty() && live.dead_count == 0);
    std::fs::create_dir_all(root.join("skip")).unwrap();
    let changed = live.changed_dirs(0);
    assert!(changed.contains(&[r.as_slice(), b"/skipx"].concat()));
    assert!(!changed.iter().any(|p| walk::blocked(p)));

    let _ = std::fs::remove_dir_all(&root);
}
