//! `walk::SKIP` is process-global, so it gets a test binary of its own.

use fsearch::index::Index;
use fsearch::live::Live;
use fsearch::walk::{self, KIND_DIR, Listing, NONE, RawEnt};
use std::os::unix::ffi::OsStrExt;

fn names(l: &Listing) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = l.ents.iter().map(|e| &l.names[e.name_off as usize..][..e.name_len as usize]).collect();
    v.sort();
    v
}

/// The ancestors of `root` as one-entry listings, then a scan of it.
fn base_for(root: &[u8]) -> Index {
    let comps: Vec<&[u8]> = root.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
    let k = comps.len() as u32;
    let mut ls: Vec<Listing> = comps
        .iter()
        .enumerate()
        .map(|(i, c)| Listing {
            id: i as u32,
            names: c.to_vec(),
            ents: vec![RawEnt { name_off: 0, name_len: c.len() as u16, kind: KIND_DIR, size: 0, mtime: 0, child: i as u32 + 1 }],
        })
        .collect();
    for mut l in walk::scan(root, 2) {
        l.id += k;
        for e in &mut l.ents {
            if e.child != NONE {
                e.child += k;
            }
        }
        ls.push(l);
    }
    Index::build(ls, 0, 0, b"")
}

#[test]
fn skipped_folders_are_never_opened() {
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!("fsearch-skip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
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
    {
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
    let mut live = Live::new(base_for(&r));
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
