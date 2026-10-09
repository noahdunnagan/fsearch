//! Linux filesystem event watching: inotify through `notify`, one recursive
//! watch over the indexed home tree. Linux keeps no persistent event
//! history; restarts recover through `synced_at` mtime relists.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::thread;

pub const MUST_SCAN_SUBDIRS: u32 = 0x1;
pub const USER_DROPPED: u32 = 0x2;
pub const KERNEL_DROPPED: u32 = 0x4;
pub const HISTORY_DONE: u32 = 0x10;

#[derive(Clone, Debug)]
pub struct Event {
    pub path: Vec<u8>,
    pub flags: u32,
    pub id: u64,
}

/// A running watch; dropping it asks the thread to stop. The old thread
/// can overlap the replacement for one poll interval (~100ms), so two
/// watchers may briefly feed the same channel. Batches are idempotent.
pub struct Stream {
    stop: Arc<AtomicBool>,
}

unsafe impl Send for Stream {}
unsafe impl Sync for Stream {}

impl Drop for Stream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn fail(tx: &Sender<Vec<Event>>, root: &[u8], id: u64, msg: &str) {
    eprintln!("fsearch watcher: {msg}");
    // The watch is dead: no HISTORY_DONE, so the apply loop never looks
    // live. One last root rescan reimports what it can; nothing follows.
    let _ = tx.send(vec![Event { path: root.to_vec(), flags: MUST_SCAN_SUBDIRS | KERNEL_DROPPED, id }]);
}

/// Watch `root`, the indexed home tree, with inotify through `notify`.
/// Ids order events in one run only. The watcher sends one `HISTORY_DONE`
/// batch once the watch is up, so the apply loop leaves replay mode. A
/// lost watch or overflow arrives as a `KERNEL_DROPPED` rescan of `root`,
/// which the apply loop reimports in place. A watch that never starts
/// sends a final `KERNEL_DROPPED` rescan with no `HISTORY_DONE`, so the
/// loop stays in replay mode instead of looking live while deaf.
///
/// Watches are established per directory (`NonRecursive`), not with one
/// fail-fast recursive watch: a single unreadable subdirectory (EACCES)
/// must skip just that subtree, never deafen the whole tree. Symlinked
/// directories are never descended, matching the walker.
pub fn watch(root: &std::path::Path, since: u64, _latency: f64, tx: Sender<Vec<Event>>) -> Stream {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let root: std::path::PathBuf = root.to_path_buf();
    thread::spawn(move || {
        use notify::{EventKind, Watcher};
        use std::os::unix::ffi::OsStrExt;
        let (ntx, nrx) = std::sync::mpsc::channel();
        let root_bytes = root.as_os_str().as_bytes().to_vec();
        let mut watcher = match notify::recommended_watcher(ntx) {
            Ok(w) => w,
            Err(e) => {
                fail(&tx, &root_bytes, since, &format!("cannot start file watcher: {e}"));
                return;
            }
        };
        let mut watched: HashSet<std::path::PathBuf> = HashSet::new();
        if let Err(fatal) = watch_tree(&mut watcher, &root, &mut watched) {
            for w in watched {
                let _ = watcher.unwatch(&w);
            }
            fail(&tx, &root_bytes, since, &fatal);
            return;
        }
        // Linux keeps no history. Tell the apply loop it is live. The id
        // matches `since` so it never advances the saved event cursor.
        let _ = tx.send(vec![Event { path: Vec::new(), flags: HISTORY_DONE, id: since }]);
        let mut next_id = if since == 0 { 1 } else { since + 1 };
        let mk_dropped = |id: u64| Event { path: root_bytes.clone(), flags: MUST_SCAN_SUBDIRS | KERNEL_DROPPED, id };
        loop {
            if stop_clone.load(Ordering::Relaxed) {
                break;
            }
            match nrx.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(first) => {
                    let mut batch = Vec::new();
                    // One storm is one relist per folder: collapse duplicate
                    // (path, flags) pairs. Relists are idempotent, so folding
                    // N events into one changes traffic, not results.
                    let mut seen = std::collections::HashSet::new();
                    let mut events = vec![first];
                    events.extend(nrx.try_iter());
                    for event in events {
                        match event {
                            Ok(evt) => {
                                // Reads must not trigger rescans.
                                // Creations, modifications, removals and unknown
                                // kinds change the index.
                                if matches!(evt.kind, EventKind::Access(_)) {
                                    continue;
                                }
                                for path in evt.paths {
                                    let path_bytes = path.as_os_str().as_encoded_bytes().to_vec();
                                    // Dropped watches must go: inotify lets go
                                    // of a watched dir on remove/rename-out,
                                    // but the set would keep it forever, leak
                                    // the descriptor and skip the re-watch on
                                    // recreate. The set stays prefix-closed,
                                    // so a missing entry means no descendant
                                    // entry either; only scan on a hit.
                                    if matches!(
                                        evt.kind,
                                        EventKind::Remove(_)
                                            | EventKind::Modify(notify::event::ModifyKind::Name(
                                                notify::event::RenameMode::From | notify::event::RenameMode::Both
                                            ))
                                    ) && watched.contains(&path)
                                    {
                                        for w in watched.iter().filter(|w| w.starts_with(&path)).cloned().collect::<Vec<_>>() {
                                            let _ = watcher.unwatch(&w);
                                            watched.remove(&w);
                                        }
                                    }
                                    // New dirs need their own watches (`NonRecursive`
                                    // parents do not extend). Fresh dirs arrive as
                                    // Create, moved-in trees as Modify(Name).
                                    let created_dir =
                                        matches!(evt.kind, EventKind::Create(_) | EventKind::Modify(notify::event::ModifyKind::Name(_)))
                                            && path.symlink_metadata().is_ok_and(|m| m.is_dir())
                                            && !watched.contains(&path);
                                    if created_dir {
                                        // Same skip-on-error as establishment;
                                        // only a full watch table (ENOSPC)
                                        // degrades to a root relist.
                                        if let Err(fatal) = watch_tree(&mut watcher, &path, &mut watched) {
                                            eprintln!("fsearch watcher: {fatal}");
                                            batch.push(mk_dropped(next_id));
                                            next_id += 1;
                                        }
                                    }
                                    // macOS reports directories. inotify
                                    // reports files, and a flat fetch of a
                                    // file path can never discover it. Relist
                                    // the parent folder instead. Directories
                                    // keep recursive semantics.
                                    let is_dir = path.symlink_metadata().is_ok_and(|m| m.is_dir());
                                    let (out, flags) = if is_dir {
                                        (path_bytes, MUST_SCAN_SUBDIRS)
                                    } else if let Some(cut) = path_bytes.iter().rposition(|&b| b == b'/') {
                                        let parent = if cut == 0 { b"/".to_vec() } else { path_bytes[..cut].to_vec() };
                                        (parent, 0)
                                    } else {
                                        (path_bytes, 0)
                                    };
                                    if seen.insert((out.clone(), flags)) {
                                        batch.push(Event { path: out, flags, id: next_id });
                                        next_id += 1;
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("fsearch watcher: lost events ({e}); relisting");
                                batch.push(mk_dropped(next_id));
                                next_id += 1;
                            }
                        }
                    }
                    if !batch.is_empty() {
                        let _ = tx.send(batch);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        for w in watched {
            let _ = watcher.unwatch(&w);
        }
    });
    Stream { stop }
}

/// Watch `root` and every reachable subdirectory, one `NonRecursive`
/// watch each. Unreadable or vanished subtrees skip just themselves with
/// a log line; only a full watch table (ENOSPC) or an unwatched root
/// fails the tree, since either would look live while deaf.
fn watch_tree(watcher: &mut impl notify::Watcher, root: &std::path::Path, watched: &mut HashSet<std::path::PathBuf>) -> Result<(), String> {
    let enospc_hint = |dir: &std::path::Path, e: &notify::Error| {
        format!("cannot watch {}: {e} (large trees may exceed /proc/sys/fs/inotify/max_user_watches)", dir.display())
    };
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let is_tree_root = dir == root;
        // Never descend symlinked dirs, matching the walker (this
        // metadata does not follow links).
        if !is_tree_root && dir.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        match watcher.watch(&dir, notify::RecursiveMode::NonRecursive) {
            Ok(()) => {
                let _ = watched.insert(dir.clone());
            }
            Err(e) => {
                if matches!(e.kind, notify::ErrorKind::MaxFilesWatch) {
                    return Err(enospc_hint(&dir, &e));
                }
                if is_tree_root {
                    return Err(format!("cannot watch {}: {e}", dir.display()));
                }
                eprintln!("fsearch watcher: skipping {}: {e}", dir.display());
                continue;
            }
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                eprintln!("fsearch watcher: skipping {}: {e}", dir.display());
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            // DirEntry::file_type does not follow symlinks, so links
            // never reach the stack.
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(entry.path()),
                _ => {}
            }
        }
    }
    Ok(())
}

/// Wall-clock nanos order events in one run only. They are not a
/// replayable cursor like FSEvents ids. Do not trust them across reboots.
pub fn get_current_event_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

pub use self::get_current_event_id as FSEventsGetCurrentEventId;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn fixture(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fsearch-watch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn teardown(p: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        // Restore permissions on any locked dirs so removal succeeds.
        let blocked = p.join("blocked");
        if blocked.exists() {
            let mut perm = std::fs::metadata(&blocked).unwrap().permissions();
            perm.set_mode(0o755);
            let _ = std::fs::set_permissions(&blocked, perm);
        }
        let _ = std::fs::remove_dir_all(p);
    }

    /// Collect batches until `want` matches or the deadline passes.
    fn collect_until(rx: &std::sync::mpsc::Receiver<Vec<Event>>, want: &dyn Fn(&Event) -> bool, timeout: Duration) -> Vec<Event> {
        let deadline = Instant::now() + timeout;
        let mut all = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(left.min(Duration::from_millis(200))) {
                Ok(batch) => {
                    if batch.iter().any(want) {
                        all.extend(batch);
                        break;
                    }
                    all.extend(batch);
                }
                Err(_) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                }
            }
        }
        all
    }

    #[test]
    fn unreadable_subdir_does_not_kill_watch() {
        use std::os::unix::fs::PermissionsExt;
        let root = fixture("unreadable");
        std::fs::create_dir_all(root.join("ok")).unwrap();
        std::fs::create_dir_all(root.join("blocked")).unwrap();
        std::fs::write(root.join("ok").join("seed.txt"), b"x").unwrap();
        let mut perm = std::fs::metadata(root.join("blocked")).unwrap().permissions();
        perm.set_mode(0o000);
        std::fs::set_permissions(root.join("blocked"), perm).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let _stream = watch(&root, 0, 0.1, tx);
        let got = collect_until(&rx, &|e| e.flags & HISTORY_DONE != 0, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.flags & HISTORY_DONE != 0), "no HISTORY_DONE; batches: {got:?}");

        // Sibling subtree must still be live.
        std::fs::write(root.join("ok").join("live.txt"), b"y").unwrap();
        let ok_bytes = root.join("ok").as_os_str().as_encoded_bytes().to_vec();
        let got = collect_until(&rx, &|e| e.path == ok_bytes, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.path == ok_bytes), "sibling update never converged; batches: {got:?}");
        teardown(&root);
    }

    #[test]
    fn create_rename_delete_converge() {
        let root = fixture("crud");
        std::fs::create_dir_all(root.join("ok")).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let _stream = watch(&root, 0, 0.1, tx);
        let got = collect_until(&rx, &|e| e.flags & HISTORY_DONE != 0, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.flags & HISTORY_DONE != 0), "no HISTORY_DONE; batches: {got:?}");

        let ok_bytes = root.join("ok").as_os_str().as_encoded_bytes().to_vec();
        std::fs::write(root.join("ok").join("a.txt"), b"a").unwrap();
        let got = collect_until(&rx, &|e| e.path == ok_bytes, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.path == ok_bytes), "create never converged: {got:?}");
        std::fs::rename(root.join("ok").join("a.txt"), root.join("ok").join("b.txt")).unwrap();
        let got = collect_until(&rx, &|e| e.path == ok_bytes, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.path == ok_bytes), "rename never converged: {got:?}");
        std::fs::remove_file(root.join("ok").join("b.txt")).unwrap();
        let got = collect_until(&rx, &|e| e.path == ok_bytes, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.path == ok_bytes), "delete never converged: {got:?}");

        // Newly created dirs must be picked up too.
        std::fs::create_dir_all(root.join("ok").join("sub")).unwrap();
        std::thread::sleep(Duration::from_millis(500));
        std::fs::write(root.join("ok").join("sub").join("deep.txt"), b"d").unwrap();
        let sub_bytes = root.join("ok").join("sub").as_os_str().as_encoded_bytes().to_vec();
        let got = collect_until(&rx, &|e| e.path == sub_bytes, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.path == sub_bytes), "new-dir update never converged: {got:?}");
        teardown(&root);
    }

    #[test]
    fn delete_recreate_reconverges() {
        let root = fixture("recreate");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let _stream = watch(&root, 0, 0.1, tx);
        let got = collect_until(&rx, &|e| e.flags & HISTORY_DONE != 0, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.flags & HISTORY_DONE != 0), "no HISTORY_DONE; batches: {got:?}");

        // Remove a watched dir, let the removal propagate, then recreate
        // it. The recreated dir must reconverge (re-watched).
        std::fs::remove_dir_all(root.join("sub")).unwrap();
        std::thread::sleep(Duration::from_millis(800));
        // Drain removal batches so the recreate is a distinct step.
        while rx.try_recv().is_ok() {}
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::thread::sleep(Duration::from_millis(800));
        // Drain the recreate batch itself: liveness means writes *inside*
        // the recreated dir converge afterwards, not just the re-add relist.
        while rx.try_recv().is_ok() {}
        std::fs::write(root.join("sub").join("deep.txt"), b"d").unwrap();
        let sub_bytes = root.join("sub").as_os_str().as_encoded_bytes().to_vec();
        let got = collect_until(&rx, &|e| e.path == sub_bytes, Duration::from_secs(8));
        assert!(got.iter().any(|e| e.path == sub_bytes), "recreated dir never reconverged (stale watch?): {got:?}");
        teardown(&root);
    }

    #[test]
    fn symlinked_dirs_are_not_descended() {
        let root = fixture("symlink");
        std::fs::create_dir_all(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let _stream = watch(&root, 0, 0.1, tx);
        let got = collect_until(&rx, &|e| e.flags & HISTORY_DONE != 0, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.flags & HISTORY_DONE != 0), "no HISTORY_DONE; batches: {got:?}");

        // Write through the link: the event must arrive via the real path,
        // never under the link path (walker parity: links are never descended).
        std::fs::write(root.join("link").join("via.txt"), b"v").unwrap();
        let real_bytes = root.join("real").as_os_str().as_encoded_bytes().to_vec();
        let link_bytes = root.join("link").as_os_str().as_encoded_bytes().to_vec();
        let got = collect_until(&rx, &|e| e.path == real_bytes, Duration::from_secs(5));
        assert!(got.iter().any(|e| e.path == real_bytes), "real-path update missing: {got:?}");
        assert!(!got.iter().any(|e| e.path == link_bytes || e.path.starts_with(&link_bytes)), "watcher descended into symlinked dir: {got:?}");
        teardown(&root);
    }
}
