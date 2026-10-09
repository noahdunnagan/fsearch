//! Linux filesystem event watching: inotify through `notify`, one recursive
//! watch over the indexed home tree. Linux keeps no persistent event
//! history; restarts recover through `synced_at` mtime relists.

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
pub fn watch(root: &std::path::Path, since: u64, _latency: f64, tx: Sender<Vec<Event>>) -> Stream {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let root: std::path::PathBuf = root.to_path_buf();
    thread::spawn(move || {
        use notify::{EventKind, RecursiveMode, Watcher};
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
        if let Err(e) = watcher.watch(&root, RecursiveMode::Recursive) {
            fail(
                &tx,
                &root_bytes,
                since,
                &format!("cannot watch {}: {e} (large trees may exceed /proc/sys/fs/inotify/max_user_watches)", root.display()),
            );
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
        let _ = watcher.unwatch(&root);
    });
    Stream { stop }
}

/// Wall-clock nanos order events in one run only. They are not a
/// replayable cursor like FSEvents ids. Do not trust them across reboots.
pub fn get_current_event_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64
}

pub use self::get_current_event_id as FSEventsGetCurrentEventId;
