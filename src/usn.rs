//! NTFS USN journal as the Windows stand-in for FSEvents.
//! Same `Event` / `Stream` / `watch` surface the engine already uses.

use crate::nt;
use crate::pathwin;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MUST_SCAN_SUBDIRS: u32 = 0x1;
pub const USER_DROPPED: u32 = 0x2;
pub const KERNEL_DROPPED: u32 = 0x4;
pub const HISTORY_DONE: u32 = 0x10;

pub struct Event {
    pub path: Vec<u8>,
    pub flags: u32,
    pub id: u64,
    pub stream: u32,
}

pub struct Stream {
    stop: Arc<Mutex<bool>>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        if let Ok(mut s) = self.stop.lock() {
            *s = true;
        }
    }
}

pub fn current_id() -> u64 {
    let mut max = 0u64;
    for letter in nt::drive_letters() {
        if !nt::is_ntfs(letter) {
            continue;
        }
        let Some(h) = nt::open_volume(letter) else { continue };
        if let Some((_, next)) = nt::query_usn(&h) {
            max = max.max(next as u64);
        }
    }
    max
}

/// Watch every NTFS volume. `since` is a USN; `latency` is unused (polled).
pub fn watch(since: u64, _latency: f64, tx: Sender<Vec<Event>>, stream: u32) -> Stream {
    nt::enable_privileges();
    let stop = Arc::new(Mutex::new(false));
    let flag = stop.clone();
    std::thread::Builder::new()
        .name("fsearch-usn".into())
        .spawn(move || {
            let _ = tx.send(vec![Event { path: Vec::new(), flags: HISTORY_DONE, id: since, stream }]);
            let mut cursors: Vec<(u8, u64, i64, nt::Handle)> = Vec::new();
            for letter in nt::drive_letters() {
                if !nt::is_ntfs(letter) {
                    continue;
                }
                let Some(h) = nt::open_volume(letter) else { continue };
                let Some((jid, next)) = nt::query_usn(&h) else { continue };
                let start = if since == 0 { next } else { since as i64 };
                cursors.push((letter, jid, start, h));
            }
            loop {
                if flag.lock().map(|s| *s).unwrap_or(true) {
                    break;
                }
                let mut batch = Vec::new();
                for (letter, jid, cur, h) in &mut cursors {
                    match nt::read_usn(h, *jid, *cur) {
                        Ok((next, evs)) => {
                            *cur = next;
                            for e in evs {
                                let Some(dir) = nt::path_from_frn(h, e.parent_frn) else { continue };
                                let path = pathwin::join(&dir, &e.name);
                                batch.push(Event { path, flags: MUST_SCAN_SUBDIRS, id: next as u64, stream });
                            }
                        }
                        Err(nt::UsnErr::Wrap) => {
                            batch.push(Event { path: vec![*letter, b':', b'\\'], flags: KERNEL_DROPPED | MUST_SCAN_SUBDIRS, id: *cur as u64, stream });
                        }
                        Err(_) => {}
                    }
                }
                if !batch.is_empty() {
                    let _ = tx.send(batch);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        })
        .ok();
    Stream { stop }
}
