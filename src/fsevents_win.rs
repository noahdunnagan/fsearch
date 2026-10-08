use crate::fsevents::{Event, Stream, MUST_SCAN_SUBDIRS};
use std::sync::mpsc::Sender;
use notify::{Watcher, RecursiveMode, Event as NotifyEvent, Config};

pub fn watch(_since: u64, _latency: f64, tx: Sender<Vec<Event>>) -> Stream {
    let mut watcher = notify::RecommendedWatcher::new(
        move |res: notify::Result<NotifyEvent>| {
            if let Ok(event) = res {
                let mut batch = Vec::new();
                for path in event.paths {
                    let dir = if path.is_dir() { path.clone() } else { path.parent().map(|p| p.to_path_buf()).unwrap_or(path) };
                    
                    let path_str = dir.to_string_lossy().into_owned();
                    batch.push(Event {
                        path: path_str.into_bytes(),
                        flags: MUST_SCAN_SUBDIRS,
                        id: 0,
                    });
                }
                if !batch.is_empty() {
                    let _ = tx.send(batch);
                }
            }
        },
        Config::default()
    ).unwrap();

    let drives = unsafe { windows_sys::Win32::Storage::FileSystem::GetLogicalDrives() };
    for i in 0..26 {
        if (drives & (1 << i)) != 0 {
            let drive_path = format!("{}:\\", (b'A' + i) as char);
            let _ = watcher.watch(std::path::Path::new(&drive_path), RecursiveMode::Recursive);
        }
    }

    let ptr = Box::into_raw(Box::new(watcher));
    Stream(ptr as *mut std::ffi::c_void)
}

pub fn current_event_id() -> u64 {
    0
}

pub fn drop_stream(s: *mut std::ffi::c_void) {
    if !s.is_null() {
        unsafe {
            let _ = Box::from_raw(s as *mut notify::RecommendedWatcher);
        }
    }
}
