//! Whole-disk FSEvents stream, directory granularity, replayable by event id.

use std::ffi::{CStr, c_void};
use std::sync::mpsc::Sender;

pub const MUST_SCAN_SUBDIRS: u32 = 0x1;
pub const USER_DROPPED: u32 = 0x2;
pub const KERNEL_DROPPED: u32 = 0x4;
pub const HISTORY_DONE: u32 = 0x10;
const CREATE_FLAG_NO_DEFER: u32 = 0x2;

pub struct Event {
    pub path: Vec<u8>,
    pub flags: u32,
    pub id: u64,
}

#[repr(C)]
struct Context {
    version: isize,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

type Callback = extern "C" fn(*mut c_void, *mut c_void, usize, *mut c_void, *const u32, *const u64);

#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn FSEventStreamCreate(
        alloc: *const c_void,
        cb: Callback,
        ctx: *const Context,
        paths: *const c_void,
        since: u64,
        latency: f64,
        flags: u32,
    ) -> *mut c_void;
    fn FSEventStreamSetDispatchQueue(s: *mut c_void, q: *mut c_void);
    fn FSEventStreamStart(s: *mut c_void) -> u8;
    fn FSEventStreamStop(s: *mut c_void);
    fn FSEventStreamInvalidate(s: *mut c_void);
    fn FSEventStreamRelease(s: *mut c_void);
    pub fn FSEventsGetCurrentEventId() -> u64;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithCString(alloc: *const c_void, s: *const i8, enc: u32) -> *const c_void;
    fn CFArrayCreate(alloc: *const c_void, vals: *const *const c_void, n: isize, cbs: *const c_void) -> *const c_void;
    fn CFRelease(cf: *const c_void);
    static kCFTypeArrayCallBacks: c_void;
}

unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> *mut c_void;
    fn dispatch_release(obj: *mut c_void);
}

extern "C" fn on_events(_s: *mut c_void, info: *mut c_void, n: usize, paths: *mut c_void, flags: *const u32, ids: *const u64) {
    let tx = unsafe { &*(info as *const Sender<Vec<Event>>) };
    let paths = paths as *const *const i8;
    let batch =
        (0..n).map(|i| unsafe { Event { path: CStr::from_ptr(*paths.add(i)).to_bytes().to_vec(), flags: *flags.add(i), id: *ids.add(i) } }).collect();
    let _ = tx.send(batch);
}

/// The stream is done with its context (at deallocation, after any
/// callback in flight): free the sender.
extern "C" fn release_sender(info: *const c_void) {
    drop(unsafe { Box::from_raw(info as *mut Sender<Vec<Event>>) });
}

/// A running stream; dropping it stops it and frees what it held.
pub struct Stream {
    s: *mut c_void,
    q: *mut c_void,
}

// The stream is only started and stopped, never shared mid-call.
unsafe impl Send for Stream {}
unsafe impl Sync for Stream {}

impl Drop for Stream {
    fn drop(&mut self) {
        unsafe {
            FSEventStreamStop(self.s);
            FSEventStreamInvalidate(self.s);
            FSEventStreamRelease(self.s);
            dispatch_release(self.q);
        }
    }
}

/// Watch `paths` (normally just `/`) from `since` (an event id). Batches of
/// directory-level events arrive on `tx` until the returned stream is dropped.
pub fn watch(paths: &[&[u8]], since: u64, latency: f64, tx: Sender<Vec<Event>>) -> Stream {
    let paths: Vec<_> = paths.iter().map(|p| std::ffi::CString::new(*p).expect("path has no NUL")).collect();
    unsafe {
        let cf: Vec<*const c_void> = paths.iter().map(|p| CFStringCreateWithCString(std::ptr::null(), p.as_ptr(), 0x0800_0100)).collect();
        let arr = CFArrayCreate(std::ptr::null(), cf.as_ptr(), cf.len() as isize, &kCFTypeArrayCallBacks as *const c_void);
        // The stream frees the sender itself, once no callback can use it.
        let ctx = Context {
            version: 0,
            info: Box::into_raw(Box::new(tx)) as *mut c_void,
            retain: std::ptr::null(),
            release: release_sender as *const c_void,
            copy_description: std::ptr::null(),
        };
        // Not IgnoreSelf: linked into an app, the app's own renames and moves
        // are exactly what its search must see.
        let s = FSEventStreamCreate(std::ptr::null(), on_events, &ctx, arr, since, latency, CREATE_FLAG_NO_DEFER);
        // The stream keeps its own copy of the paths.
        CFRelease(arr);
        cf.iter().for_each(|&c| CFRelease(c));
        let q = dispatch_queue_create(c"fsearch.fsevents".as_ptr(), std::ptr::null());
        FSEventStreamSetDispatchQueue(s, q);
        FSEventStreamStart(s);
        Stream { s, q }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dropping a stream frees what it held: its sender goes too, so the
    /// receiver sees the channel close (followers re-watch on every save).
    #[test]
    fn a_dropped_stream_releases_its_sender() {
        let dir = std::env::temp_dir().canonicalize().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let s = watch(&[dir.as_os_str().as_encoded_bytes()], unsafe { FSEventsGetCurrentEventId() }, 0.05, tx);
        drop(s);
        let gone = loop {
            match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(_) => continue,
                Err(e) => break e,
            }
        };
        assert_eq!(gone, std::sync::mpsc::RecvTimeoutError::Disconnected);
    }

    /// For `leaks --atExit`: watch and drop many streams.
    #[test]
    #[ignore]
    fn churn() {
        let dir = std::env::temp_dir().canonicalize().unwrap();
        for _ in 0..50 {
            let (tx, _rx) = std::sync::mpsc::channel();
            drop(watch(&[dir.as_os_str().as_encoded_bytes()], unsafe { FSEventsGetCurrentEventId() }, 0.05, tx));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
