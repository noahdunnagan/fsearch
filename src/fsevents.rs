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
    static kCFTypeArrayCallBacks: c_void;
}

unsafe extern "C" {
    fn dispatch_queue_create(label: *const i8, attr: *const c_void) -> *mut c_void;
}

extern "C" fn on_events(_s: *mut c_void, info: *mut c_void, n: usize, paths: *mut c_void, flags: *const u32, ids: *const u64) {
    let tx = unsafe { &*(info as *const Sender<Vec<Event>>) };
    let paths = paths as *const *const i8;
    let batch =
        (0..n).map(|i| unsafe { Event { path: CStr::from_ptr(*paths.add(i)).to_bytes().to_vec(), flags: *flags.add(i), id: *ids.add(i) } }).collect();
    let _ = tx.send(batch);
}

/// A running stream; dropping it stops it.
pub struct Stream(*mut c_void);

// The stream is only started and stopped, never shared mid-call.
unsafe impl Send for Stream {}
unsafe impl Sync for Stream {}

impl Drop for Stream {
    fn drop(&mut self) {
        unsafe {
            FSEventStreamStop(self.0);
            FSEventStreamInvalidate(self.0);
            FSEventStreamRelease(self.0);
        }
    }
}

/// Watch `root` (normally `/`) from `since` (an event id). Batches of
/// directory-level events arrive on `tx` until the returned stream is dropped.
pub fn watch(root: &[u8], since: u64, latency: f64, tx: Sender<Vec<Event>>) -> Stream {
    let root = std::ffi::CString::new(root).expect("root has no NUL");
    unsafe {
        let root = CFStringCreateWithCString(std::ptr::null(), root.as_ptr(), 0x0800_0100);
        let arr = CFArrayCreate(std::ptr::null(), &root, 1, &kCFTypeArrayCallBacks as *const c_void);
        // The sender is leaked: a callback may still be in flight when the
        // stream stops, and streams are replaced rarely.
        let ctx = Context {
            version: 0,
            info: Box::into_raw(Box::new(tx)) as *mut c_void,
            retain: std::ptr::null(),
            release: std::ptr::null(),
            copy_description: std::ptr::null(),
        };
        // Not IgnoreSelf: linked into an app, the app's own renames and moves
        // are exactly what its search must see.
        let s = FSEventStreamCreate(std::ptr::null(), on_events, &ctx, arr, since, latency, CREATE_FLAG_NO_DEFER);
        let q = dispatch_queue_create(c"fsearch.fsevents".as_ptr(), std::ptr::null());
        FSEventStreamSetDispatchQueue(s, q);
        FSEventStreamStart(s);
        Stream(s)
    }
}
