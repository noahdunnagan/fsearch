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

/// CoreServices (and the CoreFoundation it brings) are loaded on first use,
/// not linked: CoreFoundation's initializer costs every process that links
/// it ~1 ms at launch, and only the daemon watches the disk.
struct Api {
    create: unsafe extern "C" fn(*const c_void, Callback, *const Context, *const c_void, u64, f64, u32) -> *mut c_void,
    set_queue: unsafe extern "C" fn(*mut c_void, *mut c_void),
    start: unsafe extern "C" fn(*mut c_void) -> u8,
    stop: unsafe extern "C" fn(*mut c_void),
    invalidate: unsafe extern "C" fn(*mut c_void),
    release: unsafe extern "C" fn(*mut c_void),
    current_id: unsafe extern "C" fn() -> u64,
    string: unsafe extern "C" fn(*const c_void, *const i8, u32) -> *const c_void,
    array: unsafe extern "C" fn(*const c_void, *const *const c_void, isize, *const c_void) -> *const c_void,
    array_callbacks: *const c_void,
}

// Function pointers and a constant's address: fine to share.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

fn api() -> &'static Api {
    static API: std::sync::OnceLock<Api> = std::sync::OnceLock::new();
    API.get_or_init(|| unsafe {
        let open = |path: &CStr| {
            let h = libc::dlopen(path.as_ptr(), libc::RTLD_LAZY);
            assert!(!h.is_null(), "cannot load {path:?}");
            h
        };
        let (cs, cf) = (
            open(c"/System/Library/Frameworks/CoreServices.framework/CoreServices"),
            open(c"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"),
        );
        Api {
            create: sym(cs, c"FSEventStreamCreate"),
            set_queue: sym(cs, c"FSEventStreamSetDispatchQueue"),
            start: sym(cs, c"FSEventStreamStart"),
            stop: sym(cs, c"FSEventStreamStop"),
            invalidate: sym(cs, c"FSEventStreamInvalidate"),
            release: sym(cs, c"FSEventStreamRelease"),
            current_id: sym(cs, c"FSEventsGetCurrentEventId"),
            string: sym(cf, c"CFStringCreateWithCString"),
            array: sym(cf, c"CFArrayCreate"),
            array_callbacks: sym(cf, c"kCFTypeArrayCallBacks"),
        }
    })
}

/// A symbol of a loaded image, as `T` (a function pointer, or a data
/// symbol's address).
unsafe fn sym<T>(h: *mut c_void, name: &CStr) -> T {
    let p = unsafe { libc::dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "missing {name:?}");
    unsafe { std::mem::transmute_copy(&p) }
}

/// The newest event id on the system.
pub fn current_id() -> u64 {
    unsafe { (api().current_id)() }
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
            let a = api();
            (a.stop)(self.0);
            (a.invalidate)(self.0);
            (a.release)(self.0);
        }
    }
}

/// Watch `/` from `since` (an event id). Batches of directory-level events
/// arrive on `tx` until the returned stream is dropped.
pub fn watch(since: u64, latency: f64, tx: Sender<Vec<Event>>) -> Stream {
    let a = api();
    unsafe {
        let root = (a.string)(std::ptr::null(), c"/".as_ptr(), 0x0800_0100);
        let arr = (a.array)(std::ptr::null(), &root, 1, a.array_callbacks);
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
        let s = (a.create)(std::ptr::null(), on_events, &ctx, arr, since, latency, CREATE_FLAG_NO_DEFER);
        let q = dispatch_queue_create(c"fsearch.fsevents".as_ptr(), std::ptr::null());
        (a.set_queue)(s, q);
        (a.start)(s);
        Stream(s)
    }
}
