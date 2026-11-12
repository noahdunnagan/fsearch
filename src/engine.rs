//! The engine: owns the live name index, follows FSEvents, keeps the content
//! index current, and answers searches. The daemon runs one; so can any app
//! that links this crate.

use crate::content::{self, Content, Grep, GrepResult};
use crate::fsevents::{self, HISTORY_DONE, KERNEL_DROPPED, MUST_SCAN_SUBDIRS, USER_DROPPED};
use crate::index::Index;
use crate::live::{Applied, Live};
use crate::query::{Query, Searcher};
use crate::walk::{self, KIND_DIR, Listing, NONE, RawEnt};
use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};

// Every search scans the whole overlay (~1 ms per 100k entries), and a
// follower starting up replays everything since the save, so fold it into
// the base once it grows — and grows with the base: a big index tolerates a
// bigger overlay. Below the soft bound compaction waits for the disk to go
// quiet; past the hard one it runs anyway. Otherwise only twice a day;
// restart replays FSEvents anyway.
const COMPACT_PENDING: usize = 50_000;
const COMPACT_HARD: usize = 500_000;
const COMPACT_QUIET: Duration = Duration::from_secs(30);
const COMPACT_EVERY: Duration = Duration::from_secs(12 * 3600);
const SCAN_THREADS: usize = 8;
const CONTENT_QUIET: Duration = Duration::from_secs(2);
const CONTENT_MAX_WAIT: Duration = Duration::from_secs(300);
/// How often a follower checks whether it can take over or reload.
const FOLLOW_EVERY: Duration = Duration::from_secs(10);
/// Seconds before the last known-good moment that a relist also covers.
const SYNC_MARGIN: u32 = 120;
/// How long FSEvents must go without dropping events before the gap is
/// replayed: restarting mid-burst only drops more. Each failed replay
/// doubles the wait, capped, so a saturated fseventsd isn't reasked hard.
const REPLAY_QUIET: Duration = Duration::from_secs(2);
const REPLAY_MAX: Duration = Duration::from_secs(60);
/// Under sustained churn a relist is itself seconds of listing that
/// immediately loses track again: at most one per this long; a due one
/// inside the window waits it out.
const RELIST_COOLDOWN: Duration = Duration::from_secs(300);

pub struct Options {
    /// Where the index lives (`index.bin`, `content/`).
    pub dir: PathBuf,
    pub home: String,
    /// Folders never to open. `None` decides from Full Disk Access: without
    /// it, the consent-gated folders are skipped, since opening one pops a
    /// privacy prompt and blocks until someone answers it.
    pub skip: Option<Vec<PathBuf>>,
}

/// One name-search result.
pub struct Found {
    pub path: PathBuf,
    /// `walk::KIND_*` in the low 2 bits, `walk::FLAG_*` above.
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
    pub score: i32,
}

#[derive(serde::Serialize)]
pub struct Status {
    #[serde(skip)]
    pub ready: bool,
    pub entries: usize,
    pub dirs: usize,
    pub overlay: usize,
    pub removed: usize,
    pub event_id: u64,
    pub index_bytes: usize,
    pub content_docs: usize,
    pub content_segments: usize,
    pub content_bytes: usize,
    pub content_pending: usize,
    pub full_disk_access: bool,
    /// Writes the index files (false: following another process's).
    pub owner: bool,
}

/// A folder listed on its own on the first run (see `Shared::with_names`).
struct Early {
    dir: Vec<u8>,
    live: Live,
    /// Its files' content build was asked for.
    indexing: AtomicBool,
}

#[derive(Clone)]
pub struct Engine {
    s: Arc<Shared>,
}

struct Shared {
    live: RwLock<Option<Live>>,
    /// A saved index is still being read in: searches wait for it rather
    /// than answer "indexing".
    loading: (Mutex<bool>, Condvar),
    content: RwLock<Content>,
    home: String,
    dir: PathBuf,
    /// Wakes the apply loop; an empty batch is a no-op wake-up.
    wake: Sender<Vec<fsevents::Event>>,
    save_requested: AtomicBool,
    content_tx: Sender<Resync>,
    content_rx: Mutex<Option<Receiver<Resync>>>,
    content_pending: AtomicUsize,
    /// Files changed since their folder's last content sync.
    dirty: content::Dirty,
    /// Holding `lock`: this engine writes the index files. Another process
    /// may own them (the daemon, an app); then this one follows: it reads
    /// the saved index, keeps it live in memory, and takes over when the
    /// owner goes away.
    owner: AtomicBool,
    lock: std::fs::File,
    stream: Mutex<Option<fsevents::Stream>>,
    /// Number of the current stream (events carry the one they came from)
    /// and the event id it started from.
    streams: std::sync::atomic::AtomicU32,
    since: AtomicU64,
    /// The data dir as FSEvents reports it (canonicalized): events under it
    /// always pass the skip filter, a follower sees its owner's writes.
    ours: Vec<u8>,
    /// The stream is still replaying history (until HISTORY_DONE).
    replaying: AtomicBool,
    /// Follower: content dir mtime when its segments were last opened.
    content_seen: Mutex<Option<std::time::SystemTime>>,
    /// First run, until the whole disk is listed: indexes of just the
    /// folders searches asked about (see `with_names`).
    early: Mutex<Vec<Arc<Early>>>,
    /// The content index holds every file it should: false while its first
    /// build runs, when greps read the files directly instead...
    content_ready: AtomicBool,
    /// ...except in these folders, built first from their early indexes.
    content_early: Mutex<Vec<Vec<u8>>>,
    /// Told the folders of each batch of disk changes (`Engine::on_change`).
    #[allow(clippy::type_complexity)]
    on_change: RwLock<Vec<Box<dyn Fn(&[(&[u8], bool)]) + Send + Sync>>>,
}

fn try_lock(f: &std::fs::File) -> bool {
    unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(f), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

fn log(msg: impl AsRef<str>) {
    eprintln!("{} {}", crate::query::now_secs(), msg.as_ref());
}

/// Never let indexing download iCloud placeholders: on the calling thread,
/// opening or listing a dataless file fails fast instead of materializing it.
pub fn no_materialize() {
    unsafe extern "C" {
        fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
    }
    // IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES, IOPOL_SCOPE_THREAD, OFF
    unsafe { setiopolicy_np(3, 1, 1) };
}

/// Searches run here, at user-interactive QoS: an app's background executor
/// (or any low-QoS caller) would otherwise put the scan on efficiency cores.
/// Each search gets it here, which notes when (`LAST_SEARCH`).
fn search_pool() -> &'static rayon::ThreadPool {
    LAST_SEARCH.store(now_ns(), Ordering::Relaxed);
    pool()
}

/// When a search last started (`now_ns`): a minute on, the search threads'
/// kept blocks go back (`alloc::drain`) if the warmer didn't send them.
static LAST_SEARCH: AtomicU64 = AtomicU64::new(0);

fn pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .thread_name(|i| format!("fsearch-search-{i}"))
            .start_handler(|_| {
                unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0) };
                crate::alloc::keep_on_this_thread();
            })
            .build()
            .unwrap()
    })
}

/// The keep-warm window: spin from `WARM_FROM` to `WARM_UNTIL` (`now_ns`).
static WARM_FROM: AtomicU64 = AtomicU64::new(0);
static WARM_UNTIL: AtomicU64 = AtomicU64::new(0);
/// The warmer is parked until the next `keep_warm`.
static WARM_IDLE: AtomicBool = AtomicBool::new(false);

fn now_ns() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

fn warmer() -> &'static std::thread::Thread {
    static T: std::sync::OnceLock<std::thread::Thread> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let t = std::thread::Builder::new().name("fsearch-warm".into()).spawn(|| {
            unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0) };
            loop {
                let (from, until, now) = (WARM_FROM.load(Ordering::SeqCst), WARM_UNTIL.load(Ordering::SeqCst), now_ns());
                if now >= until {
                    WARM_IDLE.store(true, Ordering::SeqCst);
                    if now_ns() >= WARM_UNTIL.load(Ordering::SeqCst) {
                        // Searching stopped: the blocks the search threads
                        // kept go back (`alloc`).
                        if crate::alloc::kept() {
                            pool().spawn_broadcast(|_| crate::alloc::drain());
                        }
                        std::thread::park();
                    }
                    WARM_IDLE.store(false, Ordering::SeqCst);
                } else if now < from {
                    std::thread::park_timeout(Duration::from_nanos(from - now));
                } else {
                    std::hint::spin_loop();
                }
            }
        });
        t.expect("spawn").thread().clone()
    })
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            no_materialize();
            f()
        })
        .expect("spawn");
}

impl Engine {
    /// Start indexing in the background and return at once. Searches wait
    /// while a saved index loads, and answer `Err` while the very first run
    /// builds one.
    pub fn start(mut opts: Options) -> Result<Engine, String> {
        std::fs::create_dir_all(&opts.dir).map_err(|e| e.to_string())?;
        // Home as paths are compared to it: "/h/" put nothing in content scope.
        if opts.home.len() > 1 && opts.home.ends_with('/') {
            opts.home = opts.home.trim_end_matches('/').to_string();
        }
        // One writer per index: a second one would race index writes. The
        // lock dies with the process.
        let lock = std::fs::File::create(opts.dir.join("daemon.lock")).map_err(|e| e.to_string())?;
        let owner = try_lock(&lock);
        let skip: Vec<Vec<u8>> = match opts.skip {
            // ("/a/" is /a; an empty entry would block everything.)
            Some(v) => v.iter().map(|p| crate::live::normalize(p.as_os_str().as_bytes())).filter(|p| !p.is_empty()).collect(),
            None if has_full_disk_access() && std::env::var_os("FSEARCH_RESTRICT").is_none() => Vec::new(),
            None => {
                log("no Full Disk Access: skipping consent-gated folders (grant it to fsearch to index everything)");
                gated(&opts.home)
            }
        };
        if !skip.is_empty() {
            let _ = walk::SKIP.set(skip);
        }
        // As FSEvents reports it: real (a temp dir's /var is /private/var).
        let real = opts.dir.canonicalize().unwrap_or_else(|_| opts.dir.clone());
        let ours = real.as_os_str().as_bytes().to_vec();
        // The churn folders are indexed but applied lazily (FSEARCH_NO_LAZY
        // turns that off).
        let lazy_dirs = walk::LazyDirs::build(opts.home.as_bytes(), std::env::var_os("FSEARCH_NO_LAZY").is_some_and(|v| v == "1"));
        if lazy_dirs.used() {
            let _ = walk::LAZY.set(lazy_dirs);
        }
        let dir = opts.dir;
        let loading = Index::load(&dir.join("index.bin"));
        let (tx, rx) = std::sync::mpsc::channel();
        let (ctx, crx) = std::sync::mpsc::channel();
        let content = if owner { Content::open(dir.join("content")) } else { Content::open_shared(dir.join("content")) };
        let content_ready = AtomicBool::new(!owner || !content.segs.is_empty());
        let shared = Arc::new(Shared {
            live: RwLock::new(None),
            loading: (Mutex::new(loading.is_some()), Condvar::new()),
            content: RwLock::new(content),
            home: opts.home,
            dir,
            wake: tx,
            save_requested: AtomicBool::new(false),
            content_tx: ctx,
            content_rx: Mutex::new(Some(crx)),
            content_pending: AtomicUsize::new(0),
            dirty: Default::default(),
            owner: AtomicBool::new(owner),
            lock,
            stream: Mutex::new(None),
            streams: Default::default(),
            since: AtomicU64::new(0),
            ours,
            replaying: AtomicBool::new(true),
            content_seen: Mutex::new(None),
            early: Mutex::new(Vec::new()),
            content_ready,
            content_early: Mutex::new(Vec::new()),
            on_change: RwLock::new(Vec::new()),
        });
        if owner {
            start_content(&shared);
        }
        let s = shared.clone();
        // Starting the stream (loading CoreServices) and faulting a saved
        // index in take ms each: done once searches run on the index as
        // mapped, so a restart's first answer needn't wait (`fsearch <query>`
        // with no daemon running: 33 -> 27 ms on the M6).
        spawn("fsearch-apply", move || {
            let (live, replay) = match loading {
                Some(b) => {
                    log(format!("loaded {} entries, replaying events since {}", b.n, b.event_id));
                    let from = b.event_id;
                    (Live::lazy(b), Some(from))
                }
                None if owner => {
                    // Watch before scanning so nothing that changes mid-scan
                    // is missed; replaying it afterwards is harmless (diffs
                    // are idempotent).
                    let since = fsevents::current_id();
                    s.watch(since);
                    (Live::lazy(full_build(&s, since)), None)
                }
                None => match wait_for_index(&s) {
                    // The owner is building it; follow once it exists...
                    Some(b) => {
                        s.watch(b.event_id);
                        (Live::lazy(b), None)
                    }
                    // ...or build it, if the owner quit first.
                    None => {
                        let since = fsevents::current_id();
                        s.watch(since);
                        (Live::lazy(full_build(&s, since)), None)
                    }
                },
            };
            *s.live.write().unwrap() = Some(live);
            s.early.lock().unwrap().clear();
            *s.loading.0.lock().unwrap() = false;
            s.loading.1.notify_all();
            if let Some(from) = replay {
                // (A save from before event ids were stamped: from now.)
                s.watch(if owner && from == 0 { fsevents::current_id() } else { from });
            }
            if let Some(l) = s.live.read().unwrap().as_ref() {
                l.base.prefault();
            }
            if owner {
                rescan_unskipped(&s);
            }
            apply_loop(&s, rx);
        });
        Ok(Engine { s: shared })
    }

    pub fn home(&self) -> &str {
        &self.s.home
    }

    /// Keep the cores clocked up for `d` from now. After ~20 ms idle macOS
    /// slows them down, and a search then runs 3-6x slower while they ramp
    /// back up; one spinning thread keeps them up, so the next keystroke's
    /// search starts fast. The spinning stops when a search starts (the
    /// search keeps the cores busy itself) and when `d` runs out.
    pub fn keep_warm(&self, d: Duration) {
        let w = warmer();
        let now = now_ns();
        // They stay up for the first few ms anyway.
        WARM_FROM.store(now + 2_000_000, Ordering::SeqCst);
        WARM_UNTIL.store(now + d.as_nanos() as u64, Ordering::SeqCst);
        if WARM_IDLE.load(Ordering::SeqCst) {
            w.unpark();
        }
    }

    /// Name search.
    pub fn search(&self, q: &Query) -> Result<Vec<Found>, String> {
        WARM_UNTIL.store(0, Ordering::Relaxed);
        let (found, early) = self.s.with_names(q.scope.as_deref(), |live| {
            let mut p = Vec::new();
            search_pool()
                .install(|| Searcher { live }.search(q))
                .into_iter()
                .map(|h| {
                    let (kind, size, mtime) = match &h.over {
                        Some(path) => {
                            let o = live.over[path];
                            p = path.clone();
                            (o.kind, o.size, o.mtime)
                        }
                        None => {
                            let i = h.idx as usize;
                            live.base.path(i, &mut p);
                            (live.base.kind(i), live.base.size_of(i), live.base.mtime(i))
                        }
                    };
                    Found { path: PathBuf::from(std::ffi::OsStr::from_bytes(&p)), kind, size, mtime, score: h.score }
                })
                .collect()
        })?;
        self.s.index_first(early);
        Ok(found)
    }

    /// Content search: `g` is the pattern, `q` narrows which files are read.
    /// The bool says whether the content index answered (false: files were
    /// picked from the name index and read, for folders it doesn't cover).
    pub fn grep(&self, q: &Query, g: &Grep) -> Result<(GrepResult, bool), String> {
        WARM_UNTIL.store(0, Ordering::Relaxed);
        let home = self.s.home.as_bytes();
        let indexed = q.scope.as_ref().is_none_or(|s| content::in_scope(s, home));
        let built = indexed && self.s.content_holds(q.scope.as_deref());
        if built {
            let fresh = self.s.dirty.files(q);
            let c = self.s.content.read().unwrap();
            // A folder the index holds nothing in (one its .gitignore leaves
            // out, say) is read directly, below.
            if q.scope.as_ref().is_none_or(|s| c.holds(s)) {
                // Content search brings its own reader threads; running it
                // here skips waking a pool thread just to hand the work over.
                return Ok((c.search_with(g, q, &fresh), true));
            }
        }
        // Pick files under the lock, read them after releasing it: reading can
        // be slow and a waiting writer would stall every other query.
        let scope = q.scope.as_deref();
        if indexed && !built {
            // The content index's first build is running: read the files it
            // will hold instead, so the answer is complete (and the same).
            // None there: read the folder directly, below, as once built.
            let (docs, early) = self.s.with_names(scope, |live| content::wanted(live, home, scope.unwrap_or(home), true))?;
            if !docs.is_empty() {
                let hold = walk::Hold::new();
                let r = content::grep_unindexed(g, docs, q);
                drop(hold);
                self.s.index_first(early);
                return Ok((r, false));
            }
            self.s.index_first(early);
        }
        let (paths, _) = self.s.with_names(scope, |live| search_pool().install(|| content::scan_paths(live, q.clone_for_scan())))?;
        let _hold = walk::Hold::new();
        Ok((content::verify(g, &paths, q.limit), false))
    }

    pub fn status(&self) -> Status {
        let l = self.s.live.read().unwrap();
        let c = self.s.content.read().unwrap();
        Status {
            ready: l.is_some(),
            entries: l.as_ref().map_or(0, |l| l.base.n),
            dirs: l.as_ref().map_or(0, |l| l.base.d),
            overlay: l.as_ref().map_or(0, |l| l.over.len()),
            removed: l.as_ref().map_or(0, |l| l.dead_count),
            event_id: l.as_ref().map_or(0, |l| l.event_id),
            index_bytes: l.as_ref().map_or(0, |l| l.base.bytes()),
            content_docs: c.docs(),
            content_segments: c.segs.len(),
            content_bytes: c.bytes(),
            content_pending: self.s.content_pending.load(Ordering::Relaxed),
            full_disk_access: walk::SKIP.get().is_none(),
            owner: self.s.owner(),
        }
    }

    /// The answer while the first index builds, with its progress.
    pub fn indexing(&self) -> String {
        indexing()
    }

    /// Compact and save the name index soon (on the background thread).
    pub fn save(&self) {
        self.s.save_requested.store(true, Ordering::Relaxed);
        let _ = self.s.wake.send(Vec::new());
    }

    /// Have `f` told the folders each batch of disk changes touched (true:
    /// and maybe anything below them), as the batch is applied (on the
    /// thread applying it: keep `f` quick).
    pub fn on_change(&self, f: impl Fn(&[(&[u8], bool)]) + Send + Sync + 'static) {
        self.s.on_change.write().unwrap().push(Box::new(f));
    }
}

/// (dirs, trees) for the content worker to re-sync.
type Resync = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// The answer while the first index builds, with its progress.
fn indexing() -> String {
    let n = walk::LISTED.load(Ordering::Relaxed);
    format!("indexing: {:.1}M entries so far (the first run lists the whole disk, ~25s)", n as f64 / 1e6)
}

impl Shared {
    fn live(&self) -> RwLockReadGuard<'_, Option<Live>> {
        let (loading, cv) = &self.loading;
        drop(cv.wait_while(loading.lock().unwrap(), |l| *l).unwrap());
        self.live.read().unwrap()
    }

    fn owner(&self) -> bool {
        self.owner.load(Ordering::Relaxed)
    }

    /// Run `f` on the name index. On the first run, before the whole disk
    /// is listed (~25 s), a search in a folder runs on an index of just
    /// that folder, listed for it: as fast as a tool that only ever scans
    /// that folder, and the same answer the whole index will give. That
    /// index comes back too (see `index_first`).
    fn with_names<R>(&self, scope: Option<&[u8]>, f: impl FnOnce(&Live) -> R) -> Result<(R, Option<Arc<Early>>), String> {
        loop {
            if let Some(live) = self.live().as_ref() {
                return Ok((f(live), None));
            }
            let Some(dir) = scope.filter(|s| s.len() > 1) else { return Err(indexing()) };
            if let Some(early) = self.early(dir) {
                return Ok((f(&early.live), Some(early)));
            }
        }
    }

    /// The early index of a folder holding `dir`, listing `dir` if none
    /// does; None once the whole disk is in.
    fn early(&self, dir: &[u8]) -> Option<Arc<Early>> {
        let mut early = self.early.lock().unwrap();
        if self.live.read().unwrap().is_some() {
            return None;
        }
        if let Some(e) = early.iter().find(|e| under(dir, &e.dir)) {
            return Some(e.clone());
        }
        let t = Instant::now();
        let hold = walk::Hold::new();
        let ls = folder_listings(dir);
        drop(hold);
        let live = Live::new(Index::build(ls, 0, 0, self.home.as_bytes()));
        log(format!("listed {} first: {} entries in {:.2?}", String::from_utf8_lossy(dir), live.base.n, t.elapsed()));
        let e = Arc::new(Early { dir: dir.to_vec(), live, indexing: AtomicBool::new(false) });
        early.push(e.clone());
        Some(e)
    }

    /// Once a search answered from an early index: index the contents of
    /// its folder first (from that index), so its next greps use the index
    /// within seconds instead of reading every file. Not sooner: that
    /// build reads the same files as the answer's direct scan.
    fn index_first(&self, early: Option<Arc<Early>>) {
        if let Some(e) = early
            && self.owner()
            && content::in_scope(&e.dir, self.home.as_bytes())
            && !e.indexing.swap(true, Ordering::Relaxed)
        {
            let _ = self.content_tx.send((Vec::new(), vec![e.dir.clone()]));
        }
    }

    /// Does the content index hold every file under `scope` (all it should
    /// hold, without one)?
    fn content_holds(&self, scope: Option<&[u8]>) -> bool {
        self.content_ready.load(Ordering::Acquire) || scope.is_some_and(|s| self.content_early.lock().unwrap().iter().any(|f| under(s, f)))
    }

    /// (Re)start the FSEvents stream from `since`, replacing any old one.
    fn watch(&self, since: u64) {
        self.replaying.store(true, Ordering::Relaxed);
        self.since.store(since, Ordering::Relaxed);
        let n = self.streams.fetch_add(1, Ordering::Relaxed) + 1;
        // 0.5 s of latency lets fseventsd batch a burst of churn into one
        // wakeup instead of one per write (an isolated change still arrives
        // at once: the stream keeps NO_DEFER). `Pace` keeps a busy folder
        // from being listed that often anyway.
        let new = fsevents::watch(since, self.wake.clone(), n, &self.ours);
        *self.stream.lock().unwrap() = Some(new);
    }

    /// A follower picks up what the owner wrote: a newer name-index save
    /// (replaying FSEvents from it) and content segment changes.
    fn follow(&self) {
        let path = self.dir.join("index.bin");
        let saved = Index::saved_event_id(&path).unwrap_or(0);
        let ours = self.live.read().unwrap().as_ref().map_or(0, |l| l.base.event_id);
        if saved > ours
            && let Some(base) = Index::load(&path)
        {
            log(format!("following the owner's save: {} entries, replaying since {}", base.n, base.event_id));
            self.watch(base.event_id);
            *self.live.write().unwrap() = Some(Live::new(base));
        }
        let cdir = self.dir.join("content");
        let changed = std::fs::metadata(&cdir).and_then(|m| m.modified()).ok();
        let mut seen = self.content_seen.lock().unwrap();
        if changed != *seen {
            *seen = changed;
            *self.content.write().unwrap() = Content::open_shared(cdir);
        }
    }
}

fn start_content(s: &Arc<Shared>) {
    let Some(rx) = s.content_rx.lock().unwrap().take() else { return };
    let s = s.clone();
    spawn("fsearch-content", move || content_loop(&s, rx));
}

/// A follower takes over the index files once their owner is gone.
fn try_upgrade(s: &Arc<Shared>) -> bool {
    if s.owner() {
        return true;
    }
    if !try_lock(&s.lock) {
        return false;
    }
    s.owner.store(true, Ordering::Relaxed);
    log("took over the index from a previous owner");
    *s.content.write().unwrap() = Content::open(s.dir.join("content"));
    rescan_unskipped(s);
    start_content(s);
    true
}

/// Next to index.bin: the folders it lacks for want of access, one per
/// line (skipped, or refused by macOS).
const SKIPPED: &str = "skipped";

fn note_skipped(dir: &Path) {
    let denied = walk::DENIED.lock().unwrap();
    // (A folder listed early is listed again by the whole-disk crawl.)
    let mut all: Vec<&Vec<u8>> = walk::SKIP.get().into_iter().flatten().chain(denied.iter()).collect();
    all.sort();
    all.dedup();
    let mut out = Vec::new();
    for p in all {
        out.extend_from_slice(p);
        out.push(b'\n');
    }
    if let Err(e) = std::fs::write(dir.join(SKIPPED), out) {
        log(format!("save failed: {e}"));
    }
}

/// Full Disk Access granted since the save: the folders it lacked stay
/// missing, since no FSEvents replay brings them back. Rescan them like a
/// must-scan-subdirs event would; ones still refused carry over to the next
/// save. (A save from before this was recorded rescans the gated folders.)
fn rescan_unskipped(shared: &Shared) {
    let was: Vec<Vec<u8>> = match std::fs::read(shared.dir.join(SKIPPED)) {
        Ok(b) => b.split(|&c| c == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec).collect(),
        Err(_) => gated(&shared.home),
    };
    let mut now = Vec::new();
    for path in was {
        if walk::blocked(&path) {
            continue;
        }
        let readable = std::fs::read_dir(std::ffi::OsStr::from_bytes(&path)).map_or_else(|e| e.raw_os_error() != Some(libc::EPERM), |_| true);
        if readable {
            now.push(fsevents::Event { path, flags: MUST_SCAN_SUBDIRS, id: 0, stream: 0 });
        } else {
            walk::DENIED.lock().unwrap().push(path);
        }
    }
    if now.is_empty() {
        return;
    }
    log(format!("rescanning {} folders the saved index lacked", now.len()));
    let _ = shared.wake.send(now);
    // Saved soon, so the next start doesn't rescan them again.
    shared.save_requested.store(true, Ordering::Relaxed);
}

/// Is `path` `dir` or inside it?
pub(crate) fn under(path: &[u8], dir: &[u8]) -> bool {
    path.starts_with(dir) && (path.len() == dir.len() || path[dir.len()] == b'/')
}

/// Threads for listing one folder a search waits on (the whole-disk crawl
/// pauses meanwhile): on the M6, Linux's 102k entries list in 131 ms on 8,
/// 106 on 12, 95 on 16.
const EARLY_THREADS: usize = 16;

/// Listings for an index of just `dir`: a level from "/" down to it, each
/// with the one entry its parent's listing has for the next, then `dir`'s
/// whole subtree. Where the whole-disk crawl would not descend (a mount
/// point, a file, a missing or skipped folder) the chain stops, and the
/// index has nothing under `dir` either.
fn folder_listings(dir: &[u8]) -> Vec<Listing> {
    let comps: Vec<&[u8]> = dir.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
    let (mut out, mut path) = (Vec::new(), b"/".to_vec());
    for (i, &c) in comps.iter().enumerate() {
        let found = walk::list_one(&path).and_then(|l| l.ents.iter().copied().find(|e| &l.names[e.name_off as usize..][..e.name_len as usize] == c));
        let Some(e) = found else { return out };
        path = crate::live::join(&path, c);
        let descend = e.kind & 3 == KIND_DIR && e.kind & walk::FLAG_MOUNT == 0 && !walk::blocked(&path);
        let child = if descend { i as u32 + 1 } else { NONE };
        out.push(Listing { id: i as u32, names: c.to_vec(), ents: vec![RawEnt { name_off: 0, child, ..e }] });
        if !descend {
            return out;
        }
    }
    let k = comps.len() as u32;
    for mut l in walk::scan(dir, EARLY_THREADS) {
        l.id += k;
        for e in l.ents.iter_mut().filter(|e| e.child != NONE) {
            e.child += k;
        }
        out.push(l);
    }
    out
}

/// The index the owner saves, or None once we took over from an owner that
/// quit before saving one.
fn wait_for_index(s: &Arc<Shared>) -> Option<Index> {
    loop {
        if let Some(b) = Index::load(&s.dir.join("index.bin")) {
            return Some(b);
        }
        if try_upgrade(s) {
            return Index::load(&s.dir.join("index.bin"));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[rustfmt::skip]
const GATED_IN_HOME: &[&str] = &[
    "Desktop", "Documents", "Downloads", "Library/Mobile Documents", "Library/Containers", "Library/Group Containers",
    "Library/CloudStorage", "Pictures/Photos Library.photoslibrary", "Music/Music", "Movies/TV",
];

/// Folders macOS guards with a consent prompt (or that hold other volumes).
pub fn gated(home: &str) -> Vec<Vec<u8>> {
    let home = home.trim_end_matches('/');
    GATED_IN_HOME.iter().map(|d| format!("{home}/{d}").into_bytes()).chain([b"/Volumes".to_vec()]).collect()
}

/// The system TCC database is readable only with Full Disk Access, and
/// trying without it fails immediately (no prompt).
pub fn has_full_disk_access() -> bool {
    std::fs::File::open("/Library/Application Support/com.apple.TCC/TCC.db").is_ok()
}

fn content_pool(threads: usize, qos: libc::qos_class_t) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .start_handler(move |_| unsafe {
            libc::pthread_set_qos_class_self_np(qos, 0);
            no_materialize();
        })
        .build()
        .unwrap()
}

fn content_loop(shared: &Shared, rx: Receiver<Resync>) {
    // Indexing file contents is background work: utility QoS keeps it off
    // the user's way (lower CPU priority and IO tier).
    unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0) };
    let pool = content_pool(4, libc::qos_class_t::QOS_CLASS_UTILITY);
    let home = shared.home.as_bytes().to_vec();
    // First run, while the whole disk is listed: index the folders searches
    // ask about from their early indexes. (A request that comes as the
    // whole index lands is dropped: the sync of all of home covers it.)
    while shared.live.read().unwrap().is_none() {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok((_, dirs)) => {
                for dir in dirs {
                    let Some(e) = shared.early.lock().unwrap().iter().find(|e| e.dir == dir).cloned() else { continue };
                    sync_wants(shared, &pool, content::wants(&e.live, &home, &[], std::slice::from_ref(&dir)));
                    shared.content_early.lock().unwrap().push(dir);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
    // Reconcile all of home once, right away (cheap when nothing changed),
    // then follow along with the name index's changes.
    sync(shared, &pool, &home, &[], std::slice::from_ref(&home));
    shared.content_ready.store(true, Ordering::Release);
    // Per-folder debounce: a folder is processed 2s after its last change,
    // or 5 min after its first pending one if it never goes quiet. A file you
    // save lands in ~2s; files apps rewrite every second (state, logs) cost
    // one reindex per 5 min instead of one per event batch.
    let mut pending: HashMap<(Vec<u8>, bool), (Instant, Instant)> = HashMap::new();
    loop {
        let wait = if pending.is_empty() { Duration::from_secs(3600) } else { Duration::from_millis(250) };
        match rx.recv_timeout(wait) {
            Ok(first) => {
                let now = Instant::now();
                let mut changed = Vec::new();
                for (d, t) in std::iter::once(first).chain(rx.try_iter()) {
                    for key in d.into_iter().map(|p| (p, false)).chain(t.into_iter().map(|p| (p, true))) {
                        // Most of the disk's churn (Library, caches) is outside the indexed area.
                        if content::in_scope(&key.0, &home)
                            || (key.1 && home.starts_with(&key.0) && (key.0.ends_with(b"/") || home[key.0.len()..].starts_with(b"/")))
                        {
                            pending.entry(key.clone()).and_modify(|e| e.1 = now).or_insert((now, now));
                            changed.push(key);
                        }
                    }
                }
                // Until they are synced, searches read their changed files.
                changed.sort();
                changed.dedup();
                let wants = shared.live.read().unwrap().as_ref().map(|l| content::wanted_now(l, &home, &changed));
                if let Some(w) = wants {
                    shared.dirty.mark(&shared.content.read().unwrap(), w);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let ripe: Vec<(Vec<u8>, bool)> = pending
            .iter()
            .filter(|(_, (first, last))| last.elapsed() >= CONTENT_QUIET || first.elapsed() >= CONTENT_MAX_WAIT)
            .map(|(k, _)| k.clone())
            .collect();
        if ripe.is_empty() {
            continue;
        }
        let (mut dirs, mut trees) = (Vec::<Vec<u8>>::new(), Vec::<Vec<u8>>::new());
        for k in &ripe {
            pending.remove(k);
            if k.1 { trees.push(k.0.clone()) } else { dirs.push(k.0.clone()) }
        }
        sync(shared, &pool, &home, &dirs, &trees);
        shared.dirty.clear(&ripe);
    }
}

/// Bring the content index in line with the name index for these folders
/// (direct children) and trees.
fn sync(shared: &Shared, pool: &rayon::ThreadPool, home: &[u8], dirs: &[Vec<u8>], trees: &[Vec<u8>]) {
    let wants = {
        let g = shared.live.read().unwrap();
        let Some(live) = g.as_ref() else { return };
        content::wants(live, home, dirs, trees)
    };
    sync_wants(shared, pool, wants);
}

/// `sync`, given what the name index wants.
fn sync_wants(shared: &Shared, pool: &rayon::ThreadPool, wants: Vec<(Vec<u8>, bool, content::Docs)>) {
    let t = Instant::now();
    // (A folder built early leaves segments behind; the build is still the first.)
    let first = !shared.content_ready.load(Ordering::Acquire);
    let todo = shared.content.write().unwrap().diff(wants);
    if todo.is_empty() {
        return;
    }
    let n = todo.len();
    shared.content_pending.store(n, Ordering::Relaxed);
    // A first build (fresh install, format change) is a one-time wait the
    // user is watching: 8 threads at user-initiated QoS. Each thread keeps
    // its next files opened ahead, and past 8 threads those opens only
    // contend in the kernel. Measured on HOME (730k files, M4 Max, with
    // speed-content's open-ahead build): 99-155 s on the 4 utility threads;
    // 8 threads 17.2-17.5 s (61 s system CPU), 12 threads 22.0-24.3 s, 16
    // threads 27.2-30.1 s (250-300 s system CPU).
    let fast;
    let pool = if first {
        let threads = std::thread::available_parallelism().map_or(8, |n| n.get()).min(8);
        fast = content_pool(threads, libc::qos_class_t::QOS_CLASS_USER_INITIATED);
        &fast
    } else {
        pool
    };
    build_batches(shared, pool, &todo);
    drop(todo);
    // Keep the segment count small: merge size tiers of 8.
    loop {
        let plan = shared.content.read().unwrap().merge_plan();
        let Some(ids) = plan else { break };
        let (dir, id) = {
            let mut c = shared.content.write().unwrap();
            (c.dir.clone(), c.alloc_id())
        };
        let merged = {
            let c = shared.content.read().unwrap();
            pool.install(|| content::merge(&dir, id, &c.segments(&ids)))
        };
        match merged {
            Some(seg) => shared.content.write().unwrap().replace(&ids, seg),
            None => break,
        }
    }
    if n > 100 {
        log(format!("content: indexed {n} files in {:.2?}", t.elapsed()));
    }
    release_memory();
}

/// Build `todo` into segments one batch (`Docs::batches`) at a time, each
/// pushed when done. Two in flight overlapped one's single-threaded tail
/// with the next one's reads: on the M6 (Linux, ABBA n=10) 3.07 s instead
/// of 3.33, but a first-run peak of 616 MB instead of 375.
fn build_batches(shared: &Shared, pool: &rayon::ThreadPool, todo: &content::Docs) {
    let dir = shared.content.read().unwrap().dir.clone();
    for range in todo.batches() {
        walk::yield_to_searches();
        let id = shared.content.write().unwrap().alloc_id();
        if let Some(seg) = pool.install(|| content::build_segment(&dir, id, todo, range.clone())) {
            shared.content.write().unwrap().push(seg);
        }
        shared.content_pending.fetch_sub(range.len(), Ordering::Relaxed);
    }
}

fn full_build(shared: &Shared, event_id: u64) -> Index {
    let t = Instant::now();
    let started = crate::query::now_secs();
    let ls = walk::scan_disk(SCAN_THREADS);
    let idx = Index::build(ls, event_id, started, shared.home.as_bytes());
    let path = shared.dir.join("index.bin");
    let saved = idx.save(&path);
    if let Err(e) = &saved {
        log(format!("save failed: {e}"));
    }
    note_skipped(&shared.dir);
    log(format!("indexed {} entries in {:.2?}", idx.n, t.elapsed()));
    release_memory();
    // Re-map from the file so the index is clean, evictable page cache
    // rather than anonymous memory. (After a failed save the file is older.)
    if saved.is_ok() { Index::load(&path).unwrap_or(idx) } else { idx }
}

unsafe extern "C" {
    fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
}

/// Hand freed allocator memory back to the OS after big transient work
/// (index builds, content batches) instead of letting malloc cache it.
fn release_memory() {
    unsafe { malloc_zone_pressure_relief(std::ptr::null_mut(), 0) };
}

fn compact(shared: &Shared) {
    let t = Instant::now();
    let (ls, eid, synced) = {
        let g = shared.live.read().unwrap();
        let live = g.as_ref().unwrap();
        (live.to_listings(), live.event_id, live.synced_at)
    };
    let idx = Index::build(ls, eid, synced, shared.home.as_bytes());
    let path = shared.dir.join("index.bin");
    let saved = idx.save(&path);
    if let Err(e) = &saved {
        log(format!("save failed: {e}"));
    }
    note_skipped(&shared.dir);
    // (After a failed save the file is older: keep the one just built.)
    let idx = if saved.is_ok() { Index::load(&path).unwrap_or(idx) } else { idx };
    let n = idx.n;
    *shared.live.write().unwrap() = Some(Live::new(idx));
    // Rare enough to afford the lstats: forget cache dirs whose tag is gone.
    if let Some(l) = walk::LAZY.get() {
        l.prune();
    }
    release_memory();
    log(format!("compacted to {n} entries in {:.2?}", t.elapsed()));
}

/// FSEvents lost track of / (dropped events, or no history back to our
/// save): relist every folder modified since we were last in sync, plus the
/// folders of indexed text files edited since (an edit in place doesn't
/// touch its folder). Seconds, instead of recrawling the whole disk.
fn relist_changed(shared: &Shared, why: &str, flags: u32) {
    let t = Instant::now();
    let started = crate::query::now_secs();
    // synced_at 0 (unknown) relists everything: a full crawl, done in place.
    let (from, mut dirs) = {
        let g = shared.live.read().unwrap();
        let live = g.as_ref().unwrap();
        let from = live.synced_at.saturating_sub(SYNC_MARGIN);
        (from, live.changed_dirs(from))
    };
    dirs.extend(shared.content.read().unwrap().changed_dirs(from));
    dirs.sort();
    dirs.dedup();
    let stat_time = t.elapsed();
    // Disk reads under the read lock, one folder per write, so searches keep
    // answering meanwhile.
    for d in &dirs {
        let f = shared.live.read().unwrap().as_ref().unwrap().fetch(d, false);
        shared.live.write().unwrap().as_mut().unwrap().apply(f);
    }
    let trees = {
        let mut g = shared.live.write().unwrap();
        let live = g.as_mut().unwrap();
        live.synced_at = started;
        std::mem::take(&mut live.trees)
    };
    let n = dirs.len();
    let _ = shared.content_tx.send((dirs, trees));
    shared.on_change.read().unwrap().iter().for_each(|f| f(&[(&b"/"[..], true)]));
    log(format!(
        "FSEvents lost track of / ({why}, flags {flags:#x}): relisted {n} folders changed since {from} in {:.2?} ({stat_time:.2?} checking)",
        t.elapsed()
    ));
}

/// Folders are listed again as their events come, but a folder may spend
/// at most 1/RELIST_SHARE of the time being listed, running at most
/// RELIST_AHEAD ahead of that: a folder changed a few times in a row
/// (save, rename, delete) is listed each time, while a hot one of 5000
/// entries (2.2 ms a listing) settles at ~9 listings a second.
const RELIST_SHARE: u32 = 50;
const RELIST_AHEAD: Duration = Duration::from_millis(2500);

/// Folders whose events wait because they were listed a lot lately.
#[derive(Default)]
struct Pace {
    /// Per folder: when the time its listings may take is paid for (listing
    /// time x RELIST_SHARE, from when it was listed).
    paid: HashMap<Vec<u8>, Instant>,
    /// Folders waiting for that: (recursive, oldest event id).
    held: HashMap<Vec<u8>, (bool, u64)>,
    /// `paid`'s size after it was last pruned of folders paid up.
    kept: usize,
}

impl Pace {
    /// May `dir` be listed now?
    fn free(&self, dir: &[u8], now: Instant) -> bool {
        self.paid.get(dir).is_none_or(|&t| t <= now + RELIST_AHEAD)
    }

    /// Hold back the folders of `dirs` that ran too far ahead; add the held
    /// ones now free.
    fn sort(&mut self, dirs: &mut HashMap<Vec<u8>, (bool, u64)>, now: Instant) {
        let early: Vec<Vec<u8>> = dirs.keys().filter(|d| !self.free(d, now)).cloned().collect();
        for d in early {
            let (r, id) = dirs.remove(&d).unwrap();
            let h = self.held.entry(d).or_insert((r, id));
            *h = (h.0 | r, h.1.min(id));
        }
        let due: Vec<Vec<u8>> = self.held.keys().filter(|d| self.free(d, now)).cloned().collect();
        for d in due {
            let (r, id) = self.held.remove(&d).unwrap();
            let e = dirs.entry(d).or_insert((r, id));
            *e = (e.0 | r, e.1.min(id));
        }
    }

    fn listed(&mut self, dir: &[u8], took: Duration, now: Instant) {
        if self.paid.len() > 2 * self.kept.max(2048) {
            self.paid.retain(|_, t| *t > now);
            self.kept = self.paid.len();
        }
        // (A listing that also scanned a big new subfolder holds it 1 s at most.)
        let from = self.paid.get(dir).map_or(now, |&t| t.max(now));
        self.paid.insert(dir.to_vec(), (from + took * RELIST_SHARE).min(now + RELIST_AHEAD + Duration::from_secs(1)));
    }

    /// Until the first held folder is free.
    fn wait(&self, now: Instant) -> Option<Duration> {
        let free_at = |d: &Vec<u8>| self.paid.get(d).map_or(now, |&t| t.checked_sub(RELIST_AHEAD).unwrap_or(now));
        self.held.keys().map(free_at).min().map(|t| t.saturating_duration_since(now))
    }

    /// Event ids from this one on are not all applied yet.
    fn floor(&self) -> u64 {
        self.held.values().map(|h| h.1).min().unwrap_or(u64::MAX)
    }
}

/// A lazy unit's pending changes flush once quiet for this long, or once
/// this old under churn that never quiets; past this many folders in one
/// unit the unit is rescanned whole.
const LAZY_QUIET: Duration = Duration::from_secs(5);
const LAZY_MAX: Duration = Duration::from_secs(60);
const LAZY_COLLAPSE: usize = 2048;

/// A lazy unit's pending changes.
#[derive(Default)]
struct LazyPending {
    /// Folders to relist, each with its recursive flag.
    dirs: HashMap<Vec<u8>, bool>,
    /// Too many folders pending: rescan the whole unit instead.
    whole: bool,
    /// When the unit's first pending event arrived (its Instant and wall
    /// time), the latest's, and the lowest event id seen.
    first: Option<(Instant, u32)>,
    last: Option<Instant>,
    min_id: u64,
}

/// Churn folders' pending changes, by lazy unit.
#[derive(Default)]
struct Lazy {
    units: HashMap<Vec<u8>, LazyPending>,
}

impl Lazy {
    fn add(&mut self, unit: &[u8], dir: Vec<u8>, recursive: bool, id: u64, now: Instant, wall: u32) {
        let p = self.units.entry(unit.to_vec()).or_default();
        p.first.get_or_insert((now, wall));
        p.last = Some(now);
        p.min_id = if p.min_id == 0 { id } else { p.min_id.min(id) };
        if !p.whole {
            *p.dirs.entry(dir).or_default() |= recursive;
            if p.dirs.len() > LAZY_COLLAPSE {
                p.whole = true;
                p.dirs.clear();
            }
        }
    }

    /// (Folder, recursive) pairs due at `now`, draining their units.
    fn due(&mut self, now: Instant) -> Vec<(Vec<u8>, bool)> {
        let due = |p: &LazyPending| {
            now.saturating_duration_since(p.last.unwrap()) >= LAZY_QUIET || now.saturating_duration_since(p.first.unwrap().0) >= LAZY_MAX
        };
        let mut out = Vec::new();
        for (u, p) in self.units.iter().filter(|(_, p)| due(p)) {
            if p.whole {
                out.push((u.clone(), true));
            } else {
                out.extend(p.dirs.iter().map(|(d, &r)| (d.clone(), r)));
            }
        }
        out.sort();
        self.units.retain(|_, p| !due(p));
        out
    }

    /// When the soonest unit is due, if any are pending.
    fn wait(&self, now: Instant) -> Option<Duration> {
        self.units
            .values()
            .map(|p| {
                LAZY_QUIET
                    .saturating_sub(now.saturating_duration_since(p.last.unwrap()))
                    .min(LAZY_MAX.saturating_sub(now.saturating_duration_since(p.first.unwrap().0)))
            })
            .min()
    }

    /// Event ids from this one on are not all applied yet.
    fn floor(&self) -> u64 {
        self.units.values().map(|p| p.min_id).min().unwrap_or(u64::MAX)
    }

    /// The wall time of the oldest pending lazy event: `synced_at` caps
    /// there rather than freezing while a unit churns on.
    fn earliest_wall(&self) -> Option<u32> {
        self.units.values().filter_map(|p| p.first).map(|(_, w)| w).min()
    }
}

fn apply_loop(shared: &Arc<Shared>, rx: Receiver<Vec<fsevents::Event>>) {
    let mut last_save = Instant::now();
    let mut last_follow = Instant::now();
    let ours = shared.ours.as_slice();
    // Events fseventsd dropped before we read them: (replay from, last drop).
    let mut gap: Option<(u64, Instant)> = None;
    // Replays in a row that dropped again; the third falls back to a relist.
    let mut replays = 0;
    // A relist due inside RELIST_COOLDOWN, as (why, root flags).
    let mut relist_due: Option<(&'static str, u32)> = None;
    let mut last_relist: Option<Instant> = None;
    // The last batch's pending count and base size, for the wait below.
    let (mut pending, mut n_base) = (0usize, 0usize);
    // When the apply loop last received a non-empty event batch.
    let mut last_events = Instant::now();
    // The highest event id ever seen: the watermark may rise to it once
    // nothing is pending, even on wakes that applied nothing new.
    let mut seen_max = 0u64;
    let mut pace = Pace::default();
    // Churn folders' pending changes, batched by lazy unit.
    let mut lazy = Lazy::default();
    loop {
        let mut wait = if gap.is_some() && relist_due.is_none() { Duration::from_millis(250) } else { Duration::from_secs(60) };
        if let Some(w) = pace.wait(Instant::now()) {
            wait = wait.min(w);
        }
        // Wake when the compaction quiet window closes while enough is
        // pending, when a deferred relist's cooldown ends (now, if it
        // already has), and when the earliest lazy unit is due.
        if pending > COMPACT_PENDING.max(n_base / 8) {
            wait = wait.min(COMPACT_QUIET.saturating_sub(last_events.elapsed()));
        }
        if relist_due.is_some() {
            wait = wait.min(relist_in(last_relist, Instant::now()).unwrap_or(Duration::ZERO));
        }
        if let Some(w) = lazy.wait(Instant::now()) {
            wait = wait.min(w);
        }
        let mut events = match rx.recv_timeout(wait) {
            Ok(b) => b,
            Err(RecvTimeoutError::Timeout) => Vec::new(),
            Err(RecvTimeoutError::Disconnected) => return,
        };
        events.extend(rx.try_iter().flatten());
        // The owner wrote the index files: a follower picks that up now
        // rather than at its next periodic check.
        let owner_wrote = events.iter().any(|e| under(&e.path, ours));
        let (mut rebuild, mut root_flags, had_events) = (false, 0, !events.is_empty());
        if had_events {
            last_events = Instant::now();
        }
        let mut dirs: HashMap<Vec<u8>, (bool, u64)> = HashMap::new();
        if had_events {
            let (evt, wall) = (Instant::now(), crate::query::now_secs());
            let mut last_good = shared.live.read().unwrap().as_ref().map_or(0, |l| l.event_id);
            let current = shared.streams.load(Ordering::Relaxed);
            for e in events {
                if e.path == b"/" && e.flags & MUST_SCAN_SUBDIRS != 0 {
                    // fseventsd still logged what it dropped for us (a kernel
                    // drop never reached it): replay from the last event we
                    // did get, once the drops stop; a drop during a replay
                    // starts that replay over. A replaced stream's drop is
                    // covered by the stream that replaced it.
                    if e.flags & (USER_DROPPED | KERNEL_DROPPED) == USER_DROPPED {
                        if e.stream == current {
                            let from = if shared.replaying.load(Ordering::Relaxed) { shared.since.load(Ordering::Relaxed) } else { last_good };
                            gap = Some((gap.map_or(from, |(g, _)| g.min(from)), Instant::now()));
                        }
                        continue;
                    }
                    root_flags |= e.flags;
                }
                seen_max = seen_max.max(e.id);
                if gap.is_none() {
                    last_good = last_good.max(e.id);
                }
                if e.flags & HISTORY_DONE != 0 {
                    log("replay done");
                    shared.replaying.store(false, Ordering::Relaxed);
                    if gap.is_none() {
                        replays = 0;
                    }
                    continue;
                }
                let d = crate::live::normalize(&e.path);
                // A lazy folder's changes batch under its unit instead of
                // listing now; Pace is for prompt paths only.
                if let Some(u) = walk::LAZY.get().and_then(|l| l.unit(&d)) {
                    let unit = d[..u].to_vec();
                    lazy.add(&unit, d, e.flags & MUST_SCAN_SUBDIRS != 0, e.id, evt, wall);
                    continue;
                }
                let d = dirs.entry(d).or_insert((false, e.id));
                *d = (d.0 | (e.flags & MUST_SCAN_SUBDIRS != 0), d.1.min(e.id));
            }
        }
        let now = Instant::now();
        pace.sort(&mut dirs, now);
        let had_dirs = !dirs.is_empty();
        if had_dirs {
            // The folders listed now (a held one is told when it is due).
            let hooks = shared.on_change.read().unwrap();
            if !hooks.is_empty() {
                let changed: Vec<(&[u8], bool)> = dirs.iter().map(|(p, &(r, _))| (p.as_slice(), r)).collect();
                hooks.iter().for_each(|f| f(&changed));
            }
            drop(hooks);
            let mut trees = Vec::new();
            // Read the disk under the read lock, then apply in memory: a
            // search never waits on a folder listing or a new subtree's scan.
            let fetched: Vec<_> = {
                let g = shared.live.read().unwrap();
                let live = g.as_ref().unwrap();
                dirs.iter()
                    .map(|(p, &(recursive, _))| {
                        let t = Instant::now();
                        let f = live.fetch(p, recursive);
                        pace.listed(p, t.elapsed(), now);
                        f
                    })
                    .collect()
            };
            {
                let mut g = shared.live.write().unwrap();
                let live = g.as_mut().unwrap();
                for f in fetched {
                    if let Applied::Rebuild = live.apply(f) {
                        rebuild = true;
                    }
                }
                // With a gap, everything is applied only up to its start;
                // with folders held back or lazy changes pending, only up
                // to their first event.
                live.event_id = advance(live.event_id, seen_max, pace.floor().min(lazy.floor()), gap.map(|(from, _)| from));
                trees.append(&mut live.trees);
            }
            let (rec, flat): (Vec<_>, Vec<_>) = dirs.into_iter().partition(|(_, (r, _))| *r);
            trees.extend(rec.into_iter().map(|(p, _)| p));
            let _ = shared.content_tx.send((flat.into_iter().map(|(p, _)| p).collect(), trees));
        }
        // A lazy unit flushes once quiet (or once too old): its folders go
        // through the same fetch-under-read-lock, apply-under-write-lock
        // path prompt ones do — minus Pace.
        let due = lazy.due(now);
        if !due.is_empty() {
            let hooks = shared.on_change.read().unwrap();
            if !hooks.is_empty() {
                let changed: Vec<(&[u8], bool)> = due.iter().map(|(p, r)| (p.as_slice(), *r)).collect();
                hooks.iter().for_each(|f| f(&changed));
            }
            drop(hooks);
            let mut trees = Vec::new();
            let fetched: Vec<_> = {
                let g = shared.live.read().unwrap();
                let live = g.as_ref().unwrap();
                due.iter().map(|(p, r)| live.fetch(p, *r)).collect()
            };
            {
                let mut g = shared.live.write().unwrap();
                let live = g.as_mut().unwrap();
                for f in fetched {
                    if let Applied::Rebuild = live.apply(f) {
                        rebuild = true;
                    }
                }
                live.event_id = advance(live.event_id, seen_max, pace.floor().min(lazy.floor()), gap.map(|(from, _)| from));
                trees.append(&mut live.trees);
            }
            let (rec, flat): (Vec<_>, Vec<_>) = due.into_iter().partition(|(_, r)| *r);
            trees.extend(rec.into_iter().map(|(p, _)| p));
            let _ = shared.content_tx.send((flat.into_iter().map(|(p, _)| p).collect(), trees));
        } else if !had_dirs {
            // A wake that applied nothing — the floor may still have
            // risen: the watermark catches up to what arrived.
            let mut g = shared.live.write().unwrap();
            let live = g.as_mut().unwrap();
            live.event_id = advance(live.event_id, seen_max, pace.floor().min(lazy.floor()), gap.map(|(from, _)| from));
        }
        let replay = gap.filter(|(_, at)| at.elapsed() >= replay_delay(replays)).map(|(from, _)| from);
        if rebuild || (replay.is_some() && replays >= 3) && relist_due.is_none() {
            let why = match root_flags {
                f if f & KERNEL_DROPPED != 0 => "kernel dropped events",
                0 => "events dropped again while replaying",
                _ => "history unavailable",
            };
            // A relist due inside the cooldown waits it out: the gap stays
            // (events before it are not all applied), and one relist runs
            // when the window ends instead of a relist per burst.
            relist_due = Some((why, root_flags));
        }
        if let Some((why, flags)) = relist_due {
            if relist_in(last_relist, Instant::now()).is_none() {
                relist_changed(shared, why, flags);
                (gap, replays, relist_due, last_relist) = (None, 0, None, Some(Instant::now()));
            }
        } else if let Some(from) = replay {
            log(format!("FSEvents dropped events before we read them: replaying from {from}"));
            shared.watch(from);
            // Ids past `from` arrive again from the replay: the watermark
            // mustn't run ahead of them on what was seen before the drop.
            seen_max = from;
            (gap, replays) = (None, replays + 1);
        } else if had_events && gap.is_none() && pace.held.is_empty() && !shared.replaying.load(Ordering::Relaxed) {
            // Everything up to this batch is applied (a change's event can
            // trail it by the stream latency; relisting keeps a margin) —
            // except pending lazy changes, so cap at the oldest one's
            // arrival rather than freezing while a unit churns on.
            let wall = crate::query::now_secs();
            shared.live.write().unwrap().as_mut().unwrap().synced_at = lazy.earliest_wall().map_or(wall, |w| wall.min(w));
        }
        if let Some(l) = shared.live.read().unwrap().as_ref() {
            l.names_cache.trim_if_idle(Duration::from_secs(60));
        }
        if now_ns().saturating_sub(LAST_SEARCH.load(Ordering::Relaxed)) > 60_000_000_000 && crate::alloc::kept() {
            pool().spawn_broadcast(|_| crate::alloc::drain());
        }
        if !shared.owner() && (owner_wrote || last_follow.elapsed() > FOLLOW_EVERY) {
            last_follow = Instant::now();
            if !try_upgrade(shared) {
                shared.follow();
            }
        }
        if !shared.owner() {
            continue;
        }
        let stale;
        {
            let g = shared.live.read().unwrap();
            let live = g.as_ref().unwrap();
            (pending, n_base) = (live.over.len() + live.dead_count, live.base.n);
            stale = live.event_id != live.base.event_id;
        };
        let asked = shared.save_requested.swap(false, Ordering::Relaxed);
        if should_compact(pending, n_base, last_events.elapsed(), stale.then(|| last_save.elapsed()), asked) {
            compact(shared);
            last_save = Instant::now();
        }
    }
}

/// The watermark to stamp: never past an unflushed event (`floor`), never
/// past a gap's start, and never backwards.
fn advance(cur: u64, seen_max: u64, floor: u64, gap: Option<u64>) -> u64 {
    gap.map_or(cur.max(seen_max.min(floor.saturating_sub(1))), |from| cur.min(from))
}

/// Whether to fold the overlay into the base now: always when asked; past
/// the hard bound even mid-churn; past the soft one once the disk has been
/// quiet for COMPACT_QUIET; or with unsaved changes twice a day, again once
/// quiet. (`stale_for`: how long the last save is, when changes are
/// unsaved.)
fn should_compact(pending: usize, n_base: usize, quiet_for: Duration, stale_for: Option<Duration>, asked: bool) -> bool {
    let soft = COMPACT_PENDING.max(n_base / 8);
    let hard = COMPACT_HARD.max(n_base / 2);
    asked
        || pending > hard
        || (pending > soft && quiet_for >= COMPACT_QUIET)
        || (stale_for.is_some_and(|s| s >= COMPACT_EVERY) && quiet_for >= COMPACT_QUIET)
}

/// How long a replay after `replays` failed ones waits for quiet first,
/// doubling each time (2, 4, 8, ... capped at a minute).
fn replay_delay(replays: u32) -> Duration {
    REPLAY_QUIET.saturating_mul(1 << replays.min(5)).min(REPLAY_MAX)
}

/// How long until a relist may run again; None: it may now.
fn relist_in(last: Option<Instant>, now: Instant) -> Option<Duration> {
    let left = RELIST_COOLDOWN.saturating_sub(now.saturating_duration_since(last?));
    (left > Duration::ZERO).then_some(left)
}

/// Default data dir: `~/Library/Application Support/FSearch`.
pub fn default_dir(home: &str) -> PathBuf {
    Path::new(home).join("Library/Application Support/FSearch")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An engine that follows (the lock is held for good, so it never
    /// crawls the disk). walk::SKIP is set once per process, so every test
    /// passes the same list: folders that don't exist, written oddly.
    fn follower(name: &str, home: &str) -> Engine {
        let d = std::env::temp_dir().join(format!("fsearch-engine-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let held = std::fs::File::create(d.join("daemon.lock")).unwrap();
        assert!(try_lock(&held));
        std::mem::forget(held);
        let skip = Some(vec![PathBuf::from("/nonexistent-fsearch-skip/"), PathBuf::new()]);
        let e = Engine::start(Options { dir: d.clone(), home: home.into(), skip }).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        e
    }

    /// Home written with a trailing slash is home: content scope and the
    /// gated folders compare paths to it.
    #[test]
    fn home_with_trailing_slash() {
        assert_eq!(gated("/h/")[0], b"/h/Desktop");
        assert_eq!(follower("home", "/h//").home(), "/h");
    }

    /// Skip entries are folders however written: "/a/" is /a, and an empty
    /// one blocks nothing.
    #[test]
    fn skip_entries() {
        follower("skip", "/h");
        assert!(walk::blocked(b"/nonexistent-fsearch-skip/x") && !walk::blocked(b"/usr"));
    }

    /// Compaction: always when asked, past the hard bound even mid-churn,
    /// past the soft one only once quiet, and twice a day for unsaved
    /// changes — also only once quiet.
    #[test]
    fn compact_decides() {
        assert!(should_compact(0, 0, Duration::ZERO, None, true));
        assert!(should_compact(COMPACT_HARD + 1, 0, Duration::ZERO, None, false));
        assert!(!should_compact(COMPACT_PENDING + 1, 0, Duration::ZERO, None, false));
        assert!(should_compact(COMPACT_PENDING + 1, 0, COMPACT_QUIET, None, false));
        // Both bounds grow with the base: under soft for a 1M-entry index
        // even when quiet, and over the old hard bound but under the grown
        // one for a 2M-entry index while churn goes on.
        assert!(!should_compact(COMPACT_PENDING + 1, 1_000_000, COMPACT_QUIET, None, false));
        assert!(!should_compact(COMPACT_HARD + 1, 2_000_000, Duration::ZERO, None, false));
        assert!(should_compact(1_000_001, 2_000_000, Duration::ZERO, None, false));
        assert!(should_compact(1, 0, COMPACT_QUIET, Some(COMPACT_EVERY), false));
        assert!(!should_compact(1, 0, COMPACT_QUIET, Some(Duration::from_secs(60)), false));
        assert!(!should_compact(1, 0, Duration::ZERO, Some(COMPACT_EVERY), false));
        assert!(!should_compact(1, 0, COMPACT_QUIET, None, false));
    }

    /// Replay backoff doubles and caps; a relist inside its cooldown tells
    /// the caller how long is left.
    #[test]
    fn backoff_and_cooldown() {
        assert_eq!(replay_delay(0), Duration::from_secs(2));
        assert_eq!(replay_delay(1), Duration::from_secs(4));
        assert_eq!(replay_delay(3), Duration::from_secs(16));
        assert_eq!(replay_delay(5), REPLAY_MAX);
        assert_eq!(replay_delay(9), REPLAY_MAX);
        let t = Instant::now();
        assert!(relist_in(None, t).is_none());
        assert_eq!(relist_in(Some(t), t), Some(RELIST_COOLDOWN));
        assert_eq!(relist_in(Some(t), t + Duration::from_secs(60)), Some(Duration::from_secs(240)));
        assert_eq!(relist_in(Some(t), t + RELIST_COOLDOWN), None);
    }

    /// The watermark: reaches seen_max once nothing is pending, stays
    /// under a pending unit's floor and a gap's start, never backwards.
    #[test]
    fn advance_caps() {
        assert_eq!(advance(5, 100, u64::MAX, None), 100);
        // A pending lazy unit holds it under that unit's first event.
        assert_eq!(advance(5, 100, 50, None), 49);
        // A gap floors it at the gap's start; never backwards either way.
        assert_eq!(advance(90, 30, u64::MAX, Some(40)), 40);
        assert_eq!(advance(90, 30, u64::MAX, None), 90);
        // floor of 0 (an id at 0) leaves no room to advance at all.
        assert_eq!(advance(0, 100, 0, None), 0);
    }

    /// A lazy unit flushes once quiet or once too old, collapses past
    /// LAZY_COLLAPSE folders, and keeps the loop's event floor honest.
    #[test]
    fn lazy_flushes() {
        let t0 = Instant::now();
        let mut l = Lazy::default();
        l.add(b"/u", b"/u/a".to_vec(), false, 10, t0, 100);
        l.add(b"/u", b"/u/b".to_vec(), true, 8, t0 + Duration::from_millis(50), 100);
        l.add(b"/v", b"/v".to_vec(), false, 5, t0, 90);
        assert_eq!(l.floor(), 5);
        assert_eq!(l.earliest_wall(), Some(90));
        assert!(l.due(t0 + Duration::from_secs(1)).is_empty());
        // /v quieted; /u is still fresh.
        assert_eq!(l.due(t0 + LAZY_QUIET), vec![(b"/v".to_vec(), false)]);
        assert_eq!(l.floor(), 8);
        // /u flushes once too old, quiet or not.
        assert_eq!(l.due(t0 + LAZY_MAX), vec![(b"/u/a".to_vec(), false), (b"/u/b".to_vec(), true)]);
        assert_eq!(l.floor(), u64::MAX);
        assert!(l.earliest_wall().is_none());
        // Past LAZY_COLLAPSE folders, the unit is rescanned whole.
        let mut l = Lazy::default();
        for i in 0..=LAZY_COLLAPSE {
            l.add(b"/u", format!("/u/d{i}").into_bytes(), false, i as u64 + 1, t0, 100);
        }
        assert_eq!(l.due(t0 + LAZY_QUIET), vec![(b"/u".to_vec(), true)]);
    }
}
