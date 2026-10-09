//! The engine: owns the live name index, follows FSEvents, keeps the content
//! index current, and answers searches. The daemon runs one; so can any app
//! that links this crate.

use crate::content::{self, Content, Grep, GrepResult};
use crate::fsevents::{self, HISTORY_DONE, KERNEL_DROPPED, MUST_SCAN_SUBDIRS, USER_DROPPED};
use crate::index::Index;
use crate::live::{Applied, Live};
use crate::query::{Query, Searcher};
use crate::walk;
use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

// Every search scans the whole overlay (~1 ms per 100k entries), and a
// follower starting up replays everything since the save, so fold it into
// the base once it grows: ~1 s of CPU and a ~280 MB write, about hourly on a
// busy disk. Otherwise only twice a day; restart replays FSEvents anyway.
const COMPACT_PENDING: usize = 50_000;
const COMPACT_EVERY: Duration = Duration::from_secs(12 * 3600);
const SCAN_THREADS: usize = 8;
const CONTENT_QUIET: Duration = Duration::from_secs(2);
const CONTENT_MAX_WAIT: Duration = Duration::from_secs(300);
/// How often a follower checks whether it can take over or reload.
const FOLLOW_EVERY: Duration = Duration::from_secs(10);
/// Seconds before the last known-good moment that a relist also covers.
const SYNC_MARGIN: u32 = 120;

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

#[derive(Clone)]
pub struct Engine {
    s: Arc<Shared>,
}

struct Shared {
    live: RwLock<Option<Live>>,
    content: RwLock<Content>,
    home: String,
    dir: PathBuf,
    /// Wakes the apply loop; an empty batch is a no-op wake-up.
    wake: Sender<Vec<fsevents::Event>>,
    save_requested: AtomicBool,
    content_tx: Sender<Resync>,
    content_rx: Mutex<Option<Receiver<Resync>>>,
    content_pending: AtomicUsize,
    /// Holding `lock`: this engine writes the index files. Another process
    /// may own them (the daemon, an app); then this one follows: it reads
    /// the saved index, keeps it live in memory, and takes over when the
    /// owner goes away.
    owner: AtomicBool,
    lock: std::fs::File,
    stream: Mutex<Option<fsevents::Stream>>,
    /// The stream is still replaying history (until HISTORY_DONE).
    replaying: AtomicBool,
    /// Follower: content dir mtime when its segments were last opened.
    content_seen: Mutex<Option<std::time::SystemTime>>,
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
fn search_pool() -> &'static rayon::ThreadPool {
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .thread_name(|i| format!("fsearch-search-{i}"))
            .start_handler(|_| unsafe {
                libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0);
            })
            .build()
            .unwrap()
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
    /// Start indexing in the background and return at once; searches answer
    /// `Err` until the index is loaded (or, on the very first run, built).
    pub fn start(opts: Options) -> Result<Engine, String> {
        std::fs::create_dir_all(&opts.dir).map_err(|e| e.to_string())?;
        // One writer per index: a second one would race index writes. The
        // lock dies with the process.
        let lock = std::fs::File::create(opts.dir.join("daemon.lock")).map_err(|e| e.to_string())?;
        let owner = try_lock(&lock);
        let skip: Vec<Vec<u8>> = match opts.skip {
            Some(v) => v.into_iter().map(|p| p.as_os_str().as_bytes().to_vec()).collect(),
            None if has_full_disk_access() && std::env::var_os("FSEARCH_RESTRICT").is_none() => Vec::new(),
            None => {
                log("no Full Disk Access: skipping consent-gated folders (grant it to fsearch to index everything)");
                gated(&opts.home)
            }
        };
        if !skip.is_empty() {
            let _ = walk::SKIP.set(skip);
        }
        let dir = opts.dir;
        let (tx, rx) = std::sync::mpsc::channel();
        let (ctx, crx) = std::sync::mpsc::channel();
        let content = if owner { Content::open(dir.join("content")) } else { Content::open_shared(dir.join("content")) };
        let shared = Arc::new(Shared {
            live: RwLock::new(None),
            content: RwLock::new(content),
            home: opts.home,
            dir,
            wake: tx,
            save_requested: AtomicBool::new(false),
            content_tx: ctx,
            content_rx: Mutex::new(Some(crx)),
            content_pending: AtomicUsize::new(0),
            owner: AtomicBool::new(owner),
            lock,
            stream: Mutex::new(None),
            replaying: AtomicBool::new(true),
            content_seen: Mutex::new(None),
        });
        let base = Index::load(&shared.dir.join("index.bin"));
        let since = match &base {
            Some(b) if b.event_id != 0 => b.event_id,
            _ => unsafe { fsevents::FSEventsGetCurrentEventId() },
        };
        if owner {
            // Watch before scanning so nothing that changes mid-scan is
            // missed; replaying it afterwards is harmless (diffs are idempotent).
            shared.watch(since);
        }
        let s = shared.clone();
        spawn("fsearch-apply", move || {
            let base = match base {
                Some(b) => {
                    log(format!("loaded {} entries, replaying events since {}", b.n, b.event_id));
                    if !owner {
                        s.watch(b.event_id);
                    }
                    b
                }
                None if owner => full_build(&s, since),
                None => {
                    // The owner is building it; follow once it exists.
                    let b = wait_for_index(&s.dir);
                    s.watch(b.event_id);
                    b
                }
            };
            *s.live.write().unwrap() = Some(Live::new(base));
            if owner {
                rescan_unskipped(&s);
                start_content(&s);
            }
            apply_loop(&s, rx);
        });
        Ok(Engine { s: shared })
    }

    pub fn home(&self) -> &str {
        &self.s.home
    }

    /// Name search.
    pub fn search(&self, q: &Query) -> Result<Vec<Found>, String> {
        let g = self.s.live.read().unwrap();
        let Some(live) = g.as_ref() else { return Err(INDEXING.into()) };
        let mut p = Vec::new();
        Ok(search_pool()
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
                        (live.base.kind()[i], live.base.size_of(i), live.base.mtime()[i])
                    }
                };
                Found { path: PathBuf::from(std::ffi::OsStr::from_bytes(&p)), kind, size, mtime, score: h.score }
            })
            .collect())
    }

    /// Content search: `g` is the pattern, `q` narrows which files are read.
    /// The bool says whether the content index answered (false: files were
    /// picked from the name index and read, for folders it doesn't cover).
    pub fn grep(&self, q: &Query, g: &Grep) -> Result<(GrepResult, bool), String> {
        let home = self.s.home.as_bytes();
        let indexed = q.scope.as_ref().is_none_or(|s| content::in_scope(s, home));
        if indexed {
            return Ok((search_pool().install(|| self.s.content.read().unwrap().search(g, q)), true));
        }
        // Pick files under the lock, read them after releasing it: reading can
        // be slow and a waiting writer would stall every other query.
        let paths = {
            let l = self.s.live.read().unwrap();
            let Some(live) = l.as_ref() else { return Err(INDEXING.into()) };
            search_pool().install(|| content::scan_paths(live, q.clone_for_scan()))
        };
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

    /// Compact and save the name index soon (on the background thread).
    pub fn save(&self) {
        self.s.save_requested.store(true, Ordering::Relaxed);
        let _ = self.s.wake.send(Vec::new());
    }
}

/// (dirs, trees) for the content worker to re-sync.
type Resync = (Vec<Vec<u8>>, Vec<Vec<u8>>);

const INDEXING: &str = "indexing (first run scans the whole disk, ~20s)";

impl Shared {
    fn owner(&self) -> bool {
        self.owner.load(Ordering::Relaxed)
    }

    /// (Re)start the FSEvents stream from `since`, replacing any old one.
    fn watch(&self, since: u64) {
        self.replaying.store(true, Ordering::Relaxed);
        let new = fsevents::watch(since, 0.1, self.wake.clone());
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
    // Reconcile all of home once (cheap when nothing changed), then follow
    // along with the name index's changes.
    let _ = s.content_tx.send((Vec::new(), vec![s.home.as_bytes().to_vec()]));
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
    let mut out = Vec::new();
    for p in walk::SKIP.get().into_iter().flatten().chain(walk::DENIED.lock().unwrap().iter()) {
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
            now.push(fsevents::Event { path, flags: MUST_SCAN_SUBDIRS, id: 0 });
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

fn wait_for_index(dir: &Path) -> Index {
    loop {
        if let Some(b) = Index::load(&dir.join("index.bin")) {
            return b;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[rustfmt::skip]
const GATED_IN_HOME: &[&str] = &[
    "Desktop", "Documents", "Downloads", "Library/Mobile Documents", "Library/Containers", "Library/Group Containers",
    "Library/CloudStorage", "Pictures/Photos Library.photoslibrary",
];

/// Folders macOS guards with a consent prompt (or that hold other volumes).
pub fn gated(home: &str) -> Vec<Vec<u8>> {
    GATED_IN_HOME.iter().map(|d| format!("{home}/{d}").into_bytes()).chain([b"/Volumes".to_vec()]).collect()
}

/// The system TCC database is readable only with Full Disk Access, and
/// trying without it fails immediately (no prompt).
pub fn has_full_disk_access() -> bool {
    std::fs::File::open("/Library/Application Support/com.apple.TCC/TCC.db").is_ok()
}

fn content_loop(shared: &Shared, rx: Receiver<Resync>) {
    // Indexing file contents is background work: utility QoS keeps it off
    // the user's way (lower CPU priority and IO tier).
    unsafe { libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0) };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .start_handler(|_| unsafe {
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0);
            no_materialize();
        })
        .build()
        .unwrap();
    let home = shared.home.as_bytes().to_vec();
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
                for (d, t) in std::iter::once(first).chain(rx.try_iter()) {
                    for key in d.into_iter().map(|p| (p, false)).chain(t.into_iter().map(|p| (p, true))) {
                        // Most of the disk's churn (Library, caches) is outside the indexed area.
                        if content::in_scope(&key.0, &home) || (key.1 && home.starts_with(&key.0)) {
                            pending.entry(key).and_modify(|e| e.1 = now).or_insert((now, now));
                        }
                    }
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
        for k in ripe {
            pending.remove(&k);
            if k.1 { trees.push(k.0) } else { dirs.push(k.0) }
        }
        let t = Instant::now();
        let wants = {
            let g = shared.live.read().unwrap();
            let Some(live) = g.as_ref() else { continue };
            content::wants(live, &home, &dirs, &trees)
        };
        let todo = shared.content.write().unwrap().diff(wants);
        if todo.is_empty() {
            continue;
        }
        let n = todo.len();
        shared.content_pending.store(n, Ordering::Relaxed);
        for batch in todo.batches() {
            let (dir, id) = {
                let mut c = shared.content.write().unwrap();
                (c.dir.clone(), c.alloc_id())
            };
            let len = batch.len();
            if let Some(seg) = pool.install(|| content::build_segment(&dir, id, &todo, batch)) {
                shared.content.write().unwrap().push(seg);
            }
            shared.content_pending.fetch_sub(len, Ordering::Relaxed);
        }
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
}

fn full_build(shared: &Shared, event_id: u64) -> Index {
    let t = Instant::now();
    let started = crate::query::now_secs();
    let ls = walk::scan(b"/", SCAN_THREADS);
    let idx = Index::build(ls, event_id, started, shared.home.as_bytes());
    let path = shared.dir.join("index.bin");
    if let Err(e) = idx.save(&path) {
        log(format!("save failed: {e}"));
    }
    note_skipped(&shared.dir);
    log(format!("indexed {} entries in {:.2?}", idx.n, t.elapsed()));
    release_memory();
    // Re-map from the file so the index is clean, evictable page cache
    // rather than anonymous memory.
    Index::load(&path).unwrap_or(idx)
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
    if let Err(e) = idx.save(&path) {
        log(format!("save failed: {e}"));
    }
    note_skipped(&shared.dir);
    let idx = Index::load(&path).unwrap_or(idx);
    let n = idx.n;
    *shared.live.write().unwrap() = Some(Live::new(idx));
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
    log(format!(
        "FSEvents lost track of / ({why}, flags {flags:#x}): relisted {n} folders changed since {from} in {:.2?} ({stat_time:.2?} checking)",
        t.elapsed()
    ));
}

fn apply_loop(shared: &Arc<Shared>, rx: Receiver<Vec<fsevents::Event>>) {
    let mut last_save = Instant::now();
    let mut last_follow = Instant::now();
    let ours = shared.dir.as_os_str().as_bytes();
    loop {
        let mut events = match rx.recv_timeout(Duration::from_secs(60)) {
            Ok(b) => b,
            Err(RecvTimeoutError::Timeout) => Vec::new(),
            Err(RecvTimeoutError::Disconnected) => return,
        };
        events.extend(rx.try_iter().flatten());
        // The owner wrote the index files: a follower picks that up now
        // rather than at its next periodic check.
        let owner_wrote = events.iter().any(|e| e.path.starts_with(ours));
        if !events.is_empty() {
            let mut dirs: HashMap<Vec<u8>, bool> = HashMap::new();
            let (mut max_id, mut root_flags) = (0, 0);
            for e in events {
                max_id = max_id.max(e.id);
                if e.path == b"/" && e.flags & MUST_SCAN_SUBDIRS != 0 {
                    root_flags |= e.flags;
                }
                if e.flags & HISTORY_DONE != 0 {
                    log("replay done");
                    shared.replaying.store(false, Ordering::Relaxed);
                    continue;
                }
                *dirs.entry(crate::live::normalize(&e.path)).or_default() |= e.flags & MUST_SCAN_SUBDIRS != 0;
            }
            let mut rebuild = false;
            let mut trees = Vec::new();
            // Read the disk under the read lock, then apply in memory: a
            // search never waits on a folder listing or a new subtree's scan.
            let fetched: Vec<_> = {
                let g = shared.live.read().unwrap();
                let live = g.as_ref().unwrap();
                dirs.iter().map(|(p, recursive)| live.fetch(p, *recursive)).collect()
            };
            {
                let mut g = shared.live.write().unwrap();
                let live = g.as_mut().unwrap();
                for f in fetched {
                    if let Applied::Rebuild = live.apply(f) {
                        rebuild = true;
                    }
                }
                live.event_id = live.event_id.max(max_id);
                trees.append(&mut live.trees);
            }
            let (rec, flat): (Vec<_>, Vec<_>) = dirs.into_iter().partition(|(_, r)| *r);
            trees.extend(rec.into_iter().map(|(p, _)| p));
            let _ = shared.content_tx.send((flat.into_iter().map(|(p, _)| p).collect(), trees));
            if rebuild {
                let why = match root_flags {
                    f if f & KERNEL_DROPPED != 0 => "kernel dropped events",
                    f if f & USER_DROPPED != 0 => "events dropped before we read them",
                    _ => "history unavailable",
                };
                relist_changed(shared, why, root_flags);
            } else if !shared.replaying.load(Ordering::Relaxed) {
                // Everything up to this batch is applied (a change's event can
                // trail it by the stream latency; relisting keeps a margin).
                shared.live.write().unwrap().as_mut().unwrap().synced_at = crate::query::now_secs();
            }
        }
        if let Some(l) = shared.live.read().unwrap().as_ref() {
            l.names_cache.trim_if_idle(Duration::from_secs(60));
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
        let (pending, stale) = {
            let g = shared.live.read().unwrap();
            let live = g.as_ref().unwrap();
            (live.over.len() + live.dead_count, live.event_id != live.base.event_id)
        };
        let asked = shared.save_requested.swap(false, Ordering::Relaxed);
        if asked || pending > COMPACT_PENDING || (stale && last_save.elapsed() > COMPACT_EVERY) {
            compact(shared);
            last_save = Instant::now();
        }
    }
}

/// Default data dir: `~/Library/Application Support/FSearch`.
pub fn default_dir(home: &str) -> PathBuf {
    Path::new(home).join("Library/Application Support/FSearch")
}
