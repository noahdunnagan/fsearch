//! Git status for search results (annotations, `git:modified` filters) and
//! which files your recent commits touched (frecency). A repo's status is read
//! once with `git status`, then only for the folders FSEvents reports
//! changed, in the background: a search never waits on git, and a busy repo
//! costs a pathspec-limited status per change instead of a full one (on
//! Chromium 0.05-0.13 s vs 7.5 s).

use crate::frecency::decay;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Status bits. Changed in the worktree:
pub const MODIFIED: u8 = 1;
/// Changed in the index (staged): also ADDED, RENAMED or DELETED.
pub const STAGED: u8 = 2;
pub const ADDED: u8 = 4;
pub const RENAMED: u8 = 8;
pub const DELETED: u8 = 16;
pub const UNTRACKED: u8 = 32;
pub const IGNORED: u8 = 64;
pub const CONFLICT: u8 = 128;

/// The word results carry for a status (none when clean).
pub fn word(s: u8) -> Option<&'static str> {
    Some(match s {
        0 => return None,
        s if s & CONFLICT != 0 => "conflict",
        s if s & UNTRACKED != 0 => "untracked",
        s if s & IGNORED != 0 => "ignored",
        s if s & MODIFIED != 0 => "modified",
        s if s & ADDED != 0 => "added",
        s if s & RENAMED != 0 => "renamed",
        s if s & DELETED != 0 => "deleted",
        _ => "staged",
    })
}

/// A `git:` filter (`git:modified`, or a prefix: `git:m`).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Sel {
    /// Changed in any way: modified, staged, untracked (fff's sense).
    Modified,
    Untracked,
    Staged,
    Clean,
    Ignored,
    Tracked,
    Conflict,
}

impl Sel {
    pub fn parse(v: &str) -> Option<Sel> {
        let all = [
            ("modified", Sel::Modified),
            ("untracked", Sel::Untracked),
            ("staged", Sel::Staged),
            ("clean", Sel::Clean),
            ("ignored", Sel::Ignored),
            ("tracked", Sel::Tracked),
            ("conflict", Sel::Conflict),
        ];
        all.into_iter().find(|(n, _)| !v.is_empty() && n.starts_with(v)).map(|(_, s)| s)
    }

    /// Does a file with status `s` (None: in no repo) pass?
    pub fn test(self, s: Option<u8>) -> bool {
        let Some(s) = s else { return false };
        match self {
            Sel::Modified => s & !IGNORED != 0,
            Sel::Untracked => s & UNTRACKED != 0,
            Sel::Staged => s & STAGED != 0,
            Sel::Clean => s == 0,
            Sel::Ignored => s & IGNORED != 0,
            Sel::Tracked => s & (UNTRACKED | IGNORED) == 0,
            Sel::Conflict => s & CONFLICT != 0,
        }
    }

    /// The statuses a snapshot lists: such files can be enumerated. (Clean
    /// and tracked files aren't listed, so those filters check each hit.)
    pub fn listed(self) -> bool {
        !matches!(self, Sel::Clean | Sel::Tracked)
    }
}

/// What a repo's status said: paths relative to its root, files and the
/// folders git reports whole (untracked or ignored, `dir/`).
#[derive(Default, Clone)]
pub struct Snap {
    pub files: HashMap<Box<[u8]>, u8>,
    pub dirs: HashMap<Box<[u8]>, u8>,
    /// Your own commits of the last two months (non-merge, under 50 files
    /// each) as frecency at `at`: each an open of its files when written.
    pub history: HashMap<Box<[u8]>, f32>,
    pub at: u32,
    /// The commit HEAD was at when `history` was read.
    head: Vec<u8>,
    /// Its config names programs git would run (see `Git::trusted`): no
    /// status is read.
    untrusted: bool,
    /// Folders ("" the root) holding a `.gitignore` above an ignored entry:
    /// only deleting one of those can un-ignore anything.
    ignores: HashSet<Box<[u8]>>,
}

impl Snap {
    pub fn status(&self, rel: &[u8]) -> u8 {
        if rel == b".git" || rel.starts_with(b".git/") {
            return IGNORED;
        }
        if let Some(&s) = self.files.get(rel) {
            return s;
        }
        let mut p = rel;
        loop {
            if let Some(&s) = self.dirs.get(p) {
                return s;
            }
            match p.iter().rposition(|&b| b == b'/') {
                Some(i) => p = &p[..i],
                None => return 0,
            }
        }
    }
}

pub struct Repo {
    pub root: Vec<u8>,
    snap: RwLock<Option<Arc<Snap>>>,
    loaded: (Mutex<bool>, Condvar),
    /// Changes waiting to be read: folders (relative; true: and all below)
    /// and whether `.git` changed (index, HEAD, refs).
    pending: Mutex<(HashMap<Vec<u8>, bool>, bool)>,
    last_event: AtomicU64,
    /// When a search last asked (ms): repos unused for a while are dropped.
    used: AtomicU64,
    queued: AtomicBool,
}

impl Repo {
    /// The latest snapshot, waiting up to `wait` for the first.
    pub fn snap(&self, wait: Duration) -> Option<Arc<Snap>> {
        self.used.store(ms(), Ordering::Relaxed);
        if wait > Duration::ZERO {
            let (m, cv) = &self.loaded;
            drop(cv.wait_timeout_while(m.lock().unwrap(), wait, |done| !*done).unwrap());
        }
        self.snap.read().unwrap().clone()
    }

    fn rel<'a>(&self, path: &'a [u8]) -> Option<&'a [u8]> {
        let r = path.strip_prefix(self.root.as_slice())?;
        match r {
            [] => Some(r),
            [b'/', rest @ ..] => Some(rest),
            _ => None,
        }
    }
}

pub struct Git {
    home: Vec<u8>,
    bin: Option<std::path::PathBuf>,
    repos: Mutex<Vec<Arc<Repo>>>,
    /// Folder → the repo holding it (None: none), as found walking up.
    dirs: Mutex<HashMap<Vec<u8>, Option<Arc<Repo>>>>,
    work: Mutex<Sender<Arc<Repo>>>,
}

/// Changes settle this long before a repo is re-read.
const QUIET: Duration = Duration::from_millis(100);
/// A repo no search asked about for this long is dropped (re-read when
/// asked again), so only repos in use cost anything...
const IDLE_MS: u64 = 20 * 60 * 1000;
/// ...checked this often while any is held (never, with none: no wakeups).
const IDLE_CHECK: Duration = Duration::from_secs(5 * 60);
/// A git command still running after this long is killed.
const GIT_TIMEOUT: Duration = Duration::from_secs(60);

/// The git command running now (one at a time: the worker's), as its own
/// process group, until its output is in.
static RUNNING: AtomicI32 = AtomicI32::new(0);

/// Have SIGTERM and SIGINT stop the running git command too, then the
/// daemon as before: it would run on, orphaned (a Chromium status, seconds).
pub fn kill_on_term() {
    extern "C" fn on_term(sig: i32) {
        let p = RUNNING.load(Ordering::Relaxed);
        if p > 0 {
            unsafe { libc::kill(-p, libc::SIGKILL) };
        }
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
    for sig in [libc::SIGTERM, libc::SIGINT] {
        unsafe { libc::signal(sig, on_term as extern "C" fn(i32) as libc::sighandler_t) };
    }
}
/// Past this many changed folders at once, re-read the whole repo.
const MAX_PATHSPECS: usize = 2000;

fn ms() -> u64 {
    static T0: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    T0.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

impl Git {
    pub fn new(home: &str) -> Arc<Git> {
        let (tx, rx) = std::sync::mpsc::channel();
        let g =
            Arc::new(Git { home: home.as_bytes().to_vec(), bin: git_bin(), repos: Mutex::default(), dirs: Mutex::default(), work: Mutex::new(tx) });
        let w = g.clone();
        std::thread::Builder::new().name("fsearch-git".into()).spawn(move || w.worker(rx)).expect("spawn");
        g
    }

    /// The repo holding `path` (a file or folder), found walking up from
    /// its folder (remembered per folder); not one rooted at the home
    /// folder or `/` (dotfiles: not a project).
    pub fn repo(&self, path: &[u8]) -> Option<Arc<Repo>> {
        self.bin.as_ref()?;
        let dir = &path[..path.iter().rposition(|&b| b == b'/').unwrap_or(0)];
        let mut memo = self.dirs.lock().unwrap();
        let mut seen = Vec::new();
        let mut d = dir;
        let found = loop {
            if let Some(r) = memo.get(d) {
                break r.clone();
            }
            seen.push(d.to_vec());
            if d.len() > 1 && d != self.home.as_slice() && std::fs::symlink_metadata(OsStr::from_bytes(&[d, b"/.git"].concat())).is_ok() {
                break Some(self.add(d));
            }
            match d.iter().rposition(|&b| b == b'/') {
                Some(i) if d.len() > 1 => d = &d[..i.max(1)],
                _ => break None,
            }
        };
        if memo.len() > 100_000 {
            memo.clear();
        }
        for s in seen {
            memo.insert(s, found.clone());
        }
        found
    }

    /// `repo`, its status read (in the background) if it isn't yet: only
    /// the repos searches are about get read, never every repo a result
    /// happens to be in (a full status costs seconds on a big one).
    pub fn load(&self, path: &[u8]) -> Option<Arc<Repo>> {
        let r = self.repo(path)?;
        r.used.store(ms(), Ordering::Relaxed);
        if r.snap.read().unwrap().is_none() {
            self.kick(&r);
        }
        Some(r)
    }

    fn add(&self, root: &[u8]) -> Arc<Repo> {
        let mut repos = self.repos.lock().unwrap();
        if let Some(r) = repos.iter().find(|r| r.root == root) {
            return r.clone();
        }
        let r = Arc::new(Repo {
            root: root.to_vec(),
            snap: RwLock::new(None),
            loaded: (Mutex::new(false), Condvar::new()),
            pending: Mutex::default(),
            last_event: AtomicU64::new(0),
            used: AtomicU64::new(ms()),
            queued: AtomicBool::new(false),
        });
        repos.push(r.clone());
        r
    }

    /// The status of `path`: None if it is in no repo, or one whose status
    /// isn't read (see `load`).
    pub fn status(&self, path: &[u8]) -> Option<u8> {
        let r = self.repo(path)?;
        let s = r.snap(Duration::ZERO)?;
        Some(s.status(r.rel(path)?))
    }

    /// `path`'s frecency from your commits (`Snap::history`), now; 0 if its
    /// repo's status isn't read.
    pub fn history(&self, path: &[u8], now: u32) -> f32 {
        let Some(r) = self.repo(path) else { return 0.0 };
        let Some(s) = r.snap(Duration::ZERO) else { return 0.0 };
        r.rel(path).and_then(|rel| s.history.get(rel)).map_or(0.0, |&h| h * decay(now.saturating_sub(s.at)))
    }

    /// The files your commits touched under `dir`, by the history of the
    /// repo holding it, with their frecency now.
    pub fn history_under(&self, dir: &[u8], now: u32) -> Vec<(Vec<u8>, f32)> {
        let Some(r) = self.repo(&[dir, b"/."].concat()) else { return Vec::new() };
        let Some(s) = r.snap(Duration::ZERO) else { return Vec::new() };
        let d = decay(now.saturating_sub(s.at));
        let paths = s.history.iter().map(|(rel, &h)| ([&r.root[..], b"/", rel].concat(), h * d));
        paths.filter(|(p, _)| p.starts_with(dir) && p.get(dir.len()) == Some(&b'/')).collect()
    }

    /// Repos already known at or under `dir`.
    pub fn known_under(&self, dir: &[u8]) -> Vec<Arc<Repo>> {
        self.repos.lock().unwrap().iter().filter(|r| r.root.starts_with(dir) && r.root.get(dir.len()).is_none_or(|&b| b == b'/')).cloned().collect()
    }

    /// FSEvents saw these folders change (`Engine::on_change`; true: and
    /// maybe anything below, as when it lost track of a subtree or of /):
    /// queue the ones in loaded repos.
    pub fn changed(&self, dirs: &[(&[u8], bool)]) {
        // A memoized folder that gained or lost a `.git` (git init, rm -rf)
        // makes the memo stale.
        {
            let mut memo = self.dirs.lock().unwrap();
            let stale = dirs.iter().any(|(d, _)| {
                memo.get(*d).is_some_and(|r| {
                    let root = r.as_ref().is_some_and(|r| r.root == *d);
                    root != std::fs::symlink_metadata(OsStr::from_bytes(&[d, &b"/.git"[..]].concat())).is_ok()
                })
            });
            if stale {
                memo.clear();
            }
        }
        let repos = self.repos.lock().unwrap().clone();
        let mut hit: Vec<&Arc<Repo>> = Vec::new();
        for &(d, below) in dirs {
            // Anything below a folder above a repo: all of the repo.
            let above = |r: &&Arc<Repo>| below && r.root.starts_with(d) && (d.ends_with(b"/") || r.root.get(d.len()) == Some(&b'/'));
            let mut todo: Vec<(&Arc<Repo>, &[u8])> = repos.iter().filter(above).map(|r| (r, &b""[..])).collect();
            // The deepest repo holding it decides (a nested repo is its own).
            todo.extend(repos.iter().filter_map(|r| Some((r, r.rel(d)?))).max_by_key(|(r, _)| r.root.len()));
            for (r, rel) in todo {
                let mut p = r.pending.lock().unwrap();
                if rel == b".git" || rel.starts_with(b".git/refs") || rel == b".git/info" {
                    p.1 = true;
                } else if !rel.starts_with(b".git/") {
                    *p.0.entry(rel.to_vec()).or_insert(false) |= below;
                } else {
                    continue;
                }
                if !hit.iter().any(|h| Arc::ptr_eq(h, r)) {
                    hit.push(r);
                }
            }
        }
        for r in hit {
            r.last_event.store(ms(), Ordering::Relaxed);
            self.kick(r);
        }
    }

    fn kick(&self, r: &Arc<Repo>) {
        if !r.queued.swap(true, Ordering::Relaxed) {
            let _ = self.work.lock().unwrap().send(r.clone());
        }
    }

    fn worker(&self, rx: Receiver<Arc<Repo>>) {
        let mut queue: Vec<Arc<Repo>> = Vec::new();
        loop {
            let wait = match queue.is_empty() {
                true if self.repos.lock().unwrap().is_empty() => None,
                true => Some(IDLE_CHECK),
                false => Some(QUIET),
            };
            let got = match wait {
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(t) => rx.recv_timeout(t),
            };
            match got {
                Ok(r) => queue.push(r),
                Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {}
            }
            queue.extend(rx.try_iter());
            queue.dedup_by(|a, b| Arc::ptr_eq(a, b));
            let now = ms();
            let ripe = |r: &Arc<Repo>| {
                r.snap.read().unwrap().is_none() || now.saturating_sub(r.last_event.load(Ordering::Relaxed)) >= QUIET.as_millis() as u64
            };
            while let Some(i) = queue.iter().position(ripe) {
                let r = queue.swap_remove(i);
                r.queued.store(false, Ordering::Relaxed);
                self.refresh(&r);
            }
            self.drop_idle();
        }
    }

    /// Forget repos no search asked about lately (their status goes stale
    /// unwatched; they're re-read when asked again).
    fn drop_idle(&self) {
        let now = ms();
        let mut repos = self.repos.lock().unwrap();
        let idle: Vec<Arc<Repo>> = repos.iter().filter(|r| now.saturating_sub(r.used.load(Ordering::Relaxed)) > IDLE_MS).cloned().collect();
        if idle.is_empty() {
            return;
        }
        repos.retain(|r| !idle.iter().any(|i| Arc::ptr_eq(i, r)));
        drop(repos);
        self.dirs.lock().unwrap().retain(|_, r| r.as_ref().is_none_or(|r| !idle.iter().any(|i| Arc::ptr_eq(i, r))));
    }

    /// Bring a repo's snapshot up to date: all of it the first time, then
    /// the folders that changed, and the index when `.git` did.
    fn refresh(&self, r: &Repo) {
        let (dirs, head) = std::mem::take(&mut *r.pending.lock().unwrap());
        let old = r.snap.read().unwrap().clone();
        let t = Instant::now();
        let new = match old {
            None => self.read_all(r),
            Some(old) => self.update(r, &old, dirs, head),
        };
        if let Some(s) = new {
            *r.snap.write().unwrap() = Some(Arc::new(s));
        }
        let first = !std::mem::replace(&mut *r.loaded.0.lock().unwrap(), true);
        r.loaded.1.notify_all();
        if first || t.elapsed() > Duration::from_millis(500) {
            eprintln!("{} git: read {} in {:.2?}", fsearch::query::now_secs(), String::from_utf8_lossy(&r.root), t.elapsed());
        }
    }

    fn read_all(&self, r: &Repo) -> Option<Snap> {
        let mut s = Snap::default();
        if !self.trusted(&r.root) {
            s.untrusted = true;
            return Some(s);
        }
        let found = parse(&self.run(&r.root, &status_args(), &[])?);
        note_ignores(&mut s, &r.root, &found);
        for (path, bits) in found {
            insert(&mut s, path, bits);
        }
        s.head = self.head(&r.root);
        (s.history, s.at) = self.history_of(&r.root);
        Some(s)
    }

    /// Whether git can be run in the repo: not if its own config names a
    /// filter (`git status` runs clean filters on changed files), which
    /// would then run with the daemon's Full Disk Access. Such a repo gets
    /// no status.
    fn trusted(&self, root: &[u8]) -> bool {
        let filters = self.run(root, &["config", "--local", "--includes", "--get-regexp", r"^filter\..*\.(clean|smudge|process)$"], &[]);
        if filters.as_ref().is_some_and(|f| !f.is_empty()) {
            eprintln!("{} git: {} configures its own filters; not reading its status", fsearch::query::now_secs(), String::from_utf8_lossy(root));
            return false;
        }
        true
    }

    /// The commit HEAD is at (empty before the first).
    fn head(&self, root: &[u8]) -> Vec<u8> {
        self.run(root, &["rev-parse", "-q", "--verify", "HEAD"], &[]).unwrap_or_default()
    }

    fn update(&self, r: &Repo, old: &Snap, dirs: HashMap<Vec<u8>, bool>, head: bool) -> Option<Snap> {
        if old.untrusted {
            // Until its config changes (`.git` did).
            return if head { self.read_all(r) } else { None };
        }
        let mut s = old.clone();
        // A changed .gitignore re-decides everything below it, and an event on
        // a previously collapsed untracked/ignored dir re-checks its subtree.
        let mut dirs = dirs;
        for (d, rec) in dirs.iter_mut() {
            if s.dirs.contains_key(d.as_slice()) {
                *rec = true;
            }
            let gi = [&r.root[..], b"/", d, if d.is_empty() { b"" } else { b"/" }, b".gitignore"].concat();
            // A deleted one re-decides only if it ignored something.
            let recheck = match std::fs::metadata(OsStr::from_bytes(&gi)) {
                Ok(m) => m.modified().is_ok_and(|m| m.elapsed().is_ok_and(|e| e < Duration::from_secs(5))),
                Err(_) => s.ignores.remove(d.as_slice()),
            };
            *rec |= recheck;
        }
        if dirs.iter().any(|(d, rec)| *rec && d.is_empty()) || dirs.len() > MAX_PATHSPECS {
            return self.read_all(r);
        }
        let mut specs: Vec<Vec<u8>> = Vec::new();
        for (d, rec) in &dirs {
            if *rec {
                specs.push([b":(literal)", &d[..]].concat());
            } else if d.is_empty() {
                // The root's own entries, one by one (a folder as itself, not
                // all below): a `*` there makes git look through every folder
                // for untracked files (1.5 s on Chromium).
                for e in std::fs::read_dir(OsStr::from_bytes(&r.root)).into_iter().flatten().flatten() {
                    let name = e.file_name();
                    if name.as_bytes() == b".git" {
                        continue;
                    }
                    specs.push(match e.file_type().is_ok_and(|t| t.is_dir()) {
                        true => [b":(glob)", &glob_escape(name.as_bytes())[..]].concat(),
                        false => [b":(literal)", name.as_bytes()].concat(),
                    });
                }
            } else {
                specs.push([b":(glob)", &glob_escape(d)[..], b"/*"].concat());
            }
        }
        // `.git` changed: the files staged now or before, by what the index
        // holds against HEAD and what the snapshot says (a file staged
        // again, `git add` after more edits, stays staged but its worktree
        // is no longer modified); your commits again if HEAD moved.
        if head {
            if !self.trusted(&r.root) {
                return Some(Snap { untrusted: true, ..Snap::default() });
            }
            let cached = self.run(&r.root, &["diff", "--cached", "--name-only", "-z", "--no-ext-diff", "--no-textconv"], &[])?;
            let now: HashSet<&[u8]> = cached.split(|&b| b == 0).filter(|p| !p.is_empty()).collect();
            let was: HashSet<&[u8]> = s.files.iter().filter(|(_, b)| **b & STAGED != 0).map(|(p, _)| &p[..]).collect();
            // Staging a file inside a collapsed untracked/ignored dir splits it:
            // ask git for that dir recursively so remaining siblings stay listed.
            for p in s.dirs.keys() {
                if now.union(&was).any(|r| *r == p.as_ref() || (r.starts_with(p.as_ref()) && r.get(p.len()) == Some(&b'/'))) {
                    specs.push([b":(literal)", p.as_ref()].concat());
                }
            }
            specs.extend(now.union(&was).map(|p| [b":(literal)", *p].concat()));
            let h = self.head(&r.root);
            if h != s.head {
                (s.history, s.at) = self.history_of(&r.root);
                s.head = h;
            }
        }
        if specs.len() > MAX_PATHSPECS {
            return self.read_all(r);
        }
        if specs.is_empty() {
            return Some(s);
        }
        let found = parse(&self.run(&r.root, &status_args(), &specs)?);
        // Out with what the pathspecs covered, in with what git says now.
        let covered = |p: &[u8]| {
            let parent = &p[..p.iter().rposition(|&b| b == b'/').unwrap_or(0)];
            dirs.iter().any(|(d, rec)| if *rec { d.is_empty() || p == &d[..] || p.starts_with(&[&d[..], b"/"].concat()) } else { parent == &d[..] })
        };
        let restaged: HashSet<Vec<u8>> = specs.iter().filter_map(|s| s.strip_prefix(b":(literal)")).map(<[u8]>::to_vec).collect();
        s.files.retain(|p, _| !covered(p) && !restaged.contains(&p[..]));
        s.dirs.retain(|p, _| {
            !covered(p)
                && !dirs.contains_key(p.as_ref())
                && !restaged.iter().any(|r| r == p.as_ref() || (r.starts_with(p.as_ref()) && r.get(p.len()) == Some(&b'/')))
        });
        note_ignores(&mut s, &r.root, &found);
        for (path, bits) in found {
            insert(&mut s, path, bits);
        }
        Some(s)
    }

    /// See `Snap::history`. By author time (a rebase isn't new work), as
    /// `user.email`; none without one.
    fn history_of(&self, root: &[u8]) -> (HashMap<Box<[u8]>, f32>, u32) {
        let (mut out, now) = (HashMap::new(), fsearch::query::now_secs());
        let me = self.run(root, &["config", "user.email"], &[]).map(|e| String::from_utf8_lossy(&e).trim().to_string());
        let Some(me) = me.filter(|e| !e.is_empty()) else { return (out, now) };
        let author = format!("--author=<{me}>");
        let args = ["log", "-F", &author, "--since=60.days", "-n", "1000", "--no-merges", "--name-only", "--format=%x00%at"];
        for commit in self.run(root, &args, &[]).unwrap_or_default().split(|&b| b == 0).filter(|c| !c.is_empty()) {
            let mut lines = commit.split(|&b| b == b'\n');
            let t: u32 = lines.next().and_then(|l| std::str::from_utf8(l).ok()?.trim().parse().ok()).unwrap_or(0);
            let files: Vec<&[u8]> = lines.filter(|l| !l.is_empty()).collect();
            if files.len() > 50 {
                continue;
            }
            let w = decay(now.saturating_sub(t));
            for f in files {
                *out.entry(f.into()).or_insert(0.0) += w;
            }
        }
        (out, now)
    }

    /// Run git in `root` (never taking its locks, nor running a program the
    /// repo's config names: no fsmonitor hook, no signature checks; below
    /// normal priority, killed after GIT_TIMEOUT); its output if it
    /// succeeded.
    fn run(&self, root: &[u8], args: &[&str], specs: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut c = std::process::Command::new(self.bin.as_ref()?);
        c.arg("-C").arg(OsStr::from_bytes(root));
        let safe = ["-c", "core.fsmonitor=false", "-c", "log.showSignature=false"];
        c.args(["--no-optional-locks", "-c", "core.quotePath=false", "-c", "core.preloadIndex=false"]).args(safe).args(args);
        if !specs.is_empty() {
            c.arg("--").args(specs.iter().map(|s| OsStr::from_bytes(s)));
        }
        c.env("GIT_OPTIONAL_LOCKS", "0").env("GIT_TERMINAL_PROMPT", "0");
        c.stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null()).stdout(std::process::Stdio::piped());
        unsafe {
            c.pre_exec(|| {
                libc::setpriority(libc::PRIO_PROCESS, 0, 10);
                Ok(())
            });
        }
        c.process_group(0);
        let mut child = c.spawn().ok()?;
        RUNNING.store(child.id() as i32, Ordering::Relaxed);
        let mut stdout = child.stdout.take()?;
        // Read on another thread, so a git that hangs is killed through its
        // handle before it is waited for (its pid can't have been reused).
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = std::io::Read::read_to_end(&mut stdout, &mut out);
            let _ = tx.send(out);
        });
        let out = rx.recv_timeout(GIT_TIMEOUT).ok();
        // Before it's waited for: a signal must never find a reaped pid here.
        RUNNING.store(0, Ordering::Relaxed);
        if out.is_none() {
            let _ = child.kill();
        }
        let ok = child.wait().is_ok_and(|s| s.success());
        out.filter(|_| ok)
    }
}

fn status_args() -> [&'static str; 6] {
    ["status", "--porcelain=v2", "-z", "--ignored=traditional", "--untracked-files=normal", "--ignore-submodules=all"]
}

/// Record the folders above `found`'s ignored entries that hold a `.gitignore`
/// (see `Snap::ignores`). One stat per folder not yet seen.
fn note_ignores(s: &mut Snap, root: &[u8], found: &[(Vec<u8>, u8)]) {
    let mut seen: HashSet<&[u8]> = HashSet::new();
    for (path, _) in found.iter().filter(|(_, b)| b & IGNORED != 0) {
        let path = path.strip_suffix(b"/").unwrap_or(path);
        let ends = std::iter::once(0).chain(path.iter().enumerate().filter(|(_, b)| **b == b'/').map(|(i, _)| i));
        for end in ends {
            let d = &path[..end];
            if !seen.insert(d) || s.ignores.contains(d) {
                continue;
            }
            let gi = [root, b"/", d, if d.is_empty() { b"" } else { b"/" }, b".gitignore"].concat();
            if std::fs::metadata(OsStr::from_bytes(&gi)).is_ok_and(|m| m.is_file()) {
                s.ignores.insert(d.into());
            }
        }
    }
}

fn insert(s: &mut Snap, path: Vec<u8>, bits: u8) {
    match path.strip_suffix(b"/") {
        Some(d) => s.dirs.insert(d.into(), bits),
        None => s.files.insert(path.into(), bits),
    };
}

/// `git status --porcelain=v2 -z` as (path, status bits); folders end in `/`.
fn parse(out: &[u8]) -> Vec<(Vec<u8>, u8)> {
    let mut v = Vec::new();
    let mut recs = out.split(|&b| b == 0);
    while let Some(rec) = recs.next() {
        let field = |n: usize| rec.splitn(n + 1, |&b| b == b' ').nth(n);
        let (path, bits) = match rec.first() {
            Some(b'1') => (field(8), xy(rec)),
            Some(b'2') => {
                recs.next(); // the original path
                (field(9), xy(rec))
            }
            Some(b'u') => (field(10), CONFLICT),
            Some(b'?') => (rec.get(2..), UNTRACKED),
            Some(b'!') => (rec.get(2..), IGNORED),
            _ => (None, 0),
        };
        if let Some(p) = path.filter(|p| !p.is_empty()) {
            v.push((p.to_vec(), bits));
        }
    }
    v
}

/// The bits of an ordinary or renamed entry's XY field.
fn xy(rec: &[u8]) -> u8 {
    let (x, y) = (rec.get(2).copied().unwrap_or(b'.'), rec.get(3).copied().unwrap_or(b'.'));
    let staged = match x {
        b'M' | b'T' => STAGED,
        b'A' => STAGED | ADDED,
        b'D' => STAGED | DELETED,
        b'R' | b'C' => STAGED | RENAMED,
        _ => 0,
    };
    let work = match y {
        b'M' | b'T' => MODIFIED,
        b'D' => DELETED,
        _ => 0,
    };
    staged | work
}

fn glob_escape(p: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for &b in p {
        if matches!(b, b'*' | b'?' | b'[' | b']' | b'\\') {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}

/// A git that runs without asking: not /usr/bin/git's stub, which pops up
/// an installer when the developer tools are missing.
fn git_bin() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let dirs = std::env::split_paths(&path).filter(|d| d != std::path::Path::new("/usr/bin"));
    dirs.chain(["/Library/Developer/CommandLineTools/usr/bin".into(), "/Applications/Xcode.app/Contents/Developer/usr/bin".into()])
        .map(|d| d.join("git"))
        .find(|g| g.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let out = b"1 .M N... 100644 100644 100644 a b src/main.rs\x001 A. N... 0 100644 100644 a b new.rs\x002 R. N... 100644 100644 100644 a b R100 to.rs\x00from.rs\x00u UU N... 1 2 3 4 a b c x.rs\x00? junk/\x00! target/\x00";
        let v = parse(out);
        let get = |p: &[u8]| v.iter().find(|(q, _)| q == p).map(|(_, b)| *b);
        assert_eq!(get(b"src/main.rs"), Some(MODIFIED));
        assert_eq!(get(b"new.rs"), Some(STAGED | ADDED));
        assert_eq!(get(b"to.rs"), Some(STAGED | RENAMED));
        assert_eq!(get(b"from.rs"), None);
        assert_eq!(get(b"x.rs"), Some(CONFLICT));
        assert_eq!(get(b"junk/"), Some(UNTRACKED));
        let mut s = Snap::default();
        for (p, b) in v {
            insert(&mut s, p, b);
        }
        assert_eq!(s.status(b"target/debug/x"), IGNORED);
        assert_eq!(s.status(b"junk/a/b.txt"), UNTRACKED);
        assert_eq!(s.status(b"src/lib.rs"), 0);
        assert_eq!(s.status(b".git/config"), IGNORED);
        assert_eq!(Sel::parse("m"), Some(Sel::Modified));
        assert_eq!(Sel::parse("c"), Some(Sel::Clean));
        assert!(Sel::Modified.test(Some(UNTRACKED)) && !Sel::Modified.test(Some(IGNORED)) && !Sel::Clean.test(None));
    }

    #[test]
    fn changes_below() {
        let g = Git::new("/nonexistent");
        let r = g.add(b"/p/repo");
        // Queued already: the worker never takes what's pending here.
        r.queued.store(true, Ordering::Relaxed);
        let pending = || {
            let (dirs, head) = std::mem::take(&mut *r.pending.lock().unwrap());
            (dirs.into_iter().collect::<Vec<_>>(), head)
        };
        g.changed(&[(&b"/p/repo/src"[..], false)]);
        assert_eq!(pending(), (vec![(b"src".to_vec(), false)], false));
        g.changed(&[(&b"/p/repo/src"[..], true)]);
        assert_eq!(pending(), (vec![(b"src".to_vec(), true)], false), "and all below");
        g.changed(&[(&b"/p"[..], true), (&b"/p/re"[..], true)]);
        assert_eq!(pending(), (vec![(Vec::new(), true)], false), "a folder above the repo: all of it");
        g.changed(&[(&b"/"[..], true)]);
        assert_eq!(pending(), (vec![(Vec::new(), true)], false), "FSEvents lost track of /");
        g.changed(&[(&b"/p/repo/.git"[..], false)]);
        assert_eq!(pending(), (Vec::new(), true));
    }

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let p = std::env::temp_dir().join(format!("fsearch-git-test-{}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed), name));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn run_git(dir: &std::path::Path, args: &[&str]) {
        let out = std::process::Command::new(git_bin().expect("git binary")).arg("-C").arg(dir).args(args).output().unwrap();
        assert!(out.status.success(), "git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn update_clears_dirs_on_commit_and_gitignore_delete() {
        let tmp = TempDir::new("repo");
        let root = &tmp.0;
        run_git(root, &["init"]);
        run_git(root, &["config", "user.email", "test@example.com"]);
        run_git(root, &["config", "user.name", "Test"]);
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir_all(root.join("sub/deep")).unwrap();
        std::fs::write(root.join("init.txt"), b"init").unwrap();
        std::fs::write(root.join("a/tracked.txt"), b"t").unwrap();
        std::fs::write(root.join("sub/deep/tracked.txt"), b"t").unwrap();
        run_git(root, &["add", "init.txt", "a/tracked.txt", "sub/deep/tracked.txt"]);
        run_git(root, &["commit", "-m", "init"]);

        // Untracked dir `newdir/{a,b}.txt`, untracked `a/b/c.txt`, and `sub/.gitignore` ignoring `deep/ign/` & `deep/*.log`.
        std::fs::create_dir_all(root.join("newdir")).unwrap();
        std::fs::write(root.join("newdir/a.txt"), b"a").unwrap();
        std::fs::write(root.join("newdir/b.txt"), b"b").unwrap();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("a/b/c.txt"), b"c").unwrap();
        std::fs::create_dir_all(root.join("sub/deep/ign")).unwrap();
        std::fs::write(root.join("sub/.gitignore"), b"ign/\n*.log\n").unwrap();
        std::fs::write(root.join("sub/deep/ign/f.txt"), b"ign").unwrap();
        std::fs::write(root.join("sub/deep/x.log"), b"log").unwrap();

        let g = Git::new("/nonexistent");
        let r = g.add(root.as_os_str().as_bytes());
        let old = g.read_all(&r).unwrap();
        assert_eq!(old.dirs.get(b"newdir".as_slice()), Some(&UNTRACKED));
        assert_eq!(old.dirs.get(b"a/b".as_slice()), Some(&UNTRACKED));
        assert_eq!(old.status(b"sub/deep/ign/f.txt"), IGNORED);
        assert_eq!(old.status(b"sub/deep/x.log"), IGNORED);

        // 1. `git add newdir/a.txt` with only `.git` events (`dirs` empty, `head = true`)
        //    clears collapsed `s.dirs["newdir"]` while keeping sibling `newdir/b.txt` untracked.
        run_git(root, &["add", "newdir/a.txt"]);
        let snap1a = g.update(&r, &old, HashMap::new(), true).unwrap();
        assert_eq!(snap1a.dirs.get(b"newdir".as_slice()), None);
        assert_eq!(snap1a.status(b"newdir/a.txt"), STAGED | ADDED);
        assert_eq!(snap1a.status(b"newdir/b.txt"), UNTRACKED);
        run_git(root, &["commit", "-m", "add newdir"]);
        let snap1 = g.update(&r, &snap1a, HashMap::new(), true).unwrap();
        assert_eq!(snap1.dirs.get(b"newdir".as_slice()), None);
        assert_eq!(snap1.status(b"newdir/a.txt"), 0);
        assert_eq!(snap1.status(b"newdir/b.txt"), UNTRACKED);

        // 2. Direct event on `d = b"a/b"` after `a/b/c.txt` is committed clears `s.dirs["a/b"]`.
        run_git(root, &["add", "a/b/c.txt"]);
        run_git(root, &["commit", "-m", "add a/b"]);
        let snap2 = g.update(&r, &snap1, HashMap::from([(b"a/b".to_vec(), false)]), false).unwrap();
        assert_eq!(snap2.dirs.get(b"a/b".as_slice()), None);
        assert_eq!(snap2.status(b"a/b/c.txt"), 0);

        // 3. Deleting `sub/.gitignore` re-evaluates ignored entries under `sub`.
        std::fs::remove_file(root.join("sub/.gitignore")).unwrap();
        let snap3 = g.update(&r, &snap2, HashMap::from([(b"sub".to_vec(), false)]), false).unwrap();
        assert_eq!(snap3.status(b"sub/deep/ign/f.txt"), UNTRACKED);
        assert_eq!(snap3.status(b"sub/deep/x.log"), UNTRACKED);
    }

    /// Only folders whose `.gitignore` ignores something are tracked (so an
    /// event at a root without one is not a full re-read); one added later is
    /// tracked once it ignores something, and deleting it re-evaluates its folder.
    #[test]
    fn gitignore_folders_are_tracked() {
        let tmp = TempDir::new("gitignore-track");
        let root = &tmp.0;
        run_git(root, &["init"]);
        std::fs::write(root.join(".gitignore"), b"*.log\n").unwrap();
        std::fs::create_dir_all(root.join("a/deep")).unwrap();
        std::fs::create_dir_all(root.join("sub/ign")).unwrap();
        std::fs::write(root.join("a/deep/x.log"), b"log").unwrap();
        std::fs::write(root.join("a/deep/t.txt"), b"t").unwrap();
        std::fs::write(root.join("sub/.gitignore"), b"ign/\n").unwrap();
        std::fs::write(root.join("sub/ign/f.txt"), b"f").unwrap();

        let g = Git::new("/nonexistent");
        let r = g.add(root.as_os_str().as_bytes());
        let old = g.read_all(&r).unwrap();
        let set = |s: &Snap| {
            let mut v: Vec<Vec<u8>> = s.ignores.iter().map(|d| d.to_vec()).collect();
            v.sort();
            v
        };
        // `a` and `a/deep` hold ignored entries but no `.gitignore`.
        assert_eq!(set(&old), vec![b"".to_vec(), b"sub".to_vec()]);

        // A `.gitignore` added in `a` is tracked once it ignores something...
        std::fs::write(root.join("a/.gitignore"), b"*.tmp\n").unwrap();
        std::fs::write(root.join("a/deep/z.tmp"), b"z").unwrap();
        let snap = g.update(&r, &old, HashMap::from([(b"a".to_vec(), false), (b"a/deep".to_vec(), false)]), false).unwrap();
        assert_eq!(snap.status(b"a/deep/z.tmp"), IGNORED);
        assert_eq!(set(&snap), vec![b"".to_vec(), b"a".to_vec(), b"sub".to_vec()]);

        // ...and deleting it re-evaluates `a` recursively.
        std::fs::remove_file(root.join("a/.gitignore")).unwrap();
        let snap = g.update(&r, &snap, HashMap::from([(b"a".to_vec(), false)]), false).unwrap();
        assert_eq!(snap.status(b"a/deep/z.tmp"), UNTRACKED);
        assert_eq!(snap.status(b"a/deep/x.log"), IGNORED);
        assert_eq!(set(&snap), vec![b"".to_vec(), b"sub".to_vec()]);
    }

    #[test]
    fn update_reevaluates_on_gitignore_delete() {
        let tmp = TempDir::new("gitignore-del");
        let root = &tmp.0;
        run_git(root, &["init"]);
        run_git(root, &["config", "user.email", "test@example.com"]);
        run_git(root, &["config", "user.name", "Test"]);
        std::fs::write(root.join("init.txt"), b"init").unwrap();
        run_git(root, &["add", "init.txt"]);
        run_git(root, &["commit", "-m", "init"]);

        std::fs::create_dir_all(root.join("sub/deep/ign")).unwrap();
        std::fs::write(root.join("sub/deep/tracked.txt"), b"t").unwrap();
        run_git(root, &["add", "sub/deep/tracked.txt"]);
        run_git(root, &["commit", "-m", "track sub/deep"]);
        std::fs::write(root.join("sub/.gitignore"), b"ign/\n*.log\n").unwrap();
        std::fs::write(root.join("sub/deep/ign/f.txt"), b"ign").unwrap();
        std::fs::write(root.join("sub/deep/x.log"), b"log").unwrap();

        let g = Git::new("/nonexistent");
        let r = g.add(root.as_os_str().as_bytes());
        let old = g.read_all(&r).unwrap();
        assert_eq!(old.dirs.get(b"sub/deep/ign".as_slice()), Some(&IGNORED));
        assert_eq!(old.status(b"sub/deep/ign/f.txt"), IGNORED);
        assert_eq!(old.status(b"sub/deep/x.log"), IGNORED);

        std::fs::remove_file(root.join("sub/.gitignore")).unwrap();
        let snap = g.update(&r, &old, HashMap::from([(b"sub".to_vec(), false)]), false).unwrap();
        assert_eq!(snap.dirs.get(b"sub/deep/ign".as_slice()), Some(&UNTRACKED));
        assert_eq!(snap.status(b"sub/deep/ign/f.txt"), UNTRACKED);
        assert_eq!(snap.status(b"sub/deep/x.log"), UNTRACKED);
    }
}
