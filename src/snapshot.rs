//! Windows snapshot engine. Explicit rebuilds share the name and content
//! indexes with macOS; live notifications and daemon ownership come later.

use crate::content::{self, Content, Grep, GrepResult};
use crate::engine_types::{Found, Options, Status};
use crate::index::Index;
use crate::live::Live;
use crate::query::{Query, Searcher};
use crate::{paths, walk};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct Engine {
    snapshot: Arc<Snapshot>,
}

struct Snapshot {
    live: Live,
    content: Content,
    home: String,
    home_key: Vec<u8>,
}

struct PendingGeneration {
    dir: PathBuf,
    published: bool,
}

impl Drop for PendingGeneration {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn lock(dir: &Path, exclusive: bool) -> Result<std::fs::File, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let lock =
        std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(dir.join("daemon.lock")).map_err(|e| e.to_string())?;
    let result = if exclusive { lock.try_lock() } else { lock.try_lock_shared() };
    result.map_err(|e| format!("index is busy; retry after the current rebuild finishes: {e}"))?;
    Ok(lock)
}

impl Engine {
    /// Open a saved snapshot. On Windows, call `rebuild` or `fsearch index`
    /// first. Each engine holds a consistent snapshot until reopened.
    pub fn start(opts: Options) -> Result<Self, String> {
        let _lock = lock(&opts.dir, false)?;
        let dir = current(&opts.dir)?.ok_or("no index; run fsearch index [folder ...] first")?;
        let base = Index::load(&dir.join("index.bin")).ok_or("no valid index; run fsearch index [folder ...] first")?;
        Ok(Self::from_parts(base, Content::open_snapshot(dir.join("content"))?, opts.home))
    }

    /// Search only the saved filenames, without opening the content index.
    pub fn search_saved(opts: Options, query: &Query) -> Result<Vec<Found>, String> {
        let base = {
            let _lock = lock(&opts.dir, false)?;
            let dir = current(&opts.dir)?.ok_or("no index; run fsearch index [folder ...] first")?;
            Index::load(&dir.join("index.bin")).ok_or("no valid index; run fsearch index [folder ...] first")?
        };
        Ok(search_live(&Live::new_unwarmed(base), query))
    }

    pub fn saved_roots(dir: &Path) -> Result<Vec<PathBuf>, String> {
        let _lock = lock(dir, false)?;
        let Some(dir) = current(dir)? else { return Ok(Vec::new()) };
        let bytes = std::fs::read(dir.join("roots.json")).map_err(|e| e.to_string())?;
        let roots: Vec<Vec<u8>> = serde_json::from_slice(&bytes).map_err(|e| format!("invalid roots.json: {e}"))?;
        roots.iter().map(|p| paths::try_decode(p).map_err(|e| e.to_string())).collect()
    }

    /// Enumerate the selected folders, replace the name index and reconcile
    /// indexed text under `home`. Empty roots enumerate all drive letters.
    /// Does not require administrator privileges. Rebuilds hold one writer lock.
    pub fn rebuild(opts: Options, roots: &[PathBuf]) -> Result<Self, String> {
        let _lock = lock(&opts.dir, true)?;
        // An invalid or unreadable pointer must not prevent `index` from
        // repairing it. Preserve all generations until publication in that case.
        if let Ok(keep) = current(&opts.dir) {
            cleanup_generations(&opts.dir, keep.as_deref());
        }
        if let Some(skip) = opts.skip {
            let skip: Vec<_> = skip.iter().map(|p| paths::encode(p)).collect();
            if walk::SKIP.get().is_some_and(|old| old != &skip) {
                return Err("skip folders cannot change within one process".into());
            }
            let _ = walk::SKIP.set(skip);
        }
        let home_path = std::fs::canonicalize(&opts.home).unwrap_or_else(|_| PathBuf::from(&opts.home));
        let home_key = paths::encode(&home_path);
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).min(8);
        walk::LISTED.store(0, std::sync::atomic::Ordering::Relaxed);
        let listings = walk::scan_roots(roots, threads).map_err(|e| e.to_string())?;
        let live = Live::new(Index::build(listings, 0, crate::query::now_secs(), &home_key));
        // Build a new generation before publishing it. Existing engines may
        // still map the previous files, which Windows cannot replace in place.
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
        let generation = format!("snapshot-{}-{stamp}", std::process::id());
        let dir = opts.dir.join(&generation);
        std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
        let mut pending = PendingGeneration { dir: dir.clone(), published: false };
        let mut content = Content::open(dir.join("content"));
        let wants = content::wants(&live, &home_key, &[], std::slice::from_ref(&home_key));
        let todo = content.diff(wants);
        for range in todo.batches() {
            let id = content.alloc_id();
            let segment = content::build_segment(&content.dir, id, &todo, range).ok_or("could not write content segment; previous snapshot kept")?;
            content.push(segment);
        }
        // Content's background API makes manifest writes best effort. A
        // synchronous snapshot must report a failed write before publishing.
        let manifest: String = content.segs.iter().map(|s| format!("{}\n", s.id)).collect();
        std::fs::write(dir.join("content/manifest"), manifest).map_err(|e| e.to_string())?;
        live.base.save(&dir.join("index.bin")).map_err(|e| format!("save index: {e}"))?;
        let roots: Vec<_> =
            roots.iter().map(|p| std::fs::canonicalize(p).map(|p| paths::encode(&p))).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
        std::fs::write(dir.join("roots.json"), serde_json::to_vec(&roots).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let tmp = opts.dir.join("current.tmp");
        std::fs::write(&tmp, &generation).and_then(|_| std::fs::rename(&tmp, opts.dir.join("current"))).map_err(|e| e.to_string())?;
        pending.published = true;
        // Old mapped files can remain until their reader exits. Retry cleanup
        // on the next rebuild; never overwrite or truncate those files.
        cleanup_generations(&opts.dir, Some(&dir));
        Ok(Self { snapshot: Arc::new(Snapshot { live, content, home: opts.home, home_key }) })
    }

    fn from_parts(base: Index, content: Content, home: String) -> Self {
        let path = std::fs::canonicalize(&home).unwrap_or_else(|_| PathBuf::from(&home));
        Self { snapshot: Arc::new(Snapshot { live: Live::new(base), content, home_key: paths::encode(&path), home }) }
    }

    pub fn home(&self) -> &str {
        &self.snapshot.home
    }

    pub fn search(&self, query: &Query) -> Result<Vec<Found>, String> {
        Ok(search_live(&self.snapshot.live, query))
    }

    pub fn grep(&self, query: &Query, grep: &Grep) -> Result<(GrepResult, bool), String> {
        let indexed = query.scope.as_ref().is_none_or(|s| content::in_scope(s, &self.snapshot.home_key));
        if indexed {
            Ok((self.snapshot.content.search(grep, query), true))
        } else {
            let paths = content::scan_paths(&self.snapshot.live, query.clone_for_scan());
            Ok((content::verify(grep, &paths, query.limit), false))
        }
    }

    pub fn status(&self) -> Status {
        let s = &self.snapshot;
        Status {
            ready: true,
            entries: s.live.base.n,
            dirs: s.live.base.d,
            overlay: 0,
            removed: 0,
            event_id: 0,
            index_bytes: s.live.base.bytes(),
            content_docs: s.content.docs(),
            content_segments: s.content.segs.len(),
            content_bytes: s.content.bytes(),
            content_pending: 0,
            full_disk_access: false,
            owner: false,
        }
    }

    /// Windows snapshots are saved by `rebuild`; opening one never modifies it.
    pub fn save(&self) {}

    pub fn keep_warm(&self, _duration: Duration) {}

    pub fn indexing(&self) -> String {
        "run fsearch index to refresh this Windows snapshot".into()
    }
}

fn search_live(live: &Live, query: &Query) -> Vec<Found> {
    let mut path = Vec::new();
    Searcher { live }
        .search(query)
        .into_iter()
        .map(|h| {
            let i = h.idx as usize;
            live.base.path(i, &mut path);
            Found { path: paths::decode(&path), kind: live.base.kind()[i], size: live.base.size_of(i), mtime: live.base.mtime()[i], score: h.score }
        })
        .collect()
}

fn cleanup_generations(dir: &Path, keep: Option<&Path>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        if entry.file_name().to_str().is_some_and(valid_generation) && Some(entry.path().as_path()) != keep {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn valid_generation(name: &str) -> bool {
    name.strip_prefix("snapshot-").is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
}

fn current(dir: &Path) -> Result<Option<PathBuf>, String> {
    match std::fs::read_to_string(dir.join("current")) {
        Ok(name) if valid_generation(&name) => Ok(Some(dir.join(name))),
        Ok(_) => Err("invalid snapshot name; run fsearch index [folder ...]".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub fn default_dir(home: &str) -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(|| Path::new(home).join("AppData/Local")).join("FSearch")
}

/// Full Disk Access is a macOS feature. Windows uses the caller's permissions.
pub fn has_full_disk_access() -> bool {
    false
}
pub fn gated(_home: &str) -> Vec<Vec<u8>> {
    Vec::new()
}
pub fn no_materialize() {}
