//! The index as it is right now: the immutable base, a bitset of base
//! entries that are gone, and a small overlay of entries added since.
//!
//! Every FSEvents directory event is handled the same way: list that one
//! directory and diff it against what we have. The diff is idempotent, so
//! replaying history, duplicate events, and events that race a compaction
//! are all harmless.

use crate::index::{Index, enc_size};
use crate::walk::{self, FLAG_MOUNT, KIND_DIR, Listing, NONE, RawEnt};
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy)]
pub struct OEnt {
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
    /// `index::name_mask` of the entry's name, so a search rejects most of
    /// the overlay with one AND.
    pub mask: u64,
    /// Location prior of the nearest folder the base knows (set on insert).
    pub prior: i8,
}

impl OEnt {
    /// `path` may be the whole path or just the name.
    pub fn new(path: &[u8], kind: u8, size: u64, mtime: u32) -> OEnt {
        let name = &path[path.iter().rposition(|&b| b == b'/').map_or(0, |p| p + 1)..];
        OEnt { kind, size, mtime, mask: crate::index::name_mask(name), prior: 0 }
    }
}

pub struct Live {
    pub base: Index,
    dead: Vec<u64>,
    pub dead_count: usize,
    pub over: BTreeMap<Vec<u8>, OEnt>,
    /// Last FSEvents id fully applied.
    pub event_id: u64,
    /// Paths of directories added or removed since last drained; the
    /// content index re-syncs these whole subtrees.
    pub trees: Vec<Vec<u8>>,
    /// The last name search's scored names, reused while you type.
    pub names_cache: crate::query::NameCache,
    /// Wall-clock second up to which every change is known applied.
    pub synced_at: u32,
    /// Overlay folder -> prior of its nearest base folder.
    priors: HashMap<Vec<u8>, i8>,
}

/// What `Live::fetch` read from disk for one folder update.
pub struct Fetched {
    path: Vec<u8>,
    recursive: bool,
    blocked: bool,
    attrs: Option<OEnt>,
    listing: Option<Listing>,
    scans: HashMap<Vec<u8>, Vec<Listing>>,
}

pub enum Applied {
    Done,
    /// The whole disk needs rescanning (history lost at the root).
    Rebuild,
}

impl Live {
    pub fn new(base: Index) -> Live {
        base.prefault();
        let words = base.n.div_ceil(64);
        let event_id = base.event_id;
        let synced_at = base.synced_at;
        Live {
            base,
            dead: vec![0; words],
            dead_count: 0,
            over: BTreeMap::new(),
            event_id,
            trees: Vec::new(),
            names_cache: Default::default(),
            synced_at,
            priors: HashMap::new(),
        }
    }

    /// Put an entry in the overlay, stamping the prior it ranks with.
    fn put(&mut self, path: Vec<u8>, mut e: OEnt) {
        let cut = path.iter().rposition(|&b| b == b'/').unwrap_or(0);
        e.prior = match self.priors.get(&path[..cut]) {
            Some(&p) => p,
            None => {
                let mut up = &path[..cut];
                let mut prior = 0;
                while !up.is_empty() {
                    if let Some(d) = self.base.lookup(up).and_then(|e| self.base.dir_of(e)) {
                        prior = self.base.dir_prior()[d as usize];
                        break;
                    }
                    up = &up[..up.iter().rposition(|&b| b == b'/').unwrap_or(0)];
                }
                self.priors.insert(path[..cut].to_vec(), prior);
                prior
            }
        };
        self.over.insert(path, e);
    }

    #[inline]
    pub fn is_dead(&self, i: u32) -> bool {
        self.dead[i as usize >> 6] & (1 << (i & 63)) != 0
    }

    fn kill(&mut self, i: u32) {
        let w = &mut self.dead[i as usize >> 6];
        if *w & (1 << (i & 63)) == 0 {
            *w |= 1 << (i & 63);
            self.dead_count += 1;
        }
    }

    fn kill_subtree(&mut self, e: u32) {
        self.kill(e);
        if let Some(d) = self.base.dir_of(e) {
            let (a, b) = (self.base.dir_start()[d as usize], self.base.dir_end()[d as usize]);
            for i in a..b {
                self.kill(i);
            }
        }
    }

    fn drop_over_subtree(&mut self, path: &[u8]) {
        self.over.remove(path);
        let (lo, hi) = subtree_bounds(path);
        let keys: Vec<Vec<u8>> = self.over.range(lo..hi).map(|(k, _)| k.clone()).collect();
        for k in keys {
            self.over.remove(&k);
        }
    }

    /// Alive base entry for a path, if the base has one.
    fn base_alive(&self, path: &[u8]) -> Option<u32> {
        self.base.lookup(path).filter(|&e| !self.is_dead(e))
    }

    fn remove_path(&mut self, path: &[u8]) {
        self.trees.push(path.to_vec());
        if let Some(e) = self.base_alive(path) {
            self.kill_subtree(e);
        }
        self.drop_over_subtree(path);
    }

    /// Bring one directory (or, with `recursive`, its whole subtree) in line
    /// with the disk.
    pub fn apply_dir(&mut self, path: &[u8], recursive: bool) -> Applied {
        let f = self.fetch(path, recursive);
        self.apply(f)
    }

    /// The disk half of `apply_dir`: list the folder (or stat it) and scan
    /// any folder that will be new to the index. Needs only `&self`, so the
    /// caller does this under a read lock and searches keep answering.
    pub fn fetch(&self, path: &[u8], recursive: bool) -> Fetched {
        let p = normalize(path);
        let mut f = Fetched { path: p, recursive, blocked: false, attrs: None, listing: None, scans: HashMap::new() };
        // Not even an lstat inside folders we may not touch.
        if walk::blocked(&f.path) {
            f.blocked = true;
            return f;
        }
        if recursive {
            if f.path != b"/" {
                f.attrs = lstat(&f.path);
                if f.attrs.is_some_and(|a| a.kind & 3 == KIND_DIR && a.kind & FLAG_MOUNT == 0) {
                    f.scans.insert(f.path.clone(), walk::scan(&f.path, 4));
                }
            }
            return f;
        }
        let Some(listing) = walk::list_one(&f.path) else {
            f.attrs = lstat(&f.path);
            return f;
        };
        // Children that will be added as folders get their subtree scanned now.
        let cur = self.current_children(&f.path);
        for r in &listing.ents {
            if r.kind & 3 != KIND_DIR || r.kind & FLAG_MOUNT != 0 {
                continue;
            }
            let name = &listing.names[r.name_off as usize..][..r.name_len as usize];
            let was_dir = match cur.get(name) {
                Some(Some(c)) => self.base.kind()[*c as usize] & 3 == KIND_DIR,
                Some(None) => self.over.get(&join(&f.path, name)).is_some_and(|o| o.kind & 3 == KIND_DIR),
                None => false,
            };
            if !was_dir {
                let child = join(&f.path, name);
                let ls = walk::scan(&child, 4);
                f.scans.insert(child, ls);
            }
        }
        f.listing = Some(listing);
        f
    }

    /// Children the index holds for `p`: name -> base entry, or None for an
    /// overlay entry.
    fn current_children(&self, p: &[u8]) -> HashMap<Vec<u8>, Option<u32>> {
        let mut cur: HashMap<Vec<u8>, Option<u32>> = HashMap::new();
        if let Some(d) = self.base_alive(p).and_then(|e| self.base.dir_of(e)) {
            for c in self.base.children(d) {
                if !self.is_dead(c as u32) {
                    cur.insert(self.base.name(c).to_vec(), Some(c as u32));
                }
            }
        }
        let (lo, hi) = subtree_bounds(p);
        let plen = lo.len();
        for k in self.over.range(lo..hi).map(|(k, _)| k) {
            if !k[plen..].contains(&b'/') {
                cur.insert(k[plen..].to_vec(), None);
            }
        }
        cur
    }

    /// The memory half of `apply_dir`: diff what `fetch` read into the index.
    pub fn apply(&mut self, mut f: Fetched) -> Applied {
        if f.blocked {
            return Applied::Done;
        }
        let p = std::mem::take(&mut f.path);
        if f.recursive {
            if p == b"/" {
                return Applied::Rebuild;
            }
            self.remove_path(&p);
            if let Some(attrs) = f.attrs {
                let scan = f.scans.remove(&p);
                self.add_new(p, attrs, scan);
            }
            return Applied::Done;
        }
        let Some(listing) = f.listing else {
            if f.attrs.is_none() {
                self.remove_path(&p);
            }
            return Applied::Done;
        };
        let mut cur = self.current_children(&p);
        for r in &listing.ents {
            let name = &listing.names[r.name_off as usize..][..r.name_len as usize];
            let child = join(&p, name);
            let now = OEnt::new(name, r.kind, r.size, r.mtime);
            match cur.remove(name) {
                None => {
                    let scan = f.scans.remove(&child);
                    self.add_new(child, now, scan)
                }
                Some(Some(c)) => {
                    let c = c as usize;
                    let was_kind = self.base.kind()[c];
                    if was_kind & 3 != now.kind & 3 {
                        self.kill_subtree(c as u32);
                        let scan = f.scans.remove(&child);
                        self.add_new(child, now, scan);
                    } else if now.kind & 3 != KIND_DIR && (self.base.size_raw()[c] != enc_size(now.size) || self.base.mtime()[c] != now.mtime) {
                        self.kill(c as u32);
                        self.put(child, now);
                    }
                }
                Some(None) => {
                    let old = self.over[&child];
                    if old.kind & 3 != now.kind & 3 {
                        self.drop_over_subtree(&child);
                        let scan = f.scans.remove(&child);
                        self.add_new(child, now, scan);
                    } else if (old.kind, old.size, old.mtime) != (now.kind, now.size, now.mtime) {
                        self.put(child, now);
                    }
                }
            }
        }
        for (name, c) in cur {
            let child = join(&p, &name);
            match c {
                Some(c) => {
                    if self.base.kind()[c as usize] & 3 == KIND_DIR {
                        self.trees.push(child);
                    }
                    self.kill_subtree(c)
                }
                None => {
                    if self.over.get(&child).is_some_and(|o| o.kind & 3 == KIND_DIR) {
                        self.trees.push(child.clone());
                    }
                    self.drop_over_subtree(&child)
                }
            }
        }
        Applied::Done
    }

    /// Add an entry and, if it is a directory, its subtree (`scan`, read
    /// ahead by `fetch`; scanned here if missing).
    fn add_new(&mut self, path: Vec<u8>, e: OEnt, scan: Option<Vec<Listing>>) {
        let is_dir = e.kind & 3 == KIND_DIR && e.kind & FLAG_MOUNT == 0;
        self.put(path.clone(), e);
        if !is_dir {
            return;
        }
        self.trees.push(path.clone());
        let ls = scan.unwrap_or_else(|| walk::scan(&path, 4));
        for_each_path(&ls, &path, |p, r| {
            let e = OEnt::new(&p, r.kind, r.size, r.mtime);
            self.put(p, e);
        });
    }

    /// Folders whose listing may have changed since `since` (a wall-clock
    /// second): adding, removing or renaming an entry bumps its folder's
    /// mtime. One lstat per folder, in parallel, under a read lock;
    /// relisting the few that changed is `apply_dir`'s job. This is how lost
    /// FSEvents history is recovered without crawling the whole disk.
    pub fn changed_dirs(&self, since: u32) -> Vec<Vec<u8>> {
        use rayon::prelude::*;
        let idx = &self.base;
        let de = idx.dir_entry();
        let check = |p: &[u8]| !walk::blocked(p) && lstat(p).is_some_and(|o| o.mtime >= since);
        let pool = stat_pool();
        let mut out: Vec<Vec<u8>> = pool.install(|| {
            (1..idx.d)
                .into_par_iter()
                .with_min_len(1024)
                .filter(|&k| !self.is_dead(de[k]))
                .map_init(Vec::new, |buf, k| {
                    idx.path(de[k] as usize, buf);
                    check(buf).then(|| buf.clone())
                })
                .flatten()
                .collect()
        });
        out.extend(self.over.iter().filter(|(p, o)| o.kind & 3 == KIND_DIR && o.kind & FLAG_MOUNT == 0 && check(p)).map(|(p, _)| p.clone()));
        if lstat(b"/").is_some_and(|o| o.mtime >= since) {
            out.push(b"/".to_vec());
        }
        out.sort();
        out
    }

    /// Everything alive, as listings for Index::build.
    pub fn to_listings(&self) -> Vec<Listing> {
        let mut by_parent: HashMap<&[u8], Vec<(&[u8], OEnt)>> = HashMap::new();
        for (k, v) in &self.over {
            let cut = k.iter().rposition(|&b| b == b'/').unwrap_or(0);
            let parent: &[u8] = if cut == 0 { b"/" } else { &k[..cut] };
            by_parent.entry(parent).or_default().push((&k[cut + 1..], *v));
        }
        let mut out = Vec::new();
        // (base dir id if alive in base, path, listing id)
        let mut stack: Vec<(Option<u32>, Vec<u8>, u32)> = vec![(Some(0), b"/".to_vec(), 0)];
        let mut next = 1u32;
        while let Some((bd, path, id)) = stack.pop() {
            let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
            let mut push = |l: &mut Listing, name: &[u8], kind: u8, size: u64, mtime: u32, child_path: Option<Vec<u8>>, bdir: Option<u32>| {
                let child = match child_path {
                    Some(cp) => {
                        let c = next;
                        next += 1;
                        stack.push((bdir, cp, c));
                        c
                    }
                    None => NONE,
                };
                l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, size, mtime, child });
                l.names.extend_from_slice(name);
            };
            if let Some(d) = bd {
                for c in self.base.children(d) {
                    if self.is_dead(c as u32) {
                        continue;
                    }
                    let name = self.base.name(c);
                    let k = self.base.kind()[c];
                    let sub = self.base.dir_of(c as u32);
                    let cp = sub.map(|_| join(&path, name));
                    push(&mut l, name, k, self.base.size_of(c), self.base.mtime()[c], cp, sub);
                }
            }
            if let Some(kids) = by_parent.get(path.as_slice()) {
                for &(name, o) in kids {
                    let descend = o.kind & 3 == KIND_DIR && o.kind & FLAG_MOUNT == 0;
                    push(&mut l, name, o.kind, o.size, o.mtime, descend.then(|| join(&path, name)), None);
                }
            }
            out.push(l);
        }
        out
    }
}

/// Threads for bulk lstat: path lookups scale further than opens do.
pub fn stat_pool() -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new().num_threads(12).start_handler(|_| crate::no_materialize()).build().unwrap()
}

/// Visit every entry of a scan with its full path.
pub fn for_each_path(ls: &[Listing], root: &[u8], mut f: impl FnMut(Vec<u8>, &RawEnt)) {
    let mut by_id: HashMap<u32, &Listing> = HashMap::with_capacity(ls.len());
    for l in ls {
        by_id.insert(l.id, l);
    }
    let mut stack = vec![(0u32, root.to_vec())];
    while let Some((id, path)) = stack.pop() {
        let Some(l) = by_id.get(&id) else { continue };
        for r in &l.ents {
            let p = join(&path, &l.names[r.name_off as usize..][..r.name_len as usize]);
            if r.child != NONE {
                stack.push((r.child, p.clone()));
            }
            f(p, r);
        }
    }
}

pub(crate) fn normalize(path: &[u8]) -> Vec<u8> {
    let mut p = path.to_vec();
    while p.len() > 1 && p.last() == Some(&b'/') {
        p.pop();
    }
    p
}

pub fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(dir.len() + 1 + name.len());
    p.extend_from_slice(dir);
    if dir != b"/" {
        p.push(b'/');
    }
    p.extend_from_slice(name);
    p
}

/// Key range holding everything strictly under `path`.
fn subtree_bounds(path: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let lo = join(path, b"");
    let mut hi = lo.clone();
    *hi.last_mut().unwrap() += 1; // '/' + 1 == '0'
    (lo, hi)
}

pub fn lstat(path: &[u8]) -> Option<OEnt> {
    #[cfg(unix)]
    {
        let c = std::ffi::CString::new(path).ok()?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
            return None;
        }
        let kind = match st.st_mode & (libc::S_IFMT as _) {
            v if v == libc::S_IFREG as _ => walk::KIND_FILE,
            v if v == libc::S_IFDIR as _ => KIND_DIR,
            v if v == libc::S_IFLNK as _ => walk::KIND_LINK,
            _ => walk::KIND_OTHER,
        };

        #[cfg(target_os = "macos")]
        let mtime = st.st_mtime;
        #[cfg(not(target_os = "macos"))]
        let mtime = st.st_mtime;

        Some(OEnt::new(path, kind, st.st_size as u64, mtime.clamp(0, u32::MAX as i64) as u32))
    }

    #[cfg(windows)]
    {
        let os_str = unsafe { std::ffi::OsStr::from_encoded_bytes_unchecked(path) };
        let path_obj = std::path::Path::new(os_str);
        let metadata = std::fs::symlink_metadata(path_obj).ok()?;
        let file_type = metadata.file_type();

        let kind = if file_type.is_file() {
            walk::KIND_FILE
        } else if file_type.is_dir() {
            KIND_DIR
        } else if file_type.is_symlink() {
            walk::KIND_LINK
        } else {
            walk::KIND_OTHER
        };

        let mtime = metadata.modified().ok()
            .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        Some(OEnt::new(path, kind, metadata.len(), mtime))
    }
}
