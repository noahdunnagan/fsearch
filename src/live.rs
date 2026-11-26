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
    /// Its slot in `Live::flat` (set on insert).
    slot: u32,
}

impl OEnt {
    /// `path` may be the whole path or just the name.
    pub fn new(path: &[u8], kind: u8, size: u64, mtime: u32) -> OEnt {
        let name = &path[path.iter().rposition(|&b| b == b'/').map_or(0, |p| p + 1)..];
        OEnt { kind, size, mtime, mask: crate::index::name_mask(name), prior: 0, slot: 0 }
    }
}

/// The overlay laid out for searches: every entry's name mask in one array
/// to scan (walking the map cost ~7 ns an entry, 0.35 ms a search at 50k
/// entries), its path and value in the same slot. A removed entry's slot
/// is reused; until then its mask is 0, which no name has.
#[derive(Default)]
pub struct Flat {
    pub masks: Vec<u64>,
    pub items: Vec<(Vec<u8>, OEnt)>,
    free: Vec<u32>,
}

impl Flat {
    fn set(&mut self, path: &[u8], e: OEnt) {
        let s = e.slot as usize;
        if s == self.masks.len() {
            self.masks.push(0);
            self.items.push((Vec::new(), e));
        }
        self.masks[s] = e.mask;
        if self.items[s].0 != path {
            self.items[s].0 = path.to_vec();
        }
        self.items[s].1 = e;
    }

    fn clear(&mut self, e: OEnt) {
        self.masks[e.slot as usize] = 0;
        self.items[e.slot as usize].0 = Vec::new();
        self.free.push(e.slot);
    }
}

pub struct Live {
    pub base: Index,
    dead: Vec<u64>,
    pub dead_count: usize,
    pub over: BTreeMap<Vec<u8>, OEnt>,
    /// `over` laid out for searches.
    pub flat: Flat,
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
    /// Ids of the listings in a recursive update's scan that failed.
    failed: Vec<u32>,
}

pub enum Applied {
    Done,
    /// The whole disk needs rescanning (history lost at the root).
    Rebuild,
}

impl Live {
    pub fn new(base: Index) -> Live {
        base.prefault();
        Live::lazy(base)
    }

    /// `new` without faulting the index in first: a restart's first search
    /// runs on it as mapped, and `Index::prefault` follows.
    pub fn lazy(base: Index) -> Live {
        let words = base.n.div_ceil(64);
        let event_id = base.event_id;
        let synced_at = base.synced_at;
        Live {
            base,
            dead: vec![0; words],
            dead_count: 0,
            over: BTreeMap::new(),
            flat: Flat::default(),
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
        e.slot = match self.over.get(&path) {
            Some(old) => old.slot,
            None => self.flat.free.pop().unwrap_or(self.flat.masks.len() as u32),
        };
        self.flat.set(&path, e);
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
            let (a, b) = (self.base.dir_start(d as usize), self.base.dir_end(d as usize));
            for i in a..b {
                self.kill(i);
            }
        }
    }

    fn drop_over_subtree(&mut self, path: &[u8]) {
        self.priors.remove(path);
        if let Some(o) = self.over.remove(path) {
            self.flat.clear(o);
        }
        let (lo, hi) = subtree_bounds(path);
        let keys: Vec<Vec<u8>> = self.over.range(lo..hi).map(|(k, _)| k.clone()).collect();
        for k in keys {
            self.priors.remove(&k);
            if let Some(o) = self.over.remove(&k) {
                self.flat.clear(o);
            }
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
        let mut f = Fetched { path: p, recursive, blocked: false, attrs: None, listing: None, scans: HashMap::new(), failed: Vec::new() };
        // Not even an lstat inside folders we may not touch.
        if walk::blocked(&f.path) {
            f.blocked = true;
            return f;
        }
        if recursive {
            if f.path != b"/" {
                f.attrs = lstat(&f.path);
                // Flagged as a scan would, so the mounted volume isn't crawled.
                if let Some(a) = f.attrs.as_mut().filter(|a| a.kind & 3 == KIND_DIR && walk::is_mount(&f.path)) {
                    a.kind |= FLAG_MOUNT;
                }
                if f.attrs.is_some_and(|a| a.kind & 3 == KIND_DIR && a.kind & FLAG_MOUNT == 0) {
                    let (ls, failed) = walk::scan_failing(&f.path, 4);
                    f.scans.insert(f.path.clone(), ls);
                    f.failed = failed;
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
                Some(Some(c)) => self.base.kind(*c as usize) & 3 == KIND_DIR,
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
            let Some(attrs) = f.attrs else {
                self.remove_path(&p);
                return Applied::Done;
            };
            // A folder that is there but could not be listed keeps what the index holds in it.
            if f.failed.contains(&0) && self.indexed_dir(&p) {
                return Applied::Done;
            }
            let scan = f.scans.remove(&p).map(|ls| self.graft_failed(ls, &f.failed, &p));
            self.remove_path(&p);
            self.add_new(p, attrs, scan);
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
                    let was_kind = self.base.kind(c);
                    if was_kind & 3 != now.kind & 3 {
                        // A folder no more: what was added in it goes too.
                        if was_kind & 3 == KIND_DIR {
                            self.trees.push(child.clone());
                            self.drop_over_subtree(&child);
                        }
                        self.kill_subtree(c as u32);
                        let scan = f.scans.remove(&child);
                        self.add_new(child, now, scan);
                    } else if now.kind & 3 != KIND_DIR && (self.base.size_raw(c) != enc_size(now.size) || self.base.mtime(c) != now.mtime) {
                        self.kill(c as u32);
                        self.put(child, now);
                    }
                }
                Some(None) => {
                    let old = self.over[&child];
                    if old.kind & 3 != now.kind & 3 {
                        if old.kind & 3 == KIND_DIR {
                            self.trees.push(child.clone());
                        }
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
                    if self.base.kind(c as usize) & 3 == KIND_DIR {
                        self.trees.push(child.clone());
                        self.drop_over_subtree(&child);
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

    fn indexed_dir(&self, p: &[u8]) -> bool {
        self.base_alive(p).is_some_and(|e| self.base.kind(e as usize) & 3 == KIND_DIR) || self.over.get(p).is_some_and(|o| o.kind & 3 == KIND_DIR)
    }

    /// `scan` (of `root`) with the listings `failed` replaced by what the
    /// index holds there, so removing `root` and adding `scan` keeps it.
    fn graft_failed(&self, scan: Vec<Listing>, failed: &[u32], root: &[u8]) -> Vec<Listing> {
        if failed.is_empty() {
            return scan;
        }
        let mut path_of = HashMap::from([(0, root.to_vec())]);
        for_each_path(&scan, root, |p, r| {
            if r.child != NONE {
                path_of.insert(r.child, p);
            }
        });
        let mut next = scan.iter().map(|l| l.id).max().unwrap_or(0) + 1;
        let mut grafted = HashMap::new();
        let mut extra = Vec::new();
        for id in failed {
            let Some(path) = path_of.get(id) else { continue };
            let mut ls = self.listings_from_index(path, *id, &mut next).into_iter();
            grafted.insert(*id, ls.next().unwrap());
            extra.extend(ls);
        }
        let mut out: Vec<Listing> = scan.into_iter().map(|l| grafted.remove(&l.id).unwrap_or(l)).collect();
        out.extend(extra);
        out
    }

    /// What the index holds under `path`, as listings for `add_new`: `path`'s
    /// own first, with id `id`; its folders' take ids from `next`.
    fn listings_from_index(&self, path: &[u8], id: u32, next: &mut u32) -> Vec<Listing> {
        let mut l = Listing { id, names: Vec::new(), ents: Vec::new() };
        let mut more = Vec::new();
        for (name, c) in self.current_children(path) {
            let (kind, size, mtime, descend) = match c {
                Some(c) => {
                    let c = c as usize;
                    (self.base.kind(c), self.base.size_of(c), self.base.mtime(c), self.base.dir_of(c as u32).is_some())
                }
                None => {
                    let o = self.over[&join(path, &name)];
                    (o.kind, o.size, o.mtime, o.kind & 3 == KIND_DIR && o.kind & FLAG_MOUNT == 0)
                }
            };
            let child = if descend {
                let c = *next;
                *next += 1;
                more.extend(self.listings_from_index(&join(path, &name), c, next));
                c
            } else {
                NONE
            };
            l.ents.push(RawEnt { name_off: l.names.len() as u32, name_len: name.len() as u16, kind, size, mtime, child });
            l.names.extend_from_slice(&name);
        }
        let mut out = vec![l];
        out.extend(more);
        out
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
        let de = idx.dir_entries();
        let check = |p: &[u8]| !walk::blocked(p) && lstat(p).is_some_and(|o| o.mtime >= since);
        let pool = stat_pool();
        let mut out: Vec<Vec<u8>> = pool.install(|| {
            (1..idx.d)
                .into_par_iter()
                .with_min_len(1024)
                .filter(|&k| !self.is_dead(de.get(k)))
                .map_init(Vec::new, |buf, k| {
                    idx.path(de.get(k) as usize, buf);
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
                    let k = self.base.kind(c);
                    let sub = self.base.dir_of(c as u32);
                    let cp = sub.map(|_| join(&path, &name));
                    push(&mut l, &name, k, self.base.size_of(c), self.base.mtime(c), cp, sub);
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
    let c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => walk::KIND_FILE,
        libc::S_IFDIR => KIND_DIR,
        libc::S_IFLNK => walk::KIND_LINK,
        _ => walk::KIND_OTHER,
    };
    Some(OEnt::new(path, kind, st.st_size as u64, st.st_mtime.clamp(0, u32::MAX as i64) as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// An index of `root` with real paths: the folders above it as one-entry
    /// listings, then a scan of it.
    fn base_for(root: &[u8]) -> Index {
        let comps: Vec<&[u8]> = root.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
        let k = comps.len() as u32;
        let above = |(i, c): (usize, &&[u8])| {
            let e = RawEnt { name_off: 0, name_len: c.len() as u16, kind: KIND_DIR, size: 0, mtime: 0, child: i as u32 + 1 };
            Listing { id: i as u32, names: c.to_vec(), ents: vec![e] }
        };
        let mut ls: Vec<Listing> = comps.iter().enumerate().map(above).collect();
        for mut l in walk::scan(root, 2) {
            l.id += k;
            for e in l.ents.iter_mut().filter(|e| e.child != NONE) {
                e.child += k;
            }
            ls.push(l);
        }
        Index::build(ls, 0, 0, b"")
    }

    /// A folder deleted (or made a file) while only its parent's event
    /// arrives: what was added inside it since the save goes too, and its
    /// content is resynced.
    #[test]
    fn folder_gone_takes_what_was_added() {
        let d = std::env::temp_dir().join(format!("fsearch-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for f in ["sub/old", "swap/old"] {
            std::fs::create_dir_all(d.join(f).parent().unwrap()).unwrap();
            std::fs::write(d.join(f), "x").unwrap();
        }
        let d = d.canonicalize().unwrap();
        let root = d.as_os_str().as_encoded_bytes().to_vec();
        let mut live = Live::new(base_for(&root));
        for f in ["sub", "swap"] {
            std::fs::write(d.join(f).join("new"), "x").unwrap();
            live.apply_dir(&join(&root, f.as_bytes()), false);
        }
        std::fs::remove_dir_all(d.join("sub")).unwrap();
        std::fs::remove_dir_all(d.join("swap")).unwrap();
        std::fs::write(d.join("swap"), "x").unwrap();
        live.trees.clear();
        live.apply_dir(&root, false);
        let _ = std::fs::remove_dir_all(&d);
        let rel = |k: &Vec<u8>| String::from_utf8_lossy(&k[root.len()..]).into_owned();
        assert_eq!(live.over.keys().filter(|k| k.starts_with(&root)).map(rel).collect::<Vec<_>>(), ["/swap"]);
        live.trees.sort();
        assert_eq!(live.trees.iter().map(rel).collect::<Vec<_>>(), ["/sub", "/swap"]);
    }

    /// A recursive event on a mount point (/dev here) doesn't crawl the
    /// mounted volume: it is an entry flagged as a scan flags it.
    #[test]
    fn mount_point_not_crawled() {
        let live = Live::new(Index::build(vec![Listing::default()], 0, 0, b""));
        let f = live.fetch(b"/dev", true);
        assert!(f.scans.is_empty() && f.attrs.is_some_and(|a| a.kind & FLAG_MOUNT != 0));
        assert!(!walk::is_mount(b"/usr/bin") && !walk::is_mount(b"/Users") && walk::is_mount(b"/System/Volumes/Data"));
    }
    /// A folder under the ignored target/ (not the temp dir, a lazy prefix)
    /// holding sub/file, and an index of it.
    fn sub_with_file(name: &str) -> (std::path::PathBuf, Vec<u8>, Live) {
        let d = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(format!("fsearch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/file"), "x").unwrap();
        let d = d.canonicalize().unwrap();
        let root = d.as_os_str().as_encoded_bytes().to_vec();
        let live = Live::new(base_for(&root));
        (d, root, live)
    }

    fn alive(live: &Live, p: &[u8]) -> bool {
        live.base_alive(p).is_some() || live.over.contains_key(p)
    }

    /// `apply_dir` with sub unreadable (mode 000).
    fn apply_unreadable(live: &mut Live, d: &std::path::Path, path: &[u8]) {
        let sub = d.join("sub");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000)).unwrap();
        live.apply_dir(path, true);
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A recursive rescan of a folder that is there but cannot be listed
    /// keeps its indexed children; one that lists empty does not.
    #[test]
    fn unreadable_directory_keeps_its_children() {
        let (d, root, mut live) = sub_with_file("live-unreadable");
        let (sub, file) = (join(&root, b"sub"), join(&root, b"sub/file"));
        assert!(alive(&live, &file));
        apply_unreadable(&mut live, &d, &sub);
        assert!(alive(&live, &file), "an open failure dropped indexed children");
        std::fs::remove_file(d.join("sub/file")).unwrap();
        live.apply_dir(&sub, true);
        let _ = std::fs::remove_dir_all(&d);
        assert!(!alive(&live, &file), "a folder listed empty kept a deleted child");
    }

    /// The same for a folder that cannot be listed below the one rescanned.
    #[test]
    fn unreadable_nested_directory_keeps_its_children() {
        let (d, root, mut live) = sub_with_file("live-nested");
        let file = join(&root, b"sub/file");
        apply_unreadable(&mut live, &d, &root);
        assert!(alive(&live, &file), "a nested open failure dropped indexed children");
        std::fs::remove_file(d.join("sub/file")).unwrap();
        live.apply_dir(&root, true);
        let _ = std::fs::remove_dir_all(&d);
        assert!(!alive(&live, &file), "a listed folder kept a deleted child");
    }
}
