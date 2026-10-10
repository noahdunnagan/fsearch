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

// The path helpers live in `paths` (walk uses them too); re-exported here.
pub(crate) use crate::paths::normalize;
pub use crate::paths::{is_ancestor, join, trim_dir};
use crate::walk::mtime_of;

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

    /// Drop a child the listing no longer has (or whose shape changed) and
    /// everything under it, including what was added inside it since the
    /// save. `base`: its base entry, if it has one.
    fn remove_child(&mut self, child: &[u8], base: Option<u32>) {
        let was_dir = match base {
            Some(c) => self.base.kind()[c as usize] & 3 == KIND_DIR,
            None => self.over.get(child).is_some_and(|o| o.kind & 3 == KIND_DIR),
        };
        if was_dir {
            self.trees.push(child.to_vec());
        }
        if let Some(c) = base {
            self.kill_subtree(c);
        }
        self.drop_over_subtree(child);
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
            // Only whether it still exists matters here: no mount check.
            f.attrs = stat(&f.path, false);
            return f;
        };
        // Children that will be added as folders get their subtree scanned now.
        let cur = self.current_children(&f.path);
        for r in &listing.ents {
            if r.kind & 3 != KIND_DIR || r.kind & FLAG_MOUNT != 0 {
                continue;
            }
            let name = &listing.names[r.name_off as usize..][..r.name_len as usize];
            // Scanned now unless it stays the same shape of folder (a mount
            // point that's gone, too, comes back as a folder to list).
            let was = match cur.get(name) {
                Some(Some(c)) => Some(shape(self.base.kind()[*c as usize])),
                Some(None) => self.over.get(&join(&f.path, name)).map(|o| shape(o.kind)),
                None => None,
            };
            if was != Some(shape(r.kind)) {
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
                    if shape(was_kind) != shape(now.kind) {
                        self.remove_child(&child, Some(c as u32));
                        let scan = f.scans.remove(&child);
                        self.add_new(child, now, scan);
                    } else if now.kind & 3 != KIND_DIR && (self.base.size_raw()[c] != enc_size(now.size) || self.base.mtime()[c] != now.mtime) {
                        self.kill(c as u32);
                        self.put(child, now);
                    }
                }
                Some(None) => {
                    let old = self.over[&child];
                    if shape(old.kind) != shape(now.kind) {
                        self.remove_child(&child, None);
                        let scan = f.scans.remove(&child);
                        self.add_new(child, now, scan);
                    } else if (old.kind, old.size, old.mtime) != (now.kind, now.size, now.mtime) {
                        self.put(child, now);
                    }
                }
            }
        }
        for (name, c) in cur {
            self.remove_child(&join(&p, &name), c);
        }
        // A child that changed shape was removed and re-added: resync once.
        self.trees.sort();
        self.trees.dedup();
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
        let check = |p: &[u8]| !walk::blocked(p) && mtime_of(p).is_some_and(|m| m >= since);
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
        if mtime_of(b"/").is_some_and(|m| m >= since) {
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

/// Key range holding everything strictly under `path`.
fn subtree_bounds(path: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let lo = join(path, b"");
    let mut hi = lo.clone();
    *hi.last_mut().unwrap() += 1; // '/' + 1 == '0'
    (lo, hi)
}

/// What decides how an entry is indexed: its kind, and for a folder
/// whether it's a mount point (listed, or not crossed).
fn shape(kind: u8) -> u8 {
    kind & (3 | FLAG_MOUNT)
}

pub fn lstat(path: &[u8]) -> Option<OEnt> {
    stat(path, true)
}

/// lstat as an index entry; `mount`: also ask a folder's mount status (an
/// extra syscall), for callers that compare shapes.
fn stat(path: &[u8], mount: bool) -> Option<OEnt> {
    let c = std::ffi::CString::new(path).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => walk::KIND_FILE,
        // Flagged like a scan does, so a recursive event on it isn't a
        // crawl of the mounted volume.
        libc::S_IFDIR if mount && walk::is_mount(&c) => KIND_DIR | FLAG_MOUNT,
        libc::S_IFDIR => KIND_DIR,
        libc::S_IFLNK => walk::KIND_LINK,
        _ => walk::KIND_OTHER,
    };
    Some(OEnt::new(path, kind, st.st_size as u64, st.st_mtime.clamp(0, u32::MAX as i64) as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walk::tests::Tmp;
    use crate::walk::{KIND_FILE, KIND_LINK};
    use std::collections::BTreeSet;
    use std::path::Path;

    /// An index whose paths are real: the ancestors of `root` as one-entry
    /// listings (never listing them), then a scan of `root` itself.
    /// The index an engine builds for `root` (its ancestors as one-child
    /// folders), so the live code works on real paths without listing `/`.
    fn base_for(root: &[u8]) -> Index {
        Index::build(walk::scan_rooted(root, 2), 5, 9, b"")
    }

    fn live_for(t: &Tmp) -> Live {
        Live::new(base_for(t.bytes()))
    }

    type State = BTreeMap<Vec<u8>, (u8, u64, u32)>;

    /// Everything alive under `root`. Folder size/mtime aren't tracked.
    fn state(live: &Live, root: &[u8]) -> State {
        let lo = join(root, b"");
        let norm = |k: u8, s: u64, m: u32| if k & 3 == KIND_DIR { (k, 0, 0) } else { (k, s, m) };
        let mut out = State::new();
        let mut p = Vec::new();
        for i in 0..live.base.n {
            live.base.path(i, &mut p);
            if p.starts_with(&lo) && !live.is_dead(i as u32) {
                out.insert(p.clone(), norm(live.base.kind()[i], live.base.size_of(i), live.base.mtime()[i]));
            }
        }
        for (k, o) in &live.over {
            if k.starts_with(&lo) {
                assert!(out.insert(k.clone(), norm(o.kind, o.size, o.mtime)).is_none(), "base and overlay both hold {}", String::from_utf8_lossy(k));
            }
        }
        out
    }

    /// The live state matches a fresh scan, and survives compaction.
    fn check(live: &Live, t: &Tmp) {
        let show =
            |s: State| s.into_iter().map(|(k, v)| (String::from_utf8_lossy(&k[t.bytes().len()..]).into_owned(), v)).collect::<BTreeMap<_, _>>();
        let fresh = show(state(&live_for(t), t.bytes()));
        assert_eq!(show(state(live, t.bytes())), fresh);
        let compacted = Live::new(Index::build(live.to_listings(), live.event_id, live.synced_at, b""));
        assert_eq!(show(state(&compacted, t.bytes())), fresh);
        assert!(compacted.over.is_empty());
    }

    fn set_mtime(p: &Path, secs: u64) {
        let f = std::fs::File::open(p).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)).unwrap();
    }

    fn trees(live: &mut Live, t: &Tmp) -> BTreeSet<String> {
        std::mem::take(&mut live.trees).iter().map(|p| String::from_utf8_lossy(&p[t.bytes().len()..]).into_owned()).collect()
    }

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn apply_dir_follows_disk() {
        let t = Tmp::new("live");
        t.file("a.txt", 1);
        t.file("keep", 5);
        t.file("sub/b", 2);
        t.file("sub/deep/c", 3);
        t.file("gone/x", 1);
        t.file("d2f/k1", 1);
        t.file("f2d", 1);
        t.file("d2l/k2", 1);
        t.dir("empty");
        let mut live = live_for(&t);
        assert_eq!((live.event_id, live.synced_at), (5, 9));
        check(&live, &t);
        assert!(matches!(live.apply_dir(t.bytes(), false), Applied::Done));
        assert!(live.over.is_empty() && live.dead_count == 0, "no-op diff");

        t.file("new.txt", 4);
        t.file("a.txt", 10);
        std::fs::remove_dir_all(t.p("gone")).unwrap();
        t.file("newdir/n1/n2.txt", 6);
        std::fs::remove_dir_all(t.p("d2f")).unwrap();
        t.file("d2f", 7);
        std::fs::remove_file(t.p("f2d")).unwrap();
        t.file("f2d/inner", 8);
        std::fs::remove_dir_all(t.p("d2l")).unwrap();
        t.link("sub", "d2l");
        live.apply_dir(&[t.bytes(), b"//"].concat(), false); // trailing slashes are normalized away
        check(&live, &t);
        assert_eq!(trees(&mut live, &t), set(&["/d2f", "/d2l", "/f2d", "/gone", "/newdir"]));

        // Edits to overlay entries: modify, kind changes both ways, delete.
        std::fs::remove_dir_all(t.p("newdir/n1")).unwrap();
        t.file("newdir/n1", 2);
        t.file("newdir/n3/x", 2);
        live.apply_dir(&t.b("newdir"), false);
        check(&live, &t);
        assert_eq!(trees(&mut live, &t), set(&["/newdir/n1", "/newdir/n3"]));
        std::fs::remove_file(t.p("d2f")).unwrap();
        t.dir("d2f");
        std::fs::remove_dir_all(t.p("f2d")).unwrap();
        t.file("new.txt", 40);
        live.apply_dir(t.bytes(), false);
        check(&live, &t);
        assert_eq!(trees(&mut live, &t), set(&["/d2f", "/f2d"]));
        std::fs::remove_dir_all(t.p("newdir")).unwrap();
        live.apply_dir(t.bytes(), false);
        check(&live, &t);
        assert_eq!(trees(&mut live, &t), set(&["/newdir"]));

        // Replaying the same events changes nothing.
        let (over, dead) = (live.over.len(), live.dead_count);
        live.apply_dir(t.bytes(), false);
        live.apply_dir(&t.b("sub"), false);
        assert_eq!((live.over.len(), live.dead_count), (over, dead));
    }

    #[test]
    fn deleted_base_dir_drops_overlay_children() {
        let t = Tmp::new("orphan");
        t.file("sub/old", 1);
        t.file("swap/old", 1);
        let mut live = live_for(&t);
        t.file("sub/new", 1);
        t.file("swap/new", 1);
        live.apply_dir(&t.b("sub"), false);
        live.apply_dir(&t.b("swap"), false);
        assert!(live.over.contains_key(&t.b("sub/new")));
        // The folder goes (or becomes a file) and only its parent's event
        // arrives: what was added inside it must go too.
        std::fs::remove_dir_all(t.p("sub")).unwrap();
        std::fs::remove_dir_all(t.p("swap")).unwrap();
        t.file("swap", 3);
        live.apply_dir(t.bytes(), false);
        check(&live, &t);
        assert!(!live.over.contains_key(&t.b("sub/new")));
        assert!(!live.over.contains_key(&t.b("swap/new")));
        assert_eq!(trees(&mut live, &t), set(&["/sub", "/swap"]));
    }

    #[test]
    fn rename_and_case_change() {
        let t = Tmp::new("ren");
        t.file("foo", 1);
        t.file("dir/x", 1);
        let mut live = live_for(&t);
        std::fs::rename(t.p("foo"), t.p("Foo")).unwrap();
        std::fs::rename(t.p("dir"), t.p("dir2")).unwrap();
        live.apply_dir(t.bytes(), false);
        check(&live, &t);
        assert!(live.over.contains_key(&t.b("dir2/x")));
    }

    #[test]
    fn one_folder_events() {
        let t = Tmp::new("one");
        t.file("sub/deep/c", 1);
        t.file("f", 1);
        let mut live = live_for(&t);
        // A folder that is still there but can't be listed as one (a file)
        // is left to its parent's event.
        live.apply_dir(&t.b("f"), false);
        assert_eq!(live.dead_count, 0);
        // A folder that is gone is removed with everything under it.
        std::fs::remove_dir_all(t.p("sub")).unwrap();
        live.apply_dir(&t.b("sub"), false);
        assert_eq!(live.dead_count, 3);
        live.apply_dir(&t.b("sub/deep"), false);
        assert_eq!(live.dead_count, 3);
        check(&live, &t);
        // An event for a folder the index never knew.
        t.file("sub/deep/c", 2);
        live.apply_dir(&t.b("sub/deep"), false);
        assert!(live.over.contains_key(&t.b("sub/deep/c")));
        live.apply_dir(t.bytes(), false);
        check(&live, &t);
    }

    #[test]
    fn recursive_events() {
        let t = Tmp::new("rec");
        t.file("sub/deep/c", 1);
        t.file("sub/b", 1);
        t.file("other/o", 1);
        let mut live = live_for(&t);
        t.file("sub/deep/c", 2);
        t.file("sub/deep/more/m", 2);
        std::fs::remove_file(t.p("sub/b")).unwrap();
        assert!(matches!(live.apply_dir(&t.b("sub"), true), Applied::Done));
        check(&live, &t);
        assert_eq!(trees(&mut live, &t), set(&["/sub"]));
        std::fs::remove_dir_all(t.p("other")).unwrap();
        live.apply_dir(&t.b("other"), true);
        check(&live, &t);
        // A file named as a "tree" is just re-statted.
        t.file("f", 3);
        live.apply_dir(&t.b("f"), true);
        check(&live, &t);
        assert!(matches!(live.apply_dir(b"/", true), Applied::Rebuild));
        assert!(matches!(live.apply_dir(b"//", true), Applied::Rebuild));
    }

    #[test]
    fn fetch_reads_ahead() {
        let t = Tmp::new("fetch");
        t.file("a", 1);
        let mut live = live_for(&t);
        t.file("nd/x/y", 1);
        let f = live.fetch(t.bytes(), false);
        assert!(f.scans.contains_key(&t.b("nd")));
        // Applied from what was read, not from the disk now.
        std::fs::remove_dir_all(t.p("nd")).unwrap();
        live.apply(f);
        assert!(live.over.contains_key(&t.b("nd/x/y")));
        // An existing folder isn't rescanned.
        assert!(live.fetch(t.bytes(), false).scans.is_empty());
        t.file("nd/x/y", 1);
        assert!(live.fetch(t.bytes(), false).scans.is_empty());
        // A scan missing from the fetch is done on apply.
        let mut f = live.fetch(&t.b("nd/x"), true);
        f.scans.clear();
        live.apply(f);
        check(&live, &t);
    }

    #[test]
    fn overlay_priors() {
        let t = Tmp::new("prior");
        t.dir("node_modules/pkg");
        let mut live = live_for(&t);
        t.file("node_modules/pkg/new/deeper/f", 1);
        live.apply_dir(&t.b("node_modules/pkg"), false);
        let base = &live.base;
        let pkg = base.dir_of(base.lookup(&t.b("node_modules/pkg")).unwrap()).unwrap();
        let want = base.dir_prior()[pkg as usize];
        assert!(want < 0);
        for k in ["node_modules/pkg/new", "node_modules/pkg/new/deeper", "node_modules/pkg/new/deeper/f"] {
            assert_eq!(live.over[&t.b(k)].prior, want, "{k}");
        }
        // Outside any base folder: the root's prior.
        live.put(b"/zz-not-there/x".to_vec(), OEnt::new(b"x", KIND_FILE, 0, 0));
        live.put(b"/top".to_vec(), OEnt::new(b"top", KIND_FILE, 0, 0));
        assert_eq!(live.over[&b"/zz-not-there/x"[..]].prior, 0);
        assert_eq!(live.over[&b"/top"[..]].prior, 0);
    }

    #[test]
    fn to_listings_at_root() {
        // Overlay entries straight under "/" land in the root listing.
        let t = Tmp::new("root");
        let mut live = live_for(&t);
        live.put(b"/zz-top".to_vec(), OEnt::new(b"/zz-top", KIND_FILE, 3, 4));
        let idx = Index::build(live.to_listings(), 0, 0, b"");
        let e = idx.lookup(b"/zz-top").unwrap() as usize;
        assert_eq!((idx.parent()[e], idx.size_of(e), idx.mtime()[e]), (0, 3, 4));
        // Removing "/" kills everything.
        live.remove_path(b"/");
        assert_eq!(live.dead_count, live.base.n);
        assert!(live.over.is_empty());
        assert_eq!(live.to_listings().len(), 1);
    }

    #[test]
    fn changed_dirs_by_mtime() {
        let t = Tmp::new("changed");
        t.file("a/f", 1);
        t.dir("b/c");
        t.dir("dead");
        let mut live = live_for(&t);
        t.file("ov/x", 1);
        live.apply_dir(t.bytes(), false);
        std::fs::remove_dir_all(t.p("dead")).unwrap();
        live.apply_dir(t.bytes(), false);
        t.dir("dead");
        const OLD: u64 = 1_000_000;
        const NEW: u64 = 4_000_000_000; // later than any real folder
        for d in [".", "a", "b", "b/c", "ov", "dead"] {
            set_mtime(&t.p(d), OLD);
        }
        set_mtime(&t.p("b/c"), NEW);
        set_mtime(&t.p("ov"), NEW);
        set_mtime(&t.p("dead"), NEW);
        let got = live.changed_dirs(NEW as u32 - 1);
        assert_eq!(got, [t.b("b/c"), t.b("ov")], "dead folders are skipped");
        let all = live.changed_dirs(0);
        assert!(all.contains(&b"/".to_vec()));
        assert!(all.contains(&t.b("a")));
        assert!(!all.contains(&t.b("a/f")));
        assert!(live.changed_dirs(u32::MAX).is_empty());
    }

    #[test]
    fn helpers() {
        assert_eq!(normalize(b"/a/b///"), b"/a/b");
        assert_eq!(normalize(b"///"), b"/");
        assert_eq!(normalize(b""), b"");
        assert_eq!(join(b"/", b"a"), b"/a");
        assert_eq!(join(b"/a", b"b"), b"/a/b");
        assert_eq!(join(b"/a", b""), b"/a/");
        let (lo, hi) = subtree_bounds(b"/a/b");
        let inside = |p: &[u8]| lo.as_slice() <= p && p < hi.as_slice();
        assert!(inside(b"/a/b/c"));
        assert!(inside(b"/a/b/\xff"));
        assert!(!inside(b"/a/b"));
        assert!(!inside(b"/a/bc"));
        assert!(!inside(b"/a/b.txt"));
        assert!(!inside(b"/a/b0"));
        let (lo, hi) = subtree_bounds(b"/");
        assert!(lo.as_slice() <= b"/x".as_slice() && b"/x".as_slice() < hi.as_slice());
        assert!(lo.as_slice() <= b"/\xff".as_slice() && b"/\xff".as_slice() < hi.as_slice());

        assert_eq!(OEnt::new(b"/x/y.txt", KIND_FILE, 1, 2).mask, crate::index::name_mask(b"y.txt"));
        assert_eq!(OEnt::new(b"y.txt", KIND_FILE, 1, 2).mask, crate::index::name_mask(b"y.txt"));

        let t = Tmp::new("lstat");
        t.file("f", 9);
        t.link("f", "l");
        let fifo = std::ffi::CString::new(t.b("p")).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        assert_eq!(lstat(&t.b("f")).map(|o| (o.kind, o.size)), Some((KIND_FILE, 9)));
        assert_eq!(lstat(&t.b("l")).map(|o| o.kind), Some(KIND_LINK));
        assert_eq!(lstat(&t.b("p")).map(|o| o.kind), Some(walk::KIND_OTHER));
        assert_eq!(lstat(t.bytes()).map(|o| o.kind), Some(KIND_DIR));
        assert!(lstat(&t.b("missing")).is_none());
        assert!(lstat(b"/a\0b").is_none());

        t.file("s/d/e", 1);
        let mut seen = Vec::new();
        for_each_path(&walk::scan(&t.b("s"), 1), b"/r", |p, r| seen.push((p, r.kind)));
        seen.sort();
        assert_eq!(seen, [(b"/r/d".to_vec(), KIND_DIR), (b"/r/d/e".to_vec(), KIND_FILE)]);
        assert_eq!(stat_pool().current_num_threads(), 12);
    }

    /// A folder that stops being a mount point (or becomes one) changes
    /// shape: its parent's relist must list what's really there now.
    #[test]
    fn unmounted_folder_is_listed_on_relist() {
        let t = Tmp::new("unmount");
        std::fs::create_dir_all(t.p("d")).unwrap();
        std::fs::write(t.p("d/inner.txt"), "x").unwrap();
        // The index from while a volume was mounted on d: d flagged, no contents.
        let root = t.bytes();
        let mut ls = walk::ancestors(root);
        ls.push(crate::index::tests::lst(ls.len() as u32, &[(b"d", KIND_DIR | FLAG_MOUNT, 0, NONE)]));
        let mut live = Live::new(Index::build(ls, 0, 0, b""));
        // Its contents are scanned in fetch (under the read lock), not in
        // apply under the write lock.
        let f = live.fetch(root, false);
        assert!(f.scans.contains_key(&join(root, b"d")), "d scanned ahead");
        live.apply(f);
        // Removed and re-added, but resynced once.
        let mut t = live.trees.clone();
        t.dedup();
        assert_eq!(t.len(), live.trees.len(), "{:?}", live.trees);
        let inner = join(&join(root, b"d"), b"inner.txt");
        assert!(live.over.contains_key(&inner), "d's contents after it was unmounted");
    }

    /// lstat flags a mount point the way a scan does, so a recursive event
    /// on one doesn't scan into the volume. (Only lstat here: a fetch that
    /// missed the flag would crawl the whole Data volume.) /Users is a
    /// firmlink, crossed on purpose, not a mount.
    #[test]
    fn lstat_flags_mount_points() {
        let data = lstat(b"/System/Volumes/Data").expect("the Data volume");
        assert_ne!(data.kind & FLAG_MOUNT, 0);
        assert_eq!(lstat(b"/Users").unwrap().kind & FLAG_MOUNT, 0);
        let t = Tmp::new("lstat-mount");
        assert_eq!(lstat(t.0.as_os_str().as_encoded_bytes()).unwrap().kind & FLAG_MOUNT, 0);
    }

    #[test]
    fn ancestors_end_at_a_component() {
        assert!(is_ancestor(b"/Users", b"/Users/me"));
        assert!(is_ancestor(b"/Users/me", b"/Users/me"));
        assert!(is_ancestor(b"/", b"/Users/me"));
        assert!(!is_ancestor(b"/Users/m", b"/Users/me"));
        assert!(!is_ancestor(b"/Users/me/x", b"/Users/me"));
    }
}
