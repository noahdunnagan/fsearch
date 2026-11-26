//! Frecency: what you (or an agent) worked on lately ranks higher. Editors
//! and hooks report opens (`{"op":"open","path":...}`); each path keeps a
//! count that halves every two weeks, saved in the data dir as a few KB of
//! text. Before any open is reported, your own recent commits (`git.rs`)
//! and files' modification times stand in: replaying Linux's history, the
//! file a commit was about to change ranks first for its name 72% -> 84%.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Two weeks: replays did best between one and four.
pub const HALF_LIFE: f32 = 14.0 * 86_400.0;
/// Entries that decayed below this (one open ~8 weeks ago) are dropped.
const FLOOR: f32 = 0.06;
const MAX_ENTRIES: usize = 4096;
/// Reopening within this long (an editor refocusing a tab) isn't another open.
const DEBOUNCE: u32 = 30;

/// What `age` seconds take off one open.
pub fn decay(age: u32) -> f32 {
    (-(age as f32) / HALF_LIFE).exp2()
}

/// A hit's lift for frecency `s`: one open ~+8, five +21, at most +40
/// (name scores run ~100-300).
pub fn boost(s: f32) -> i32 {
    if s > 0.0 { (12.0 * s.ln_1p()).min(40.0) as i32 } else { 0 }
}

pub struct Frecency {
    file: PathBuf,
    /// Path → (score at `last`, `last` in seconds).
    map: Mutex<HashMap<Vec<u8>, (f32, u32)>>,
    saving: AtomicBool,
    dirty: AtomicBool,
}

fn decayed((score, last): (f32, u32), now: u32) -> f32 {
    score * decay(now.saturating_sub(last))
}

impl Frecency {
    pub fn load(file: PathBuf) -> Arc<Frecency> {
        let mut map = HashMap::new();
        let text = std::fs::read(&file).unwrap_or_default();
        for line in text.split(|&b| b == b'\n') {
            let mut f = line.splitn(3, |&b| b == b'\t');
            let (Some(s), Some(t), Some(p)) = (f.next(), f.next(), f.next()) else { continue };
            let score = std::str::from_utf8(s).ok().and_then(|s| s.parse::<f32>().ok()).filter(|s| s.is_finite() && *s >= 0.0);
            let ts = std::str::from_utf8(t).ok().and_then(|t| t.parse::<u32>().ok());
            let p = if p.first() == Some(&b'"') { serde_json::from_slice::<String>(p).ok().map(String::into_bytes) } else { Some(p.to_vec()) };
            if let (Some(s), Some(t), Some(p)) = (score, ts, p) {
                map.insert(p, (s, t));
            }
        }
        Arc::new(Frecency { file, map: Mutex::new(map), saving: AtomicBool::new(false), dirty: AtomicBool::new(false) })
    }

    /// Record an open of `path`; its new score.
    pub fn open(self: &Arc<Self>, path: &[u8], now: u32) -> f32 {
        let mut map = self.map.lock().unwrap();
        let e = map.entry(path.to_vec()).or_insert((0.0, now));
        if e.0 > 0.0 && now.saturating_sub(e.1) < DEBOUNCE {
            return e.0;
        }
        *e = (decayed(*e, now) + 1.0, now);
        let score = e.0;
        if map.len() > MAX_ENTRIES {
            let mut v: Vec<(Vec<u8>, (f32, u32))> = map.drain().collect();
            v.sort_by(|a, b| decayed(b.1, now).total_cmp(&decayed(a.1, now)));
            v.truncate(MAX_ENTRIES * 3 / 4);
            map.extend(v);
        }
        drop(map);
        self.save_soon();
        score
    }

    /// `path`'s score now (0 if never opened).
    pub fn score(&self, path: &[u8], now: u32) -> f32 {
        self.map.lock().unwrap().get(path).map_or(0.0, |&e| decayed(e, now))
    }

    /// Every path under `dir` (`/`: anywhere) with its score.
    pub fn under(&self, dir: &[u8], now: u32) -> Vec<(Vec<u8>, f32)> {
        let map = self.map.lock().unwrap();
        let inside = |p: &[u8]| dir == b"/" || (p.starts_with(dir) && p.get(dir.len()) == Some(&b'/'));
        map.iter().filter(|(p, _)| inside(p)).map(|(p, &e)| (p.clone(), decayed(e, now))).collect()
    }

    /// Write the file a couple of seconds after a change (one write for a
    /// burst of opens), dropping what decayed away.
    fn save_soon(self: &Arc<Self>) {
        self.dirty.store(true, Ordering::SeqCst);
        if self.saving.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(2));
                me.dirty.store(false, Ordering::SeqCst);
                let now = fsearch::query::now_secs();
                let mut out = Vec::new();
                {
                    let mut map = me.map.lock().unwrap();
                    map.retain(|_, e| decayed(*e, now) >= FLOOR);
                    for (p, &(s, t)) in map.iter() {
                        // One line each: a path with a newline (or starting
                        // with a quote) as a JSON string, if it's UTF-8.
                        let quoted = (p.contains(&b'\n') || p.first() == Some(&b'"'))
                            .then(|| std::str::from_utf8(p).ok().map(|p| serde_json::json!(p).to_string()));
                        let p = match &quoted {
                            None => &p[..],
                            Some(Some(q)) => q.as_bytes(),
                            Some(None) => continue,
                        };
                        out.extend_from_slice(format!("{s:.3}\t{t}\t").as_bytes());
                        out.extend_from_slice(p);
                        out.push(b'\n');
                    }
                }
                let tmp = me.file.with_extension("new");
                if let Err(e) = std::fs::write(&tmp, out).and_then(|_| std::fs::rename(&tmp, &me.file)) {
                    eprintln!("{now} frecency: save failed: {e}");
                }
                if me.dirty.load(Ordering::SeqCst) {
                    continue;
                }
                me.saving.store(false, Ordering::SeqCst);
                if !me.dirty.load(Ordering::SeqCst) || me.saving.swap(true, Ordering::SeqCst) {
                    break;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decays_and_persists() {
        let dir = std::env::temp_dir().join(format!("fsearch-frecency-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = Frecency::load(dir.join("frecency"));
        let t = fsearch::query::now_secs() - 1000;
        assert_eq!(f.open(b"/p/src/a.rs", t), 1.0);
        assert_eq!(f.open(b"/p/src/a.rs", t + 10), 1.0, "refocusing isn't an open");
        assert!((f.open(b"/p/src/a.rs", t + 1000) - 2.0).abs() < 0.01);
        assert!((f.score(b"/p/src/a.rs", t + 1000 + 14 * 86_400) - 1.0).abs() < 0.01, "two weeks halve it");
        assert_eq!(f.under(b"/p", t + 1000).len(), 1);
        assert!(f.under(b"/p/s", t + 1000).is_empty());
        assert_eq!((boost(0.0), boost(1.0), boost(5.0), boost(100.0)), (0, 8, 21, 40));
        assert_eq!(f.open(b"/p/a\nb.rs", t), 1.0);
        std::thread::sleep(std::time::Duration::from_millis(2500));
        let g = Frecency::load(dir.join("frecency"));
        assert!((g.score(b"/p/src/a.rs", t + 1000) - 2.0).abs() < 0.01, "saved");
        assert!((g.score(b"/p/a\nb.rs", t) - 1.0).abs() < 0.01, "a newline in a name is kept");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_ignores_invalid_scores_and_timestamps() {
        let dir = std::env::temp_dir().join(format!("fsearch-frecency-invalid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("frecency");
        let now = fsearch::query::now_secs();
        let content = format!(
            "NaN\t{now}\t/p/nan.rs\n\
             inf\t{now}\t/p/inf.rs\n\
             -inf\t{now}\t/p/neginf.rs\n\
             1e40\t{now}\t/p/overflow.rs\n\
             -1.0\t{now}\t/p/neg.rs\n\
             1.5\t{now}.5\t/p/float_ts.rs\n\
             1.5\t-10\t/p/neg_ts.rs\n\
             1.5\tbad\t/p/bad_ts.rs\n\
             2.0\t{now}\t/p/valid.rs\n"
        );
        std::fs::write(&file, content).unwrap();
        let f = Frecency::load(file);
        let entries = f.under(b"/p", now);
        assert_eq!(entries.len(), 1, "expected only valid entry, got {entries:?}");
        assert_eq!(entries[0].0, b"/p/valid.rs");
        assert!((entries[0].1 - 2.0).abs() < 0.01);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn concurrent_open_bursts_persist_cleanly() {
        let dir = std::env::temp_dir().join(format!("fsearch-frecency-burst-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("frecency");
        let f = Frecency::load(file.clone());
        let now = fsearch::query::now_secs();
        std::thread::scope(|s| {
            for tid in 0..8usize {
                let f = &f;
                s.spawn(move || {
                    for i in 0..32usize {
                        let p = format!("/p/t{tid}/f{i}.rs");
                        f.open(p.as_bytes(), now);
                    }
                });
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(2500));
        assert!(!file.with_extension("new").exists(), "temp file should not remain after save");
        let reloaded = Frecency::load(file);
        assert_eq!(reloaded.under(b"/p", now).len(), 8 * 32);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
