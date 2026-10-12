use fsearch::{Grep, GrepMode, Query, content, index::Index, live, paths, walk};
use std::path::PathBuf;

struct Temp(PathBuf);

impl Temp {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("fsearch-test-{}-{n}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        Self(std::fs::canonicalize(dir).unwrap())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn scanner_metadata_names_and_saved_index() {
    let dir = Temp::new();
    std::fs::create_dir(dir.0.join("docs")).unwrap();
    std::fs::write(dir.0.join("docs/café-資料.txt"), "hello portable search\n").unwrap();
    std::fs::write(dir.0.join("readme.md"), "readme\n").unwrap();
    let root = paths::encode(&dir.0);
    let listings = walk::scan(&root, 2);
    let mut scanned = Vec::new();
    live::for_each_path(&listings, &root, |p, e| scanned.push((paths::decode(&p), e.kind & 3, e.size, e.mtime)));
    assert_eq!(scanned.len(), 3);
    assert!(scanned.iter().any(|(p, k, s, t)| p == &dir.0.join("docs/café-資料.txt") && *k == walk::KIND_FILE && *s == 22 && *t > 0));

    // Index::build uses / as the scan's root on both platforms.
    let index = Index::build(listings, 123, 456, b"/");
    let saved = dir.0.join("names.bin");
    index.save(&saved).unwrap();
    let loaded = Index::load(&saved).unwrap();
    assert_eq!(loaded.event_id, 123);
    assert_eq!(loaded.synced_at, 456);
    let file = loaded.lookup("/docs/café-資料.txt".as_bytes()).unwrap();
    let mut path = Vec::new();
    loaded.path(file as usize, &mut path);
    assert_eq!(path, "/docs/café-資料.txt".as_bytes());
    let live = live::Live::new(loaded);
    let q = Query::parse("readme ext:md", "").unwrap();
    let hits = fsearch::query::Searcher { live: &live }.search(&q);
    assert_eq!(hits.len(), 1);
    assert_eq!(live.base.name(hits[0].idx as usize), b"readme.md");
    let q = Query { scope: Some(b"/docs".to_vec()), ..Query::parse("ext:txt", "").unwrap() };
    assert_eq!(fsearch::query::Searcher { live: &live }.search(&q).len(), 1);
}

#[test]
fn content_reads_unicode_paths_and_rejects_directories() {
    let dir = Temp::new();
    let file = dir.0.join("資料 café.txt");
    std::fs::write(&file, "one\nPortable NEEDLE here\nthree\n").unwrap();
    let path = paths::encode(&file);
    assert_eq!(paths::decode(&path), file);
    assert!(content::open_regular(&paths::encode(&dir.0)).is_none());
    for (pattern, mode) in [("needle", GrepMode::Literal), ("Portable.*here", GrepMode::Regex)] {
        let grep = Grep::new(pattern, mode).unwrap();
        let result = content::verify(&grep, std::slice::from_ref(&path), 10);
        assert!(result.complete);
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].lines[0].0, 2);
    }
}

#[test]
fn scope_resolves_native_paths_and_tilde() {
    let dir = Temp::new();
    std::fs::create_dir(dir.0.join("folder with spaces")).unwrap();
    let home = dir.0.to_str().unwrap();
    let q = Query::parse("in:\"~/folder with spaces\"", home).unwrap();
    assert_eq!(q.scope.unwrap(), paths::encode(&dir.0.join("folder with spaces")));
    #[cfg(unix)]
    assert_eq!(Query::parse("in:/", home).unwrap().scope, Some(Vec::new()));
}

#[test]
fn snapshot_content_requires_a_valid_manifest() {
    let dir = Temp::new();
    assert!(content::Content::open_snapshot(dir.0.clone()).is_err());
    assert_eq!(content::Content::open_shared(dir.0.clone()).docs(), 0);
    let manifest = dir.0.join("manifest");
    std::fs::write(&manifest, "").unwrap();
    assert_eq!(content::Content::open_snapshot(dir.0.clone()).unwrap().docs(), 0);
    for invalid in [b"not-an-id".as_slice(), b"1\n", b"18446744073709551615\n", b"\xff"] {
        std::fs::write(&manifest, invalid).unwrap();
        assert!(content::Content::open_snapshot(dir.0.clone()).is_err());
    }
}

#[test]
fn snapshot_content_rejects_missing_corrupt_and_duplicate_segments() {
    let data = Temp::new();
    let home = Temp::new();
    let source = home.0.join("source.txt");
    let text = "a searchable needle\n";
    std::fs::write(&source, text).unwrap();
    let home_key = paths::encode(&home.0);
    let key = paths::encode(&source);
    let mut live = live::Live::new(Index::build(vec![walk::Listing { id: 0, names: Vec::new(), ents: Vec::new() }], 0, 0, &home_key));
    live.over.insert(key.clone(), live::OEnt::new(&key, walk::KIND_FILE, text.len() as u64, 0));
    let mut catalog = content::Content::open(data.0.clone());
    let docs = catalog.diff(content::wants(&live, &home_key, &[], std::slice::from_ref(&home_key)));
    assert_eq!(docs.len(), 1);
    let id = catalog.alloc_id();
    catalog.push(content::build_segment(&data.0, id, &docs, 0..docs.len()).unwrap());
    drop(catalog);
    let query = Query::parse("", home.0.to_str().unwrap()).unwrap();
    let grep = Grep::new("needle", GrepMode::Literal).unwrap();
    {
        let loaded = content::Content::open_snapshot(data.0.clone()).unwrap();
        assert_eq!(loaded.docs(), 1);
        assert_eq!(loaded.search(&grep, &query).files.len(), 1);
    }
    let manifest = data.0.join("manifest");
    std::fs::write(&manifest, format!("{id}\n{id}\n")).unwrap();
    assert!(content::Content::open_snapshot(data.0.clone()).is_err());
    std::fs::write(&manifest, format!("{id}\n")).unwrap();
    let segment = data.0.join(format!("seg-{id:06}.fsc"));
    let saved = std::fs::read(&segment).unwrap();
    std::fs::write(&segment, &saved[..12]).unwrap();
    assert!(content::Content::open_snapshot(data.0.clone()).is_err());
    let mut corrupt = saved;
    corrupt[0] ^= 0xff;
    std::fs::write(&segment, corrupt).unwrap();
    assert!(content::Content::open_snapshot(data.0.clone()).is_err());
    std::fs::remove_file(&segment).unwrap();
    assert!(content::Content::open_snapshot(data.0.clone()).is_err());
}

#[cfg(windows)]
mod windows {
    use super::*;
    use fsearch::{Engine, Options};
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    fn opts(data: &Temp, home: &Temp) -> Options {
        Options { dir: data.0.clone(), home: home.0.to_str().unwrap().to_owned(), skip: None }
    }

    #[test]
    fn snapshot_refresh_with_existing_reader_and_failed_rebuild() {
        let data = Temp::new();
        let home = Temp::new();
        let source = home.0.join("source.rs");
        std::fs::write(&source, "fn old_symbol() {}\n").unwrap();
        let old = Engine::rebuild(opts(&data, &home), &[home.0.clone()]).unwrap();
        let mapped = Engine::start(opts(&data, &home)).unwrap();
        let saved_roots = Engine::saved_roots(&data.0).unwrap();
        assert_eq!(saved_roots, vec![home.0.clone()]);
        let query = Query::parse("ext:rs", home.0.to_str().unwrap()).unwrap();
        assert_eq!(old.search(&query).unwrap().len(), 1);
        assert_eq!(mapped.search(&query).unwrap().len(), 1);

        // Same length and restored timestamp: explicit refresh must re-read
        // content even when metadata is unchanged at the index's precision.
        let mtime = std::fs::metadata(&source).unwrap().modified().unwrap();
        std::fs::write(&source, "fn new_symbol() {}\n").unwrap();
        std::fs::File::options().write(true).open(&source).unwrap().set_modified(mtime).unwrap();
        std::fs::write(home.0.join("new.rs"), "fn another() {}\n").unwrap();
        let refreshed = Engine::rebuild(opts(&data, &home), &saved_roots).unwrap();
        assert_eq!(refreshed.search(&query).unwrap().len(), 2);
        assert_eq!(mapped.search(&query).unwrap().len(), 1);
        let grep = Grep::new("new_symbol", GrepMode::Symbol).unwrap();
        let (result, indexed) = refreshed.grep(&query, &grep).unwrap();
        assert!(indexed);
        assert_eq!(result.files.len(), 1);

        let current = std::fs::read(data.0.join("current")).unwrap();
        assert!(Engine::rebuild(opts(&data, &home), &[home.0.join("missing")]).is_err());
        assert_eq!(std::fs::read(data.0.join("current")).unwrap(), current);
        assert_eq!(Engine::start(opts(&data, &home)).unwrap().search(&query).unwrap().len(), 2);
        std::fs::remove_file(&source).unwrap();
        let removed = Engine::rebuild(opts(&data, &home), &saved_roots).unwrap();
        assert_eq!(removed.search(&query).unwrap().len(), 1);
        assert!(removed.grep(&query, &grep).unwrap().0.files.is_empty());
    }

    #[test]
    fn index_writer_lock_blocks_readers_and_other_writers() {
        let data = Temp::new();
        let home = Temp::new();
        let file = std::fs::File::options().read(true).write(true).create(true).truncate(false).open(data.0.join("daemon.lock")).unwrap();
        file.try_lock().unwrap();
        assert!(Engine::rebuild(opts(&data, &home), &[home.0.clone()]).is_err());
        assert!(Engine::start(opts(&data, &home)).is_err());
        drop(file);
        assert!(Engine::rebuild(opts(&data, &home), &[home.0.clone()]).is_ok());
    }

    #[test]
    fn failed_publication_cleans_new_and_abandoned_generations() {
        let data = Temp::new();
        let home = Temp::new();
        std::fs::write(home.0.join("source.txt"), "needle\n").unwrap();
        drop(Engine::rebuild(opts(&data, &home), &[home.0.clone()]).unwrap());
        let current = std::fs::read_to_string(data.0.join("current")).unwrap();
        let abandoned = data.0.join("snapshot-999-1");
        std::fs::create_dir(&abandoned).unwrap();
        std::fs::write(abandoned.join("partial"), "unfinished write").unwrap();
        // Fail after the content and name indexes have been written.
        std::fs::create_dir(data.0.join("current.tmp")).unwrap();
        for _ in 0..2 {
            assert!(Engine::rebuild(opts(&data, &home), &[home.0.clone()]).is_err());
            assert_eq!(std::fs::read_to_string(data.0.join("current")).unwrap(), current);
            assert!(!abandoned.exists());
            let generations: Vec<_> = std::fs::read_dir(&data.0)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .filter(|n| n.to_string_lossy().starts_with("snapshot-"))
                .collect();
            assert_eq!(generations, vec![std::ffi::OsString::from(&current)]);
            assert_eq!(Engine::start(opts(&data, &home)).unwrap().status().content_docs, 1);
        }
        std::fs::remove_dir(data.0.join("current.tmp")).unwrap();
        assert_eq!(Engine::rebuild(opts(&data, &home), &[home.0.clone()]).unwrap().status().content_docs, 1);
        std::fs::write(data.0.join("current"), "invalid generation").unwrap();
        assert_eq!(Engine::rebuild(opts(&data, &home), &[home.0.clone()]).unwrap().status().content_docs, 1);
    }

    #[test]
    fn explicit_root_preserves_metadata_and_timestamp_filters() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_HIDDEN, SetFileAttributesW};
        let home = Temp::new();
        let root = home.0.join("selected-root");
        std::fs::create_dir(&root).unwrap();
        let wide: Vec<_> = root.as_os_str().encode_wide().chain([0]).collect();
        assert_ne!(unsafe { SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) }, 0);
        let metadata = std::fs::metadata(&root).unwrap();
        let modified = metadata.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32;
        let index = Index::build(walk::scan_roots(&[root.clone()], 2).unwrap(), 0, 0, &paths::encode(&home.0));
        let entry = index.lookup(&paths::encode(&root)).unwrap() as usize;
        assert_eq!(index.mtime()[entry], modified);
        assert_ne!(index.kind()[entry] & walk::FLAG_HIDDEN, 0);
        let parent = index.lookup(&paths::encode(&home.0)).unwrap() as usize;
        assert!(index.mtime()[parent] > 0);
        let live = live::Live::new(index);
        let q = Query::parse("kind:dir selected-root mtime:<7d", home.0.to_str().unwrap()).unwrap();
        assert_eq!(fsearch::query::Searcher { live: &live }.search(&q).len(), 1);
    }

    #[test]
    fn old_reader_can_first_grep_after_rebuild() {
        let data = Temp::new();
        let home = Temp::new();
        std::fs::write(home.0.join("source.txt"), "persistent needle\n").unwrap();
        drop(Engine::rebuild(opts(&data, &home), &[home.0.clone()]).unwrap());
        let reader = Engine::start(opts(&data, &home)).unwrap();
        std::fs::write(home.0.join("second.txt"), "persistent needle\n").unwrap();
        let new = Engine::rebuild(opts(&data, &home), &[home.0.clone()]).unwrap();
        let q = Query::parse("", home.0.to_str().unwrap()).unwrap();
        let grep = Grep::new("needle", GrepMode::Literal).unwrap();
        assert_eq!(reader.grep(&q, &grep).unwrap().0.files.len(), 1);
        assert_eq!(new.grep(&q, &grep).unwrap().0.files.len(), 2);
    }

    #[test]
    fn name_only_search_matches_the_full_engine() {
        let data = Temp::new();
        let home = Temp::new();
        std::fs::create_dir(home.0.join("docs")).unwrap();
        for name in ["readme.txt", "docs/readme.md", "docs/other.txt"] {
            std::fs::write(home.0.join(name), "needle\n").unwrap();
        }
        let engine = Engine::rebuild(opts(&data, &home), &[home.0.clone()]).unwrap();
        let fields = |hits: Vec<fsearch::Found>| hits.into_iter().map(|h| (h.path, h.kind, h.size, h.mtime, h.score)).collect::<Vec<_>>();
        for query in ["readme", "rdme", "ext:txt", "kind:dir", "docs readme", "readme !other", "mtime:<7d", "in:~/docs"] {
            let q = Query::parse(query, home.0.to_str().unwrap()).unwrap();
            assert_eq!(fields(Engine::search_saved(opts(&data, &home), &q).unwrap()), fields(engine.search(&q).unwrap()), "{query}");
        }
    }

    #[test]
    fn cli_accepts_native_roots_and_skips_content_for_name_queries() {
        use std::os::windows::ffi::OsStringExt;
        let home = Temp::new();
        let data = Temp::new();
        let root = home.0.join(std::ffi::OsString::from_wide(&[b'r' as u16, 0xd800]));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("readme.txt"), "needle\n").unwrap();
        let cmd = || {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_fsearch"));
            cmd.env("USERPROFILE", &home.0).env("FSEARCH_DATA_DIR", &data.0);
            cmd
        };
        let indexed = cmd().arg("index").arg(&root).output().unwrap();
        assert!(indexed.status.success(), "{}", String::from_utf8_lossy(&indexed.stderr));
        assert_eq!(Engine::saved_roots(&data.0).unwrap(), vec![root]);
        let before = cmd().args(["readme", "--json"]).output().unwrap();
        assert!(before.status.success());
        let mut expected: serde_json::Value = serde_json::from_slice(&before.stdout).unwrap();
        expected.as_object_mut().unwrap().remove("took_us");
        assert_eq!(expected["hits"].as_array().unwrap().len(), 1);
        let current = std::fs::read_to_string(data.0.join("current")).unwrap();
        std::fs::remove_dir_all(data.0.join(current).join("content")).unwrap();
        let after = cmd().args(["readme", "--json"]).output().unwrap();
        assert!(after.status.success(), "{}", String::from_utf8_lossy(&after.stderr));
        let mut actual: serde_json::Value = serde_json::from_slice(&after.stdout).unwrap();
        actual.as_object_mut().unwrap().remove("took_us");
        assert_eq!(actual, expected);
        assert!(Engine::start(opts(&data, &home)).is_err());
        for query in ["status", "grep:needle", "content:needle", "regex:needle", "sym:needle", "symbol:needle"] {
            let output = cmd().args([query, "--json"]).output().unwrap();
            assert!(!output.status.success(), "{query}");
        }
        let invalid = cmd().arg(std::ffi::OsString::from_wide(&[0xd800])).output().unwrap();
        assert!(!invalid.status.success());
        assert!(!String::from_utf8_lossy(&invalid.stderr).contains("panicked"));
    }

    #[test]
    fn scanner_preserves_surrogates_long_paths_hidden_flags_and_overlapping_roots() {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_HIDDEN, SetFileAttributesW};
        let root = Temp::new();
        let mut long = root.0.clone();
        for _ in 0..6 {
            long.push("long-directory-component-1234567890");
        }
        std::fs::create_dir_all(&long).unwrap();
        let name = std::ffi::OsString::from_wide(&[b'x' as u16, 0xd800, b'.' as u16, b't' as u16, b'x' as u16, b't' as u16]);
        let file = long.join(name);
        std::fs::write(&file, "surrogate needle\n").unwrap();
        let wide: Vec<_> = file.as_os_str().encode_wide().chain([0]).collect();
        assert_ne!(unsafe { SetFileAttributesW(wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) }, 0);
        let ls = walk::scan_roots(&[root.0.clone(), long], 2).unwrap();
        let idx = Index::build(ls, 0, 0, &paths::encode(&root.0));
        let key = paths::encode(&file);
        assert_eq!(paths::decode(&key), file);
        let i = idx.lookup(&key).unwrap() as usize;
        assert_ne!(idx.kind()[i] & walk::FLAG_HIDDEN, 0);
        let mut actual = Vec::new();
        idx.path(i, &mut actual);
        assert_eq!(actual, key);
        assert_eq!(content::verify(&Grep::new("needle", GrepMode::Literal).unwrap(), &[key], 10).files.len(), 1);
    }

    #[test]
    fn junctions_are_indexed_without_recursing() {
        let root = Temp::new();
        let outside = Temp::new();
        std::fs::write(outside.0.join("do-not-follow.txt"), "outside").unwrap();
        let link = root.0.join("junction");
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(paths::display_native(&link).as_ref())
            .arg(paths::display_native(&outside.0).as_ref())
            .status()
            .unwrap();
        assert!(status.success());
        let ls = walk::scan_roots(&[root.0.clone()], 2).unwrap();
        let idx = Index::build(ls, 0, 0, &paths::encode(&root.0));
        let i = idx.lookup(&paths::encode(&link)).unwrap() as usize;
        assert_eq!(idx.kind()[i] & 3, walk::KIND_LINK);
        assert!(idx.lookup(&paths::encode(&link.join("do-not-follow.txt"))).is_none());
        assert!(walk::scan_roots(&[link], 2).is_err());
    }

    #[test]
    fn cli_index_search_refresh_and_json_lines() {
        let home = Temp::new();
        let data = Temp::new();
        std::fs::write(home.0.join("readme.txt"), "a searchable needle\n").unwrap();
        let cmd = || {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_fsearch"));
            cmd.env("USERPROFILE", &home.0).env("FSEARCH_DATA_DIR", &data.0);
            cmd
        };
        let indexed = cmd().arg("index").arg(&home.0).output().unwrap();
        assert!(indexed.status.success(), "{}", String::from_utf8_lossy(&indexed.stderr));
        let found = cmd().args(["readme", "--json"]).output().unwrap();
        assert!(found.status.success());
        let json: serde_json::Value = serde_json::from_slice(&found.stdout).unwrap();
        assert_eq!(json["hits"].as_array().unwrap().len(), 1);
        let mut child = cmd().arg("stdio").stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        for request in [r#"{"op":"ping","id":1}"#, r#"{"op":"grep","pattern":"needle","id":2}"#, "not json"] {
            writeln!(input, "{request}").unwrap();
            let mut line = String::new();
            assert!(output.read_line(&mut line).unwrap() > 0);
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            if request == "not json" {
                assert_eq!(value["ok"], false);
            } else {
                assert_eq!(value["ok"], true);
                if value["id"] == 2 {
                    assert_eq!(value["files"].as_array().unwrap().len(), 1);
                }
            }
        }
        drop(input);
        assert!(child.wait().unwrap().success());
        std::fs::write(home.0.join("second.txt"), "another").unwrap();
        assert!(cmd().arg("index").status().unwrap().success());
        let output = cmd().args(["second", "--json"]).output().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["hits"].as_array().unwrap().len(), 1);
    }
}
