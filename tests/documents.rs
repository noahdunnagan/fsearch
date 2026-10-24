//! Authored fixtures exercise the same readers used by indexed and scan grep.
use fsearch::{
    Grep,
    content::{self, Content},
    document,
    index::Index,
    live::Live,
    query::{GrepMode, Query},
    walk,
};
use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
};

#[test]
fn documents_index_scan_cache_and_lifecycle() {
    let root = std::env::temp_dir().join(format!("fsearch-documents-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(root.clone());
    let home = root.join("home");
    let state = root.join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state).unwrap();
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/documents");
    let mut paths = Vec::new();
    for ext in ["doc", "docx", "pdf", "xls", "xlsx"] {
        let path = home.join(format!("sample.{ext}"));
        fs::copy(fixtures.join(format!("sample.{ext}")), &path).unwrap();
        paths.push(path.as_os_str().as_bytes().to_vec());
    }
    let bytes = home.as_os_str().as_bytes();
    let snapshot = || {
        // Index paths are rooted at /; graft this isolated scan below its parents.
        let parts: Vec<_> = bytes.split(|&b| b == b'/').filter(|p| !p.is_empty()).collect();
        let n = parts.len() as u32;
        let mut listings = walk::scan(bytes, 2);
        for listing in &mut listings {
            listing.id += n;
            for e in &mut listing.ents {
                if e.child != walk::NONE {
                    e.child += n;
                }
            }
        }
        for (id, name) in parts.into_iter().enumerate() {
            listings.push(walk::Listing {
                id: id as u32,
                names: name.to_vec(),
                ents: vec![walk::RawEnt { name_off: 0, name_len: name.len() as u16, kind: walk::KIND_DIR, size: 0, mtime: 0, child: id as u32 + 1 }],
            });
        }
        Live::new(Index::build(listings, 0, 0, bytes))
    };
    assert!(!document::enabled());
    assert_eq!(content::wanted(&snapshot(), bytes, bytes, true).len(), 0);
    document::set_enabled(&state, true).unwrap();
    assert_eq!(fs::read(state.join("document-indexing")).unwrap(), b"1\n");
    assert_eq!(content::wanted(&snapshot(), bytes, bytes, true).len(), 5);
    let mut index = Content::open(state.join("content"));
    let sync = |index: &mut Content| {
        let docs = index.diff(content::wanted_now(&snapshot(), bytes, &[(bytes.to_vec(), true)]));
        if !docs.is_empty() {
            let id = index.alloc_id();
            index.push(content::build_segment(&index.dir, id, &docs, 0..docs.len()).unwrap());
        }
    };
    sync(&mut index);
    let query = Query::parse("", home.to_str().unwrap()).unwrap();
    let grep = |needle: &str| {
        let mut g = Grep::new(needle, GrepMode::Literal).unwrap();
        g.budget = None;
        g
    };
    for needle in ["秦前坤", "document_needle_42"] {
        let g = grep(needle);
        assert_eq!(content::verify(&g, &paths, 100).files.len(), 5, "scan: {needle}");
        assert_eq!(index.search(&g, &query).files.len(), 5, "index: {needle}");
    }
    assert_eq!(index.search(&grep("table_needle_73"), &query).files.len(), 3);
    // Plain-text extraction caches are private and reused on subsequent reads.
    let cache = state.join("document-text-v1");
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 5);
    assert_eq!(fs::metadata(&cache).unwrap().permissions().mode() & 0o777, 0o700);
    for entry in fs::read_dir(&cache).unwrap() {
        assert_eq!(entry.unwrap().metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(content::scan_paths(&snapshot(), query.clone_for_scan()).len(), 5);
    // A same-size rewrite with a restored mtime must invalidate cached text.
    let doc = home.join("sample.doc");
    let old_meta = fs::metadata(&doc).unwrap();
    let mut data = fs::read(&doc).unwrap();
    let before: Vec<u8> = "秦前坤".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let after: Vec<u8> = "陈小明".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let offset = data.windows(before.len()).position(|w| w == before).expect("DOC fixture contains UTF-16 text");
    data[offset..offset + after.len()].copy_from_slice(&after);
    fs::write(&doc, data).unwrap();
    fs::File::options().write(true).open(&doc).unwrap().set_times(fs::FileTimes::new().set_modified(old_meta.modified().unwrap())).unwrap();
    let p = doc.as_os_str().as_bytes();
    let text = document::read(p, content::open_regular(p).unwrap()).unwrap();
    assert!(String::from_utf8(text).unwrap().contains("陈小明"));
    assert!(content::grep_file(&grep("秦前坤"), p).files.is_empty());
    sync(&mut index);
    assert_eq!(index.search(&grep("陈小明"), &query).files.len(), 1);
    fs::rename(home.join("sample.xlsx"), home.join("renamed.xlsx")).unwrap();
    fs::remove_file(home.join("sample.xls")).unwrap();
    sync(&mut index);
    let result = index.search(&grep("document_needle_42"), &query);
    assert_eq!(result.files.len(), 4);
    assert!(result.files.iter().any(|f| f.path.ends_with(b"renamed.xlsx")));
    for (name, source) in [("corrupt.pdf", None), ("scan.pdf", Some("image-only.pdf"))] {
        let path = home.join(name);
        if let Some(source) = source {
            fs::copy(fixtures.join(source), &path).unwrap();
        } else {
            fs::write(&path, b"not a PDF").unwrap();
        }
        assert!(content::grep_file(&grep("document_needle_42"), path.as_os_str().as_bytes()).files.is_empty());
    }
    document::set_enabled(&state, false).unwrap();
    assert!(content::verify(&grep("document_needle_42"), &paths, 100).files.is_empty());
    assert!(index.search(&grep("document_needle_42"), &query).files.is_empty());
    sync(&mut index);
    assert_eq!(index.docs(), 0);
}
