//! C-compatible FFI bindings for `fsearch`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::ptr;
use std::time::Duration;

use crate::content::Grep;
use crate::engine::{Engine, Options, Status};
use crate::query::{GrepMode, Query};

/// Opaque wrapper around `Engine`.
pub struct FSearchEngine {
    inner: Engine,
}

/// Status struct exposed to C/Swift.
#[repr(C)]
pub struct FSearchStatus {
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
    pub owner: bool,
}

/// One name search result hit.
#[repr(C)]
pub struct FSearchHit {
    /// UTF-8 null-terminated path. Must NOT be freed individually.
    pub path: *const c_char,
    pub kind: u8,
    pub size: u64,
    pub mtime: u32,
    pub score: i32,
}

/// Array of name search hits.
pub struct FSearchResults {
    hits: Vec<FSearchHit>,
    _paths: Vec<CString>,
}

/// Single line match within a file.
#[repr(C)]
pub struct FSearchGrepLine {
    pub line_number: usize,
    /// UTF-8 null-terminated match line. Must NOT be freed individually.
    pub text: *const c_char,
}

/// File containing grep matches.
#[repr(C)]
pub struct FSearchGrepFile {
    /// UTF-8 null-terminated file path.
    pub path: *const c_char,
    pub lines: *const FSearchGrepLine,
    pub lines_len: usize,
}

/// Complete grep search result.
pub struct FSearchGrepResult {
    files: Vec<FSearchGrepFile>,
    _lines: Vec<Vec<FSearchGrepLine>>,
    _paths: Vec<CString>,
    _texts: Vec<Vec<CString>>,
    candidates: usize,
    read: usize,
    complete: bool,
}

unsafe fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() { None } else { unsafe { CStr::from_ptr(p).to_str().ok() } }
}

/// Start an engine instance.
///
/// `dir`: Directory for index data. Pass NULL to use default (`~/Library/Application Support/FSearch`).
/// `home`: Home directory. Pass NULL to use `$HOME` environment variable.
/// `err_out`: Optional pointer to receive error string if initialization fails.
///
/// Returns NULL on failure. Caller owns the returned engine and must call `fsearch_engine_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_engine_start(dir: *const c_char, home: *const c_char, err_out: *mut *mut c_char) -> *mut FSearchEngine {
    let home_str = match unsafe { cstr_to_str(home) } {
        Some(s) => s.to_string(),
        None => match std::env::var("HOME") {
            Ok(h) => h,
            Err(e) => {
                if !err_out.is_null() {
                    unsafe { *err_out = CString::new(format!("Missing HOME: {e}")).unwrap().into_raw() };
                }
                return ptr::null_mut();
            }
        },
    };

    let dir_buf = match unsafe { cstr_to_str(dir) } {
        Some(d) => PathBuf::from(d),
        None => crate::engine::default_dir(&home_str),
    };

    let opts = Options { dir: dir_buf, home: home_str, skip: None };

    match Engine::start(opts) {
        Ok(engine) => Box::into_raw(Box::new(FSearchEngine { inner: engine })),
        Err(e) => {
            if !err_out.is_null() {
                unsafe { *err_out = CString::new(e).unwrap().into_raw() };
            }
            ptr::null_mut()
        }
    }
}

/// Frees an engine instance.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_engine_free(engine: *mut FSearchEngine) {
    if !engine.is_null() {
        drop(unsafe { Box::from_raw(engine) });
    }
}

/// Keep cores clocked up for `duration_ms` milliseconds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_engine_keep_warm(engine: *mut FSearchEngine, duration_ms: u64) {
    if let Some(e) = unsafe { engine.as_ref() } {
        e.inner.keep_warm(Duration::from_millis(duration_ms));
    }
}

/// Fetch engine status.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_engine_status(engine: *const FSearchEngine, out_status: *mut FSearchStatus) -> bool {
    let Some(e) = (unsafe { engine.as_ref() }) else { return false };
    if out_status.is_null() {
        return false;
    }

    let s: Status = e.inner.status();
    unsafe {
        *out_status = FSearchStatus {
            ready: s.ready,
            entries: s.entries,
            dirs: s.dirs,
            overlay: s.overlay,
            removed: s.removed,
            event_id: s.event_id,
            index_bytes: s.index_bytes,
            content_docs: s.content_docs,
            content_segments: s.content_segments,
            content_bytes: s.content_bytes,
            content_pending: s.content_pending,
            full_disk_access: s.full_disk_access,
            owner: s.owner,
        };
    }
    true
}

/// Returns a description of initial index building progress, or NULL. Caller must free with `fsearch_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_engine_indexing_status(engine: *const FSearchEngine) -> *mut c_char {
    let Some(e) = (unsafe { engine.as_ref() }) else { return ptr::null_mut() };
    let msg = e.inner.indexing();
    CString::new(msg).unwrap().into_raw()
}

/// Search files by name/filters.
///
/// `query_str`: The query string, e.g. "main ext:rs" or "photo in:~/Pictures".
/// `err_out`: Optional error string pointer.
///
/// Returns pointer to `FSearchResults`, or NULL on error. Free with `fsearch_results_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_search(engine: *const FSearchEngine, query_str: *const c_char, err_out: *mut *mut c_char) -> *mut FSearchResults {
    let Some(e) = (unsafe { engine.as_ref() }) else {
        if !err_out.is_null() {
            unsafe { *err_out = CString::new("Null engine").unwrap().into_raw() };
        }
        return ptr::null_mut();
    };

    let q_str = match unsafe { cstr_to_str(query_str) } {
        Some(s) => s,
        None => {
            if !err_out.is_null() {
                unsafe { *err_out = CString::new("Invalid UTF-8 query string").unwrap().into_raw() };
            }
            return ptr::null_mut();
        }
    };

    let query = match Query::parse(q_str, e.inner.home()) {
        Ok(q) => q,
        Err(err) => {
            if !err_out.is_null() {
                unsafe { *err_out = CString::new(err).unwrap().into_raw() };
            }
            return ptr::null_mut();
        }
    };

    match e.inner.search(&query) {
        Ok(found_vec) => {
            let mut c_paths = Vec::with_capacity(found_vec.len());
            let mut hits = Vec::with_capacity(found_vec.len());

            for f in found_vec {
                use std::os::unix::ffi::OsStrExt;
                let c_path = CString::new(f.path.as_os_str().as_bytes()).unwrap_or_default();
                hits.push(FSearchHit { path: c_path.as_ptr(), kind: f.kind, size: f.size, mtime: f.mtime, score: f.score });
                c_paths.push(c_path);
            }

            Box::into_raw(Box::new(FSearchResults { hits, _paths: c_paths }))
        }
        Err(err) => {
            if !err_out.is_null() {
                unsafe { *err_out = CString::new(err).unwrap().into_raw() };
            }
            ptr::null_mut()
        }
    }
}

/// Get length of search results array.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_results_len(results: *const FSearchResults) -> usize {
    (unsafe { results.as_ref() }).map_or(0, |r| r.hits.len())
}

/// Get pointer to contiguous array of `FSearchHit`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_results_data(results: *const FSearchResults) -> *const FSearchHit {
    (unsafe { results.as_ref() }).map_or(ptr::null(), |r| r.hits.as_ptr())
}

/// Free search results.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_results_free(results: *mut FSearchResults) {
    if !results.is_null() {
        drop(unsafe { Box::from_raw(results) });
    }
}

/// Mode for grep search:
/// 0 = Literal
/// 1 = Regex
/// 2 = Symbol
#[repr(C)]
pub enum FSearchGrepMode {
    Literal = 0,
    Regex = 1,
    Symbol = 2,
}

/// Search file contents.
///
/// `pattern`: String or regex to search.
/// `mode`: Literal, Regex, or Symbol.
/// `filter_query`: Optional query string to restrict files (e.g. "ext:swift in:~/Developer"), or NULL.
/// `max_matches_per_file`: Maximum number of lines per file (0 defaults to 5).
/// `budget_ms`: Search time budget in ms (0 defaults to 250ms).
/// `err_out`: Optional error string pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_grep(
    engine: *const FSearchEngine,
    pattern: *const c_char,
    mode: FSearchGrepMode,
    filter_query: *const c_char,
    max_matches_per_file: usize,
    budget_ms: u64,
    err_out: *mut *mut c_char,
) -> *mut FSearchGrepResult {
    let Some(e) = (unsafe { engine.as_ref() }) else {
        if !err_out.is_null() {
            unsafe { *err_out = CString::new("Null engine").unwrap().into_raw() };
        }
        return ptr::null_mut();
    };

    let pat = match unsafe { cstr_to_str(pattern) } {
        Some(s) => s,
        None => {
            if !err_out.is_null() {
                unsafe { *err_out = CString::new("Invalid pattern UTF-8").unwrap().into_raw() };
            }
            return ptr::null_mut();
        }
    };

    let grep_mode = match mode {
        FSearchGrepMode::Literal => GrepMode::Literal,
        FSearchGrepMode::Regex => GrepMode::Regex,
        FSearchGrepMode::Symbol => GrepMode::Symbol,
    };

    let mut grep = match Grep::new(pat, grep_mode) {
        Ok(g) => g,
        Err(err) => {
            if !err_out.is_null() {
                unsafe { *err_out = CString::new(err).unwrap().into_raw() };
            }
            return ptr::null_mut();
        }
    };

    if max_matches_per_file > 0 {
        grep.max_per_file = max_matches_per_file;
    }
    if budget_ms > 0 {
        grep.budget = Some(Duration::from_millis(budget_ms));
    }

    let f_str = (unsafe { cstr_to_str(filter_query) }).unwrap_or("");
    let query = match Query::parse(f_str, e.inner.home()) {
        Ok(q) => q,
        Err(err) => {
            if !err_out.is_null() {
                unsafe { *err_out = CString::new(err).unwrap().into_raw() };
            }
            return ptr::null_mut();
        }
    };

    match e.inner.grep(&query, &grep) {
        Ok((res, _indexed)) => {
            let mut c_paths = Vec::with_capacity(res.files.len());
            let mut c_texts = Vec::with_capacity(res.files.len());
            let mut line_structs = Vec::with_capacity(res.files.len());
            let mut file_structs = Vec::with_capacity(res.files.len());

            for f in &res.files {
                let p = CString::new(f.path.clone()).unwrap_or_default();
                let mut text_cstrings = Vec::with_capacity(f.lines.len());
                let mut lines = Vec::with_capacity(f.lines.len());

                for (num, text) in &f.lines {
                    let t = CString::new(text.clone()).unwrap_or_default();
                    lines.push(FSearchGrepLine { line_number: *num, text: t.as_ptr() });
                    text_cstrings.push(t);
                }

                file_structs.push(FSearchGrepFile { path: p.as_ptr(), lines: lines.as_ptr(), lines_len: lines.len() });

                c_paths.push(p);
                c_texts.push(text_cstrings);
                line_structs.push(lines);
            }

            Box::into_raw(Box::new(FSearchGrepResult {
                files: file_structs,
                _lines: line_structs,
                _paths: c_paths,
                _texts: c_texts,
                candidates: res.candidates,
                read: res.read,
                complete: res.complete,
            }))
        }
        Err(err) => {
            if !err_out.is_null() {
                unsafe { *err_out = CString::new(err).unwrap().into_raw() };
            }
            ptr::null_mut()
        }
    }
}

/// Number of matching files.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_grep_files_len(res: *const FSearchGrepResult) -> usize {
    (unsafe { res.as_ref() }).map_or(0, |r| r.files.len())
}

/// Pointer to array of `FSearchGrepFile`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_grep_files_data(res: *const FSearchGrepResult) -> *const FSearchGrepFile {
    (unsafe { res.as_ref() }).map_or(ptr::null(), |r| r.files.as_ptr())
}

/// Grep candidate count.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_grep_candidates(res: *const FSearchGrepResult) -> usize {
    (unsafe { res.as_ref() }).map_or(0, |r| r.candidates)
}

/// Grep files read count.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_grep_read(res: *const FSearchGrepResult) -> usize {
    (unsafe { res.as_ref() }).map_or(0, |r| r.read)
}

/// True if search completed before time budget ran out.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_grep_is_complete(res: *const FSearchGrepResult) -> bool {
    (unsafe { res.as_ref() }).map_or(false, |r| r.complete)
}

/// Free grep result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_grep_result_free(res: *mut FSearchGrepResult) {
    if !res.is_null() {
        drop(unsafe { Box::from_raw(res) });
    }
}

/// Free a C string allocated by fsearch.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fsearch_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}
