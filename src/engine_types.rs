use std::path::PathBuf;

pub struct Options {
    /// Where the index lives. Windows stores immutable snapshot generations here.
    pub dir: PathBuf,
    pub home: String,
    /// Folders never to open during a scan. On macOS, `None` decides from Full Disk Access: without
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
    /// macOS Full Disk Access. Always false on Windows; ACLs still apply.
    pub full_disk_access: bool,
    /// Writes the live index files. Windows snapshot readers return false.
    pub owner: bool,
}
