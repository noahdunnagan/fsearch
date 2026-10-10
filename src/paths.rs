//! Path helpers shared by the walker, the live index and the content index.

/// `trim_dir`, owned.
pub(crate) fn normalize(path: &[u8]) -> Vec<u8> {
    trim_dir(path).to_vec()
}

/// A folder path without trailing slashes (`/` stays `/`): "/h/" and "/h"
/// name the same folder.
pub fn trim_dir(p: &[u8]) -> &[u8] {
    let end = p.iter().rposition(|&b| b != b'/').map_or(p.len().min(1), |i| i + 1);
    &p[..end]
}

/// `dir` is `path` or a folder above it (not just a name prefix: `/a/b`
/// is not above `/a/bc`).
pub fn is_ancestor(dir: &[u8], path: &[u8]) -> bool {
    path.starts_with(dir) && (dir.ends_with(b"/") || path.len() == dir.len() || path[dir.len()] == b'/')
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
