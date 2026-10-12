//! Paths as byte vectors. Unix keeps the OS bytes; Windows stores UTF-8 with `\`.

use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

#[inline]
pub fn path_from_bytes(b: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(std::ffi::OsStr::from_bytes(b))
    }
    #[cfg(windows)]
    {
        PathBuf::from(String::from_utf8_lossy(b).replace('/', "\\"))
    }
}

#[inline]
pub fn bytes_from_path(p: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        p.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        crate::pathwin::normalize(p.to_string_lossy().as_bytes())
    }
}

#[inline]
pub fn os_from_bytes(b: &[u8]) -> PathBuf {
    path_from_bytes(b)
}
