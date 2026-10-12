//! Paths in the index use slash-separated bytes. Windows paths use WTF-8
//! so even unpaired UTF-16 surrogates round-trip without replacement.
//! The virtual root contains drive letters: `C:\\Users` is `/C:/Users`.
//! UNC paths use `/UNC/server/share`. Convert at filesystem boundaries.

use std::path::{Path, PathBuf};

pub fn encode(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        windows_key(&encode_wide(path.as_os_str().encode_wide()))
    }
}

pub fn decode(path: &[u8]) -> PathBuf {
    try_decode(path).expect("invalid WTF-8 in index path")
}

pub fn try_decode(path: &[u8]) -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(path)))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        // A malformed saved path must never alias a real filename.
        let native = windows_native(path);
        let wide = decode_wide(&native).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid WTF-8 path"))?;
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
    }
}

pub fn display(path: &[u8]) -> String {
    display_native(&decode(path)).into_owned()
}

pub fn display_native(path: &Path) -> std::borrow::Cow<'_, str> {
    let text = path.to_string_lossy();
    #[cfg(windows)]
    {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}").into();
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return rest.to_owned().into();
        }
    }
    text
}

/// Encode one filename without adding the virtual root.
#[cfg(windows)]
pub(crate) fn name(name: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    encode_wide(name.encode_wide())
}

#[cfg(any(windows, test))]
fn windows_key(path: &[u8]) -> Vec<u8> {
    let mut p: Vec<u8> = path.iter().map(|&b| if b == b'\\' { b'/' } else { b }).collect();
    if p.starts_with(b"//?/UNC/") {
        p = [b"/UNC/".as_slice(), &p[8..]].concat();
    } else if p.starts_with(b"//?/") {
        p.drain(..4);
    } else if p.starts_with(b"//") {
        p = [b"/UNC/".as_slice(), &p[2..]].concat();
    }
    if p.len() >= 2 && p[0].is_ascii_alphabetic() && p[1] == b':' {
        p[0] = p[0].to_ascii_uppercase();
        p.insert(0, b'/');
    }
    while p.len() > 1 && p.last() == Some(&b'/') {
        p.pop();
    }
    p
}

#[cfg(any(windows, test))]
fn windows_native(path: &[u8]) -> Vec<u8> {
    let mut p = if let Some(rest) = path.strip_prefix(b"/UNC/") {
        [b"\\\\?\\UNC\\".as_slice(), rest].concat()
    } else if path.len() >= 3 && path[0] == b'/' && path[1].is_ascii_alphabetic() && path[2] == b':' {
        let mut p = [b"\\\\?\\".as_slice(), &path[1..]].concat();
        if path.len() == 3 {
            p.push(b'/');
        }
        p
    } else {
        path.to_vec()
    };
    for b in &mut p {
        if *b == b'/' {
            *b = b'\\';
        }
    }
    p
}

#[cfg(any(windows, test))]
fn encode_wide(wide: impl IntoIterator<Item = u16>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for c in char::decode_utf16(wide) {
        match c {
            Ok(c) => bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
            Err(e) => {
                let s = e.unpaired_surrogate();
                bytes.extend_from_slice(&[(0xe0 | (s >> 12)) as u8, (0x80 | ((s >> 6) & 0x3f)) as u8, (0x80 | (s & 0x3f)) as u8]);
            }
        }
    }
    bytes
}

#[cfg(any(windows, test))]
fn decode_wide(mut bytes: &[u8]) -> Option<Vec<u16>> {
    let mut wide = Vec::new();
    while !bytes.is_empty() {
        // UTF-8 reserves these sequences for UTF-16's unpaired surrogates.
        if bytes.len() >= 3 && bytes[0] == 0xed && (0xa0..=0xbf).contains(&bytes[1]) && (0x80..=0xbf).contains(&bytes[2]) {
            let unit = ((bytes[0] as u16 & 0xf) << 12) | ((bytes[1] as u16 & 0x3f) << 6) | (bytes[2] as u16 & 0x3f);
            // A pair must use its canonical four-byte UTF-8 sequence.
            if unit >= 0xdc00 && wide.last().is_some_and(|u| (0xd800..=0xdbff).contains(u)) {
                return None;
            }
            wide.push(unit);
            bytes = &bytes[3..];
        } else {
            let n = match bytes[0] {
                0..=0x7f => 1,
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => return None,
            };
            wide.extend(std::str::from_utf8(bytes.get(..n)?).ok()?.encode_utf16());
            bytes = &bytes[n..];
        }
    }
    Some(wide)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drive_and_unc_paths() {
        for (native, key) in [
            (r"c:\Users\Ada\", "/C:/Users/Ada"),
            (r"C:\", "/C:"),
            (r"\\?\C:\資料\café", "/C:/資料/café"),
            (r"\\server\share\folder", "/UNC/server/share/folder"),
            (r"\\?\UNC\server\share\folder", "/UNC/server/share/folder"),
        ] {
            assert_eq!(windows_key(native.as_bytes()), key.as_bytes());
            assert_eq!(windows_key(&windows_native(key.as_bytes())), key.as_bytes());
        }
        assert_eq!(windows_native(b"/C:"), br"\\?\C:\");
    }

    #[test]
    fn filenames_round_trip_all_utf16_code_units() {
        for unit in 0..=u16::MAX {
            assert_eq!(decode_wide(&encode_wide([unit])), Some(vec![unit]));
        }
        let name: Vec<_> = "資料-😀-café.txt".encode_utf16().chain([0xd800, 0x61, 0xdc00]).collect();
        assert_eq!(decode_wide(&encode_wide(name.clone())), Some(name));
        assert!(decode_wide(&[0xf0, 0x80]).is_none());
        assert!(decode_wide(&[0xed, 0xa0, 0x80, 0xed, 0xb0, 0x80]).is_none());
    }
}
