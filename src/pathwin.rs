//! UTF-8 path helpers using `\` as the stored separator.

pub const SEP: u8 = b'\\';

#[inline]
pub fn is_sep(b: u8) -> bool {
    b == b'\\' || b == b'/'
}

pub fn normalize(path: &[u8]) -> Vec<u8> {
    let mut p: Vec<u8> = path.iter().map(|&b| if b == b'/' { SEP } else { b }).collect();
    while p.len() > 3 && p.last() == Some(&SEP) {
        p.pop();
    }
    if p.len() >= 4 && p.starts_with(br"\\?\") {
        p.drain(..4);
    }
    if p.len() >= 3 && p[1] == b':' {
        p[0] = p[0].to_ascii_uppercase();
    }
    p
}

pub fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    if dir.is_empty() {
        return name.to_vec();
    }
    let mut p = Vec::with_capacity(dir.len() + 1 + name.len());
    p.extend_from_slice(dir);
    if !(dir.len() == 2 && dir[1] == b':') && p.last() != Some(&SEP) {
        p.push(SEP);
    }
    if dir.len() == 2 && dir[1] == b':' {
        p.push(SEP);
    }
    p.extend_from_slice(name);
    p
}

/// `C:\Users\foo` → `["C:", "Users", "foo"]`
pub fn split(path: &[u8]) -> Vec<&[u8]> {
    let p = path;
    let mut out = Vec::new();
    if p.len() >= 2 && p[1] == b':' {
        out.push(&p[..2]);
        let rest = if p.len() > 2 && is_sep(p[2]) { &p[3..] } else { &p[2..] };
        out.extend(rest.split(|&b| is_sep(b)).filter(|c| !c.is_empty()));
    } else {
        out.extend(p.split(|&b| is_sep(b)).filter(|c| !c.is_empty()));
    }
    out
}

pub fn parent(path: &[u8]) -> &[u8] {
    if let Some(i) = path.iter().rposition(|&b| is_sep(b)) {
        if i == 2 && path.get(1) == Some(&b':') {
            return &path[..2];
        }
        return &path[..i];
    }
    b""
}

pub fn name(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| is_sep(b)) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

pub fn to_wide(path: &[u8]) -> Vec<u16> {
    String::from_utf8_lossy(path).encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn long_wide(path: &[u8]) -> Vec<u16> {
    let n = normalize(path);
    if n.starts_with(br"\\") {
        return to_wide(&n);
    }
    let mut s = Vec::with_capacity(4 + n.len());
    s.extend_from_slice(br"\\?\");
    s.extend_from_slice(&n);
    to_wide(&s)
}

pub fn from_wide(w: &[u16]) -> Vec<u8> {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end]).into_bytes()
}

pub fn strip_nt_prefix(mut p: Vec<u8>) -> Vec<u8> {
    if p.starts_with(br"\\?\UNC\") {
        p.drain(..7);
        p.insert(0, b'\\');
        return normalize(&p);
    }
    if p.starts_with(br"\\?\") {
        p.drain(..4);
    }
    normalize(&p)
}
