//! Content reads enforce the filename policy on a stable directory walk.

use crate::content_policy;
use std::ffi::{CString, OsStr};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};

pub(crate) fn open_regular(path: &[u8]) -> Option<File> {
    if !content_policy::allows(path) {
        return None;
    }
    let requested = Path::new(OsStr::from_bytes(path));
    if !std::fs::symlink_metadata(requested).ok()?.is_file() {
        return None;
    }
    let resolved = std::fs::canonicalize(requested).ok()?;
    if !content_policy::allows(resolved.as_os_str().as_bytes()) {
        return None;
    }
    let file = open_without_links(&resolved)?;
    file.metadata().ok()?.is_file().then_some(file)
}

fn open_without_links(path: &Path) -> Option<File> {
    let mut directory = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open("/").ok()?;
    let mut components = path.components().skip(1).peekable();
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else { return None };
        let name = CString::new(name.as_bytes()).ok()?;
        let last = components.peek().is_none();
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | if last { libc::O_NONBLOCK } else { libc::O_DIRECTORY };
        // Each parent is held by descriptor. A later directory-link swap cannot
        // redirect the next open to a credential tree after the policy check.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return None;
        }
        // openat returned a new owned descriptor; File closes it on every exit.
        let opened = unsafe { File::from_raw_fd(descriptor) };
        if last {
            return Some(opened);
        }
        directory = opened;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::open_regular;
    use std::fs::{self, DirBuilder};
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{DirBuilderExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
                "fsearch-content-reads-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ordinary_text_is_read_but_known_credentials_are_not_opened() {
        // Given one ordinary file and three existing credential files.
        let fixture = Fixture::new();
        let public = fixture.0.join("notes.txt");
        fs::write(&public, b"expected public text").unwrap();
        let private_paths = [fixture.0.join(".ENV.LOCAL"), fixture.0.join("server.PEM"), fixture.0.join("credentials.json")];
        for path in &private_paths {
            fs::write(path, b"synthetic private text").unwrap();
            assert!(path.is_file());
        }

        // When the same production read boundary opens those paths.
        let mut text = String::new();
        open_regular(public.as_os_str().as_bytes()).unwrap().read_to_string(&mut text).unwrap();
        let opened: Vec<bool> = private_paths.iter().map(|path| open_regular(path.as_os_str().as_bytes()).is_some()).collect();

        // Then only the ordinary file's exact content is readable.
        assert_eq!(text, "expected public text");
        assert_eq!(opened, vec![false, false, false]);
    }

    #[test]
    fn a_directory_alias_cannot_open_a_file_in_a_credential_tree() {
        // Given a public-looking alias to a real credential directory.
        let fixture = Fixture::new();
        let private = fixture.0.join(".SSH");
        fs::create_dir(&private).unwrap();
        fs::write(private.join("notes.txt"), b"synthetic key marker").unwrap();
        let alias = fixture.0.join("public_alias");
        symlink(&private, &alias).unwrap();
        let requested = alias.join("notes.txt");
        assert!(requested.is_file());

        // When the production boundary resolves and opens the alias path.
        let file = open_regular(requested.as_os_str().as_bytes());

        // Then no content file is returned.
        assert!(file.is_none(), "a directory alias exposed private text");
    }

    #[test]
    fn a_file_link_and_a_directory_are_not_content_files() {
        // Given a real text file, its symbolic link, and a directory.
        let fixture = Fixture::new();
        let real = fixture.0.join("real.txt");
        fs::write(&real, b"public text").unwrap();
        let alias = fixture.0.join("alias.txt");
        symlink(&real, &alias).unwrap();
        assert!(alias.is_file());

        // When the production boundary is called for the link and directory.
        let opened = [open_regular(alias.as_os_str().as_bytes()).is_some(), open_regular(fixture.0.as_os_str().as_bytes()).is_some()];

        // Then neither unsupported file type is opened.
        assert_eq!(opened, [false, false]);
    }
}
