//! Private on-disk state. Other users must not read or replace search data.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

fn denied(path: &Path, reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("{}: {reason}", path.display()))
}

// Native macOS ACL values from <sys/acl.h>. Changing Unix mode bits does
// not remove these extra grants.
const ACL_TYPE_EXTENDED: i32 = 0x100;
const ACL_ALLOW: i32 = 1;
const ACL_MUTATION: u64 = (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 12) | (1 << 13);

unsafe extern "C" {
    fn acl_init(count: i32) -> *mut libc::c_void;
    fn acl_free(acl: *mut libc::c_void) -> i32;
    fn acl_get_fd_np(fd: i32, kind: i32) -> *mut libc::c_void;
    fn acl_set_fd_np(fd: i32, acl: *mut libc::c_void, kind: i32) -> i32;
    fn acl_get_entry(acl: *mut libc::c_void, index: i32, entry: *mut *mut libc::c_void) -> i32;
    fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut i32) -> i32;
    fn acl_get_permset_mask_np(entry: *mut libc::c_void, permissions: *mut u64) -> i32;
}

struct AccessList(*mut libc::c_void);

impl Drop for AccessList {
    fn drop(&mut self) {
        unsafe { acl_free(self.0) };
    }
}

fn clear_access_list(file: &File) -> io::Result<()> {
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    let acl = AccessList(acl);
    if unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn has_mutation_acl(file: &File) -> io::Result<bool> {
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        // The descriptor is already open. ENOENT/ENOATTR here means that
        // this existing directory has no extended ACL.
        return if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOATTR)) { Ok(false) } else { Err(error) };
    }
    let acl = AccessList(acl);
    let mut index = 0; // ACL_FIRST_ENTRY; ACL_NEXT_ENTRY is -1.
    loop {
        let mut entry = std::ptr::null_mut();
        if unsafe { acl_get_entry(acl.0, index, &mut entry) } != 0 {
            let error = io::Error::last_os_error();
            // A retrieved ACL is valid; EINVAL here means no next entry.
            return if error.raw_os_error() == Some(libc::EINVAL) { Ok(false) } else { Err(error) };
        }
        let mut tag = 0;
        let mut permissions = 0;
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Reject mutation grants to any identity. This conservative parent
        // rule needs no directory-service lookup or group membership guess.
        if tag == ACL_ALLOW && permissions & ACL_MUTATION != 0 {
            return Ok(true);
        }
        index = -1;
    }
}

/// Create a private state directory without following symbolic links.
/// Ancestors may belong to root or this user, but cannot let another user
/// replace a path component. The root-owned sticky temporary directory is
/// the only shared-directory exception.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "state directory path cannot be empty"));
    }
    let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    let mut current = PathBuf::new();
    let components: Vec<_> = absolute.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir | Component::Normal(_) => current.push(component.as_os_str()),
            Component::CurDir => continue,
            _ => return Err(denied(path, "state path cannot contain a parent component")),
        }
        if !current.exists() {
            match DirBuilder::new().mode(0o700).create(&current) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        let directory = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&current)?;
        let metadata = directory.metadata()?;
        let uid = unsafe { libc::geteuid() };
        let leaf = index + 1 == components.len();
        if leaf {
            if metadata.uid() != uid {
                return Err(denied(&current, "state directory belongs to another user"));
            }
            directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
            clear_access_list(&directory)?;
        } else {
            let trusted_temp = metadata.uid() == 0 && metadata.mode() & u32::from(libc::S_ISVTX) != 0;
            if (metadata.uid() != uid && metadata.uid() != 0) || (metadata.mode() & 0o022 != 0 && !trusted_temp) {
                return Err(denied(&current, "state directory has an unsafe parent"));
            }
            if has_mutation_acl(&directory)? {
                return Err(denied(&current, "state directory parent has ACL mutation grants"));
            }
        }
    }
    Ok(())
}

fn open_private(path: &Path, append: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .append(append)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1 {
        return Err(denied(path, "state file must be a regular file owned by this user with one link"));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    clear_access_list(&file)?;
    Ok(file)
}

/// Open a private lock without truncating another process's lock file.
pub fn open_private_file(path: &Path) -> io::Result<File> {
    open_private(path, false)
}

/// Append to the private daemon log.
pub fn open_private_log(path: &Path) -> io::Result<File> {
    open_private(path, true)
}

/// Validate a state file before replacing its contents.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = open_private_file(path)?;
    file.set_len(0)?;
    file.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!(
                "fsearch-private-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            DirBuilder::new().mode(0o700).create(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn state_directories_are_private() {
        // Given an empty fixture directory and a state directory with broad permissions.
        let fixture = Fixture::new();
        let state = fixture.0.join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o755);

        // When the state directory is made private.
        ensure_private_dir(&state).unwrap();

        // Then other users cannot access the directory.
        assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn new_state_files_are_private() {
        // Given a private fixture directory with no lock file.
        let fixture = Fixture::new();
        let path = fixture.0.join("lock");
        assert!(!path.exists());

        // When a new state lock is opened.
        let lock = open_private_file(&path).unwrap();

        // Then only this user can read and write the file.
        assert_eq!(lock.metadata().unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn symlinked_state_paths_are_rejected() {
        // Given a symbolic link to a fixture-owned directory.
        let fixture = Fixture::new();
        let real = fixture.0.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = fixture.0.join("link");
        symlink(&real, &link).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());

        // When a state directory is requested through the link.
        let result = ensure_private_dir(&link.join("state"));

        // Then the link is not followed and no state directory is created.
        assert!(result.is_err());
        assert!(!real.join("state").exists(), "unsafe path created state behind a symbolic link");
    }

    #[test]
    fn linked_state_files_are_rejected_without_changing_the_target() {
        // Given an existing fixture file with a second hard link.
        let fixture = Fixture::new();
        let target = fixture.0.join("target");
        std::fs::write(&target, b"keep this content").unwrap();
        let link = fixture.0.join("lock");
        std::fs::hard_link(&target, &link).unwrap();
        assert_eq!(std::fs::metadata(&target).unwrap().nlink(), 2);

        // When the linked path is opened as a private state file.
        let result = open_private_file(&link);

        // Then opening fails and the target content stays intact.
        assert!(result.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep this content");
    }

    #[test]
    fn symlinked_state_files_are_rejected_without_changing_the_target() {
        // Given a symbolic link to an existing fixture file.
        let fixture = Fixture::new();
        let target = fixture.0.join("target");
        std::fs::write(&target, b"keep this content").unwrap();
        let link = fixture.0.join("lock");
        symlink(&target, &link).unwrap();
        assert!(std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());

        // When the link is opened as a private state file.
        let result = open_private_file(&link);

        // Then opening fails and the target content stays intact.
        assert!(result.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep this content");
    }

    #[test]
    fn a_parent_that_other_users_can_change_is_rejected() {
        // Given a writable parent directory in a private fixture.
        let fixture = Fixture::new();
        let unsafe_parent = fixture.0.join("shared");
        std::fs::create_dir(&unsafe_parent).unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let state = unsafe_parent.join("state");
        assert!(!state.exists());

        // When private state creation is requested below the writable parent.
        let result = ensure_private_dir(&state);

        // Then the unsafe ancestor is rejected before any state is created.
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(!state.exists(), "state was created under an unsafe parent");
    }

    fn add_acl(path: &Path, entry: &str) {
        let status = std::process::Command::new("chmod").args(["+a", entry]).arg(path).status().unwrap();
        assert!(status.success(), "could not set fixture ACL");
    }

    fn acl_entries(path: &Path) -> usize {
        let output = std::process::Command::new("ls").arg("-lde").arg(path).output().unwrap();
        assert!(output.status.success(), "could not inspect fixture ACL");
        String::from_utf8(output.stdout).unwrap().lines().count() - 1
    }

    #[test]
    fn private_state_clears_extended_access_grants() {
        // Given a mode-private directory with an ACL that grants access to everyone.
        let fixture = Fixture::new();
        let state = fixture.0.join("state");
        DirBuilder::new().mode(0o700).create(&state).unwrap();
        add_acl(&state, "everyone allow read,write,execute,delete,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit");
        assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o700);
        assert_eq!(acl_entries(&state), 1);

        // When the directory is made private for search state.
        ensure_private_dir(&state).unwrap();

        // Then no extended grant can override the private Unix mode.
        assert_eq!(acl_entries(&state), 0);
        assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn private_files_clear_extended_access_grants() {
        // Given a mode-private file with an ACL that grants read and write access to everyone.
        let fixture = Fixture::new();
        let file = fixture.0.join("lock");
        std::fs::write(&file, b"private state").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        add_acl(&file, "everyone allow read,write");
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        assert_eq!(acl_entries(&file), 1);

        // When the file is opened as private search state.
        let opened = open_private_file(&file).unwrap();

        // Then the file has no extended grants and keeps its contents.
        assert_eq!(acl_entries(&file), 0);
        assert_eq!(opened.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&file).unwrap(), b"private state");
    }

    #[test]
    fn a_parent_with_acl_mutation_grants_is_rejected() {
        // Given a mode-safe parent whose ACL allows other users to replace child paths.
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        DirBuilder::new().mode(0o700).create(&parent).unwrap();
        add_acl(&parent, "everyone allow add_file,add_subdirectory,delete_child");
        let state = parent.join("state");
        assert!(!state.exists());
        assert_eq!(acl_entries(&parent), 1);

        // When state creation is requested through this parent.
        let result = ensure_private_dir(&state);

        // Then the ACL is rejected before any state directory is created.
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(!state.exists(), "unsafe ancestor ACL permitted state creation");
    }

    #[test]
    fn a_parent_with_a_default_delete_denial_remains_usable() {
        // Given a safe parent with the default macOS delete-denial ACL.
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        DirBuilder::new().mode(0o700).create(&parent).unwrap();
        add_acl(&parent, "everyone deny delete");
        assert_eq!(acl_entries(&parent), 1);
        let state = parent.join("state");

        // When a private state directory is created through the safe parent.
        ensure_private_dir(&state).unwrap();

        // Then state is private and the ancestor denial remains intact.
        assert_eq!(std::fs::metadata(&state).unwrap().mode() & 0o777, 0o700);
        assert_eq!(acl_entries(&state), 0);
        assert_eq!(acl_entries(&parent), 1);
    }
}
