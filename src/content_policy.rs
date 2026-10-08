//! File-name rules for content reads. Name search does not use this policy.
//!
//! These rules exclude common credential stores. They cannot identify secrets
//! saved under other names. Callers must also check the resolved path and open
//! without following directory symlinks before they read file contents.

const CREDENTIAL_DIRS: &[&[u8]] = &[b".ssh", b".aws", b".gnupg"];
const CREDENTIAL_NAMES: &[&[u8]] =
    &[b".netrc", b".npmrc", b".pypirc", b".envrc", b".git-credentials", b"credentials.json", b"id_rsa", b"id_dsa", b"id_ecdsa", b"id_ed25519"];
const KEY_EXTENSIONS: &[&[u8]] = &[b"pem", b"key", b"p12", b"pfx"];

/// Whether content search may read this Unix path. Case-insensitive comparisons
/// also cover the default case-insensitive macOS file system.
pub(crate) fn allows(path: &[u8]) -> bool {
    if path.split(|&b| b == b'/').any(|part| CREDENTIAL_DIRS.iter().any(|name| part.eq_ignore_ascii_case(name))) {
        return false;
    }
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    if name.eq_ignore_ascii_case(b".env") || name.get(..5).is_some_and(|prefix| prefix.eq_ignore_ascii_case(b".env.")) {
        // A sample-file name does not prove that its values are safe to read.
        return false;
    }
    if CREDENTIAL_NAMES.iter().any(|blocked| name.eq_ignore_ascii_case(blocked)) || is_git_credential_store(path) {
        return false;
    }
    let extension = name.rsplit(|&b| b == b'.').next().unwrap_or(name);
    !name.contains(&b'.') || !KEY_EXTENSIONS.iter().any(|blocked| extension.eq_ignore_ascii_case(blocked))
}

fn is_git_credential_store(path: &[u8]) -> bool {
    const STORE: &[u8] = b".config/git/credentials";
    let Some(start) = path.len().checked_sub(STORE.len()) else { return false };
    path[start..].eq_ignore_ascii_case(STORE) && (start == 0 || path[start - 1] == b'/')
}

#[cfg(test)]
mod tests {
    use super::allows;

    #[test]
    fn credential_file_names_are_excluded() {
        // Given common credential-file paths, including sample-file names.
        let paths: &[&[u8]] = &[
            b"/home/project/.env",
            b"/home/project/.env.local",
            b"/home/project/.env.example",
            b"/home/project/.env.sample",
            b"/home/project/.env.template",
            b"/home/project/.ENV.PRODUCTION",
            b"/home/.netrc",
            b"/home/.npmrc",
            b"/home/.pypirc",
            b"/home/project/.envrc",
            b"/home/.git-credentials",
            b"/home/project/credentials.json",
            b"/home/keys/id_rsa",
            b"/home/keys/id_dsa",
            b"/home/keys/id_ecdsa",
            b"/home/keys/id_ed25519",
            b"/home/keys/server.pem",
            b"/home/keys/server.KEY",
            b"/home/keys/server.p12",
            b"/home/keys/server.pfx",
            b"/home/.config/git/credentials",
            b".config/git/credentials",
            b"/home/.CONFIG/GIT/CREDENTIALS",
        ];

        // When content read permission is checked for each path.
        let actual: Vec<bool> = paths.iter().map(|path| allows(path)).collect();

        // Then every credential path is excluded.
        assert_eq!(actual, vec![false; paths.len()], "credential paths: {paths:?}");
    }

    #[test]
    fn credential_directory_components_are_excluded() {
        // Given credential directories at different depths and letter cases.
        let paths: &[&[u8]] = &[
            b"/home/.ssh/config",
            b"/home/.aws/credentials",
            b"/home/.gnupg/pubring.kbx",
            b"/backup/project/.ssh/key.txt",
            b"/home/.SSH/known_hosts",
            b"/home/.AWS/config",
            b"/home/.GNUPG/private-keys-v1.d/key",
            b".ssh/config",
        ];

        // When content read permission is checked for each path.
        let actual: Vec<bool> = paths.iter().map(|path| allows(path)).collect();

        // Then each path in a credential directory is excluded.
        assert_eq!(actual, vec![false; paths.len()], "credential directory paths: {paths:?}");
    }

    #[test]
    fn ordinary_files_and_similar_names_remain_allowed() {
        // Given code, configuration, public keys, and names near rule boundaries.
        let paths: &[&[u8]] = &[
            b"/home/project/src/main.rs",
            b"/home/project/README.md",
            b"/home/project/.gitignore",
            b"/home/project/.editorconfig",
            b"/home/project/config.json",
            b"/home/project/.environment",
            b"/home/project/my.env.example",
            b"/home/.ssh-backup/notes.txt",
            b"/home/.awsome/notes.txt",
            b"/home/.gnupg-old/notes.txt",
            b"/home/keys/id_rsa.pub",
            b"/home/keys/id_ed25519.pub",
            b"/home/keys/keyboard.txt",
            b"/home/keys/server.key.txt",
            b"/home/keys/pem",
            b"/home/config/git/credentials",
            b"/home/not.config/git/credentials",
            b"/home/.config/git/credentials.txt",
            b"/home/.config/git/credentials-backup",
        ];

        // When content read permission is checked for each path.
        let actual: Vec<bool> = paths.iter().map(|path| allows(path)).collect();

        // Then all ordinary paths remain allowed by this policy.
        assert_eq!(actual, vec![true; paths.len()], "ordinary paths: {paths:?}");
    }

    #[test]
    fn non_utf8_paths_use_the_same_file_name_rules() {
        // Given Unix paths with bytes that are not UTF-8.
        let paths: &[&[u8]] = &[b"/home/\xff/.env", b"/home/\xff/.ssh/config", b"/home/\xff/server.key", b"/home/\xff/code.rs"];

        // When content read permission is checked without text conversion.
        let actual: Vec<bool> = paths.iter().map(|path| allows(path)).collect();

        // Then only the ordinary source file is allowed.
        assert_eq!(actual, vec![false, false, false, true], "non-UTF-8 paths: {paths:?}");
    }
}
