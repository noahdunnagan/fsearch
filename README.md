# FSearch

Whole-disk file search for macOS, plus an experimental Windows CLI.
Typo-tolerant filename search and indexed search inside files, usable as a CLI
or a Rust crate. Rust 1.89 or newer is required.

macOS:

```
cargo build --release && ./target/release/fsearch install   # -> ~/.local/bin/fsearch
fsearch fsearch main              # find files by name
fsearch 'ext:rs grep:apply_dir'   # search inside files
```

Windows, in PowerShell:

```powershell
cargo build --release
.\target\release\fsearch.exe index "$env:USERPROFILE\Documents"
.\target\release\fsearch.exe readme
.\target\release\fsearch.exe 'ext:rs grep:apply_dir' --json
```

Windows uses saved snapshots. Run `fsearch index` again to refresh the previous
folders. On first use, `index` without folders scans all available drive letters.
See [Windows support](docs/windows.md) for scope, the JSON interface, and limitations.

## Speed

macOS on an M4 Max, 8.3M files on disk, vs the previous version (76d612f). Same
results. Medians.

These numbers do not describe Windows performance.

| | before | now | |
|---|---:|---:|---:|
| find a file by name | 1.0 ms | 0.13 ms | 7.7× |
| typing a whole filename, all keystrokes | 23 ms | 3.0 ms | 7.5× |
| search inside files | 14 ms | 2.3 ms | 6.2× |
| slowest 10% inside files (Chromium) | 38 ms | 2.3 ms | 16× |
| CLI, launch to answer | 5.5 ms | 3.3 ms | 1.7× |
| first run, fully searchable | 101 s | 49 s | 2.1× |
| first run, peak memory | 1.2 GB | 0.9 GB | |
| index on disk (Chromium) | 0.32 GB | 0.76 GB | 2.4× bigger |

The index grew because each file carries a filter that lets search skip
files without the text.

## Queries

```
fsearch 'readme in:~/Developer'          # inside a folder
fsearch 'type:image size:>5mb mtime:<7d'
fsearch 'ext:rs regex:fn\s+\w+_dir'      # regex inside files
fsearch 'sym:apply_dir'                  # where it's defined
```

Words are fuzzy, and 5+ letter words forgive one typo (`mian.rs` finds
`main.rs`). Also `'exact`, `^prefix`, `suffix$` and `!exclude`. Filters:
`ext:` `type:` `kind:` `in:` `size:` `mtime:` `re:` `path:` `grep:` `regex:`
`sym:` `limit:`. Content search is smart-case.

## Full Disk Access on macOS

From a terminal with Full Disk Access it indexes everything. As a login
item (`fsearch install --login`), grant `~/.local/bin/fsearch` access in
System Settings > Privacy & Security, again after each rebuild. Without
access it skips protected folders instead of prompting.

## API

JSON lines through `fsearch stdio` on either platform. macOS also serves
`~/Library/Application Support/FSearch/fsearch.sock`:

```json
{"q": "fsearch main", "limit": 20}
{"op": "grep", "pattern": "apply_dir", "in": "~/Developer"}
```

Or link the crate:

```rust
let engine = fsearch::Engine::start(fsearch::Options { dir: fsearch::default_dir(&home), home: home.clone(), skip: None })?;
let hits = engine.search(&fsearch::Query::parse("fsearch main", &home)?)?;
```

On macOS, an app and the CLI share one live index: the first process owns it,
the rest follow. On Windows, run `fsearch index` or `Engine::rebuild` first;
each `Engine::start` opens a saved snapshot, and existing readers keep their
snapshot until reopened.

## How it works

- On macOS, crawls the disk once with `getattrlistbulk`, then follows FSEvents:
  changes show up in about 0.1 s, and a restart replays only what changed.
- Names live in one mmap'd file, folder by folder, so `in:` is a range. A
  bitmap of each name's letters rules out most names before scoring.
- Content search is a trigram index plus a per-file filter, so a search
  only reads files likely to match. Identical files are indexed once.
  Matches are read fresh from disk.
- On Windows, enumerates directories without NTFS-specific privileges. Each
  explicit rebuild writes a new snapshot, then publishes it for new readers.
