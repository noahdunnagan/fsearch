# FSearch

Whole-disk file search for macOS: names in about 0.1 ms, typo-tolerant,
plus indexed search inside files. A CLI with a small daemon, or a Rust crate.

```
cargo build --release && ./target/release/fsearch install   # -> ~/.local/bin/fsearch
fsearch fsearch main              # find files by name
fsearch 'ext:rs grep:apply_dir'   # search inside files
```

## Speed

M4 Max, 8.3M files on disk, vs the previous version (76d612f). Same
results. Medians.

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

## vs fff

Chromium (509k files), same Mac and queries.
[Video](demo/fsearch-vs-fff.mp4), [method](demo/vs_fff.py).

| | fsearch | [fff](https://github.com/dmtrKovalenko/fff) |
|---|---|---|
| find a file by name | 0.21 ms | 15.4 ms |
| search inside files | 2.0 ms | 64 ms |
| slowest 10% inside files | 3.9 ms | 482 ms |
| typo still finds the file first | 99% | 86% |
| ready after launch | 28 ms | 2.5 s |
| memory | 63 MB (whole disk) | 449 MB (that folder) |

Linux kernel (96k files): 0.16 vs 1.8 ms by name, 1.0 vs 26 ms inside
files. fff reads 5-10% more files: fsearch skips some file types and
`build/` and `vendor/`.

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

## Full Disk Access

From a terminal with Full Disk Access it indexes everything. As a login
item (`fsearch install --login`), grant `~/.local/bin/fsearch` access in
System Settings > Privacy & Security, again after each rebuild. Without
access it skips protected folders instead of prompting.

## API

JSON lines over `~/Library/Application Support/FSearch/fsearch.sock`, or
`fsearch stdio`:

```json
{"q": "fsearch main", "limit": 20}
{"op": "grep", "pattern": "apply_dir", "in": "~/Developer"}
```

Or link the crate:

```rust
let engine = fsearch::Engine::start(fsearch::Options { dir: fsearch::default_dir(&home), home: home.clone(), skip: None })?;
let hits = engine.search(&fsearch::Query::parse("fsearch main", &home)?)?;
```

An app and the CLI share one index: the first process owns it, the rest
follow.

## How it works

- Crawls the disk once with `getattrlistbulk`, then follows FSEvents:
  changes show up in about 0.1 s, and a restart replays only what changed.
- Names live in one mmap'd file, folder by folder, so `in:` is a range. A
  bitmap of each name's letters rules out most names before scoring.
- Content search is a trigram index plus a per-file filter, so a search
  only reads files likely to match. Identical files are indexed once.
  Matches are read fresh from disk.
