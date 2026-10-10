# FSearch

Whole-disk file search for macOS. Finds any file by name in about a tenth
of a millisecond, forgives typos, and searches inside files with an index.
Use it as a CLI (with a small daemon) or as a Rust crate.

```
cargo build --release && ./target/release/fsearch install   # -> ~/.local/bin/fsearch
fsearch fsearch main              # find files by name
fsearch 'ext:rs grep:apply_dir'   # search inside files
```

## Speed

M4 Max, 8.3M files and folders on disk. Before is the previous version
(76d612f): same Mac, same data, same results. Medians unless noted.

| | before | now | |
|---|---:|---:|---|
| find a file by name, whole disk | 1.0 ms | 0.13 ms | 7.7× faster |
| typing a filename, all keystrokes | 23 ms | 3.0 ms | 7.5× faster |
| search inside files, whole disk | 14 ms | 2.3 ms | 6.2× faster |
| find a file by name, Chromium (509k files) | 0.39 ms | 0.10 ms | 3.9× faster |
| search inside files, Chromium | 7.4 ms | 1.4 ms | 5.3× faster |
| slowest 10% of searches inside files, Chromium | 38 ms | 2.3 ms | 16× faster |
| search from the CLI | 5.5 ms | 3.3 ms | 1.7× faster |
| first run: names searchable | 27 s | 26 s | |
| first run: file contents searchable | 101 s | 49 s | 2.1× faster |
| memory peak, first run | 1.2 GB | 0.9 GB | |
| memory when idle | 58 MB | 57 MB | |
| index on disk, home folder with many repo copies | 1.15 GB | 1.41 GB | 1.2× bigger |
| index on disk, Chromium | 0.32 GB | 0.76 GB | 2.4× bigger |

The index is bigger because each file's content carries a small filter that
lets a search skip files without the text. Identical files are indexed once.
A new, renamed or deleted file shows up in about 0.1 s.

## vs fff

Chromium (509k files), same Mac, same queries. Video:
[`demo/fsearch-vs-fff.mp4`](demo/fsearch-vs-fff.mp4), method:
[`demo/vs_fff.py`](demo/vs_fff.py).

| | fsearch | [fff](https://github.com/dmtrKovalenko/fff) |
|---|---|---|
| find a file by name | 0.21 ms | 15.4 ms |
| search inside files | 2.0 ms | 64 ms |
| slowest 10% of searches inside files | 3.9 ms | 482 ms |
| typo still finds the file first | 99% | 86% |
| ready after launch | 28 ms | 2.5 s |
| memory | 63 MB (whole disk) | 449 MB (that folder) |

On the smaller Linux kernel (96k files) fsearch wins every row too: 0.16 ms
vs 1.8 ms by name, 1.0 ms vs 26 ms inside files. fff searches the contents
of about 5-10% more files, because fsearch skips some file types and
`build/` and `vendor/` folders.

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

Started from a terminal with Full Disk Access, it indexes everything. As a
login item (`fsearch install --login`), give `~/.local/bin/fsearch` its own
grant in System Settings > Privacy & Security, again after each rebuild.
Without access it skips the protected folders instead of popping a prompt.

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

An app and the CLI share one index: the first process owns it and the
others follow along.

## How it works

- Crawls the disk once with `getattrlistbulk`, then stays current from
  FSEvents. A restart replays only what changed.
- Names live in one mmap'd file, laid out folder by folder so `in:` is a
  range. Each distinct name is scored once, and a bitmap of the letters in
  each name rules out most names before scoring, 64 at a time.
- Content search uses a trigram index of your text files. Each file also
  gets a small filter of its 5- and 7-character runs, so a search reads only
  files likely to match. Identical files are indexed once. Matches are read
  fresh from disk, so they're never stale.
- The first index runs in parallel and opens files ahead of reading them.
