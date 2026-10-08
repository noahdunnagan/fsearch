# FSearch

Whole-disk file search for macOS. Finds files by name, forgives typos,
and searches inside text files with an index. Use it
as a CLI (with a small daemon) or as a Rust crate.

```
cargo build --release --locked
./target/release/fsearch install   # -> ~/.local/bin/fsearch
fsearch fsearch main              # find files by name
fsearch 'ext:rs grep:apply_dir'   # search inside files
```

Rust 1.88 or later is required. The committed lockfile pins libc 0.2.189.

## Local data and limits

Cache loaders check lengths, IDs, paths, tree structure, and posting data before
use. They load a private read-only memory snapshot, so later file changes cannot
invalidate a checked slice. A binary cache is limited to 1 GiB and its manifest
to 1 MiB. Invalid derived data is rejected and rebuilt by the index owner.
The content format is now `FSCSEG04`; old content segments are rebuilt.

Content search does not read common credential stores, including `.env` and its
variants, `.ssh`, `.aws`, `.gnupg`, private key files, and package credential files.
The same rule applies to resolved paths. File opens reject symbolic links at
each resolved path component. Name search can still return these file names.
These name rules cannot detect secrets saved under ordinary file names.
Word and PDF text extraction is not supported by this CLI.

State directories use mode `0700`; cache files, locks, logs, and the socket use
`0600`. Extended ACL grants are removed from state directories and files.
Unsafe owners, links, and parent write grants are rejected.

The service accepts only peers with the same user ID. A request frame is limited
to 16 KiB and a reply to 8 MiB. Result counts must be 1 through 200. Content
matches per file must be 1 through 20, and the read budget must be 1 through
1000 ms. The read budget is cooperative, not a hard request deadline. At most
eight socket clients run at once; idle reads and writes time out after five
seconds. `stdio` opens a new service connection for each request.

## Speed

These published measurements predate the cache safety changes. Private cache
snapshots use resident memory. Whole-disk memory and startup costs have not been
measured again after those changes.

M4 Max, 7.7M files and folders on disk.

| | |
|---|---|
| find a file by name, whole disk | p50 1.3 ms |
| search inside files | p50 9 ms |
| a new, renamed or deleted file shows up | ~0.1 s |
| first crawl of the disk | ~20 s, once |
| daemon memory | 30-135 MB |

## vs fff

This comparison also predates the cache safety changes.

Chromium (509k files), same Mac, same queries. Video:
[`demo/fsearch-vs-fff.mp4`](demo/fsearch-vs-fff.mp4), method:
[`demo/vs_fff.py`](demo/vs_fff.py).

| | fsearch | [fff](https://github.com/dmtrKovalenko/fff) |
|---|---|---|
| find a file by name | 1.1 ms | 13.8 ms |
| search inside files | 5.6 ms | 53 ms |
| typo still finds the file first | 98% | 88% |
| ready after launch | 50 ms | 2.5 s |
| memory | 50 MB (whole disk) | 358 MB (that folder) |

On the smaller Linux kernel (96k files), name search is a tie and fsearch
wins the rest. fff searches the contents of about 9% more files, because
fsearch skips some file types and `build/` and `vendor/` folders.

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

Without Full Disk Access, the engine skips protected folders. A CLI started
from a terminal with Full Disk Access can read that terminal's permitted data.
Same-user socket checks do not isolate applications with different disk access
grants. Do not expose a privileged search engine through the shared service
unless all clients of that user are trusted. A sandboxed Finder app should embed
the engine and obtain explicit folder access instead.

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
- Names live in one checked memory snapshot, laid out folder by folder so `in:` is a
  range. Each distinct name is scored once.
- Content search uses a trigram index of your text files. Matches are read
  fresh from disk, so they're never stale.
