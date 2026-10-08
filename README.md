# FSearch

Whole-disk file search for Linux and macOS, with fuzzy names, typo tolerance
and indexed content search. Use the CLI, desktop terminal picker, JSON-lines
API, or Rust crate. Linux measurements and upstream macOS comparisons are
listed separately below.

```
cargo build --release && ./target/release/fsearch install   # -> ~/.local/bin/fsearch
fsearch fsearch main              # find files by name
fsearch 'ext:rs grep:apply_dir'   # search inside files
```

## Linux installation

Requires Rust and Linux 5.17 or newer with fanotify named file-handle support:

```sh
cargo build --release --locked
sudo -v
./target/release/fsearch install --login
fsearch status
```

The installer puts the CLI in `~/.local/bin/fsearch`, a root-owned daemon
binary in `/usr/local/bin/fsearch`, and enables `fsearch-<uid>.service`.
The daemon runs as the installing user with `CAP_SYS_ADMIN` for filesystem
marks and `CAP_DAC_READ_SEARCH` for file-handle resolution. Directory scans
and content reads still check the ordinary user's permissions; the index
and socket are private. No capabilities are assigned to a user-writable binary.

Name indexing crosses local ext4, btrfs, xfs and f2fs mounts without following
symlink loops or duplicate bind trees. Unsupported filesystems and `/proc`,
`/sys`, `/dev`, `/run`, `/tmp`, `/boot`, `/var/cache`, `/var/tmp`, `/var/log`,
`/var/spool` and `/lost+found` are excluded. Content indexing covers eligible
text files in your home, with the existing generated/cache-directory exclusions.

Data lives in `${XDG_DATA_HOME:-$HOME/.local/share}/fsearch`. Linux has no
durable fanotify replay journal, so restarts reconcile the disk while live
events are queued. `fsearch uninstall` removes the service and privileged
binary but preserves the user CLI and index.

Check an installed daemon with `python3 tests/linux_smoke.py`; use
`sudo -v && python3 tests/linux_smoke.py --restart` to check offline edits too.
Run `python3 demo/linux_bench.py --samples 25` for serial warm-cache name,
typing, sort, content and real picker-reload timings on the installed daemon.
Add `--restart` with cached sudo authorization to measure five warm-disk
service starts and their background reconciliation time.

## Desktop picker

Install the Python 3 helper with `install -m 755 fsearch-desktop ~/.local/bin/`,
then run `fsearch-desktop` in a Nerd Font terminal. It uses the existing `fzf`
(tested with 0.74.4); no Python packages or nnn installation are required.
The desktop entry on this workstation opens Contour with FiraCode Nerd Font.

Results show [nnn-style single-cell icons](https://github.com/jarun/nnn/blob/master/src/icons.h),
local modification dates, human-readable sizes and parent folders. Terminal
width comes from the controlling TTY, including the first fzf reload.

| Key | Action |
|---|---|
| Alt-R / Alt-N / Alt-T | Relevance / name / type |
| Alt-D / Alt-A / Alt-S | Newest / oldest / largest |
| Enter / Ctrl-O | Open selected file / parent folder |
| Ctrl-P / Ctrl-R / Esc | Toggle metadata details / refresh / close |

The search box accepts the same filename filters as the CLI. Filenames with
quotes, tabs and newlines retain their exact paths when opened; control
characters are escaped in the display. Details never render file contents.



## Linux workstation measurements

Arch Linux, 5.15 million files/folders and 970,169 indexed text files.
Serial warm-cache requests, 25 samples each; startup uses five restarts.
Full workload details and memory counters are in
[`demo/linux_benchmark.json`](demo/linux_benchmark.json); reproduce with
[`demo/linux_bench.py`](demo/linux_bench.py).

| Workload | p50 | p95 |
|---|---:|---:|
| Global fuzzy filename search | 0.92 ms | 1.16 ms |
| Scoped typo search | 0.08 ms | 0.12 ms |
| Global newest-first sort, top 200 | 7.92 ms | 8.33 ms |
| Global name sort, top 200 | 17.23 ms | 26.60 ms |
| Global type sort, top 200 | 17.12 ms | 18.43 ms |
| Indexed content search | 23.93 ms | 26.27 ms |
| Picker reload including startup, 200 rows | 43.99 ms | 45.87 ms |
| Live file creation | 103.79 ms | 104.12 ms |
| Service start to first correct search answer | 36.75 ms | 42.31 ms |
| Service start to reconciled disk snapshot | 2472.34 ms | 2486.97 ms |

Live rename and deletion also take about 104 ms, measured by 5 ms polling.
Startup includes systemctl overhead and uses the warm OS cache; these are
not cold-disk measurements. All measured content queries completed.
After warm searches, RSS was 863 MiB: 266 MiB anonymous memory and 597 MiB
file-backed pages. The process's observed RSS high-water mark was 1.68 GiB.

Linear terminal-column clipping renders the same 200-row response in
6.07 ms versus 17.82 ms previously, measured in the same process with
byte-identical output. Linux link-count notifications no longer trigger
whole-disk rebuilds; named namespace changes still invalidate directories,
and lost events or unavailable parent context still reconcile conservatively.

## Upstream macOS speed

M4 Max, 7.7M files and folders on disk.

| | |
|---|---|
| find a file by name, whole disk | p50 1.3 ms |
| search inside files | p50 9 ms |
| a new, renamed or deleted file shows up | ~0.1 s |
| first crawl of the disk | ~20 s, once |
| daemon memory | 30-135 MB |

## vs fff

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
`sym:` `limit:` `sort:`. Content search is smart-case.

Filename sorts are `relevance` (default), `name`, `type`, `modified-desc`,
`modified-asc` and `size-desc`, applied across all matches before `limit:`.
Type puts folders first and groups files by case-insensitive extension.
For example, `fsearch 'ext:pdf sort:modified-desc limit:200'`.

## macOS Full Disk Access

Started from a terminal with Full Disk Access, it indexes everything. As a
login item (`fsearch install --login`), give `~/.local/bin/fsearch` its own
grant in System Settings > Privacy & Security, again after each rebuild.
Without access it skips the protected folders instead of popping a prompt.

## API

JSON lines over `~/Library/Application Support/FSearch/fsearch.sock` on
macOS or `${XDG_DATA_HOME:-$HOME/.local/share}/fsearch/fsearch.sock` on Linux,
or through `fsearch stdio`:

```json
{"q": "fsearch main", "limit": 20}
{"q": "", "sort": "modified-desc", "limit": 200}
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

- macOS crawls with `getattrlistbulk` and replays FSEvents on restart.
- Linux crawls with `readdir`/`fstatat`, monitors mounted filesystems with
  fanotify and reconciles after restarts or event loss.
- Names live in one mmap'd file, laid out folder by folder so `in:` is a
  range. Each distinct name is scored once.
- Content search uses a trigram index of your text files. Matches are read
  fresh from disk; nanosecond inode change timestamps detect equal-size
  content edits even when modification timestamps are restored.
