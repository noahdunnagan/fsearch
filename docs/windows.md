# Windows support

This is the first Windows port: directory scanning, saved filename and content
indexes, CLI queries, and JSON lines over standard input/output. The shared
search algorithms and index layout are unchanged. The macOS scanner, FSEvents
stream, allocator, and daemon remain in use on macOS.

## Build and use

Install Rust 1.89 or newer with the MSVC toolchain and the Visual Studio C++
Build Tools, then build from PowerShell:

```powershell
cargo build --release
$fsearch = '.\target\release\fsearch.exe'
& $fsearch index "$env:USERPROFILE\Documents" C:\src
& $fsearch 'readme ext:md'
& $fsearch 'ext:rs grep:apply_dir' --json
& $fsearch 'in:"C:\src\my project" main'
& $fsearch status
```

`index` with folders replaces the selection. `index` without folders reuses
the last selection, or enumerates every available drive letter on first use.
Explicit UNC roots such as `\\server\share\project` are accepted. Network
drives can be slow or unavailable; start with a local folder.

Run `index` again after files change. Every rebuild scans the selected folders
and rereads eligible content, including edits whose size and timestamp did
not change. Deleted files and renamed folders disappear from the new snapshot.

The data directory is `%LOCALAPPDATA%\FSearch`. Set `FSEARCH_DATA_DIR` to keep a
separate index. Eligible text files under `%USERPROFILE%` get a content index;
generated directories and `AppData` are excluded. To search content outside
the profile, supply an `in:` filter. Those candidates come from the filename
index and their contents are read directly.

One-shot filename queries open only the name index. They do not load the
content catalog. `stdio`, `status`, and content queries open the complete
snapshot and report missing or invalid content files as errors. Rebuild with
`index` to repair that snapshot. For one-shot filename queries, JSON `took_us`
includes opening the name index and searching it. For `stdio` and content
queries, it measures the search after the engine opens. Use process wall time
to measure CLI startup and the complete request.

## JSON and Rust

`fsearch stdio` opens one snapshot and answers multiple JSON lines. Close and
restart it to see a newly built snapshot. Request fields and responses match
the macOS interface:

```json
{"id":1,"q":"readme","in":"C:\\src","limit":20}
{"id":2,"op":"grep","pattern":"apply_dir","in":"C:\\src"}
```

The `save` operation returns an error on Windows directing callers to `index`.
It does not imply that a refresh was scheduled. Windows status reports
`owner: false`, `event_id: 0`, and `full_disk_access: false`; the latter is a
macOS permission setting, not a Windows ACL check.

In Rust, `Engine::rebuild(options, &roots)` synchronously builds a snapshot;
`Engine::start(options)` opens the saved one. The options and query API are
shared. Multiple readers can retain old snapshots while one writer builds a
new one. Opening or rebuilding during another rebuild returns a busy error.
`Engine::search_saved(options, &query)` performs a single filename query
without opening content files. It returns the same filename results as
`Engine::start(options)?.search(&query)`.

Each generation has its own name index, content files, and saved root list.
A rebuild publishes a small `current` file only after those writes succeed.
Old mapped files are never truncated or replaced. Old generations are removed
when possible, with another cleanup attempt on the next rebuild if Windows
still has them open. An interrupted build leaves the previous generation selected.
Failed rebuilds discard their unpublished files. A subsequent rebuild also
reclaims abandoned generations before starting work, preserving the current one.

## Paths and filesystem behavior

- Native paths are encoded losslessly as WTF-8 inside the index. The internal
  root contains drive letters, for example `/C:/Users/Ada`, and UNC paths use
  `/UNC/server/share`. Use `paths::encode` and `paths::decode` when working with
  the low-level byte-path APIs. `path:` regular expressions use this internal
  slash-separated form.
- Filesystem access uses wide Windows paths, including the extended-length
  prefix for long paths. CLI and JSON display ordinary Windows separators.
  JSON cannot represent unpaired UTF-16 surrogates, so those characters are
  replaced for display only. Rust `Found.path` retains the original filename.
- Directory enumeration works with the caller's permissions and does not
  require raw volume access. Inaccessible descendants are skipped. An explicit
  root that cannot be opened reports an error.
- Reparse points, including junctions and symlinks, are listed as links and
  are not traversed. Offline and recall-marked entries are not opened for
  content search. This initial port conservatively skips reparse-point files,
  including locally available cloud files that retain that attribute.

## Validation and follow-up work

`cargo test --all-targets` covers directory scanning, filename queries, Unicode
content reads, saved indexes, and path conversion. Windows-only tests also
cover snapshot refresh while an old reader is open, writer contention,
same-size edits, deletion, long paths, unpaired surrogates, hidden attributes,
junctions, and the CLI/stdio protocol. CI runs tests and release builds on
macOS and Windows. Cross-compiling with `cargo check` checks types but does
not replace running these tests on Windows.

This port has no MFT enumeration, USN journal checkpoints, filesystem watcher,
named-pipe daemon, Windows Service, or login installation. Windows throughput,
memory use, removable-drive behavior, and UNC performance still need native
measurements. The README's M4 Max benchmarks apply only to macOS.

Windows API references: [file attributes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca28ec38-f155-4768-81d6-4bfeb8586fc9),
[reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations),
and [Rust file locking](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock).
