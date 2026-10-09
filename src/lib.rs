//! Whole-disk file search for macOS: a fuzzy name index over every entry on
//! disk, kept live from FSEvents, plus a trigram content index for text
//! files. `Engine` runs it all in-process; the `fsearch` binary wraps one in
//! a daemon with a JSON-lines socket.
//!
//! On Linux, fsearch indexes `$HOME` instead of the whole disk. See the README.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("fsearch supports macOS and Linux only");

pub mod content;
mod engine;
#[cfg(target_os = "macos")]
mod fsevents;
#[cfg(target_os = "linux")]
mod fsevents_linux;
pub mod index;
pub mod live;
pub mod query;
pub mod walk;

pub use content::{FileMatches, Grep, GrepResult};
pub use engine::{Engine, Found, Options, Status, default_dir, gated, has_full_disk_access, no_materialize};
pub use query::{GrepMode, Query};
