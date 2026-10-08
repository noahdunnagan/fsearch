//! Whole-disk file search for Linux and macOS: a fuzzy name index kept live
//! by native filesystem events, plus a trigram content index for text files.
//! `Engine` runs it in-process; the binary exposes a JSON-lines daemon.

pub mod content;
mod engine;
#[cfg(target_os = "macos")]
#[path = "fsevents.rs"]
mod events;
#[cfg(target_os = "linux")]
#[path = "events_linux.rs"]
mod events;
pub mod index;
pub mod live;
pub mod query;
#[cfg(target_os = "macos")]
pub mod walk;
#[cfg(target_os = "linux")]
#[path = "walk_linux.rs"]
pub mod walk;

pub use content::{FileMatches, Grep, GrepResult};
pub use engine::{Engine, Found, Options, Status, default_dir};
#[cfg(target_os = "macos")]
pub use engine::{gated, has_full_disk_access, no_materialize};
pub use query::{GrepMode, Query};
