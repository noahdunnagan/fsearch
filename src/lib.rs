//! Fuzzy filename and indexed content search for macOS and Windows.
//! macOS keeps a whole-disk index live with FSEvents and a socket daemon.
//! Windows currently uses explicit directory scans and saved snapshots;
//! `Engine::start` opens one after `Engine::rebuild` or `fsearch index`.

#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("fsearch currently supports macOS and Windows");

pub mod content;
#[cfg(target_os = "macos")]
mod engine;
#[cfg(windows)]
#[path = "snapshot.rs"]
mod engine;
mod engine_types;
#[cfg(target_os = "macos")]
mod fsevents;
pub mod index;
pub mod live;
pub mod paths;
#[doc(hidden)]
pub mod platform;
pub mod query;
pub mod walk;

pub use content::{FileMatches, Grep, GrepResult};
pub use engine::{Engine, default_dir, gated, has_full_disk_access, no_materialize};
pub use engine_types::{Found, Options, Status};
pub use query::{GrepMode, Query};
