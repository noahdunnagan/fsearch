//! Whole-disk file search: fuzzy names, typo tolerance, indexed content grep.
//! macOS uses getattrlistbulk + FSEvents; Windows uses `$MFT` + the USN journal.

pub mod alloc;
pub mod content;
mod engine;
#[cfg(target_os = "macos")]
mod fsevents;
#[cfg(windows)]
#[path = "usn.rs"]
mod fsevents;
#[cfg(windows)]
pub mod nt;
pub mod ospath;
#[cfg(windows)]
pub mod pathwin;
#[cfg(windows)]
mod winpriv;
pub mod index;
pub mod live;
pub mod query;
#[cfg(not(windows))]
pub mod walk;
#[cfg(windows)]
#[path = "walk_win.rs"]
pub mod walk;

pub use content::{Case, FileMatches, Grep, GrepResult, Hit};
pub use engine::{Engine, Found, Options, Status, default_dir, gated, has_full_disk_access, no_materialize};
pub use query::{GrepMode, Query};
