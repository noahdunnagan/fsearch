//! Whole-disk file search for macOS: a fuzzy name index over every entry on
//! disk, kept live from FSEvents, plus a trigram content index for text
//! files. `Engine` runs it all in-process; the `fsearch` binary wraps one in
//! a daemon with a JSON-lines socket.

pub mod content;
mod engine;
mod fsevents;
pub mod index;
pub mod live;
mod paths;
pub mod query;
pub mod walk;

pub use content::{FileMatches, Grep, GrepResult};
pub use engine::{Engine, Found, Options, Status, default_dir, gated, has_full_disk_access, no_materialize, try_lock};
pub use query::{GrepMode, Query};
