//! Log levels, verbosity, and the writer that redacts what leaves the process.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds four separable things: what a level *is* and how it parses, how verbose the process is right now,
//! what the logger has counted, and the writer that removes secrets on the way out. In one file the redaction — the
//! part where a mistake leaks a credential to a log file — sat below a hundred lines of verbosity bookkeeping.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `level` | the level enum, its parsing, and the level it does not recognise |
//! | `verbosity` | how verbose the process is, and the clock that decides when it lapses |
//! | `stats` | what the logger has counted |
//! | `writer` | the redacting writer, the field list, and the line redactor |

mod level;
mod verbosity;
mod stats;
mod writer;
mod file;
mod init;
mod nonblocking;
mod reader;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use level::{LogLevel, UnknownLevel};
pub use stats::LogStats;
pub use verbosity::{VERBOSE_WINDOW, Verbosity};
pub use writer::{DEFAULT_REDACTED_FIELDS, RedactingWriter, redact_line};
pub use file::{DEFAULT_KEEP, DEFAULT_MAX_BYTES, LOG_FILE_NAME, RotatingFile};
pub use init::{LogConfig, LogError, LogGuard, init, stats_of};
pub use nonblocking::DEFAULT_QUEUE_CAPACITY;
pub use reader::{
    DEFAULT_TAIL_LINES, FOLLOW_POLL, FollowSummary, LogTail, follow, is_debug_or_trace, newest_file, path_in,
    tail,
};
