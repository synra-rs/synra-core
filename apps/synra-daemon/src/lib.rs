//! The kernel's windowless host.
//!
//! # What it exists for
//!
//! The kernel must work without a window, and the way to check a claim
//! like that is to build the thing that would break if it were false. This binary has no window at all: no WebView, no
//! Tauri, no framework. If it compiles and runs, the kernel's boundary is clean.
//!
//! It is also the shape a user gets when they want the kernel to keep serving after the interface closes, which the
//! design document calls an optional form of the same kernel rather than a second product.
//!
//! # The two things that are actually interesting
//!
//! **Which process owns a data directory.** Two daemons over one database is a correctness problem rather than a
//! performance one: both open the same SQLite file, both believe they are the only one, and each holds half the truth
//! about which devices are paired. [`lock`] is the claim, and the hard half of it is a process that died without
//! cleaning up — an ordinary case, not an exception.
//!
//! **What the platform can do.** Nothing that would need a user. [`synra_platform::HeadlessPlatform`] refuses every
//! action that would open a window, write the clipboard or synthesize a keystroke, so a plugin under this host gets an
//! honest `Unsupported` rather than silence. A daemon that quietly did nothing when a plugin asked to open a browser
//! would be a daemon whose plugins fail in a way nobody can trace.
//!
//! # What is not here
//!
//! No socket, no session, no scheduler, no plugin loading. Those are the kernel's, and this crate is a *host*: it
//! decides where the data is, claims it, builds the platform, and reports. Everything decidable is in [`plan`] and
//! [`lock`] where a test can reach it, which is also why the binary is short.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod args;
pub mod dispatch;
pub mod lock;
pub mod plan;
pub mod runtime;
pub mod serve;
pub mod startup;
pub mod transport;

pub use args::{ClaimFile, DaemonArgs, Parsed, refresh_claim};
pub use lock::{
    Claim, HEARTBEAT_INTERVAL_MS, HEARTBEAT_STALE_AFTER_MS, LOCK_FORMAT_VERSION, LockError,
    LockFile, LockOwner, decide,
};
pub use startup::{
    Startup, StartupReport, begin, looks_like_a_data_dir, mark_clean_shutdown, now_ms, release,
    startup,
};
pub use runtime::{Runtime, now_ms as runtime_now_ms};
pub use serve::serve;
pub use plan::{
    DATA_DIR_VAR, DEFAULT_DISCOVERY_PORT, DEFAULT_LISTEN_PORT, DaemonOptions, DaemonPlan,
    LOCK_FILE_NAME, PlanError, checked_component, data_root_from, default_data_root,
};