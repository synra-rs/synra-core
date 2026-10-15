//! What the daemon answers a client with.
//!
//! # The honesty this module is built around
//!
//! The daemon can serve the control socket, own the data directory and say what it is. It cannot yet read devices or
//! plugins, because there is no database implementation and no session layer behind them. So the commands split in two:
//!
//! | Command | Answer |
//! | --- | --- |
//! | `status`, `logs`, `plugins` | real, and it says what is not implemented |
//! | `devices`, `send` | a refusal naming the missing layer |
//!
//! # Why a refusal rather than an empty list
//!
//! "No devices" and "I cannot tell you about devices" are different answers, and only one of them is true. A client that
//! received an empty list would report that nothing is paired — and a user would go looking for a pairing problem in an
//! installation where the real problem is that the code is not written.
//!
//! That is the same rule the daemon's own start-up follows: it prints `no kernel is started yet` rather than reporting
//! success. A host that reported success without running a kernel would be worse than one that says what it did not do.

mod commands;
mod devices;
mod plugin_host;
mod plugins;
mod refusals;
mod reports;
mod state;

pub use plugins::{
    Discovered, LoadedSummary, Refused, build_set, load_installed, record_discovered_plugins,
};
pub use state::{Runtime, now_ms};

#[cfg(test)]
mod tests;
