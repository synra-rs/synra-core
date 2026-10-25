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

pub mod catalog;
mod commands;
mod devices;
pub mod install;
pub mod intent;
pub(crate) mod intents;
mod pairing;
pub(crate) mod plugin_host;
mod plugin_settings;
mod plugins;
mod publishers;
mod refusals;
mod registry_install;
mod reports;
pub(crate) mod retry;
mod state;
pub(crate) mod updates;

pub use install::{
    InstallRefusal, Installed, from_directory as install_from_directory,
    from_package as install_from_package,
};
pub use plugins::{
    Discovered, LoadedSummary, Refused, build_set, load_installed, load_installed_with_config,
    record_discovered_plugins,
};
pub use state::{Runtime, now_ms};

/// Points the store's write timer at this kernel's recorder.
///
/// # Why this is a named function rather than three lines in `serve`
///
/// Because the metric's name and its labels are one decision, and a test that wants to see a store write counted should
/// call the same function the daemon calls — not build a second histogram with the same name and hope the two agree.
pub fn observe_db_writes(
    db: &mut synra_store::SynraDb,
    metrics: &std::sync::Arc<synra_observe::metrics::RingRecorder>,
) {
    let recorder = std::sync::Arc::clone(metrics);
    db.observe_writes(std::sync::Arc::new(move |kind, elapsed| {
        recorder.histogram_observe(
            &synra_observe::metrics::SeriesKey::new(
                "db_write_duration_us",
                [("kind".to_owned(), kind.to_owned())],
            ),
            elapsed.as_secs_f64() * 1_000_000.0,
        );
    }));
}

#[cfg(test)]
mod tests;
