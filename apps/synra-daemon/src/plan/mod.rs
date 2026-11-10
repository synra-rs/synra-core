//! What the daemon will do when it starts, decided before it does any of it.
//!
//! # Why the plan is a value
//!
//! A daemon's start-up is a sequence of decisions — which directories, which ports, whether to take the data
//! directory's claim, whether to refuse — and the interesting failures are all *combinations*: a port out of range, a
//! data directory inside the plugin sandbox, a claim that cannot be taken. Deciding them as a value means the refusals
//! are decidable in a test, rather than discovered on a user's machine at the moment they tried to start something.
//!
//! It also keeps `main` short for the same reason the CLI's is: `main` is the one place nobody writes tests, so
//! everything decidable elsewhere goes elsewhere.
//!
//! # The daemon has no interface, and that is the point
//!
//! The kernel must work without a window, and this binary is the half
//! of that claim which has no window at all. So the platform is [`HeadlessPlatform`]: every action that would need a
//! user — opening a URL, writing the clipboard, simulating a keystroke — returns `Unsupported` rather than pretending
//! to have happened. A daemon that silently did nothing when a plugin asked to open a browser would be a daemon whose
//! plugins fail in a way nobody can trace.
//!
//! # Ports are chosen, not defaulted
//!
//! The transport port and the discovery port are named in the plan rather than read from a constant at the point of
//! use, because "which port" is the thing that collides. A second instance on a machine — a user with two profiles —
//! needs to move them, and a plan is where that decision is visible.

mod options;
mod paths;
mod resolved;

pub use options::{
    DATA_DIR_VAR, DEFAULT_DISCOVERY_PORT, DEFAULT_LISTEN_PORT, DaemonOptions, data_root_from,
    default_data_root,
};
pub use paths::checked_component;
pub use resolved::{DaemonPlan, PlanError};

/// The name of the claim file.
pub const LOCK_FILE_NAME: &str = "daemon.lock";

#[cfg(test)]
mod tests;
