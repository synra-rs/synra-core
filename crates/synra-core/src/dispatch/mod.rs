//! The seam between what the user asked for and the plugin that will do it.
//!
//! # What this module is
//!
//! Two things exist on either side of it. On one side, [`crate::intent::Board`] decides when to stop asking plugins and
//! when a user's choice becomes an action. On the other, [`synra_plugin_host`] compiles a component, keeps an instance,
//! and runs one entry point under a budget. Nothing connected them: the Board could be filled by nothing, and the
//! plugin host could be driven only by tests. Both halves being complete and tested is what made the gap invisible —
//! the code volume looked like progress and there was no line anywhere that did not run.
//!
//! So this module is that line. It is deliberately thin: it does not re-decide what [`crate::intent::Board`] decides,
//! and it does not re-decide what the gate allows. It answers one question — *given a share, what did each plugin say?* —
//! and puts the answers where the Board's state machine can take them.
//!
//! # Why it is in the kernel rather than in a host
//!
//! Because a share has to work with no window at all. `synra-daemon` is the kernel's windowless form, and it must be
//! able to match an intent exactly as the desktop can; a matcher that only existed inside the Tauri shell would make
//! "works without UI" untrue for the one path where it is hardest to check.
//!
//! # Why the engine arrives from outside
//!
//! Because this module must not decide which engine exists. See [`plugins`] for why that is a build-size question and
//! not just an aesthetic one.

pub mod execute;
pub mod matching;
pub mod orchestrate;
pub mod plugins;

#[cfg(test)]
mod tests;

pub use execute::{EXECUTE_BUDGET_MS, REMOTE_RESULT_WAIT, execute, execute_budget};
pub use orchestrate::{RouteError, Router};
pub use matching::{MatchReport, Matcher};
pub use plugins::{PluginSet, PluginSetError, PluginSpec};
