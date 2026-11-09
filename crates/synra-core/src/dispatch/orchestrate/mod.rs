//! Routing a share: asking the plugins, applying the answer, running what was chosen.
//!
//! # ★ Why this is in the library rather than in a host
//!
//! Because **two hosts need it**. The daemon routes a share that arrives from a peer and one the CLI hands it; the desktop
//! shell routes one from this machine's own share sheet. Until this module existed, the whole of that orchestration lived
//! in `synra-daemon/src/runtime/intent.rs` — **inside a binary** — so the shell could not reuse a line of it and would
//! have had to duplicate roughly two hundred and fifty. The shell's `Board` was constructed and never used, and its four
//! intent commands were explained away as "needs the intent board behind `AppState`", which was false: the board was
//! already there.
//!
//! # What is decided here, and what is not
//!
//! This raises the intent, runs the matching pass, closes the window, applies the user's answer and runs the action they
//! chose. What it does **not** do is decide *where* the action runs: a target that is not this device is a message to
//! another device, and sending one is the transport's business rather than this module's. That case is refused rather than
//! run locally, which would be doing the user's action on the machine they shared *from*.
//!
//! # Why the errors are the protocol's own codes
//!
//! Because the two hosts report failures differently — the daemon as a control-protocol refusal, the shell as an
//! `IpcError` — and a library that picked one would make the other translate a foreign type. [`RouteError`] carries the
//! `ErrorCode` the contract already defines and a sentence for a person, and each host wraps that in its own shape: one
//! line each, and no shared vocabulary invented for the purpose.

use std::sync::Arc;

use parking_lot::Mutex;

use synra_protocol::ids::{DeviceId, PluginId};
use synra_protocol::inbound::ShareItem;

use super::matching::Matcher;
use super::plugins::PluginSet;
use crate::intent::{Board, IntentSource};

/// Cancellation messages.
mod cancel;
/// Applying a user's choice.
mod decision;
/// Small conversions shared by the actor modules.
mod helpers;
/// Remote invocation and result handling.
mod remote;
/// Raising and observing intents.
mod route;
/// The routing vocabulary and host-facing DTOs.
mod types;

pub use cancel::*;
pub use decision::*;
pub use remote::*;
pub use route::*;
pub use types::*;

use helpers::{candidates_of, parse_intent, refuse_intent, state_name};
use remote::invocation;

#[cfg(test)]
mod outcome_tests;
#[cfg(test)]
mod tests;
