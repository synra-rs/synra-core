//! An intent that runs on another device.
//!
//! # What this is, and why it did not exist
//!
//! `decide` answers "run this, there" by building an envelope — and it used to refuse instead, because nothing could send
//! one. The design names the three events (`INTENT_INVOKE` / `INTENT_RESULT` / `INTENT_CANCEL`), they are in the
//! catalogue, in the automatic-ack table and in `inbound`'s kernel-event list, and **nothing anywhere sent or received
//! one**. So remote dispatch was never a missing contract; it was a missing implementation of four things: send the
//! message, run the plugin locally on receipt, reply with the result, and be idempotent by request identifier.
//!
//! # Why the envelopes are built here rather than in a host
//!
//! The same reason a request that carries a profile gives: the event name, the addressing and the trace have to be
//! right, and a host is not the only thing that will want to ask. It is also what lets a test check the envelope without
//! a socket — a request built inline in a command handler cannot be inspected without running the command.
//!
//! # Why the library builds the envelope and does not send it
//!
//! Because this crate has no transport and should not grow one: `worker`'s doc makes the same argument for storage
//! ("this crate knows nothing about storage ... the caller owns the write"). A host takes the [`Outbound`] that
//! [`crate::dispatch::orchestrate::decide`] returns, dials, and hands the link to [`exchange`] — the half after the dial,
//! shared so the window and the daemon cannot disagree about what counts as an answer.
//!
//! # The payload, which the design does not specify
//!
//! The documents name the three constants and say nothing about what goes in them, so the shape is decided here and
//! written down:
//!
//! * [`Invoke`] — the plugin, its version, the action, and the arguments the plugin itself proposed. The action and the
//!   arguments are taken from the board's own candidate rather than from whatever the caller sent, for the reason
//!   `board::confirm` gives: acting on a choice that was never shown would run something the user did not choose.
//! * [`InvokeResult`] — whether it ran, what it returned, and why not when it did not.
//! * [`Cancel`] — why a dispatched action is being withdrawn.
//!
//! Both are `camelCase` JSON, like every other payload in this workspace.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::event::{events, EventName};
use synra_protocol::ids::{DeviceId, PluginId, RequestId, TraceId};
use synra_protocol::{ErrorCode, SynraError};

use crate::link::{LinkError, PeerLink};
use crate::messaging::MessageError;

mod envelope;
mod payload;
mod transport;

pub use envelope::*;
pub use payload::*;
pub use transport::*;

#[cfg(test)]
mod tests;
