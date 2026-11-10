//! An intent: what a user asked for, before anything has decided how to do it.
//!
//! # Why this is a type of its own and not a message
//!
//! Because the interesting part of the product is the *gap* between "the user shared a link" and "a plugin opened a
//! browser on another machine", and everything that happens in that gap is a decision somebody has to make: which
//! plugins are even asked, which of their answers count, whether a user is interrupted, which device runs it, and what
//! happens when the answer never comes. A message struct cannot hold a decision that is still being made.
//!
//! # What is here and what is not
//!
//! This module is the **vocabulary**: what an intent is made of, what a candidate is, and every way one can end. The
//! board that sequences them — matching, deadlines, idempotency — is [`crate::intent`], and it is deliberately a
//! separate file because the two have different readers: this one is read by whoever adds a source of intents, and the
//! board by whoever changes the order things happen in.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use synra_protocol::ids::{DeviceId, IntentId, PluginId, RequestId, TraceId};

use synra_protocol::SynraError;

use crate::admission::AdmissionRefusal;

mod action;
mod record;
mod source;
mod state;

pub use action::*;
pub use record::*;
pub use source::*;
pub use state::*;
