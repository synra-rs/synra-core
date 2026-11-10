//! Sending a plugin to another device: what the far end has, what to do about it, and what the receiver owes itself.
//!
//! # Why this is a decision and not a transfer
//!
//! The bytes move over [`crate::transfer`], which already has sessions, resumption and a digest. What is *not* there is
//! everything that makes this a plugin sync rather than a file copy: comparing two devices' versions, refusing to
//! downgrade, isolating one round of sync from the next, and the receiver's own obligation to re-verify a package that
//! came from a device it trusts.
//!
//! # The two rules that are the whole design
//!
//! **A device never downgrades another's plugin.** The default conflict policy is [`ConflictPolicy::NeverDowngrade`],
//! and the reason is not tidiness: an automatic downgrade can put a device back on a version with a known
//! vulnerability, and "my software was remotely rolled back" is a thing users are right to refuse.
//!
//! **The receiver decides.** Signature, digest, manifest, archive limits and the grant are all checked *again* on the
//! receiving side, by the same [`crate::verify`] pipeline an install from a registry goes through. A device that
//! trusted the sender's word would be a device where compromising one plugin on one machine compromises every machine
//! it can reach — which is the shape of the attack this product exists to make boring.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use synra_protocol::ids::{DeviceId, PluginId, TraceId, TransferId};
use synra_protocol::session::{PluginList, PluginSummary};

mod decision;
mod decision_policy;
mod outcome;
mod receiver_check;
mod receiver_inbox;
mod receiver_round;
mod record_models;
mod record_table;
mod session;

pub use decision::*;
pub use decision_policy::*;
pub use outcome::*;
pub use receiver_check::*;
pub use receiver_inbox::*;
pub use receiver_round::*;
pub use record_models::*;
pub use record_table::*;
pub use session::*;

#[cfg(test)]
#[path = "../plugin_sync_tests.rs"]
mod tests;
