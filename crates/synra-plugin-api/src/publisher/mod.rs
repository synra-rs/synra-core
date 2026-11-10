//! The signature on a published plugin, and the decisions a device makes about publishers.
//!
//! # What a signature is *for*, and what it is not
//!
//! It proves that whoever holds a private key produced this combination of manifest and artifacts. It does **not**
//! say the plugin is safe, and it does not say the publisher is who their name claims: those are judgements a user
//! makes, and this module's job is to give them the two facts the judgement needs — *which* key signed this, and
//! whether this device has seen that key before for that name.
//!
//! That second fact is the whole reason [`PublisherTrustStore`] exists. A name is free; a key is not. So a plugin
//! signed by `imba97` is only as good as the answer to "is this the same key the last `imba97` plugin had?", and a
//! store that answered "yes, the id matches" without comparing the key would be the vulnerability the design document
//! names: an id is forgeable, a key is not.
//!
//! # Why the signed bytes are canonical and hand-built
//!
//! Because a signature is over **bytes**, and `serde_json::to_string` on a struct is a promise about field order that
//! a later refactor can break silently. A signature that stopped verifying after an unrelated change to a struct is
//! indistinguishable from a tampered package, and every user would be told their plugin had been altered. So the
//! payload is built by hand, in a fixed order, with the two things that could vary — map iteration and whitespace —
//! absent by construction.
//!
//! # What is deliberately not here
//!
//! Key rotation. The design document puts it in v2 and says the first version supports one key per publisher, which
//! is also what makes the rule below so blunt: an id whose key changed is **untrusted**, not "possibly rotated". A
//! host that guessed would be a host that could be made to accept a different key by whoever controlled the id.

#[cfg(test)]
use base64::Engine;
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;

/// The only signing algorithm this version knows.
pub const ALGORITHM: &str = "ed25519";

/// The version of the signature document.
pub const SIGNATURE_VERSION: u32 = 1;

/// The file a published package carries its signature in.
pub const SIGNATURE_FILE: &str = "signature.json";

mod errors;
mod file;
mod subject;
mod trust;

pub use errors::SignatureError;
pub use file::{Fingerprint, SignatureFile, VerifyOutcome};
pub use subject::{Digests, SigningSubject};
pub use trust::{PluginTrust, PublisherTrustStore, SignatureCheck, Untrusted, check};

#[cfg(test)]
mod tests;

