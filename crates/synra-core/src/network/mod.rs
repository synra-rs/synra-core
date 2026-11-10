//! What a plugin's outbound request is allowed to reach.
//!
//! # Why this exists
//!
//! Because a request a plugin asks the kernel to make is a request the **user's network** makes, from inside whatever
//! firewall that user is behind — and the interesting targets on such a network are not the plugin's to reach. A cloud
//! instance's metadata service lives at `169.254.169.254`, a router's admin page at `192.168.0.1`, and a development
//! database at `127.0.0.1`. A plugin that can fetch any of them has a capability nobody granted it.
//!
//! The design puts the checks in a fixed order (`10 §4.4`), and this module is that order:
//!
//! 1. **the scheme**, closed rather than "anything but http" — `javascript:`, `data:` and `file:` are all things that can
//!    be written where a URL is expected;
//! 2. **the host**, normalised and then required to be one the capability granted;
//! 3. **the addresses it resolved to**, checked after resolution because that is the only moment the answer is known —
//!    and every one of them must pass, not the first;
//! 4. **each redirect**, because a redirect is a second request to a URL nobody authorised.
//!
//! # Why the resolution is a parameter and not a call
//!
//! Because this crate performs no DNS, and a guard that resolved names would be a guard that could not be tested without a
//! network. [`NetworkGuard::check_resolved`] takes what the resolver returned, so the rule that matters — *every* address
//! must pass — is testable with a list somebody wrote down.
//!
//! # What this is not
//!
//! It is not a firewall and it is not a substitute for one. It is the check that stops a plugin reaching the metadata
//! service, and it is honest about the limit the design names: a name that resolves to a public address during the check
//! and to a private one when the connection is made is a **DNS rebinding** attack, and the defence is to connect to the
//! address that was checked — see `10 §4.4` step 3 — rather than to look the name up a second time. That is the caller's
//! obligation, and [`Checked::host`] exists so it can be honoured: the connection goes to a checked address, the `Host`
//! header carries this.

use std::net::IpAddr;

use synra_protocol::error::ErrorCode;

mod guard;
mod hostname;
mod policy;
mod types;

pub use guard::*;
pub use hostname::*;
pub use types::*;

#[cfg(test)]
mod tests;
