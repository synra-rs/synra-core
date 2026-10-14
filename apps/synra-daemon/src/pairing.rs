//! Reading the pairing record a handshake needs, and turning it into an answer.
//!
//! # Why this is a function over a database rather than code inside the handshake closure
//!
//! The handshake takes a closure, and the closure it was given answered `Unknown` unconditionally — which made every link
//! untrusted, every device list empty, and `send` refuse every device by name. The reasoning it needed is two steps: find
//! the token this device stored for the dialler, then decide what the presented token means. Neither step needs a socket,
//! so neither belongs inside a closure the handshake only calls once.
//!
//! `synra_core::peer::pairing_state` is the second step. This is the first, plus the error policy between them.
//!
//! # Why a database that cannot be read answers `Stale` rather than `Current`
//!
//! Because the only safe direction to fail in is the one that asks the user to pair again. `Current` is what lets a link
//! carry business messages, so a lookup that could not run must not produce it — and `Stale` is the honest description of
//! a device whose record this build cannot read.

use synra_protocol::handshake::{LinkToken, PairingState};
use synra_protocol::ids::DeviceId;
use synra_store::SynraDb;

/// Decides what a dialler's token means, using this device's own record of the pairing.
///
/// Returns `PairingState::Stale` when the record cannot be read, so a database that is locked, missing or corrupt refuses
/// trusted access rather than granting it.
#[must_use]
pub fn state_for(
    db: &SynraDb,
    device_id: DeviceId,
    presented: Option<&LinkToken>,
) -> PairingState {
    let stored = match db.link_token_for(&device_id.to_string()) {
        Ok(stored) => stored,
        Err(error) => {
            // Said out loud rather than swallowed: a device that cannot read its own pairings will refuse every peer, and
            // the reason is the only thing that distinguishes that from "nobody has paired with us".
            eprintln!("synra-daemon: the pairing record could not be read: {error}");
            return PairingState::Stale;
        }
    };

    synra_core::peer::pairing_state(stored.as_deref(), presented)
}
