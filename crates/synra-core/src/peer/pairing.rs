//! What a presented link token means.
//!
//! # Why this is a function and not a callback
//!
//! The handshake takes a closure that answers this question, because the answer needs a database and the handshake must
//! not. That leaves the *reasoning* — which of the three states a token produces — with nowhere to live: a caller writes
//! it inline, and an inline `match` inside a closure cannot be tested without a socket, a peer and a handshake.
//!
//! So the reasoning is here, as one total function over two `Option`s, with the closure reduced to a lookup:
//!
//! ```text
//!  presented   stored for that device   the link is
//!  ──────────────────────────────────────────────────
//!  Some(tok)   Some(same text)          Current   — trusted
//!  Some(tok)   Some(other text)         Stale     — pair again
//!  Some(tok)   None                     Stale     — pair again
//!  None        anything                 Unknown   — first time
//! ```
//!
//! # Why a mismatched token is `Stale` and not a refusal
//!
//! Because "this device does not recognise you" and "this device no longer knows the pairing you remember" are different
//! answers, and only the second has an action attached to it. A user whose other device was reset needs to be told to
//! pair again; a user whose token was rejected outright is told nothing they can act on.
//!
//! # Why the device identifier is not a parameter
//!
//! Because it does not change the answer, and a parameter that is ignored is a parameter that invites a caller to believe
//! it was consulted. The caller has already used the identifier to fetch `stored`; passing it again would only make this
//! function look as though it double-checks something.
//!
//! The one thing this function must never do is answer `Current` for a token it did not recognise. That state is what
//! lets a link carry business messages, so treating an unknown token as trusted would be the whole pairing model failing
//! open.

use synra_protocol::handshake::{LinkToken, PairingState};

/// Decides what a dialler's token means, given the token this device stored for it.
///
/// `stored` is the token from the pairing record — `None` when there is no record for that device, or when the record
/// predates tokens being stored. `presented` is what arrived in the `Hello`.
#[must_use]
pub fn pairing_state(stored: Option<&str>, presented: Option<&LinkToken>) -> PairingState {
    let Some(presented) = presented else {
        // No token at all is a first-time pairing: a device that has never paired presents nothing, and one that has
        // presents its token.
        return PairingState::Unknown;
    };

    match stored {
        // Compared as hex text, because that is how the token is stored and how it travels on the wire, so a token
        // parsed from a `Hello` and a token read from the database compare without either being decoded first.
        Some(stored) if stored.eq_ignore_ascii_case(&presented.to_hex()) => PairingState::Current,
        // Either this device has no record of the pairing, or it has one under a different token. Both mean the same
        // thing to the user — pair again — and neither is a refusal.
        _ => PairingState::Stale,
    }
}
