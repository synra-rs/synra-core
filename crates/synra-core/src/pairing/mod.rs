//! The receiving half of a pairing: one request on screen, one answer, and the order those happen in.
//!
//! # What this decides, and what it deliberately does not
//!
//! It decides **which request may be pending, what answering one produces, and in what order**. It does not decide when
//! a prompt appears, what it looks like, or how a user answers it — those are the interface's. And it does not write to a
//! database: the record it needs written is handed to a writer, so this can be driven to every state in a test.
//!
//! # The rule that shapes everything here
//!
//! **An acceptance is only answered after the pairing is durable.** The protocol document states it as a rule, and the
//! reason is that the alternative has no recovery: a peer told `accepted: true` records its side and presents its token
//! on the next link, while this side has nothing to compare it against — so the user is told they paired successfully and
//! then refused by the device they just paired with. Persisting second means the failure mode is an error the user can
//! see, at the moment they caused it.
//!
//! # Why only one request at a time
//!
//! Because a prompt is a decision somebody is in the middle of. Queueing a second behind it means the second is answered
//! minutes later by a user who has forgotten what they were agreeing to — which is not consent. A second request while
//! one is pending is refused with [`PairRefusal::Busy`], and the dialer may ask again.

use synra_protocol::handshake::LinkToken;
use synra_protocol::ids::{DeviceId, RequestId};

pub mod desk;

pub use desk::{Offer, PairingDesk, Waiter};
use synra_protocol::session::PairRequest;

/// What the kernel needs written down when a pairing is accepted.
///
/// Passed to the writer rather than assembled by it, so the fields recorded and the fields answered cannot be derived
/// from two different values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRecord {
    /// The device that asked.
    pub device_id: DeviceId,
    /// The name it gave, for a list the user reads.
    pub display_name: String,
    /// The platform it reported.
    pub platform: synra_protocol::session::PlatformKind,
    /// The token this side will expect on later links, as lowercase hex.
    pub link_token: String,
}

/// A request waiting for the user, with what it will be recorded as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPairing {
    /// The envelope's request id, which is what a dialer correlates the answer with.
    ///
    /// Held beside the payload rather than in it, because a `PairRequest` carries none of its own: the id belongs to the
    /// envelope that delivered it.
    pub request_id: RequestId,
    /// The request as it arrived.
    pub request: PairRequest,
    /// The token this side will expect if the user accepts.
    ///
    /// Chosen when the request arrives rather than when it is answered, so the value a user is shown and the value
    /// written are decided once. A token minted at acceptance would be a second place to get it wrong.
    pub token: LinkToken,
    /// The short code the user compares against the one the other device shows.
    ///
    /// See [`verification_code`] for why this is derived rather than random, and what it does and does not prove.
    pub verification_code: String,
}

/// The code two devices both display, for a user to compare before pairing.
///
/// # Why this is derived from the two device identifiers
///
/// Because both ends must arrive at the same string without exchanging anything further, and both already know both
/// identifiers: the dialer knows who it is and who it dialled, and the acceptor learns the dialer's identity from the
/// `Hello` that carried the request. Deriving it means there is no extra message to lose, no version of the protocol
/// where one side shows a code and the other shows nothing.
///
/// # Why the two identifiers are ordered before hashing
///
/// Because the derivation must not know which of the two is asking. The dialer computes this with `(peer, self)` and the
/// acceptor with `(self, peer)`, so a derivation that labelled the arguments by role produced two different codes for the
/// same honest pair. A check that always disagrees is one users learn to ignore, which is the same as having no check —
/// and the test comparing both ends caught exactly that mistake in the first version of this function.
///
/// # What it proves, and what it does not
///
/// It proves that **the device asking is the device the user thinks it is**. A device on the same network that asks to
/// pair while claiming somebody else's identifier produces a code that does not match the one on the other screen, and
/// the user sees it. That is the threat the prompt exists for: a request arriving from an address the user cannot
/// interpret, answered by a name the requester chose.
///
/// It does **not** prove possession of a secret, because it is not one: anyone who knows both identifiers can compute it.
/// It is a check a person performs, not a signature, and it is deliberately not a substitute for the token — the token is
/// what a later link is trusted by, and it never leaves the two devices.
///
/// # Why it is six characters
///
/// Long enough that a wrong device is unlikely to collide by accident, short enough to read aloud and compare at a
/// glance. The first character is forced to be a letter, because a code made only of digits can be misread as a quantity
/// and a leading `0` is the case people drop.
#[must_use]
pub fn verification_code(first: DeviceId, second: DeviceId) -> String {
    use sha2::{Digest, Sha256};

    // Ordered, so the answer does not depend on which device is asking. The dialer computes this with `(peer, self)` and
    // the acceptor with `(self, peer)`, so a derivation that labelled the arguments by role produced two different codes
    // for the same honest pair — which the test comparing both ends caught.
    let (low, high) = {
        let low = first.to_string();
        let high = second.to_string();
        if low <= high { (low, high) } else { (high, low) }
    };

    let mut hasher = Sha256::new();
    // A separator between them, because two identifiers joined bare would let one pair's input equal another's.
    hasher.update(low.as_bytes());
    hasher.update(b":");
    hasher.update(high.as_bytes());
    let digest = hasher.finalize();

    // Three bytes of the digest, as six hex characters. Taken from the front rather than spread out: a display code has
    // no need to resist analysis, and a simple derivation is one a reader can check.
    let mut digits = String::with_capacity(6);
    for byte in digest.iter().take(3) {
        let _ = std::fmt::Write::write_fmt(&mut digits, format_args!("{byte:02x}"));
    }

    // The first character is forced into `a`..=`f`, so a code never reads as a quantity and never begins with a zero —
    // the digit people drop when they repeat one back.
    let mut characters = digits.chars();
    let first = characters.next().and_then(|c| c.to_digit(16)).unwrap_or(0);
    let mut out = String::with_capacity(6);
    out.push(char::from(b'a' + u8::try_from(first % 6).unwrap_or(0)));
    out.extend(characters);
    out
}

