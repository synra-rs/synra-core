//! The asking half of a pairing: one request outstanding, and what its answer means.
//!
//! # What this decides, and what it deliberately does not
//!
//! It decides **what to send, how long to wait, and what an answer means**. It does not open sockets, and it does not
//! write to a database: the record a successful pairing produces is handed back for the caller to store, so every state
//! here is reachable in a test.
//!
//! # Why the waiting state exists rather than a plain function call
//!
//! Because the answer arrives on the connection and the *decision to stop waiting* is a clock's, not a message's. A
//! one-shot exchange — send, block on a read — would leave the dialer's only way out of a silent peer being the socket
//! timeout, and the protocol document states the rule this implements: a request that times out must clear the local
//! waiting state, because **a dialer that hangs for ever is worse than one that fails**.
//!
//! # Why a refusal is not an error
//!
//! Because "the other device said no" is an answer, and a user may ask again over the same link — the protocol's rule is
//! that a refusal does not end a connection. Reporting it as a failure would tell a caller to tear down a link that is
//! still perfectly usable.

use std::time::Duration;

use synra_protocol::handshake::LinkToken;
use synra_protocol::ids::{DeviceId, RequestId};
use synra_protocol::session::{PairRequest, PairResponse};

/// Who is being asked, as this side already knows them.
///
/// # Why the peer's details are carried separately from the request
///
/// Because a `PairRequest` carries **the asker's** profile — its whole purpose is that the other user sees a name rather
/// than an identifier. So nothing in a request or its answer says what the *asked* device calls itself, and a pairing
/// record built from the request alone would record this device's own name against the peer's identifier. The name comes
/// from what discovery heard, which is the only place either side learns the other's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTarget {
    /// The device to ask.
    pub device_id: DeviceId,
    /// What discovery said it calls itself.
    pub display_name: String,
    /// What platform discovery reported.
    pub platform: synra_protocol::session::PlatformKind,
}

/// A pairing this device has asked for and is waiting on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPairing {
    /// The device being asked, and what is known about it.
    target: PairingTarget,
    /// The request the answer must name. Checked rather than assumed: an answer to a *different* request arriving on the
    /// same link would otherwise be read as the answer to this one, which is how a device ends up paired with the wrong
    /// peer.
    request_id: RequestId,
    /// When this stops being worth waiting for.
    deadline_ms: i64,
}

/// What an arriving answer means for a pairing that is waiting.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Answered {
    /// The peer agreed, and this is the token to present on later links.
    Accepted {
        /// The device that agreed.
        device_id: DeviceId,
        /// The name it gave, for a list the user reads.
        display_name: String,
        /// The platform it reported.
        platform: synra_protocol::session::PlatformKind,
        /// The token later links must present, as lowercase hex.
        link_token: String,
    },
    /// The peer said no, or could not record the pairing. The link is still usable.
    Refused {
        /// Why, for the user.
        reason: String,
    },
    /// The window closed with no answer at all.
    TimedOut,
}

/// Why an answer could not be matched to the request that is waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NotAnAnswer {
    /// The answer named a different request.
    ///
    /// Refused rather than treated as this pairing's answer, because the two would be indistinguishable to the user: a
    /// device would be recorded as paired on the strength of a message about something else.
    #[error("the answer names request {theirs}, not the one waiting ({ours})")]
    WrongRequest {
        /// The request the answer named.
        theirs: RequestId,
        /// The request this side is waiting on.
        ours: RequestId,
    },
    /// The peer agreed but issued no token.
    ///
    /// Treated as a refusal rather than an acceptance, because an acceptance with nothing to present produces a pairing
    /// record that fails on the very next link — which reads to a user as the pairing having silently undone itself.
    #[error("the peer accepted but issued no token")]
    NoToken,
}

impl OutboundPairing {
    /// Asks a device to pair, starting the wait.
    ///
    /// `ours` is **this** device's profile, not the peer's: the request carries who is asking, so the other user sees a
    /// name rather than an identifier. `peer` is who is being asked, and is kept here because the answer names a request
    /// rather than a device — so the device an acceptance belongs to is this side's record of whom it asked.
    ///
    /// `pairing_window` is how long the answer is waited for. It comes from the caller rather than a constant here so it
    /// is the same number the receiving side uses: two different windows would mean a prompt answered just inside one and
    /// just outside the other.
    #[must_use]
    pub fn ask(
        target: PairingTarget,
        ours: synra_protocol::session::PeerProfile,
        pairing_window: Duration,
        now_ms: i64,
    ) -> (Self, PairRequest) {
        let request = PairRequest { profile: ours, user_hint: None };
        let window = i64::try_from(pairing_window.as_millis()).unwrap_or(i64::MAX);
        (
            Self {
                target,
                request_id: RequestId::new(),
                deadline_ms: now_ms.saturating_add(window),
            },
            request,
        )
    }

    /// The request this side is waiting on, so the answer can be correlated.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// The device being asked.
    #[must_use]
    pub const fn peer(&self) -> DeviceId {
        self.target.device_id
    }

    /// Whether the window has closed.
    #[must_use]
    pub const fn has_expired(&self, now_ms: i64) -> bool {
        now_ms > self.deadline_ms
    }

    /// Turns an arriving answer into what it means, or says why it is not this pairing's answer.
    ///
    /// # Errors
    ///
    /// [`NotAnAnswer`] when the message is not the answer to this request, or is an acceptance with nothing to present.
    pub fn accept_answer(&self, answer: &PairResponse, request_id: RequestId) -> Result<Answered, NotAnAnswer> {
        if request_id != self.request_id {
            return Err(NotAnAnswer::WrongRequest { theirs: request_id, ours: self.request_id });
        }

        if !answer.accepted {
            return Ok(Answered::Refused {
                reason: answer.reason.clone().unwrap_or_else(|| "declined".to_owned()),
            });
        }

        let Some(token) = answer.issued_token() else {
            return Err(NotAnAnswer::NoToken);
        };

        Ok(Answered::Accepted {
            // The device this side asked. The answer names a request rather than a device, so this is the only place the
            // pairing knows who it is with — and the request's own profile is *this* device, so reading the identifier
            // from there would pair this device with itself.
            device_id: self.target.device_id,
            display_name: self.target.display_name.clone(),
            platform: self.target.platform,
            link_token: token.to_owned(),
        })
    }

    /// The token to present on a later link, if the peer issued one.
    ///
    /// Parsed here rather than at the point of use, so a token that cannot be read is discovered while the user is still
    /// looking at the pairing rather than on the next connection attempt.
    #[must_use]
    pub fn token_of(answer: &Answered) -> Option<LinkToken> {
        match answer {
            Answered::Accepted { link_token, .. } => LinkToken::from_hex(link_token).ok(),
            Answered::Refused { .. } | Answered::TimedOut => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use synra_protocol::handshake::LinkToken;
    use synra_protocol::ids::{DeviceId, RequestId};
    use synra_protocol::session::{PairResponse, PeerProfile, PlatformKind};

    use super::{Answered, NotAnAnswer, OutboundPairing, PairingTarget};

    fn device(text: &str) -> DeviceId {
        text.parse().expect("a valid device id")
    }

    /// This device, as the request will carry it.
    fn ours() -> PeerProfile {
        PeerProfile {
            device_id: device("01a139a9-8f3c-72ce-9c96-2b2c81f14550"),
            display_name: "This device".to_owned(),
            platform: PlatformKind::Desktop,
            app_version: "0.1.0".to_owned(),
        }
    }

    /// The device being asked, as discovery described it.
    fn target() -> PairingTarget {
        PairingTarget {
            device_id: device("01a139a9-8f3c-72ce-9c96-2b2c81f14551"),
            display_name: "Laptop".to_owned(),
            platform: PlatformKind::Desktop,
        }
    }

    fn window() -> Duration {
        Duration::from_secs(30)
    }

    #[test]
    fn asking_produces_a_request_carrying_this_device_rather_than_the_peer() {
        // The request's profile is who is asking: its whole purpose is that the other user sees a name rather than an
        // identifier. Putting the peer's identifier there would ask a device to pair with itself.
        let (_pairing, request) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        assert_eq!(request.profile.device_id, ours().device_id);
        assert_eq!(request.profile.display_name, "This device");
        assert_eq!(request.profile.device_id, device("01a139a9-8f3c-72ce-9c96-2b2c81f14550"));
    }

    #[test]
    fn an_acceptance_names_the_device_that_was_asked() {
        // The answer names a request, not a device, so the peer's identity comes from what this side asked. Reading it
        // from the request's profile would record this device as having paired with itself.
        let (pairing, _) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        let token = LinkToken::from_bytes([0x11; LinkToken::LEN]);
        let answer = PairResponse::accepted(token.to_hex());

        let Answered::Accepted { device_id, display_name, platform, link_token } =
            pairing.accept_answer(&answer, pairing.request_id()).expect("this pairing's answer")
        else {
            panic!("an acceptance must be an acceptance");
        };
        assert_eq!(device_id, target().device_id);
        assert_eq!(display_name, "Laptop", "the peer's name, not this device's");
        assert_eq!(platform, PlatformKind::Desktop);
        assert_eq!(link_token, token.to_hex());
    }

    #[test]
    fn an_acceptance_carries_a_token_that_parses_back() {
        let (pairing, _) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        let token = LinkToken::from_bytes([0x42; LinkToken::LEN]);
        let answer = PairResponse::accepted(token.to_hex());
        let answered = pairing.accept_answer(&answer, pairing.request_id()).expect("an answer");

        assert_eq!(OutboundPairing::token_of(&answered), Some(token));
    }

    #[test]
    fn an_acceptance_with_no_token_is_refused_rather_than_recorded() {
        // A pairing recorded without a token fails on the very next link, which reads to a user as the pairing having
        // silently undone itself. Better to say so now, while they are looking at it.
        let (pairing, _) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        let answer = PairResponse { accepted: true, reason: None, link_token: None };
        assert_eq!(
            pairing.accept_answer(&answer, pairing.request_id()),
            Err(NotAnAnswer::NoToken)
        );
    }

    #[test]
    fn a_refusal_is_an_answer_rather_than_an_error() {
        // The link is still usable, so the caller must not be told to tear it down.
        let (pairing, _) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        let answer = PairResponse::refused("declined");
        let answered = pairing.accept_answer(&answer, pairing.request_id()).expect("an answer");

        assert_eq!(answered, Answered::Refused { reason: "declined".to_owned() });
        assert_eq!(OutboundPairing::token_of(&answered), None);
    }

    #[test]
    fn an_answer_to_a_different_request_is_not_this_pairings_answer() {
        // Two pairings in flight on one link, or a delayed answer to an earlier attempt. Reading either as this
        // pairing's answer would record a device as paired on the strength of a message about something else.
        let (pairing, _) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        let other = RequestId::new();
        let answer = PairResponse::accepted(LinkToken::from_bytes([0x11; LinkToken::LEN]).to_hex());

        assert_eq!(
            pairing.accept_answer(&answer, other),
            Err(NotAnAnswer::WrongRequest { theirs: other, ours: pairing.request_id() })
        );
    }

    #[test]
    fn the_window_closes_and_says_so() {
        // Rule 4 of the pairing section: a dialer that times out must clear its waiting state. A dialer that hangs for
        // ever is worse than one that fails, so the deadline is a property of the pairing rather than the socket's.
        let (pairing, _) = OutboundPairing::ask(target(), ours(), Duration::from_millis(100), 1_000);
        assert!(!pairing.has_expired(1_050), "inside the window");
        assert!(!pairing.has_expired(1_100), "the deadline itself is still inside");
        assert!(pairing.has_expired(1_101), "past the deadline");
    }

    #[test]
    fn a_timed_out_pairing_has_no_token_to_present() {
        assert_eq!(OutboundPairing::token_of(&Answered::TimedOut), None);
    }

    #[test]
    fn asking_twice_produces_two_different_requests() {
        // The request id is what correlates an answer, so two attempts must not share one — an answer to the first
        // would otherwise be read as the answer to the second.
        let (first, _) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        let (second, _) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        assert_ne!(first.request_id(), second.request_id());
    }

    #[test]
    fn the_pairing_remembers_which_device_it_asked() {
        let (pairing, _) = OutboundPairing::ask(target(), ours(), window(), 1_000);
        assert_eq!(pairing.peer(), target().device_id);
    }
}