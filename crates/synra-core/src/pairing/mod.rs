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
use synra_protocol::session::{PairRefusal, PairRequest, PairResponse};

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

/// The receiving side of one pairing at a time.
#[derive(Debug)]
pub struct InboundPairing {
    /// This device, which the verification code is derived from along with the dialer.
    local: DeviceId,
    pending: Option<PendingPairing>,
}

impl InboundPairing {
    /// A pairing state for this device, with nothing on screen.
    ///
    /// The local identifier is held rather than passed to each call, because the code a user is shown has to be derived
    /// from it and a call that forgot to pass it would produce a code the other screen does not match — which reads to a
    /// user as an attacker rather than as a missing argument.
    #[must_use]
    pub const fn new(local: DeviceId) -> Self {
        Self { local, pending: None }
    }

    /// The request waiting for a user, if there is one.
    #[must_use]
    pub const fn pending(&self) -> Option<&PendingPairing> {
        self.pending.as_ref()
    }

    /// Offers an arriving request.
    ///
    /// # Returns
    ///
    /// The answer to send immediately. `None` means the request was taken and is now waiting for a user; `Some` carries
    /// a refusal, and the only refusal this can produce is [`PairRefusal::Busy`].
    ///
    /// # Why there is no target check here
    ///
    /// Because a `PairRequest` carries no target: the envelope does, and the envelope is checked before a request reaches
    /// this type at all. Taking a `local` id as a parameter would make this look as though it verified the addressing
    /// while only repeating a check that has already happened where the information actually exists.
    pub fn offer(&mut self, request_id: RequestId, request: PairRequest) -> Option<PairResponse> {
        // One prompt at a time. Queueing a second behind the first means it is answered minutes later by a user who has
        // forgotten what they were agreeing to, which is not consent.
        if self.pending.is_some() {
            return Some(PairResponse::refused(PairRefusal::Busy.as_str()));
        }

        // Minted here rather than at acceptance, so the value shown to a user and the value written are one decision
        // made once. The verification code is derived rather than minted, because both ends must arrive at it without
        // exchanging anything further.
        let code = verification_code(request.profile.device_id, self.local);
        self.pending = Some(PendingPairing { request_id, request, token: LinkToken::random(), verification_code: code });
        None
    }

    /// Answers the request on screen.
    ///
    /// `write` is what makes the pairing durable, and it is called **before** the answer is built. When it fails, the
    /// answer is a refusal carrying that failure and the pending request is kept: the user's decision is still theirs to
    /// retry, and telling the dialer the pairing succeeded would be a claim this side cannot honour.
    ///
    /// # Returns
    ///
    /// `None` when there is nothing to answer, which is what an interface that answers a prompt twice produces.
    pub fn answer(
        &mut self,
        accepted: bool,
        write: impl FnOnce(&PairingRecord) -> Result<(), String>,
    ) -> Option<PairResponse> {
        let pending = self.pending.take()?;
        let profile = &pending.request.profile;

        if !accepted {
            // Rule 6: a refusal ends the prompt, not the link. The dialer may ask again over the same connection.
            return Some(PairResponse::refused("declined"));
        }

        let record = PairingRecord {
            device_id: profile.device_id,
            display_name: profile.display_name.clone(),
            platform: profile.platform,
            link_token: pending.token.to_hex(),
        };

        match write(&record) {
            Ok(()) => Some(PairResponse::accepted(record.link_token)),
            Err(why) => {
                // Put back: the user's answer was not carried out, so the decision is still pending rather than lost.
                // Nothing was written, so there is no half-made pairing to clean up — which is the point of writing
                // first.
                self.pending = Some(pending);
                Some(PairResponse::refused(format!("could-not-record: {why}")))
            }
        }
    }

    /// Drops a request that waited too long.
    ///
    /// # Returns
    ///
    /// Whether there was one, so a caller can decide whether the interface has anything to refresh.
    pub fn expire(&mut self) -> bool {
        self.pending.take().is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use synra_protocol::ids::{DeviceId, RequestId};

    use synra_protocol::session::{PairRequest, PeerProfile, PlatformKind};

    use super::{InboundPairing, PairingRecord};

    /// This device, for the verification code.
    fn local() -> DeviceId {
        device("01a139a9-8f3c-72ce-9c96-2b2c81f14550")
    }

    fn device(text: &str) -> DeviceId {
        text.parse().expect("a valid device id")
    }

    fn request(name: &str) -> PairRequest {
        PairRequest {
            profile: PeerProfile {
                device_id: device("01a139a9-8f3c-72ce-9c96-2b2c81f14551"),
                display_name: name.to_owned(),
                platform: PlatformKind::Desktop,
                app_version: "0.1.0".to_owned(),
            },
            user_hint: None,
        }
    }

    /// A writer that records what it was asked to write, and can be told to fail.
    fn writer(log: &RefCell<Vec<String>>, fail: bool) -> impl FnOnce(&PairingRecord) -> Result<(), String> + '_ {
        move |record: &PairingRecord| {
            log.borrow_mut().push(format!("{}:{}", record.display_name, record.link_token));
            if fail { Err("the disk said no".to_owned()) } else { Ok(()) }
        }
    }

    #[test]
    fn a_request_waits_for_a_user_rather_than_being_answered() {
        let mut pairing = InboundPairing::new(local());
        assert!(pairing.offer(RequestId::new(), request("Laptop")).is_none(), "nothing to send back yet");
        assert_eq!(pairing.pending().map(|p| p.request.profile.display_name.as_str()), Some("Laptop"));
    }

    #[test]
    fn a_second_request_while_one_waits_is_refused_as_busy() {
        // Not queued: a prompt is a decision somebody is in the middle of, and the second would be answered minutes later
        // by a user who has forgotten what they agreed to.
        let mut pairing = InboundPairing::new(local());
        assert!(pairing.offer(RequestId::new(), request("First")).is_none());

        let answer = pairing.offer(RequestId::new(), request("Second")).expect("a busy answer");
        assert!(!answer.accepted);
        assert_eq!(answer.reason.as_deref(), Some("busy"));
        assert_eq!(pairing.pending().map(|p| p.request.profile.display_name.as_str()), Some("First"),
            "the first request must still be the one on screen");
    }

    #[test]
    fn accepting_writes_the_record_before_it_answers() {
        // Rule 5, and the reason this is asserted rather than assumed: the alternative has no recovery. A peer told
        // `accepted` stores its side and presents its token next time, while this side has nothing to compare it with —
        // so the user is told they paired and then refused by the device they just paired with.
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        pairing.offer(RequestId::new(), request("Laptop"));

        let answer = pairing.answer(true, writer(&log, false)).expect("an answer");
        assert!(answer.accepted);

        let written = log.borrow();
        assert_eq!(written.len(), 1, "the record must be written exactly once");
        let token = answer.issued_token().expect("an acceptance issues a token");
        assert!(written[0].ends_with(token), "the token written and the token answered must be one value: {written:?}");
        assert_eq!(pairing.pending(), None, "the prompt is finished");
    }

    #[test]
    fn a_write_that_fails_refuses_rather_than_claiming_success() {
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        pairing.offer(RequestId::new(), request("Laptop"));

        let answer = pairing.answer(true, writer(&log, true)).expect("an answer");
        assert!(!answer.accepted, "a pairing that was not recorded must not be answered as accepted");
        assert_eq!(answer.issued_token(), None, "nothing was issued, so nothing may be presented");
        assert!(answer.reason.as_deref().is_some_and(|why| why.contains("could-not-record")), "{answer:?}");
    }

    #[test]
    fn a_failed_write_keeps_the_decision_pending() {
        // The user's answer was not carried out, so it is still theirs to retry. Dropping it would leave them believing
        // they had decided something.
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        pairing.offer(RequestId::new(), request("Laptop"));

        let _ = pairing.answer(true, writer(&log, true));
        assert!(pairing.pending().is_some(), "the request must still be answerable");

        // And retrying over the same prompt succeeds, which is what "kept" has to mean.
        let answer = pairing.answer(true, writer(&log, false)).expect("an answer");
        assert!(answer.accepted);
        assert_eq!(pairing.pending(), None);
    }

    #[test]
    fn a_failed_write_issues_the_same_token_on_the_retry() {
        // The token was minted when the request arrived, so a retry writes the value the user was already shown rather
        // than a second one. A token minted at acceptance would make the shown value and the written value two decisions.
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        pairing.offer(RequestId::new(), request("Laptop"));
        let first_shown = pairing.pending().expect("pending").token.to_hex();

        let told = pairing.answer(true, writer(&log, true)).expect("an answer");
        assert!(!told.accepted);
        assert_eq!(pairing.pending().expect("still pending").token.to_hex(), first_shown);

        let answer = pairing.answer(true, writer(&log, false)).expect("an answer");
        assert_eq!(answer.issued_token(), Some(first_shown.as_str()));
    }

    #[test]
    fn declining_writes_nothing_and_refuses() {
        // Rule 6: the link survives a refusal, so the dialer may ask again over the same connection.
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        pairing.offer(RequestId::new(), request("Laptop"));

        let answer = pairing.answer(false, writer(&log, false)).expect("an answer");
        assert!(!answer.accepted);
        assert_eq!(answer.reason.as_deref(), Some("declined"));
        assert!(log.borrow().is_empty(), "a refusal records nothing");
        assert_eq!(pairing.pending(), None, "the prompt is finished either way");
    }

    #[test]
    fn a_refusal_frees_the_slot_for_the_next_request() {
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        pairing.offer(RequestId::new(), request("First"));
        let _ = pairing.answer(false, writer(&log, false));

        assert!(pairing.offer(RequestId::new(), request("Second")).is_none(), "the next request may be shown");
        assert_eq!(pairing.pending().map(|p| p.request.profile.display_name.as_str()), Some("Second"));
    }

    #[test]
    fn answering_a_prompt_twice_answers_once() {
        // An interface that fires the answer twice — a double click, a re-render — must not produce two pairings.
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        pairing.offer(RequestId::new(), request("Laptop"));

        assert!(pairing.answer(true, writer(&log, false)).is_some());
        assert!(pairing.answer(true, writer(&log, false)).is_none(), "there is nothing left to answer");
        assert_eq!(log.borrow().len(), 1, "and nothing was written a second time");
    }

    #[test]
    fn answering_with_nothing_pending_is_not_an_error() {
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        assert!(pairing.answer(true, writer(&log, false)).is_none());
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn an_expired_request_frees_the_slot_and_says_whether_it_did() {
        // Rule 3: the pending request has a timeout. The dialer is never told, because a request nobody answered is
        // indistinguishable from one nobody looked at — and rule 4 makes the dialer give up on its own clock.
        let mut pairing = InboundPairing::new(local());
        assert!(!pairing.expire(), "there was nothing to expire");

        pairing.offer(RequestId::new(), request("Laptop"));
        assert!(pairing.expire());
        assert_eq!(pairing.pending(), None);
        assert!(!pairing.expire(), "and expiring twice reports nothing the second time");

        // The slot is free, so the device that timed out may ask again.
        assert!(pairing.offer(RequestId::new(), request("Laptop")).is_none());
    }

    #[test]
    fn an_expired_request_cannot_then_be_accepted() {
        let log = RefCell::new(Vec::new());
        let mut pairing = InboundPairing::new(local());
        pairing.offer(RequestId::new(), request("Laptop"));
        assert!(pairing.expire());

        assert!(pairing.answer(true, writer(&log, false)).is_none(), "a request that expired is gone");
        assert!(log.borrow().is_empty(), "and nothing may be written for it");
    }
}