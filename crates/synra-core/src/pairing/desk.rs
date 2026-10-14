//! The shared pairing desk: who is waiting for a user, and how the user's answer reaches them.
//!
//! # Why this type exists at all
//!
//! A per-connection pairing state is one conversation's worth of state, and that is right for deciding *what a request
//! means*. It is wrong for deciding *whether a prompt exists*, because the user answers on one screen while the
//! connection that asked is a different thread holding a socket. Two per-connection states never see each other, so an
//! answer given on one would never reach the other — and the dialer would sit until its own timeout.
//!
//! This is not a hypothetical: an earlier version of this module held exactly that per-connection state, and it had to be
//! deleted once the desk existed, because a type nobody calls is one the next reader mistakes for a live path.
//!
//! So the desk is shared, and it is indexed by **device** rather than by request. That index is the whole design: the
//! protocol's rule is one pending request per device, and a structure keyed by device makes the second request from the
//! same device a lookup that finds something rather than a comparison somebody has to remember to write.
//!
//! # How an answer travels back
//!
//! A connection offers a request and receives a [`Waiter`] — a one-shot channel plus the name of the request it belongs
//! to. It then blocks on that channel. Whoever answers the prompt calls [`PairingDesk::answer`] with the request name,
//! and the answer is delivered through the channel to the thread that can actually write it to the socket.
//!
//! The channel carries *the response*, not the decision, so the order the protocol document requires — record first,
//! answer second — happens once, on the answering side, where the database is.
//!
//! # Why the deadline lives here
//!
//! Because the desk is the only thing that sees every pending request at once. A per-connection timer would expire a
//! request without telling the desk, so the prompt would stay on screen after the dialer had given up — a user deciding
//! about a pairing that can no longer happen.

use std::collections::HashMap;
use std::time::Duration;

use parking_lot::Mutex;
use synra_protocol::handshake::LinkToken;
use synra_protocol::ids::{DeviceId, RequestId};
use synra_protocol::session::{PairRefusal, PairRequest, PairResponse};

use crate::pairing::{PendingPairing, verification_code};

/// What a shared desk hands back when a request is offered.
#[derive(Debug)]
#[non_exhaustive]
pub enum Offer {
    /// Nothing to send: the request is on screen, and this connection waits for the answer.
    Waiting(Waiter),
    /// Answer immediately. The link stays up, so the dialer may ask again.
    Refused(PairResponse),
}

/// The receiving end of one pending request.
///
/// Holds the name the request is filed under, so a caller that only has the waiter can find the prompt again — and so
/// [`PairingDesk::answer`] can be given a waiter rather than a device identifier the caller would have to have kept.
#[derive(Debug)]
pub struct Waiter {
    request: RequestId,
    answer: std::sync::mpsc::Receiver<PairResponse>,
}

impl Waiter {
    /// The request this waiter is waiting for.
    #[must_use]
    pub const fn request(&self) -> RequestId {
        self.request
    }

    /// Blocks until a user answers, or until the pairing window closes.
    ///
    /// # Returns
    ///
    /// The response to send. A window that closes with no answer produces a refusal rather than nothing, because a peer
    /// left holding an open connection with no answer is worse to debug than one told the request expired.
    #[must_use]
    pub fn wait(self, patience: Duration) -> PairResponse {
        self.answer.recv_timeout(patience).unwrap_or_else(|_| {
            PairResponse::refused(PairRefusal::Expired.as_str())
        })
    }
}

/// One request waiting for a user, as the desk holds it.
#[derive(Debug)]
struct Entry {
    pending: PendingPairing,
    answer: std::sync::mpsc::Sender<PairResponse>,
    deadline_ms: i64,
}

/// The shared pairing desk.
#[derive(Debug)]
pub struct PairingDesk {
    local: DeviceId,
    /// How long a request may wait for a user.
    pairing_window_ms: i64,
    entries: Mutex<HashMap<DeviceId, Entry>>,
}


impl PairingDesk {
    /// A desk for this device, with no prompts on it.
    #[must_use]
    pub fn new(local: DeviceId, pairing_window: Duration) -> Self {
        Self {
            local,
            pairing_window_ms: i64::try_from(pairing_window.as_millis()).unwrap_or(i64::MAX),
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The requests currently waiting for a user, ordered so two reads agree.
    ///
    /// Ordered because this is what an interface lists: an order that changed between reads would make a prompt move
    /// while a user was reading it.
    #[must_use]
    pub fn pending(&self) -> Vec<(DeviceId, RequestId)> {
        // Scoped so the lock is released once the list is built rather than when the function returns: the sort below
        // touches nothing shared, and holding a lock across work that does not need it is contention for no reason.
        let mut waiting: Vec<(DeviceId, RequestId)> = {
            let entries = self.entries.lock();
            entries
                .iter()
                .map(|(device, entry)| (*device, entry.pending.request_id))
                .collect()
        };
        waiting.sort_by_key(|(device, _)| device.to_string());
        waiting
    }

    /// Every request waiting for a user, with what a prompt needs to show.
    ///
    /// # Why this is not the shape [`PairingDesk::pending`] returns
    ///
    /// Because a screen needs the name, the address and the code, and a caller that had to fetch each prompt by request id
    /// would be reading the desk three times per prompt — with a window in between in which a prompt could be answered and
    /// the identifiers it was holding would name nothing. One read gives a consistent list.
    ///
    /// Ordered by device, for [`PairingDesk::pending`]'s reason: a list whose order changed between reads would make a
    /// prompt move while a user was reading it.
    #[must_use]
    pub fn prompts(&self) -> Vec<PendingPairing> {
        let mut waiting: Vec<PendingPairing> = {
            let entries = self.entries.lock();
            entries.values().map(|entry| entry.pending.clone()).collect()
        };
        waiting.sort_by_key(|prompt| prompt.request.profile.device_id.to_string());
        waiting
    }

    /// Offers an arriving request.
    ///
    /// `request_id` is the envelope's, because that is what a dialer correlates the answer with — the [`PairRequest`]
    /// payload carries none of its own. `address` is where it came from, as this side observed it; empty is allowed and
    /// means the caller had none to give.
    ///
    /// # Returns
    ///
    /// [`Offer::Waiting`] with the waiter this connection should block on, or [`Offer::Refused`] with the answer to send
    /// now. A second request from a device that already has one pending is refused as [`PairRefusal::Busy`], and the
    /// first prompt is left alone.
    pub fn offer(
        &self,
        request_id: RequestId,
        request: PairRequest,
        address: &str,
        now_ms: i64,
    ) -> Offer {
        let device = request.profile.device_id;
        let mut entries = self.entries.lock();

        if entries.contains_key(&device) {
            // Released before returning: the caller is a socket thread about to write a refusal, and it has no reason to
            // hold the desk while it does.
            drop(entries);
            return Offer::Refused(PairResponse::refused(PairRefusal::Busy.as_str()));
        }

        let code = verification_code(device, self.local);
        let deadline_ms = now_ms.saturating_add(self.pairing_window_ms);
        let pending = PendingPairing {
            request_id,
            request,
            token: LinkToken::random(),
            verification_code: code,
            address: address.to_owned(),
            expires_at_ms: deadline_ms,
        };
        let (sender, answer) = std::sync::mpsc::channel();
        let _ = entries.insert(device, Entry { pending, answer: sender, deadline_ms });
        // The entry is in place, so the desk is consistent. The caller may now block on the channel for as long as the
        // user takes, and holding the lock across that would stop every other connection from asking anything.
        drop(entries);

        Offer::Waiting(Waiter { request: request_id, answer })
    }

    /// The request waiting under a name, so the answering side can read what it is deciding about.
    #[must_use]
    pub fn request_of(&self, request: RequestId) -> Option<PendingPairing> {
        let entries = self.entries.lock();
        entries
            .values()
            .find(|entry| entry.pending.request_id == request)
            .map(|entry| entry.pending.clone())
    }

    /// Answers a request, delivering the response to whoever is waiting.
    ///
    /// `write` makes the pairing durable when it is accepted, and it is called **before** the response is built. When it
    /// fails the response is a refusal carrying the failure, and the entry is put back so the user's decision is still
    /// theirs to retry.
    ///
    /// # Returns
    ///
    /// The response that was delivered to the waiter, or `None` when there was nothing to answer.
    pub fn answer(
        &self,
        request: RequestId,
        accepted: bool,
        write: impl FnOnce(&crate::pairing::PairingRecord) -> Result<(), String>,
    ) -> Option<PairResponse> {
        let device = {
            let entries = self.entries.lock();
            entries
                .iter()
                .find(|(_, entry)| entry.pending.request_id == request)
                .map(|(device, _)| *device)?
        };

        if !accepted {
            // Rule 6: a refusal ends the prompt, not the link. The dialer may ask again over the same connection.
            let entry = self.entries.lock().remove(&device)?;
            let response = PairResponse::refused("declined");
            let _ = entry.answer.send(response.clone());
            return Some(response);
        }

        // Read under the lock and nothing else is: writing to a database is the slow part, and a desk held across it
        // would stop every other connection from even asking whether a prompt is free. The clone is of a name and a
        // token — small, and the price of not holding a lock across IO.
        let pending = {
            let entries = self.entries.lock();
            entries.get(&device).map(|entry| entry.pending.clone())?
        };
        let record = crate::pairing::PairingRecord {
            device_id: pending.request.profile.device_id,
            display_name: pending.request.profile.display_name.clone(),
            platform: pending.request.profile.platform,
            link_token: pending.token.to_hex(),
            // Carried from the prompt rather than re-observed here: the connection that saw the address has already
            // gone, and what a user agreed to is what was on screen.
            address: pending.address,
        };

        match write(&record) {
            Ok(()) => {
                // Removed only now, so a write that failed left the prompt exactly where it was.
                let entry = self.entries.lock().remove(&device)?;
                let response = PairResponse::accepted(record.link_token);
                let _ = entry.answer.send(response.clone());
                Some(response)
            }
            Err(why) => {
                // The prompt stays, so the user can try again. Nothing was written, so there is no half-made pairing to
                // clean up — which is the point of writing first.
                let response = PairResponse::refused(format!("could-not-record: {why}"));
                let entries = self.entries.lock();
                if let Some(entry) = entries.get(&device) {
                    let _ = entry.answer.send(response.clone());
                }
                drop(entries);
                Some(response)
            }
        }
    }

    /// Drops every request whose window has closed.
    ///
    /// # Returns
    ///
    /// How many were dropped, so a caller can decide whether an interface has anything to refresh.
    ///
    /// A request dropped here is one no user decided about. Its connection is not told: the waiter's own `wait` returns
    /// an expired refusal on the same deadline, so the dialer learns the same thing without the desk having to reach
    /// into a connection it does not own.
    pub fn sweep_expired(&self, now_ms: i64) -> usize {
        let mut entries = self.entries.lock();
        let before = entries.len();
        entries.retain(|_, entry| now_ms <= entry.deadline_ms);
        before - entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use synra_protocol::ids::{DeviceId, RequestId};
    use synra_protocol::session::{PairRefusal, PairRequest, PeerProfile, PlatformKind};

    use super::{Offer, PairingDesk};
    use crate::pairing::PairingRecord;

    fn device(text: &str) -> DeviceId {
        text.parse().expect("a valid device id")
    }

    /// This device: the desk derives the verification code from it.
    fn local() -> DeviceId {
        device("01a139a9-8f3c-72ce-9c96-2b2c81f14550")
    }

    fn peer() -> DeviceId {
        device("01a139a9-8f3c-72ce-9c96-2b2c81f14551")
    }

    fn other() -> DeviceId {
        device("01a139a9-8f3c-72ce-9c96-2b2c81f14552")
    }

    fn request(from: DeviceId, name: &str) -> PairRequest {
        PairRequest {
            profile: PeerProfile {
                device_id: from,
                display_name: name.to_owned(),
                platform: PlatformKind::Desktop,
                app_version: "0.1.0".to_owned(),
            },
            user_hint: None,
        }
    }

    fn desk() -> PairingDesk {
        PairingDesk::new(local(), Duration::from_secs(30))
    }

    /// A writer that succeeds, and records what it was asked to write.
    fn writes(log: &std::cell::RefCell<Vec<String>>) -> impl FnOnce(&PairingRecord) -> Result<(), String> + '_ {
        move |record: &PairingRecord| {
            log.borrow_mut().push(record.link_token.clone());
            Ok(())
        }
    }

    #[test]
    fn an_offered_request_waits_and_appears_on_the_desk() {
        let desk = desk();
        let id = RequestId::new();
        let Offer::Waiting(waiter) = desk.offer(id, request(peer(), "Laptop"), "127.0.0.1:5000", 1_000) else {
            panic!("a first request must wait for a user");
        };
        assert_eq!(waiter.request(), id);
        assert_eq!(desk.pending(), vec![(peer(), id)]);
        assert_eq!(
            desk.request_of(id).expect("the request is on the desk").request.profile.display_name,
            "Laptop"
        );
    }

    #[test]
    fn a_second_request_from_the_same_device_is_busy_and_leaves_the_first_alone() {
        // Keyed by device, so the second is a lookup that finds something. The first prompt must survive: replacing it
        // would mean the user answers one device's request and the other device is paired.
        let desk = desk();
        let first = RequestId::new();
        assert!(matches!(desk.offer(first, request(peer(), "First"), "127.0.0.1:5000", 1_000), Offer::Waiting(_)));

        let Offer::Refused(answer) = desk.offer(RequestId::new(), request(peer(), "Second"), "127.0.0.1:5000", 1_001) else {
            panic!("a second request from the same device must be refused");
        };
        assert_eq!(answer.reason.as_deref(), Some(PairRefusal::Busy.as_str()));
        assert_eq!(
            desk.request_of(first).expect("the first is still there").request.profile.display_name,
            "First"
        );
        assert_eq!(desk.pending().len(), 1);
    }

    #[test]
    fn two_devices_may_each_have_a_prompt() {
        // One request at a time *per device*. Refusing the second device because the first is thinking would make one
        // user's hesitation another user's failure.
        let desk = desk();
        assert!(matches!(desk.offer(RequestId::new(), request(peer(), "Laptop"), "127.0.0.1:5000", 1_000), Offer::Waiting(_)));
        assert!(matches!(desk.offer(RequestId::new(), request(other(), "Phone"), "127.0.0.1:5000", 1_000), Offer::Waiting(_)));
        assert_eq!(desk.pending().len(), 2);
    }

    #[test]
    fn accepting_delivers_the_response_to_the_waiter() {
        let desk = desk();
        let id = RequestId::new();
        let Offer::Waiting(waiter) = desk.offer(id, request(peer(), "Laptop"), "127.0.0.1:5000", 1_000) else {
            panic!("waiting");
        };

        let log = std::cell::RefCell::new(Vec::new());
        let answered = desk.answer(id, true, writes(&log)).expect("an answer");
        assert!(answered.accepted);

        // The same response reaches the connection that is blocked on the socket, and it carries the token that was
        // written — one decision, two readers.
        let delivered = waiter.wait(Duration::from_millis(10));
        assert!(delivered.accepted);
        assert_eq!(delivered.issued_token(), answered.issued_token());
        assert_eq!(log.borrow().as_slice(), [answered.issued_token().expect("a token").to_owned()]);
        assert!(desk.pending().is_empty(), "the prompt is finished");
    }

    #[test]
    fn declining_delivers_a_refusal_and_writes_nothing() {
        let desk = desk();
        let id = RequestId::new();
        let Offer::Waiting(waiter) = desk.offer(id, request(peer(), "Laptop"), "127.0.0.1:5000", 1_000) else {
            panic!("waiting");
        };

        let log = std::cell::RefCell::new(Vec::new());
        let answered = desk.answer(id, false, writes(&log)).expect("an answer");
        assert!(!answered.accepted);
        assert_eq!(answered.reason.as_deref(), Some("declined"));
        assert!(log.borrow().is_empty(), "a refusal records nothing");

        let delivered = waiter.wait(Duration::from_millis(10));
        assert!(!delivered.accepted);
        assert!(desk.pending().is_empty());
    }

    #[test]
    fn a_write_that_fails_refuses_and_leaves_the_prompt_up() {
        // Record first, answer second. A failure means the user's decision was not carried out, so it is still theirs to
        // retry — and the dialer must not be told the pairing succeeded.
        let desk = desk();
        let id = RequestId::new();
        let Offer::Waiting(waiter) = desk.offer(id, request(peer(), "Laptop"), "127.0.0.1:5000", 1_000) else {
            panic!("waiting");
        };

        let answered = desk
            .answer(id, true, |_: &PairingRecord| Err("the disk said no".to_owned()))
            .expect("an answer");
        assert!(!answered.accepted);
        assert_eq!(answered.issued_token(), None);
        assert!(answered.reason.as_deref().is_some_and(|why| why.contains("could-not-record")));

        let delivered = waiter.wait(Duration::from_millis(10));
        assert!(!delivered.accepted, "the waiting connection is told the same thing");
        assert_eq!(desk.pending().len(), 1, "and the prompt is still there to retry");
        assert_eq!(desk.request_of(id).expect("still there").request.profile.display_name, "Laptop");
    }

    #[test]
    fn answering_twice_answers_once() {
        let desk = desk();
        let id = RequestId::new();
        let _ = desk.offer(id, request(peer(), "Laptop"), "127.0.0.1:5000", 1_000);

        let log = std::cell::RefCell::new(Vec::new());
        assert!(desk.answer(id, true, writes(&log)).is_some());
        assert!(desk.answer(id, true, writes(&log)).is_none(), "there is nothing left to answer");
        assert_eq!(log.borrow().len(), 1, "and nothing was written twice");
    }

    #[test]
    fn answering_a_request_nobody_made_is_not_an_error() {
        let desk = desk();
        let log = std::cell::RefCell::new(Vec::new());
        assert!(desk.answer(RequestId::new(), true, writes(&log)).is_none());
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn a_waiter_whose_window_closed_is_told_the_request_expired() {
        // The dialer must not be left holding an open connection with no answer: "this request expired" is something a
        // user can act on, and silence is not.
        let desk = PairingDesk::new(local(), Duration::from_millis(1));
        let Offer::Waiting(waiter) = desk.offer(RequestId::new(), request(peer(), "Laptop"), "127.0.0.1:5000", 1_000) else {
            panic!("waiting");
        };

        let delivered = waiter.wait(Duration::from_millis(50));
        assert!(!delivered.accepted);
        assert_eq!(delivered.reason.as_deref(), Some(PairRefusal::Expired.as_str()));
    }

    #[test]
    fn sweeping_drops_only_the_windows_that_closed() {
        let desk = PairingDesk::new(local(), Duration::from_millis(100));
        let _ = desk.offer(RequestId::new(), request(peer(), "Old"), "127.0.0.1:5000", 1_000);
        let _ = desk.offer(RequestId::new(), request(other(), "New"), "127.0.0.1:5000", 1_090);

        // At 1_050 the first is past its deadline (1_100 is not yet reached — it is still open); the second's is 1_190.
        assert_eq!(desk.sweep_expired(1_150), 1, "only the first window has closed");
        assert_eq!(desk.pending().len(), 1);
        assert_eq!(desk.sweep_expired(1_150), 0, "sweeping again finds nothing");
    }

    #[test]
    fn sweeping_makes_the_dialer_expire_rather_than_wait_for_ever() {
        // The desk drops the entry, which drops the sender, which closes the channel — so the connection blocked on the
        // socket is released instead of waiting for a prompt that no longer exists.
        let desk = PairingDesk::new(local(), Duration::from_millis(1));
        let Offer::Waiting(waiter) = desk.offer(RequestId::new(), request(peer(), "Laptop"), "127.0.0.1:5000", 1_000) else {
            panic!("waiting");
        };
        assert_eq!(desk.sweep_expired(2_000), 1);

        let delivered = waiter.wait(Duration::from_millis(50));
        assert!(!delivered.accepted);
        assert_eq!(delivered.reason.as_deref(), Some(PairRefusal::Expired.as_str()));
    }

    #[test]
    fn the_prompt_carries_the_code_the_other_screen_derives() {
        let desk = desk();
        let id = RequestId::new();
        let _ = desk.offer(id, request(peer(), "Laptop"), "127.0.0.1:5000", 1_000);

        let shown = desk.request_of(id).expect("on the desk");
        assert_eq!(shown.verification_code, crate::pairing::verification_code(peer(), local()));
        assert_eq!(shown.verification_code.chars().count(), 6);
    }
}