//! What an inbound connection does when it is carrying a file.
//!
//! # Where this sits
//!
//! [`crate::listener`] owns the socket: it accepts, handshakes, and reads frames. This owns the **state** — a connection
//! that is mid-transfer is one where a `TransferRequest` has been seen and blocks are arriving, and something has to
//! remember which file they belong to. That memory is here, so the socket code stays a loop over frames.
//!
//! # Why the file name from the peer is not trusted
//!
//! Because it arrives over the network and it becomes a **path**. A name of `../../../.ssh/authorized_keys`, or one
//! containing a NUL, or one that is a Windows device like `CON`, would either escape the inbox or fail in a way the user
//! cannot diagnose. The name is passed through the store's `sanitise_component`, which is the same rule plugin identifiers
//! already follow — one sanitiser for every untrusted name that becomes part of a path, rather than a second one here that
//! would drift.
//!
//! # Why the destination is inside the data directory
//!
//! Because that is the only directory this process may certainly write to, and a kernel that guessed a user's Downloads
//! folder would be one that writes where it was not asked to. A file lands in `<data>/inbox`, and moving it from there is
//! the interface's job, where the user can be asked.

use std::path::{Path, PathBuf};

use crate::link::PeerLink;
use synra_protocol::ids::TraceId;
use crate::session::{self, Receiving, Received};

/// The directory incoming files land in, under the data directory.
pub const INBOX_DIR: &str = "inbox";

/// How long a transfer in progress may be quiet before the connection is abandoned.
///
/// # Why this is generous
///
/// Because a transfer is not idle: blocks are arriving, and each one is evidence the peer is there. What this bounds is a
/// peer that stops mid-file — which is worth waiting a long time for, because giving up throws away a transfer that was
/// almost complete. The connection as a whole is bounded by the process that owns it, not by this.
const TRANSFER_PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);

/// The shared item an envelope carries, when it carries one.
///
/// # ★ Why the event name is not enough
///
/// Because `_synra.clipboard.received` is how a peer's shared text arrives, and everything a plugin is asked about — the
/// text, the mime, which device sent it — is in the body. The daemon reported the name and dropped the body, so a share
/// could arrive and be announced while nothing could act on it.
///
/// # Why a body that cannot be read is `None` rather than an error
///
/// Because a peer may send a well-formed envelope this build cannot interpret, and that is not a broken link: the frame
/// was delivered, the connection is working, and there is simply nothing here to route. Returning an error would make the
/// caller close a link over a message it merely did not understand.
fn share_of(envelope: &synra_protocol::envelope::Envelope) -> Option<synra_protocol::inbound::ShareItem> {
    if envelope.event.as_str() != synra_protocol::event::builtin::CLIPBOARD_RECEIVED {
        return None;
    }
    // ★ The device in the payload is the sender's **claim**; the envelope's own `from` is what the handshake established.
    // The claim is dropped rather than trusted, so a peer cannot attribute its share to another device.
    let text = crate::text_from(envelope).ok()?;
    Some(synra_protocol::inbound::ShareItem {
        from: envelope.from,
        mime: text.mime,
        text: Some(text.text),
        // A text message carries no transfer, and an id invented here would name a transfer that does not exist.
        transfers: Vec::new(),
        context_id: None,
    })
}

/// What to do with a message that arrived on an inbound connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// A transfer was proposed and accepted; blocks may now arrive.
    Accepted {
        /// Which transfer.
        transfer_id: String,
        /// Which file it will become.
        file_name: String,
    },
    /// A block was stored.
    Stored {
        /// Which block.
        index: u32,
        /// Whether it had already arrived.
        duplicate: bool,
    },
    /// The transfer finished and the file was verified.
    Finished {
        /// Where it is.
        path: PathBuf,
        /// How large.
        byte_length: u64,
        /// Which plugin it is a bundle for, when it is one.
        ///
        /// Carried rather than guessed from the file name: `proposed_name` builds `plugin-<id>.wasm`, and a consumer
        /// that parsed that back would be wrong the first time somebody sent a file called `plugin-notes.wasm`.
        bundle: Option<synra_protocol::ids::PluginId>,
    },
    /// The transfer ended without a usable file.
    Failed {
        /// Why.
        why: String,
    },
    /// A message for another feature, reported rather than dropped.
    ///
    /// # Why this is not `Ignored`
    ///
    /// Because "not a transfer" and "nothing to do with this connection" are different, and the difference is what a user
    /// is told. A peer that sent text has sent a message this kernel received — there is simply no event bus wired up to
    /// deliver it — and a daemon that reported neither would be one whose log looks identical whether the message arrived
    /// or was lost in the network.
    Delivered {
        /// The event the message carried.
        event: String,
        /// What was shared, when the message was a share this kernel can route.
        ///
        /// ★ Why the payload travels after all.
        ///
        /// This variant carried the event's **name** alone, which was right for its original purpose — reporting that
        /// something arrived — and wrong for the one that matters: a peer's shared text is precisely what the router
        /// needs, and everything else about it (the mime, which device sent it) is in the body. A name is not enough to
        /// ask a plugin "can you handle this?", so the share was reported and dropped.
        ///
        /// `None` for a message that is not a share, and for one whose body could not be read. The two are the same to
        /// the caller: there is nothing to route.
        share: Option<synra_protocol::inbound::ShareItem>,
    },
    /// A pairing request this kernel has an opinion about, and the answer to send back.
    ///
    /// # Why the envelope is not rebuilt from the event name
    ///
    /// Because a pairing answer is a *reply*: it carries the request's id, the request's trace, and is addressed to the
    /// device that asked. All three come from the envelope that arrived, which is here and is not available to whoever
    /// would otherwise construct the reply from `Delivered`'s single string.
    Pairing {
        /// What to tell the dialer, or `None` when the request was refused before it reached the desk.
        answer: Option<PairingAnswer>,
        /// The message that arrived, so the reply can be addressed and correlated.
        request: Box<synra_protocol::envelope::Envelope>,
    },
    /// A message this connection has nothing to do with.
    Ignored,
    /// Nothing arrived and the wait is over, so the connection has nothing more to say.
    ///
    /// # Why this is not `Failed`
    ///
    /// Because a peer that has gone quiet has not done anything wrong, and a transfer that is mid-flight has a
    /// `receiving` in progress — so this is only reached when there is **no** transfer. Treating it as a failure would
    /// report every idle connection as a fault, and treating it as `Ignored` would make the caller loop for ever.
    Idle,
}

/// What to do about a pairing request, as the dispatch layer sees it.
///
/// # Why this is two cases rather than one `Option`
///
/// Because "answer now" and "wait for a user" are different instructions to the connection, and an `Option<PairResponse>`
/// collapses them: `None` could only mean "send nothing", which for a request on the desk would be right and for a request
/// that failed to parse would leave the dialer waiting for an answer nobody will ever give it.
///
/// # Why the waiter is behind a lock and an [`Arc`]
///
/// Because a `Waiter` holds a channel receiver, which can be neither cloned nor compared — and [`Decision`] is both, so
/// a caller may keep one and a test may compare two. The alternative was to drop those from [`Decision`], a public type
/// whose other variants a reader compares for the ordinary reason: to say which case a decision was.
///
/// The lock is honest about what a waiter is: **something taken once**. A caller gets it by taking it out, and a second
/// caller finds nothing rather than blocking for ever on a receiver that has already been consumed.
#[derive(Debug)]
#[non_exhaustive]
pub enum PairingAnswer {
    /// Send this to the dialer now. The link stays up, so it may ask again.
    Now(synra_protocol::session::PairResponse),
    /// The request is on the desk. Block on this until a user decides, then send what it produces.
    Waiting(std::sync::Arc<parking_lot::Mutex<Option<crate::pairing::Waiter>>>),
}

impl PairingAnswer {
    /// Takes the waiter out, once.
    #[must_use]
    pub fn take_waiter(&self) -> Option<crate::pairing::Waiter> {
        match self {
            Self::Now(_) => None,
            Self::Waiting(slot) => slot.lock().take(),
        }
    }
}

impl Clone for PairingAnswer {
    /// Clones the immediately-available answer, and shares the waiter.
    ///
    /// A waiter is not duplicable: two callers blocking on one channel would each receive the same answer, which for a
    /// pairing means two responses written to two connections for one request.
    fn clone(&self) -> Self {
        match self {
            Self::Now(answer) => Self::Now(answer.clone()),
            Self::Waiting(slot) => Self::Waiting(std::sync::Arc::clone(slot)),
        }
    }
}

impl PartialEq for PairingAnswer {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Now(mine), Self::Now(theirs)) => mine == theirs,
            // Two waiters are the same when they are the same waiter. Comparing what they will deliver would mean
            // blocking on both, which is not something a comparison may do.
            (Self::Waiting(mine), Self::Waiting(theirs)) => std::sync::Arc::ptr_eq(mine, theirs),
            _ => false,
        }
    }
}

impl Eq for PairingAnswer {}

/// A connection's transfer state.
///
/// # Why one transfer at a time
///
/// Because a connection carries one conversation, and the protocol's `transfer_id` is what says so. Two transfers on one
/// link would be legal, and nothing here would interleave them correctly — so the second proposal is refused rather than
/// silently mixed into the first, which is the failure that would produce a corrupt file with no clue why.
#[derive(Debug, Default)]
pub struct Inbox {
    receiving: Option<Receiving>,
    /// The trace the transfer's messages share, remembered when the proposal is accepted.
    ///
    /// Held here rather than read off [`Receiving`] at each report, because reading it would need the same `&self` the
    /// report already borrows — and a trace is the connection's, not the transfer's.
    trace: TraceId,
    inbox: PathBuf,
}

impl Inbox {
    /// Prepares to receive into `<data>/inbox`.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        Self { receiving: None, trace: TraceId::new(), inbox: data_dir.join(INBOX_DIR) }
    }

    /// Whether a transfer is in progress.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.receiving.is_some()
    }

    /// The directory files land in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.inbox
    }

    /// Reads one inbound message and does whatever it calls for.
    ///
    /// # Errors
    ///
    /// Whatever the session reports: a link failure, a malformed message, or a file that cannot be written. A transfer
    /// that fails to *verify* is not an error — it is [`Decision::Failed`], because the transfer ended and how it ended is
    /// what the caller reports.
    pub fn absorb(
        &mut self,
        link: &mut PeerLink,
        now_ms: i64,
        patience: std::time::Duration,
        pairing: &crate::pairing::PairingDesk,
        peer_address: &str,
    ) -> Result<Decision, crate::SessionError> {
        // * The patience is re-armed on **every** call, and it is what bounds a *quiet* peer rather than a slow one. An
        // earlier version computed the deadline once from the connection's start, so a receiver that was still working
        // through a large transfer ran out of patience and closed the link with the sender's completion unread -- which is
        // exactly what an end-to-end run showed: the file arrived byte-for-byte and the confirmation was never sent.
        //
        // A transfer in progress gets a long wait, because blocks are arriving and each arrival is the evidence that the
        // peer is still there. A connection with nothing in progress gets the short one, so a peer that connects and says
        // nothing is still abandoned promptly.
        let patience = if self.receiving.is_some() { TRANSFER_PATIENCE } else { patience };
        let deadline = std::time::Instant::now() + patience;
        // ★ The proposal arrives as an envelope, before there is anything to receive into. A block that arrives with no
        // transfer in progress is a protocol violation rather than something to guess about — the peer is sending part of
        // something this end never agreed to.
        if self.receiving.is_none() {
            // * A quiet link is not a closed one. `LinkError::TimedOut` means the socket waited out its own shorter
            // timeout, which for a link that is idle between messages is ordinary -- and treating it as a fault closed the
            // connection while the peer's completion was still on its way. That is what an end-to-end run showed: the
            // sender sent its completion and the receiver closed the link before reading it.
            let inbound = match read_patiently(link, deadline) {
                Ok(inbound) => inbound,
                // Quiet past the deadline with nothing in flight: the connection has nothing more to say.
                Err(crate::LinkError::TimedOut) => return Ok(Decision::Idle),
                Err(error) => return Err(crate::SessionError::Link(error)),
            };
            let Inbound::Envelope(envelope) = inbound else {
                return Ok(Decision::Failed {
                    why: "a block arrived before any transfer was proposed".to_owned(),
                });
            };
            if session::classify(&envelope) != Some(session::Message::Request) {
                // ★ A pairing request is the one non-transfer message this kernel answers rather than merely reports. It is
                // handled before the transfer path because it is not one: there is no file, no `transfer_id`, and no block
                // to follow — and a pairing request reported as `Delivered` would leave a user's other device waiting for an
                // answer this kernel never sends while the prompt, if it appeared at all, sat unanswered on a screen.
                if envelope.event.as_str() == synra_protocol::event::events::PAIR_REQUEST {
                    return Ok(self.pairing_request(&envelope, pairing, peer_address));
                }
                return Ok(Decision::Delivered {
                    event: envelope.event.as_str().to_owned(),
                    share: share_of(&envelope),
                });
            }
            let name = proposed_name(&envelope)?;
            let destination = self.destination_for(&name);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(|error| crate::SessionError::Payload {
                    message: "inbox",
                    why: format!("could not create {}: {error}", parent.display()),
                })?;
            }
            let trace = envelope.trace_id;
            let receiving = Receiving::accept(&envelope, &destination, trace)?;
            let transfer_id = receiving.transfer_id().to_string();
            self.trace = trace;
            self.receiving = Some(receiving);
            return Ok(Decision::Accepted { transfer_id, file_name: name });
        }

        let Some(receiving) = self.receiving.as_mut() else {
            return Ok(Decision::Ignored);
        };
        match receiving.absorb(link, now_ms, deadline)? {
            Received::Block { index, duplicate } => {
                // ★ The report the sender is waiting for, and the daemon never sent it. Its absence is what made **every**
                // transfer cost one whole `HELLO_TIMEOUT`: the sender writes a window and then blocks on a report that never
                // comes, so it only proceeds when its socket read times out — six seconds for a 2 KB file, six for 300 KB,
                // and six per window for anything larger, which is why a 5 MB file ran to the sender's 300-second deadline.
                //
                // Only the engine and the tests ever called this. The daemon, which is the only thing that runs a real
                // transfer, did not — so a fix that lived in a function nothing ran looked like it had been tried.
                session::report_progress(link, receiving.receiver(), self.trace, now_ms)?;
                Ok(Decision::Stored { index, duplicate })
            }
            Received::Verified { .. } => {
                // The transfer is over, so the state is released whatever happens to the file afterwards.
                let path = receiving.path().to_path_buf();
                let byte_length = receiving.byte_length();
                // Taken before the receiver is dropped, because this is the moment the "what it was" is about to be
                // lost — after `self.receiving = None` there is a path and nothing else.
                let bundle = receiving.bundle().cloned();
                self.receiving = None;
                Ok(Decision::Finished { path, byte_length, bundle })
            }
            Received::Failed { why, .. } => {
                self.receiving = None;
                Ok(Decision::Failed { why })
            }
            Received::Aborted { reason, .. } => {
                self.receiving = None;
                Ok(Decision::Failed { why: format!("the peer gave up: {reason:?}") })
            }
            // A message the transfer has nothing to do with, while a transfer *is* in progress: reported so it is not lost
            // between two files.
            Received::Ignored => Ok(Decision::Delivered {
                event: "unknown".to_owned(),
                // Nothing was recognised, so there is nothing to route.
                share: None,
            }),
            // `Received` is `#[non_exhaustive]`, so a variant this build does not know is treated as a message it has
            // nothing to do with rather than as a reason to fail the connection.
            _ => Ok(Decision::Ignored),
        }
    }

    /// Takes an arriving pairing request and produces the answer, if there is one yet.
    ///
    /// # Why a malformed request is refused rather than failed
    ///
    /// Because the link is not at fault. A peer that sends a pairing request this build cannot read has made a mistake in
    /// one message, and closing the connection would take the transfer channel with it — the protocol document's rule
    /// that a refusal does not end a link applies to a request that cannot be understood for the same reason it applies
    /// to one that is declined.
    fn pairing_request(
        &self,
        envelope: &synra_protocol::envelope::Envelope,
        pairing: &crate::pairing::PairingDesk,
        peer_address: &str,
    ) -> Decision {
        let refused = |why: String| Decision::Pairing {
            answer: Some(PairingAnswer::Now(synra_protocol::session::PairResponse::refused(why))),
            request: Box::new(envelope.clone()),
        };

        let Some(json) = envelope.payload_str() else {
            return refused("the pairing request carried no payload".to_owned());
        };
        let Ok(request) = serde_json::from_str::<synra_protocol::session::PairRequest>(json) else {
            return refused("the pairing request was not readable".to_owned());
        };

        // Registered on the shared desk, which hands back the waiter this connection blocks on. The answer arrives from
        // whoever decides, through the channel the desk holds — so it does not matter that the user is not on this
        // connection, which is the whole reason the desk is shared.
        let answer = match pairing.offer(envelope.request_id, request, peer_address, synra_store::sqlite::now_ms()) {
            crate::pairing::Offer::Waiting(waiter) => Some(PairingAnswer::Waiting(
                std::sync::Arc::new(parking_lot::Mutex::new(Some(waiter))),
            )),
            crate::pairing::Offer::Refused(answer) => Some(PairingAnswer::Now(answer)),
            // ★ No wildcard, and the arm that was here is worth a sentence because it was right where it stood.
            //
            // It refused an offer this build did not recognise, and its comment said it existed because `Offer` is
            // `#[non_exhaustive]`. That is a promise made *to other crates*: within the crate that defines `Offer`, a new
            // variant is not something a match may ignore — it is a compile error. This module was in the daemon when the
            // arm was written and is in `synra-core` now, so the arm became unreachable, and removing it makes a future
            // variant fail here rather than be silently refused at run time.
        };

        Decision::Pairing { answer, request: Box::new(envelope.clone()) }
    }

    /// Where a file with this name goes.
    ///
    /// # Why the name is sanitised and then made unique
    ///
    /// Sanitised because it is untrusted and becomes a path. Made unique because two files called `report.pdf` from two
    /// devices are both legitimate, and the second overwriting the first would lose a file the user was told had arrived.
    /// The suffix is the transfer's identifier, which is already unique and needs no counter to be collision-free.
    fn destination_for(&self, name: &str) -> PathBuf {
        let safe = synra_store::sanitise_component(name);
        // A name that sanitises to nothing — every character rejected — still needs a file.
        let stem = if safe.trim_matches(['.', '-']).is_empty() { "file".to_owned() } else { safe };
        self.inbox.join(stem)
    }
}

/// Reads until a frame arrives or the deadline passes.
///
/// # Why a timeout is not reported
///
/// Because a link between two devices is idle most of the time, and the socket timeout is a short one — a read that waits
/// it out says nothing about whether the peer is still there. The deadline the caller owns is what bounds the wait, so a
/// message that arrives late is still read. Returning `Err` only for a link that has genuinely failed keeps "the peer went
/// away" meaning what it says.
///
/// # Errors
///
/// [`crate::LinkError`] for a link that failed rather than one that was quiet, and the same for a malformed frame.
fn read_patiently(
    link: &mut PeerLink,
    deadline: std::time::Instant,
) -> Result<Inbound, crate::LinkError> {
    loop {
        // ★ The link's own timeout is capped by what is left of the caller's deadline, so "give up at five seconds" gives
        // up at five seconds rather than at the link's six. Without the cap this loop waited the link's whole timeout even
        // when the deadline had already passed, which is what made a bounded test hang.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        link.set_read_timeout(Some(remaining));
        match link.receive_inbound() {
            Ok(inbound) => {
                link.set_read_timeout(None);
                return Ok(inbound);
            }
            Err(crate::LinkError::TimedOut) => {
                if std::time::Instant::now() >= deadline {
                    link.set_read_timeout(None);
                    return Err(crate::LinkError::TimedOut);
                }
            }
            Err(error) => {
                link.set_read_timeout(None);
                return Err(error);
            }
        }
    }
}

/// The file name a proposal carries.
fn proposed_name(envelope: &synra_protocol::envelope::Envelope) -> Result<String, crate::SessionError> {
    let raw = envelope.payload.as_ref().ok_or_else(|| crate::SessionError::Payload {
        message: "request",
        why: "the envelope carries no payload".to_owned(),
    })?;
    let request: synra_protocol::session::TransferRequest =
        serde_json::from_str(raw.get()).map_err(|error| crate::SessionError::Payload {
            message: "request",
            why: error.to_string(),
        })?;
    Ok(match request.meta {
        synra_protocol::session::TransferMeta::Attachment { file_name, .. } => file_name,
        // A plugin bundle is not something this kernel installs yet, and its "name" is a plugin identifier rather than a
        // file. Named as such so the file in the inbox says what it is.
        synra_protocol::session::TransferMeta::PluginBundle { plugin_id, .. } => {
            format!("plugin-{plugin_id}.wasm")
        }
        // `TransferMeta` is `#[non_exhaustive]`, so a kind this build does not know is named rather than guessed at — a
        // newer peer sending something this one cannot describe still gets a file rather than a failure.
        _ => "transfer".to_owned(),
    })
}

use crate::Inbound;

/// Decides what a dialler's token means, using this device's own record of the pairing.
///
/// # ★ Why this is a function over a database rather than code inside the handshake closure
///
/// The handshake takes a closure, and the closure it was given answered `Unknown` unconditionally — which made every link
/// untrusted, every device list empty, and `send` refuse every device by name. The reasoning it needed is two steps: find
/// the token this device stored for the dialler, then decide what the presented token means. Neither step needs a socket,
/// so neither belongs inside a closure the handshake only calls once.
///
/// [`crate::peer::pairing_state`] is the second step. This is the first, plus the error policy between them.
///
/// # ★ It lived in the daemon until the listener moved, and the two always travelled together
///
/// A listener that accepts a connection has to answer "do I trust this peer", and the answer comes from the store. Leaving
/// the read behind would have made the library's listener take a closure it cannot implement, which is the shape of
/// dependency that keeps a second host from reusing the first's work.
///
/// # Why a database that cannot be read answers `Stale` rather than `Current`
///
/// Because the only safe direction to fail in is the one that asks the user to pair again. `Current` is what lets a link
/// carry business messages, so a lookup that could not run must not produce it — and `Stale` is the honest description of
/// a device whose record this build cannot read.
#[must_use]
pub fn pairing_state_for(
    db: &synra_store::SynraDb,
    device_id: synra_protocol::ids::DeviceId,
    presented: Option<&synra_protocol::handshake::LinkToken>,
) -> synra_protocol::handshake::PairingState {
    let stored = match db.link_token_for(&device_id.to_string()) {
        Ok(stored) => stored,
        Err(error) => {
            // Said out loud rather than swallowed: a device that cannot read its own pairings will refuse every peer, and
            // the reason is the only thing that distinguishes that from "nobody has paired with us".
            eprintln!("synra: the pairing record could not be read: {error}");
            return synra_protocol::handshake::PairingState::Stale;
        }
    };

    crate::peer::pairing_state(stored.as_deref(), presented)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory that removes itself.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "synra-inbox-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a temp directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ── The name rules ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_name_that_would_escape_the_inbox_does_not() {
        // ★ The name arrives over the network and becomes a path. A traversal that survived would write wherever the peer
        // asked, which is the whole of the user's home directory.
        let dir = TempDir::new("traversal");
        let inbox = Inbox::new(dir.path());
        for hostile in [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config",
            "....//....//etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\notepad.exe",
        ] {
            let destination = inbox.destination_for(hostile);
            assert!(
                destination.starts_with(dir.path().join(INBOX_DIR)),
                "{hostile} escaped to {}",
                destination.display()
            );
        }
    }

    #[test]
    fn a_name_is_still_recognisable_after_sanitising() {
        // Sanitising is not meant to destroy the name: the user has to recognise the file they were sent.
        let dir = TempDir::new("recognisable");
        let inbox = Inbox::new(dir.path());
        let destination = inbox.destination_for("quarterly report (final).pdf");
        let name = destination.file_name().expect("a file name").to_string_lossy().into_owned();
        assert!(name.contains("quarterly"), "{name}");
        assert!(name.contains("report"), "{name}");
        assert!(name.ends_with(".pdf"), "{name}");
    }

    #[test]
    fn a_name_of_nothing_usable_still_produces_a_file() {
        // Every character rejected is possible, and a transfer that had nowhere to write would fail for a reason the user
        // cannot act on.
        let dir = TempDir::new("empty-name");
        let inbox = Inbox::new(dir.path());
        let destination = inbox.destination_for("...");
        assert!(destination.file_name().is_some());
        assert!(!destination.file_name().expect("a name").is_empty());
    }

    #[test]
    fn a_new_inbox_is_empty_and_lands_under_the_data_directory() {
        let dir = TempDir::new("new");
        let inbox = Inbox::new(dir.path());
        assert!(!inbox.is_busy());
        assert_eq!(inbox.directory(), dir.path().join(INBOX_DIR));
    }

    // ── The pairing request path ──────────────────────────────────────────────────────────────

    /// A desk for this device, with the protocol's own pairing window.
    fn desk() -> crate::pairing::PairingDesk {
        crate::pairing::PairingDesk::new(local(), synra_protocol::session::SessionTimeouts::default().pairing)
    }

    /// A local device id for a request addressed to us.
    fn local() -> synra_protocol::ids::DeviceId {
        "01a139a9-8f3c-72ce-9c96-2b2c81f14551".parse().expect("a valid device id")
    }

    /// A text-message envelope, which is how a peer shares something.
    fn share_envelope(payload: &str, from: &str) -> synra_protocol::envelope::Envelope {
        let spec = synra_protocol::envelope::OutboundSpec {
            event: synra_protocol::event::EventName::parse(
                synra_protocol::event::builtin::CLIPBOARD_RECEIVED,
            )
            .expect("a valid event name"),
            target: local(),
            from: from.parse().expect("a valid device id"),
            trace_id: TraceId::new(),
            sent_at_ms: 1_000,
            ttl_ms: None,
        };
        let raw =
            serde_json::value::RawValue::from_string(payload.to_owned()).expect("valid json");
        synra_protocol::envelope::Envelope::outbound(spec, Some(&raw))
            .expect("valid json")
    }

    #[test]
    fn a_shared_message_becomes_a_share_the_router_can_ask_about() {
        // ★ The payload, which used to be dropped.
        //
        // `Decision::Delivered` carried the event's **name** and nothing else, so a peer's shared text arrived, was
        // reported, and could not be routed: a plugin is asked about the text, the mime and the sender, and all three are
        // in the body.
        let envelope = share_envelope(
            &serde_json::json!({
                "text": "https://example.com",
                "mime": "text/plain",
                "fromDeviceId": "01a139a9-8f3c-72ce-9c96-2b2c81f14552",
            })
            .to_string(),
            "01a139a9-8f3c-72ce-9c96-2b2c81f14552",
        );

        let share = share_of(&envelope).expect("a message is a share");

        assert_eq!(share.text.as_deref(), Some("https://example.com"));
        assert_eq!(share.mime, "text/plain");
        // A text message carries no transfer, and an id invented here would name a transfer that does not exist.
        assert!(share.transfers.is_empty());
    }

    #[test]
    fn a_share_is_attributed_to_the_envelope_rather_than_to_its_own_body() {
        // ★ The body's `fromDeviceId` is a **claim**; the envelope's `from` is what the handshake established.
        //
        // Taking the body's word would let a peer attribute its share to another device — so a prompt would name the wrong
        // machine, and a plugin deciding "did this come from the device I trust" would be answered by the sender.
        let envelope = share_envelope(
            &serde_json::json!({
                "text": "hello",
                "mime": "text/plain",
                // A different device from the one that actually sent it.
                "fromDeviceId": "01a139a9-0000-7000-8000-0000000000ff",
            })
            .to_string(),
            "01a139a9-8f3c-72ce-9c96-2b2c81f14552",
        );

        let share = share_of(&envelope).expect("a message is a share");

        assert_eq!(share.from.to_string(), "01a139a9-8f3c-72ce-9c96-2b2c81f14552");
    }

    #[test]
    fn a_message_that_is_not_a_share_routes_nothing() {
        // A pairing request is answered by the desk, and an event this build does not know is reported. Neither is a
        // share, and asking plugins about one would be asking them about something no user shared.
        assert!(share_of(&pair_envelope(&request_json("Phone"))).is_none());

        // And a share whose body cannot be read is `None` rather than an error: the frame arrived and the link is
        // working, so closing it over a message this build merely cannot interpret would be worse than dropping it.
        let unreadable = share_envelope("\"not an object\"", "01a139a9-8f3c-72ce-9c96-2b2c81f14552");
        assert!(share_of(&unreadable).is_none());
        // Including one with no payload at all.
        let spec = synra_protocol::envelope::OutboundSpec {
            event: synra_protocol::event::EventName::parse(
                synra_protocol::event::builtin::CLIPBOARD_RECEIVED,
            )
            .expect("a valid event name"),
            target: local(),
            from: "01a139a9-8f3c-72ce-9c96-2b2c81f14552".parse().expect("a device id"),
            trace_id: TraceId::new(),
            sent_at_ms: 1_000,
            ttl_ms: None,
        };
        let none: Option<&serde_json::value::RawValue> = None;
        let empty = synra_protocol::envelope::Envelope::outbound(spec, none).expect("builds");
        assert!(share_of(&empty).is_none());
    }

    /// A pairing request envelope, with the payload spelled as the wire spells it.
    fn pair_envelope(payload: &str) -> synra_protocol::envelope::Envelope {
        let spec = synra_protocol::envelope::OutboundSpec {
            event: synra_protocol::event::EventName::parse(synra_protocol::event::events::PAIR_REQUEST)
                .expect("a valid event name"),
            target: local(),
            from: "01a139a9-8f3c-72ce-9c96-2b2c81f14552".parse().expect("a valid device id"),
            trace_id: TraceId::new(),
            sent_at_ms: 1_000,
            ttl_ms: None,
        };
        // The payload is a JSON **document**, not a string holding one: the encoder serialises whatever it is given, so
        // handing it `json!(payload)` would nest the document inside a JSON string and produce a request no parser
        // accepts. A helper that got this wrong would report a failure in the code rather than in the helper.
        let raw = serde_json::value::RawValue::from_string(payload.to_owned())
            .expect("the payload is valid json");
        synra_protocol::envelope::Envelope::outbound(spec, Some(&raw))
            .expect("the payload is valid json")
    }

    /// A well-formed request payload.
    fn request_json(name: &str) -> String {
        serde_json::json!({
            "profile": {
                "deviceId": "01a139a9-8f3c-72ce-9c96-2b2c81f14552",
                "displayName": name,
                "platform": "desktop",
                "appVersion": "0.1.0"
            }
        })
        .to_string()
    }

    #[test]
    fn a_readable_pairing_request_waits_for_a_user_rather_than_being_answered() {
        let inbox = Inbox::new(std::env::temp_dir().as_path());
        let pairing = desk();

        let decision = inbox.pairing_request(&pair_envelope(&request_json("Laptop")), &pairing, "127.0.0.1:5000");
        let Decision::Pairing { answer, request } = decision else {
            panic!("a pairing request must produce a pairing decision");
        };
        assert!(
                matches!(answer, Some(PairingAnswer::Waiting(_))),
                "the request is on the desk and this connection waits for a user"
            );
        assert_eq!(
            request.event.as_str(),
            synra_protocol::event::events::PAIR_REQUEST,
            "the request travels with the decision so the answer can be addressed from it"
        );
        assert_eq!(pairing.pending().len(), 1, "and the request is now on the desk");
    }

    #[test]
    fn a_second_request_while_one_waits_is_refused_without_ending_the_link() {
        // Rule 2 of the pairing section, and rule 6: a refusal is an answer, not a reason to disconnect.
        let inbox = Inbox::new(std::env::temp_dir().as_path());
        let pairing = desk();
        let _ = inbox.pairing_request(&pair_envelope(&request_json("First")), &pairing, "127.0.0.1:5000");

        let decision = inbox.pairing_request(&pair_envelope(&request_json("Second")), &pairing, "127.0.0.1:5000");
        let Decision::Pairing { answer, .. } = decision else {
            panic!("a pairing request must produce a pairing decision");
        };
        let PairingAnswer::Now(answer) = answer.expect("the second request is answered immediately") else {
                panic!("a busy refusal is sent now, not waited on");
            };
        assert!(!answer.accepted);
        assert_eq!(answer.reason.as_deref(), Some("busy"));
    }

    #[test]
    fn a_pairing_request_that_cannot_be_read_is_refused_rather_than_failing_the_link() {
        // A peer that sends a mistake in one message has not broken the connection, and closing it would take any
        // transfer on that link down for a reason the user cannot act on.
        let inbox = Inbox::new(std::env::temp_dir().as_path());
        let pairing = desk();

        for payload in [r#""a string, not an object""#, r#"{"profile":{}}"#] {
            let decision = inbox.pairing_request(&pair_envelope(payload), &pairing, "127.0.0.1:5000");
            let Decision::Pairing { answer, .. } = decision else {
                panic!("a pairing request must produce a pairing decision");
            };
            let PairingAnswer::Now(answer) = answer.expect("an unreadable request is answered immediately") else {
                    panic!("an unreadable request is refused now, not waited on");
                };
            assert!(!answer.accepted, "payload {payload} must be refused");
            assert_eq!(answer.issued_token(), None, "a refusal issues no token");
        }
        assert!(pairing.pending().is_empty(), "an unreadable request must not reach the prompt");
    }

    #[test]
    fn a_pairing_request_with_no_payload_is_refused() {
        let inbox = Inbox::new(std::env::temp_dir().as_path());
        let pairing = desk();

        let spec = synra_protocol::envelope::OutboundSpec {
            event: synra_protocol::event::EventName::parse(synra_protocol::event::events::PAIR_REQUEST)
                .expect("a valid event name"),
            target: local(),
            from: "01a139a9-8f3c-72ce-9c96-2b2c81f14552".parse().expect("a valid device id"),
            trace_id: TraceId::new(),
            sent_at_ms: 1_000,
            ttl_ms: None,
        };
        let bare = synra_protocol::envelope::Envelope::outbound::<()>(spec, None)
            .expect("a payload-less envelope is valid");

        let Decision::Pairing { answer, .. } = inbox.pairing_request(&bare, &pairing, "127.0.0.1:5000") else {
            panic!("a pairing request must produce a pairing decision");
        };
        let PairingAnswer::Now(answer) = answer.expect("answered immediately") else {
                panic!("a payload-less request is refused now, not waited on");
            };
            assert!(!answer.accepted);
    }
}
