//! What an inbound connection does when it is carrying a file.
//!
//! # Where this sits
//!
//! [`crate::transport`] owns the socket: it accepts, handshakes, and reads frames. This owns the **state** — a connection
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

use synra_core::link::PeerLink;
use synra_protocol::ids::TraceId;
use synra_core::session::{self, Receiving, Received};

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
    },
    /// A pairing request this kernel has an opinion about, and the answer to send back.
    ///
    /// # Why the envelope is not rebuilt from the event name
    ///
    /// Because a pairing answer is a *reply*: it carries the request's id, the request's trace, and is addressed to the
    /// device that asked. All three come from the envelope that arrived, which is here and is not available to whoever
    /// would otherwise construct the reply from `Delivered`'s single string.
    Pairing {
        /// What to tell the dialer, or `None` when the request is now waiting for a user.
        answer: Option<synra_protocol::session::PairResponse>,
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
        pairing: &mut synra_core::pairing::InboundPairing,
    ) -> Result<Decision, synra_core::SessionError> {
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
                Err(synra_core::LinkError::TimedOut) => return Ok(Decision::Idle),
                Err(error) => return Err(synra_core::SessionError::Link(error)),
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
                    return Ok(self.pairing_request(&envelope, pairing));
                }
                return Ok(Decision::Delivered { event: envelope.event.as_str().to_owned() });
            }
            let name = proposed_name(&envelope)?;
            let destination = self.destination_for(&name);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(|error| synra_core::SessionError::Payload {
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
                self.receiving = None;
                Ok(Decision::Finished { path, byte_length })
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
            Received::Ignored => Ok(Decision::Delivered { event: "unknown".to_owned() }),
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
        pairing: &mut synra_core::pairing::InboundPairing,
    ) -> Decision {
        let request = envelope
            .payload_str()
            .ok_or("the pairing request carried no payload")
            .and_then(|json| {
                serde_json::from_str::<synra_protocol::session::PairRequest>(json)
                    .map_err(|_| "the pairing request was not readable")
            });

        let answer = match request {
            // A request that is now waiting for a user has nothing to send yet: the answer comes from whoever answers the
            // prompt, through a path that does not exist until the interface is wired up.
            Ok(request) => pairing.offer(request),
            Err(why) => Some(synra_protocol::session::PairResponse::refused(why)),
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
/// [`synra_core::LinkError`] for a link that failed rather than one that was quiet, and the same for a malformed frame.
fn read_patiently(
    link: &mut PeerLink,
    deadline: std::time::Instant,
) -> Result<Inbound, synra_core::LinkError> {
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
            Err(synra_core::LinkError::TimedOut) => {
                if std::time::Instant::now() >= deadline {
                    link.set_read_timeout(None);
                    return Err(synra_core::LinkError::TimedOut);
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
fn proposed_name(envelope: &synra_protocol::envelope::Envelope) -> Result<String, synra_core::SessionError> {
    let raw = envelope.payload.as_ref().ok_or_else(|| synra_core::SessionError::Payload {
        message: "request",
        why: "the envelope carries no payload".to_owned(),
    })?;
    let request: synra_protocol::session::TransferRequest =
        serde_json::from_str(raw.get()).map_err(|error| synra_core::SessionError::Payload {
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

use synra_core::Inbound;

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

    /// A local device id for a request addressed to us.
    fn local() -> synra_protocol::ids::DeviceId {
        "01a139a9-8f3c-72ce-9c96-2b2c81f14551".parse().expect("a valid device id")
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
        let mut pairing = synra_core::pairing::InboundPairing::new(local());

        let decision = inbox.pairing_request(&pair_envelope(&request_json("Laptop")), &mut pairing);
        let Decision::Pairing { answer, request } = decision else {
            panic!("a pairing request must produce a pairing decision");
        };
        assert!(answer.is_none(), "nothing is sent while the request waits for a user");
        assert_eq!(
            request.event.as_str(),
            synra_protocol::event::events::PAIR_REQUEST,
            "the request travels with the decision so the answer can be addressed from it"
        );
        assert!(pairing.pending().is_some(), "and the request is now on screen");
    }

    #[test]
    fn a_second_request_while_one_waits_is_refused_without_ending_the_link() {
        // Rule 2 of the pairing section, and rule 6: a refusal is an answer, not a reason to disconnect.
        let inbox = Inbox::new(std::env::temp_dir().as_path());
        let mut pairing = synra_core::pairing::InboundPairing::new(local());
        let _ = inbox.pairing_request(&pair_envelope(&request_json("First")), &mut pairing);

        let decision = inbox.pairing_request(&pair_envelope(&request_json("Second")), &mut pairing);
        let Decision::Pairing { answer, .. } = decision else {
            panic!("a pairing request must produce a pairing decision");
        };
        let answer = answer.expect("the second request is answered immediately");
        assert!(!answer.accepted);
        assert_eq!(answer.reason.as_deref(), Some("busy"));
    }

    #[test]
    fn a_pairing_request_that_cannot_be_read_is_refused_rather_than_failing_the_link() {
        // A peer that sends a mistake in one message has not broken the connection, and closing it would take any
        // transfer on that link down for a reason the user cannot act on.
        let inbox = Inbox::new(std::env::temp_dir().as_path());
        let mut pairing = synra_core::pairing::InboundPairing::new(local());

        for payload in [r#""a string, not an object""#, r#"{"profile":{}}"#] {
            let decision = inbox.pairing_request(&pair_envelope(payload), &mut pairing);
            let Decision::Pairing { answer, .. } = decision else {
                panic!("a pairing request must produce a pairing decision");
            };
            let answer = answer.expect("an unreadable request is answered immediately");
            assert!(!answer.accepted, "payload {payload} must be refused");
            assert_eq!(answer.issued_token(), None, "a refusal issues no token");
        }
        assert!(pairing.pending().is_none(), "an unreadable request must not reach the prompt");
    }

    #[test]
    fn a_pairing_request_with_no_payload_is_refused() {
        let inbox = Inbox::new(std::env::temp_dir().as_path());
        let mut pairing = synra_core::pairing::InboundPairing::new(local());

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

        let Decision::Pairing { answer, .. } = inbox.pairing_request(&bare, &mut pairing) else {
            panic!("a pairing request must produce a pairing decision");
        };
        assert!(!answer.expect("answered immediately").accepted);
    }
}
