use std::path::{Path, PathBuf};

use crate::Inbound;
use crate::link::PeerLink;
use synra_protocol::ids::TraceId;
use synra_protocol::session::TransferAbortReason;

use super::model::share_of;
use super::model::{Decision, Offer, OfferCallback, OfferDecision, auto_accept};
use super::util::{proposed_name, read_patiently, request_of};
use super::{INBOX_DIR, TRANSFER_PATIENCE};
use crate::session::{self, Received, Receiving};

/// What one connection has in flight: the transfer being received, if any.
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
        Self {
            receiving: None,
            trace: TraceId::new(),
            inbox: data_dir.join(INBOX_DIR),
        }
    }

    /// Whether a transfer is in progress.
    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.receiving.is_some()
    }

    /// The transfer in progress, as the numbers a progress reporter needs.
    #[must_use]
    pub fn progress(&self) -> Option<session::receive::InboundProgress> {
        self.receiving.as_ref().map(Receiving::progress)
    }

    /// The directory files land in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.inbox
    }

    /// Gives up on the transfer in progress: tells the sender, forgets the transfer and removes the partial file.
    ///
    /// Answers the transfer it cancelled, or `None` when nothing was in progress. A host calls this between messages —
    /// the listener loop is the only thing holding the link — which is why it takes the link rather than keeping a
    /// handle to it: a cancel that could be called from another thread would be a second writer to the same socket.
    ///
    /// # Errors
    ///
    /// [`SessionError`] when the abort cannot be sent. The partial file is still removed: a link that is already broken
    /// is not a reason to keep bytes that nobody will finish receiving.
    pub fn cancel(
        &mut self,
        link: &mut PeerLink,
        now_ms: i64,
    ) -> Result<Option<String>, crate::SessionError> {
        let Some(receiving) = self.receiving.as_ref() else {
            return Ok(None);
        };
        let transfer_id = receiving.transfer_id();
        let partial = receiving.path().to_path_buf();
        self.receiving = None;
        let _ = std::fs::remove_file(&partial);
        crate::abort(
            link,
            transfer_id,
            TransferAbortReason::UserCancelled,
            self.trace,
            now_ms,
        )?;
        Ok(Some(transfer_id.to_string()))
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
        peer_address: &str,
    ) -> Result<Decision, crate::SessionError> {
        self.absorb_with(link, now_ms, patience, peer_address, &auto_accept)
    }

    /// [`absorb`](Self::absorb), with a host asked before a transfer is accepted.
    ///
    /// # Why a callback rather than a desk
    ///
    /// Because the decision is the host's, not the kernel's: the daemon has no window to ask and the shell has one, and a
    /// desk type here would be the kernel deciding which of the two it is. The callback also carries the whole answer —
    /// a host that wants to ask returns `Refuse` when the user says no — so there is no second place where "accepted"
    /// and "stored" could disagree.
    pub fn absorb_with(
        &mut self,
        link: &mut PeerLink,
        now_ms: i64,
        patience: std::time::Duration,
        peer_address: &str,
        ask: &OfferCallback,
    ) -> Result<Decision, crate::SessionError> {
        // * The patience is re-armed on **every** call, and it is what bounds a *quiet* peer rather than a slow one. An
        // earlier version computed the deadline once from the connection's start, so a receiver that was still working
        // through a large transfer ran out of patience and closed the link with the sender's completion unread -- which is
        // exactly what an end-to-end run showed: the file arrived byte-for-byte and the confirmation was never sent.
        //
        // A transfer in progress gets a long wait, because blocks are arriving and each arrival is the evidence that the
        // peer is still there. A connection with nothing in progress gets the short one, so a peer that connects and says
        // nothing is still abandoned promptly.
        let patience = if self.receiving.is_some() {
            TRANSFER_PATIENCE
        } else {
            patience
        };
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
                return Ok(Decision::Delivered {
                    event: envelope.event.as_str().to_owned(),
                    share: share_of(&envelope),
                    request: Some(envelope.clone()),
                });
            }
            let name = proposed_name(&envelope)?;
            let request = request_of(&envelope)?;
            let destination = self.destination_for(&name);
            let prompt = Offer {
                peer: link.peer(),
                peer_address,
                request: &request,
                file_name: &name,
                destination: &destination,
            };
            if ask(&prompt) == OfferDecision::Refuse {
                // ★ Told, not merely dropped. A sender that is not told waits out its whole transfer window, and the
                // file it thought it was sending is a peer left hanging rather than a peer answered "no".
                crate::abort(
                    link,
                    request.transfer_id,
                    TransferAbortReason::UserCancelled,
                    envelope.trace_id,
                    now_ms,
                )?;
                return Ok(Decision::Failed {
                    why: "the receiver refused the transfer".to_owned(),
                });
            }
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
            return Ok(Decision::Accepted {
                transfer_id,
                file_name: name,
            });
        }

        let Some(receiving) = self.receiving.as_mut() else {
            return Ok(Decision::Ignored);
        };
        // ★ Kept before the read, because the failure paths below drop the receiver — and a partial file left in the inbox
        // is a file the user never received, under a name that looks like one they did.
        let partial = receiving.path().to_path_buf();
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
            Received::Verified { digest, .. } => {
                // The transfer is over, so the state is released whatever happens to the file afterwards.
                let path = receiving.path().to_path_buf();
                let byte_length = receiving.byte_length();
                // Taken before the receiver is dropped, because this is the moment the "what it was" is about to be
                // lost — after `self.receiving = None` there is a path and nothing else.
                let bundle = receiving.bundle().cloned();
                let version = receiving.version().cloned();
                let request_id = receiving.request_id();
                let sync_session_id = receiving.sync_session_id();
                self.receiving = None;
                Ok(Decision::Finished {
                    path,
                    byte_length,
                    bundle,
                    digest,
                    version,
                    request_id,
                    sync_session_id,
                    trace_id: self.trace,
                })
            }
            Received::Failed { why, .. } => {
                self.receiving = None;
                let _ = std::fs::remove_file(&partial);
                Ok(Decision::Failed { why })
            }
            Received::Aborted { reason, .. } => {
                self.receiving = None;
                // ★ The peer gave up, so the bytes it had written are not a file this device received. Removing them is
                // what makes "cancelled" mean the same thing on both sides.
                let _ = std::fs::remove_file(&partial);
                Ok(Decision::Failed {
                    why: format!("the peer gave up: {reason:?}"),
                })
            }
            // A message the transfer has nothing to do with, while a transfer *is* in progress: reported so it is not lost
            // between two files.
            Received::Ignored => Ok(Decision::Delivered {
                event: "unknown".to_owned(),
                // Nothing was recognised, so there is nothing to route.
                share: None,
                // Nor an envelope to answer: the transfer's reader consumed it while looking for a block.
                request: None,
            }),
            // `Received` is `#[non_exhaustive]`, so a variant this build does not know is treated as a message it has
            // nothing to do with rather than as a reason to fail the connection.
            _ => Ok(Decision::Ignored),
        }
    }

    pub(super) fn destination_for(&self, name: &str) -> PathBuf {
        let safe = synra_store::sanitise_component(name);
        // A name that sanitises to nothing — every character rejected — still needs a file.
        let stem = if safe.trim_matches(['.', '-']).is_empty() {
            "file".to_owned()
        } else {
            safe
        };
        self.inbox.join(stem)
    }
}
