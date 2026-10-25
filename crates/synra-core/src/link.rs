//! A link that has finished its handshake, and what travels on it.
//!
//! # What this adds to the handshake
//!
//! [`crate::peer`] reaches agreement and hands back a socket. This turns that socket into a link: envelopes go out and
//! come in, and the link refuses the three things a raw socket would happily deliver.
//!
//! * **An envelope addressed to somebody else.** `synra-protocol`'s `Envelope` carries a `target`, and a peer that sends
//!   one for another device is either misconfigured or probing. The check is against this device's own identifier.
//! * **An envelope claiming to be from somebody else.** This is the one that matters: the link's peer *is* the sender,
//!   so an envelope whose `from` is a different device is a peer trying to speak for a device it is not. Without this,
//!   any paired device could send an intent that appears to come from a device the user trusts more.
//! * **A frame that is not an envelope.** A `Hello` after the handshake is a peer that has lost track of where it is,
//!   and a `Chunk` outside a transfer is one with no transfer to belong to. Both are reported rather than routed.
//!
//! # Why the receive half returns an owned envelope
//!
//! `Envelope::payload` is a `Box<RawValue>` — the protocol's own decision, so that a kernel can check a message's shape
//! without parsing it into a tree. Owning the envelope keeps that: a borrow of the frame buffer would tie the envelope's
//! lifetime to the next read, and the kernel's routing outlives one read.
//!
//! # What is not here
//!
//! Chunked transfer bodies. A `Chunk` frame belongs to a transfer that a session owns, and the pieces that own it — the
//! block bitmap, the digest check, the resumption — are the transfer layer's. This link carries envelopes and reports a
//! chunk as an unexpected frame, which is the honest answer while there is no transfer to hand it to.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

/// A byte stream backed by memory, for a link with no socket behind it.
///
/// Public because the end-to-end tests `04 §11` describes need to name it: a fixture inside `#[cfg(test)]` is one nobody
/// outside this crate can substitute.
pub mod memory;

use bytes::Bytes;
use synra_protocol::envelope::Envelope;
use synra_protocol::frame::{
    ChunkFrame, Frame, FrameBody, FrameDecoder, FrameEncoder, FrameError, FrameKind,
};
use synra_protocol::ids::DeviceId;

use crate::peer::{Flags, HandshakeError};

/// Why a link operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The captured authenticated authorization was revoked or does not match this link.
    #[error("the link is no longer authorized")]
    Unauthorized,
    /// Authorization could not be checked; the connection must not continue.
    #[error("the link authorization check failed: {why}")]
    AuthorizationUnavailable {
        /// The persistence failure, without credentials.
        why: String,
    },
    /// The stream failed.
    #[error("the link failed: {why}")]
    Transport {
        /// What the operating system said.
        why: String,
    },

    /// A read or a write waited longer than the link's timeout.
    ///
    /// ★ Both directions, and the second was missing for a long time.
    ///
    /// A read that times out means nothing arrived; a **write** that times out means the peer is alive and not taking bytes —
    /// its receive window is full. They are the same fact about the link from opposite ends, and neither is a broken
    /// connection. The write side reported every failure as [`Self::Transport`] until this variant covered it, so a caller
    /// could not tell a busy peer from a dead one.
    ///
    /// # Why this is not `Transport`
    ///
    /// Because "nothing has arrived yet" and "the connection is broken" are different facts with different answers, and
    /// flattening them into one is how a working transfer gets reported as a broken link. An end-to-end run showed exactly
    /// that: a 300 KB file arrived byte-for-byte while the sender reported `transport_not_open`, because a read had timed
    /// out while it was waiting for a confirmation that was still in flight.
    #[error("the link was quiet for longer than the timeout")]
    TimedOut,

    /// The peer closed the link.
    #[error("the peer closed the link")]
    Closed,

    /// A frame could not be encoded or decoded.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// A frame arrived that this link does not carry.
    #[error("expected an envelope and received a {found} frame")]
    Unexpected {
        /// What arrived.
        found: String,
    },

    /// An envelope could not be read or was refused.
    #[error("the envelope was refused: {why}")]
    Envelope {
        /// What the protocol's validator said.
        why: String,
    },
}

impl From<HandshakeError> for LinkError {
    fn from(error: HandshakeError) -> Self {
        // A handshake's transport failure and a link's are the same condition seen at different moments; collapsing them
        // keeps a caller from having to handle two spellings of "the connection broke".
        match error {
            HandshakeError::Transport { why } => Self::Transport { why },
            HandshakeError::Closed => Self::Closed,
            HandshakeError::Frame(inner) => Self::Frame(inner),
            other => Self::Envelope {
                why: other.to_string(),
            },
        }
    }
}

pub(crate) fn transport_error(error: &std::io::Error) -> LinkError {
    error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<LinkError>())
        .cloned()
        .unwrap_or_else(|| LinkError::Transport {
            why: error.to_string(),
        })
}

/// What arrived on a link.
///
/// # Why the envelope is boxed
///
/// Because an `Envelope` holds a `Box<RawValue>` payload and a `CompactString` event name, so it is far larger than a
/// block's four-byte header — and an enum sized for the larger variant makes every block, which is the common case during
/// a transfer, pay for the rare one.
#[derive(Debug)]
#[non_exhaustive]
pub enum Inbound {
    /// A control-plane message.
    Envelope(Box<Envelope>),
    /// A block of a file, which the transfer layer owns.
    Block {
        /// Which block, within the transfer the caller is tracking.
        chunk_id: u32,
        /// The bytes.
        data: Bytes,
    },
}

/// A byte stream a link can be built on.
///
/// ★ Why this trait exists, and what it is not.
///
/// `PeerLink` held a **concrete `TcpStream`**, so the only way to exercise a link was to open a socket — and the design's
/// end-to-end tests, which want two kernels linked in one process, had nothing to substitute. `synra-testkit` already has a
/// `MemoryTransport`, but it moves **decoded frames** while a link decodes **bytes**, so the two are type-incompatible: the
/// seam was missing, not the fixture. `04 §11` records exactly this, and this is the seam it asked for, at the byte layer
/// because that is the layer the link lives at.
///
/// # Why the methods return this crate's error rather than `std::io::Error`
///
/// Because a promise about another crate's error type is a promise about its version — `api-guard` exists to refuse exactly
/// that, and it is right to: a consumer matching on `std::io::ErrorKind` from a `synra-core` signature has tied its build to
/// whatever `std` does next. Converting at the boundary costs one `map_err` per implementation and keeps the promise where
/// it belongs.
///
/// # Why `Read` and `Write` are supertraits
///
/// Because the framing is above this line: a link reads bytes into its own decoder and writes encoded frames, and inventing
/// separate `read_bytes`/`write_bytes` methods would be a second spelling of two traits that already exist and are already
/// implemented by everything a caller might bring.
pub trait LinkStream: Read + Write + Send + std::fmt::Debug {
    /// Rechecks authorization for these actual link identities before delivering or sending a frame.
    ///
    /// Memory fixtures and legacy transports have no authority to check. Authenticated transports
    /// must compare their captured credential generation even when a frame was already buffered.
    /// # Errors
    /// Refuses revoked identities and unavailable authorization storage.
    fn authorize(&self, _local: DeviceId, _peer: DeviceId) -> Result<(), LinkError> {
        Ok(())
    }

    /// Sets the deadline one `read` call runs under.
    ///
    /// # Errors
    ///
    /// [`LinkError::Transport`] when the stream refuses the deadline — which is a real case rather than a theoretical one:
    /// Windows rejects a zero timeout outright.
    fn set_read_deadline(&self, timeout: std::time::Duration) -> Result<(), LinkError>;

    /// Sets the deadline one `write` call runs under.
    ///
    /// # Errors
    ///
    /// As [`Self::set_read_deadline`].
    fn set_write_deadline(&self, timeout: std::time::Duration) -> Result<(), LinkError>;
}

impl LinkStream for TcpStream {
    fn set_read_deadline(&self, timeout: std::time::Duration) -> Result<(), LinkError> {
        self.set_read_timeout(Some(timeout))
            .map_err(|error| LinkError::Transport {
                why: error.to_string(),
            })
    }

    fn set_write_deadline(&self, timeout: std::time::Duration) -> Result<(), LinkError> {
        self.set_write_timeout(Some(timeout))
            .map_err(|error| LinkError::Transport {
                why: error.to_string(),
            })
    }
}

/// A socket whose handshake is done.
///
/// # Why this is not the session registry's entry
///
/// `synra_core::sessions` records what the *kernel* knows about a link — its state, its heartbeat deadline, its closure
/// reason — and this is the *wire*: one socket, one decoder, and the checks that belong to this specific connection. A
/// session that lost its socket is still a session with a reason to report; a link without a socket is nothing.
#[derive(Debug)]
pub struct PeerLink {
    /// The bytes, behind the seam above.
    ///
    /// Boxed rather than generic so `PeerLink` stays one type: a generic link would put the choice of stream into every
    /// signature that mentions a link — the session registry, the listener, the daemon's transport — and none of them cares.
    stream: Box<dyn LinkStream>,
    decoder: FrameDecoder,
    /// This device, so an envelope's target can be checked.
    local: DeviceId,
    /// The peer, so an envelope's `from` can be checked.
    peer: DeviceId,
    /// What was agreed, for a caller that has to know whether a feature is available.
    agreed: synra_protocol::handshake::Agreed,
    /// Flags a read runs under.
    flags: Flags,
    /// A per-call read timeout, for a caller whose own deadline is sooner than the link's.
    read_timeout_override: Option<std::time::Duration>,
    /// A write deadline a caller asked for, in place of the negotiated one.
    ///
    /// ★ The asymmetry this fixes: a **read** timeout had an override and a write timeout did not exist at all. A caller that
    /// wanted its own write deadline had no way to say so, and the link's own deadline is the negotiated session timeout —
    /// thirty seconds — which for a transfer's first block is a long time to hold a thread that could be told sooner.
    write_timeout_override: Option<std::time::Duration>,
    /// Envelopes sent, for a report.
    sent: u64,
    /// Envelopes received and accepted, for a report.
    received: u64,
    /// Where the byte counters go, when the host has a recorder.
    ///
    /// ★ Payload bytes, not wire bytes: the frame header is the transport's accounting, and what a reader of
    /// `bytes_sent_total` is asking is "how much did this device move". A link with no recorder is a link, not a broken
    /// one — the same rule `Host::with_metrics` and the plugin host follow.
    metrics: Option<Arc<synra_observe::metrics::RingRecorder>>,
}

impl PeerLink {
    pub(crate) fn with_decoder(mut self, decoder: FrameDecoder) -> Self {
        self.decoder = decoder;
        self
    }

    /// Wraps a completed handshake.
    ///
    /// # Why the identifiers are arguments rather than read from the socket
    ///
    /// Because they came from the handshake, and a link that re-derived them from the first envelope it saw would be one
    /// a peer could address by claiming a different `from` — which is the check this type exists to make.
    #[must_use]
    pub fn new(
        stream: impl LinkStream + 'static,
        local: DeviceId,
        peer: DeviceId,
        agreed: synra_protocol::handshake::Agreed,
        flags: Flags,
    ) -> Self {
        Self {
            stream: Box::new(stream),
            decoder: FrameDecoder::new(),
            local,
            peer,
            agreed,
            flags,
            read_timeout_override: None,
            write_timeout_override: None,
            sent: 0,
            received: 0,
            metrics: None,
        }
    }

    /// Counts payload bytes into `metrics`.
    ///
    /// ★ A builder rather than a constructor argument: every existing caller keeps working, and the one place that builds
    /// a link from a dial (`Dialled::into_link`) is also the one place that now passes a recorder.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<synra_observe::metrics::RingRecorder>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Adds to one of the two byte counters, when this link has a recorder.
    fn count_bytes(&self, metric: &str, bytes: usize) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_add(
                &synra_observe::metrics::SeriesKey::new(metric, []),
                u64::try_from(bytes).unwrap_or(u64::MAX),
            );
        }
    }

    /// Counts one envelope frame by its event, in the direction named by `metric`.
    ///
    /// ★ Here rather than in `Host::send`, which was the first home of `frames_sent_total`. The host only sees the frames a
    /// caller routes through it; a dialled link that sends an offer or a pairing request writes straight to the socket, and
    /// those frames were invisible. The link is the one object every frame passes, so this is where "what did this device
    /// say" can be answered for all of them — and `Host::send` no longer counts, because two counters for one frame would
    /// double every routed message.
    fn count_frame(&self, metric: &str, event: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                metric,
                [("event".to_owned(), event.to_owned())],
            ));
        }
    }

    /// This device.
    #[must_use]
    pub const fn local(&self) -> DeviceId {
        self.local
    }

    /// The device on the other end.
    #[must_use]
    pub const fn peer(&self) -> DeviceId {
        self.peer
    }

    /// What both ends agreed on.
    #[must_use]
    pub const fn agreed(&self) -> &synra_protocol::handshake::Agreed {
        &self.agreed
    }

    /// Whether a feature is available on this link.
    #[must_use]
    pub fn supports(&self, feature: synra_protocol::handshake::Feature) -> bool {
        self.agreed.supports(feature)
    }

    /// Envelopes sent on this link.
    #[must_use]
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    /// Envelopes accepted from this link.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }

    /// Sends an envelope.
    ///
    /// # Why the envelope is not re-checked here
    ///
    /// Because the sender built it, and a sender that addressed it elsewhere or claimed another `from` is a bug in the
    /// kernel rather than a peer's attack. The checks that matter are on the way **in**, where the value is
    /// attacker-controlled — and a symmetric check here would be one that reads as protection while protecting against
    /// nothing.
    ///
    /// Writes a frame, under the link's timeout.
    ///
    /// # ★ Why a write needs a timeout, and never had one
    ///
    /// Because a write to a socket whose peer has stopped reading **blocks forever** once the kernel's send buffer and the
    /// peer's receive window are full. `PeerLink` set a read timeout and no write timeout, so a peer that stopped reading did
    /// not produce an error anywhere: the calling thread simply never came back, and the daemon's transport stopped serving
    /// every other device behind it. TCP will not report this — a full window is not a closed socket, and there is no
    /// keepalive short enough to notice.
    ///
    /// The crate written for exactly this has the reasoning: `synra_net::write_queue`'s module documentation says a peer that
    /// stops reading "turns the application into a buffer", and that the three ways to stay bounded are to drop the oldest
    /// (silent corruption), drop the newest (a message the caller believes was queued), or **close the link so the loss is
    /// visible**. A timeout is the smallest form of the third: the caller is told, and reconnection re-requests what is
    /// still needed.
    ///
    /// The second link implementation in this crate already did this (`peer/link.rs` sets a write timeout from the same
    /// negotiated `flags.timeout`), so this is one of two implementations catching up with the other rather than a new
    /// decision.
    fn write_frame(&mut self, encoded: &[u8]) -> Result<(), LinkError> {
        if let Some(timeout) = self.write_deadline() {
            self.stream.set_write_deadline(timeout)?;
        }
        self.stream.authorize(self.local, self.peer)?;
        match self
            .stream
            .write_all(encoded)
            .and_then(|()| self.stream.flush())
        {
            Ok(()) => Ok(()),
            // ★ A write that ran out of time is the same fact `TimedOut` already names for reads, from the other
            // end: the peer is **alive and not taking bytes**. Reporting it as `Transport` is the flattening that variant's own
            // documentation warns against — "nothing has arrived yet" and "the connection is broken" lead a caller to
            // different actions, and the difference here is between backing off and reconnecting. A caller that saw a slow
            // peer as a dead link would tear down a working transfer to a device that was merely busy.
            Err(error) if is_a_timeout(&error) => Err(LinkError::TimedOut),
            Err(error) => Err(transport_error(&error)),
        }
    }

    /// The deadline a write runs under: the caller's, or the negotiated one.
    ///
    /// ★ Observable on purpose. A socket's write timeout has no getter, so a test cannot ask the socket what was applied —
    /// and the interesting decision is not "did `set_write_timeout` get called" but **which of the two deadlines wins**.
    /// That is what this answers, and it is what a test can hold.
    #[must_use]
    pub fn write_deadline(&self) -> Option<std::time::Duration> {
        self.write_timeout_override.or(self.flags.timeout)
    }

    /// Sends a completed envelope.
    ///
    /// # Errors
    ///
    /// [`LinkError::Envelope`] when the envelope cannot be serialised, and [`LinkError::Transport`] when the write fails —
    /// including the timeout above, which is a peer that has stopped reading rather than one that has gone away.
    pub fn send(&mut self, envelope: &Envelope) -> Result<(), LinkError> {
        let bytes = serde_json::to_vec(envelope).map_err(|error| LinkError::Envelope {
            why: error.to_string(),
        })?;
        let frame = Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from(bytes)),
        };
        let encoded = FrameEncoder::encode_to_vec(&frame)?;
        self.write_frame(&encoded)?;
        self.sent = self.sent.saturating_add(1);
        self.count_frame("frames_sent_total", envelope.event.as_str());
        // Payload only: a frame header is the transport's accounting, and it is not what the reader of `bytes_sent_total`
        // is asking about. Counted after the write, because a refused write moved nothing.
        self.count_bytes(
            "bytes_sent_total",
            envelope
                .payload
                .as_ref()
                .map_or(0, |payload| payload.get().len()),
        );
        Ok(())
    }

    /// Sends a block of a file.
    ///
    /// # Why the block travels in its own frame kind rather than in an envelope
    ///
    /// Because the protocol says so, and the reason is arithmetic: an envelope is JSON, so binary payload in one is
    /// base64 — a third more bytes and two transcodes per block. `ChunkFrame` puts the sequence number and the bytes in
    /// the frame body with nothing between them.
    ///
    /// The block-size ceiling is the frame encoder's, so a block that is too large is refused before anything is written
    /// rather than after a partial write.
    ///
    /// # Errors
    ///
    /// [`LinkError::Frame`] for a block the protocol refuses, and [`LinkError::Transport`] when the write fails.
    pub fn send_chunk(&mut self, chunk_id: u32, data: &[u8]) -> Result<(), LinkError> {
        let frame = Frame {
            kind: FrameKind::Chunk,
            flags: 0,
            body: FrameBody::Chunk(ChunkFrame {
                chunk_id,
                data: Bytes::copy_from_slice(data),
            }),
        };
        self.send_frame(&frame)?;
        self.sent = self.sent.saturating_add(1);
        self.count_bytes("bytes_sent_total", data.len());
        Ok(())
    }

    /// Reads the next thing the peer sent, whichever plane it is on.
    ///
    /// # Why this returns a sum rather than an envelope
    ///
    /// Because a transfer interleaves two planes, and a reader that understood only envelopes would see a block as an
    /// unexpected frame and close the link — which is what [`PeerLink::receive`] does, and why this exists beside it.
    /// Heartbeats stay inside: nothing above this has anything to do with them, and a caller that had to answer a `Ping`
    /// is one that could forget to.
    ///
    /// # Errors
    ///
    /// As [`PeerLink::receive`], minus the refusal of a block.
    pub fn receive_inbound(&mut self) -> Result<Inbound, LinkError> {
        loop {
            let frame = self.read_frame()?;
            match frame.kind {
                FrameKind::Envelope => {
                    let envelope = self.parse_envelope(&frame)?;
                    self.received = self.received.saturating_add(1);
                    self.count_frame("frames_received_total", envelope.event.as_str());
                    self.count_bytes(
                        "bytes_received_total",
                        envelope
                            .payload
                            .as_ref()
                            .map_or(0, |payload| payload.get().len()),
                    );
                    return Ok(Inbound::Envelope(Box::new(envelope)));
                }
                FrameKind::Chunk => {
                    let FrameBody::Chunk(chunk) = frame.body else {
                        return Err(LinkError::Unexpected {
                            found: format!("{:?}", frame.body),
                        });
                    };
                    self.received = self.received.saturating_add(1);
                    self.count_bytes("bytes_received_total", chunk.data.len());
                    return Ok(Inbound::Block {
                        chunk_id: chunk.chunk_id,
                        data: chunk.data,
                    });
                }
                FrameKind::Ping => self.pong()?,
                FrameKind::Pong => {}
                FrameKind::Bye => return Err(LinkError::Closed),
                other => {
                    return Err(LinkError::Unexpected {
                        found: other.to_string(),
                    });
                }
            }
        }
    }

    /// Sends a heartbeat.
    ///
    /// # Errors
    ///
    /// [`LinkError::Frame`] or [`LinkError::Transport`].
    pub fn ping(&mut self) -> Result<(), LinkError> {
        self.send_frame(&Frame::empty(FrameKind::Ping))
    }

    /// Answers a heartbeat.
    ///
    /// # Errors
    ///
    /// As [`PeerLink::ping`].
    pub fn pong(&mut self) -> Result<(), LinkError> {
        self.send_frame(&Frame::empty(FrameKind::Pong))
    }

    /// Says goodbye and does not read again.
    ///
    /// # Errors
    ///
    /// As [`PeerLink::ping`].
    pub fn bye(&mut self, reason: &str) -> Result<(), LinkError> {
        self.send_frame(&Frame {
            kind: FrameKind::Bye,
            flags: 0,
            body: FrameBody::Bye {
                code: 0,
                reason: Bytes::from(reason.to_owned().into_bytes()),
            },
        })
    }

    fn send_frame(&mut self, frame: &Frame) -> Result<(), LinkError> {
        let encoded = FrameEncoder::encode_to_vec(frame)?;
        self.write_frame(&encoded)
    }

    /// Reads the next envelope, answering heartbeats on the way.
    ///
    /// # Why heartbeats are answered here rather than returned
    ///
    /// Because a caller that had to handle a `Ping` would be one that could forget to — and the consequence is a peer
    /// that concludes the link is dead while it is working. A heartbeat is the link's own business, and the only frames
    /// this returns are the ones a session has something to do with.
    ///
    /// # Errors
    ///
    /// [`LinkError::Closed`] when the peer went away, [`LinkError::Unexpected`] for a frame this link does not carry,
    /// [`LinkError::Envelope`] for an envelope addressed elsewhere or claiming another sender, and
    /// [`LinkError::Transport`] when the stream fails.
    pub fn receive(&mut self) -> Result<Envelope, LinkError> {
        // ★ Delegates rather than repeating the loop, so the two readers cannot drift. The difference is one decision:
        // this refuses a block, because a caller that asked for an envelope has nowhere to put one — and silently dropping
        // it would lose part of a file.
        match self.receive_inbound()? {
            Inbound::Envelope(envelope) => Ok(*envelope),
            Inbound::Block { .. } => Err(LinkError::Unexpected {
                found: "chunk".to_owned(),
            }),
        }
    }

    /// Parses and checks the envelope in a frame.
    fn parse_envelope(&self, frame: &Frame) -> Result<Envelope, LinkError> {
        let FrameBody::Envelope(bytes) = &frame.body else {
            return Err(LinkError::Unexpected {
                found: format!("{:?}", frame.body),
            });
        };
        let text = std::str::from_utf8(bytes).map_err(|error| LinkError::Envelope {
            why: format!("the envelope is not text: {error}"),
        })?;

        // A `RawValue` first, because that is what the protocol's parser takes — it checks shape without building a tree.
        let raw: Box<serde_json::value::RawValue> =
            serde_json::from_str(text).map_err(|error| LinkError::Envelope {
                why: error.to_string(),
            })?;

        let envelope =
            Envelope::inbound(&raw, self.local).map_err(|error| LinkError::Envelope {
                why: error.to_string(),
            })?;

        // ★ The check only a link can make. The peer **is** the sender, so an envelope whose `from` is a different
        // device is a peer speaking for a device it is not — and without this, any paired device could send an intent
        // that appears to come from one the user trusts more.
        if envelope.from != self.peer {
            return Err(LinkError::Envelope {
                why: format!(
                    "the envelope claims to be from {} and this link's peer is {}",
                    envelope.from, self.peer
                ),
            });
        }
        Ok(envelope)
    }

    /// Sets how long the next read may wait, overriding the link's own timeout.
    ///
    /// # Why a caller needs this
    ///
    /// Because a link's timeout is a poor deadline for a caller that has its own. A loop that reads until a deadline — a
    /// daemon waiting for a peer's message — would otherwise wait the link's whole timeout even when its deadline is
    /// sooner, so "give up at five seconds" took eleven. Passing `None` restores the link's own timeout, which is what
    /// every other caller wants.
    pub const fn set_read_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.read_timeout_override = timeout;
    }

    /// Sets this link's write deadline, or restores the negotiated one.
    ///
    /// The same reasoning as [`Self::set_read_timeout`], and one more: a caller that has just decided a peer is not worth
    /// waiting for should be able to say so for writes without waiting out the session timeout first.
    pub const fn set_write_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.write_timeout_override = timeout;
    }

    /// Reads one frame.
    ///
    /// # Why a read timeout does not abandon a half-read frame
    ///
    /// Because a socket read timeout is a deadline on **one `read` call**, not on a frame. A 256 KiB block is far more than
    /// one buffer, so it arrives over several reads — and treating a timeout between two of them as a transport failure
    /// threw away the bytes already buffered and reported a broken link. That is what an end-to-end run showed: a 300 KB
    /// file arrived byte-for-byte while both ends reported `WSAETIMEDOUT`, and the receiver's completion was one of the
    /// frames lost that way.
    ///
    /// So a timeout while a frame is **partly** buffered is retried rather than reported: the peer is mid-frame, which is
    /// not the same as a peer that has gone quiet. A timeout with nothing buffered is reported as [`LinkError::TimedOut`],
    /// which is a quiet link rather than a broken one.
    fn read_frame(&mut self) -> Result<Frame, LinkError> {
        if let Some(timeout) = self.read_timeout_override.or(self.flags.timeout) {
            self.stream.set_read_deadline(timeout)?;
        }

        let mut buffer = [0u8; 8 * 1024];
        loop {
            // This check also covers frames prefetched by Hello or an earlier read.
            self.stream.authorize(self.local, self.peer)?;
            if let Some(frame) = self.decoder.next_frame()? {
                return Ok(frame);
            }
            // Whether anything of the current frame has arrived. Checked before the read, because the read is what
            // advances it.
            let partial = self.decoder.buffered() > 0;
            let read = match self.stream.read(&mut buffer) {
                Ok(0) => return Err(LinkError::Closed),
                Ok(read) => read,
                Err(error) if crate::peer::peer_went_away(&error) => return Err(LinkError::Closed),
                // A timeout with a frame partly buffered is retried, because the peer is mid-frame rather than silent.
                Err(error) if partial && is_a_timeout(&error) => continue,
                // A timeout with nothing buffered is reported as what it is — a quiet link — rather than as a broken one.
                Err(error) if is_a_timeout(&error) => return Err(LinkError::TimedOut),
                Err(error) => return Err(transport_error(&error)),
            };
            let chunk = buffer.get(..read).ok_or_else(|| LinkError::Transport {
                why: "a read reported more bytes than the buffer".to_owned(),
            })?;
            // The result is propagated: a poisoned decoder would otherwise report "no frame yet" for ever, which is a
            // read loop that never ends rather than a refused link.
            self.decoder.push_slice(chunk)?;
        }
    }
}

/// Whether an error is a read that ran out of time rather than a broken connection.
///
/// # Why the kinds are matched rather than the message
///
/// Because a message is translated: on a Chinese Windows the timeout says so in Chinese, and a check on the text would
/// silently stop working. `WouldBlock` is what a non-blocking socket reports and `TimedOut` is what a timed-out one does;
/// both are the same situation from here.
fn is_a_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::memory::MemoryStream;
    use super::*;
    use std::net::Ipv4Addr;
    use synra_protocol::envelope::OutboundSpec;
    use synra_protocol::event::EventName;
    use synra_protocol::ids::TraceId;

    const LOCAL: &str = "11111111-1111-4111-8111-111111111111";
    const PEER: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER: &str = "33333333-3333-4333-8333-333333333333";

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    /// A pair of connected sockets, as an established link would have.
    fn connected() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("binds");
        let address = listener.local_addr().expect("an address");
        let dialer = TcpStream::connect(address).expect("connects");
        let (accepted, _) = listener.accept().expect("accepts");
        (dialer, accepted)
    }

    fn agreed() -> synra_protocol::handshake::Agreed {
        synra_protocol::handshake::Agreed {
            common: vec![synra_protocol::handshake::Feature::EventStream],
            missing_required: Vec::new(),
        }
    }

    fn link_with_timeout(
        stream: TcpStream,
        local: &str,
        peer: &str,
        timeout: std::time::Duration,
    ) -> PeerLink {
        PeerLink::new(
            stream,
            device(local),
            device(peer),
            agreed(),
            Flags {
                timeout: Some(timeout),
            },
        )
    }

    #[test]
    fn the_callers_write_deadline_wins_over_the_negotiated_one() {
        // ★ The decision, which is the part a test can hold: a socket's write timeout has no getter, so "was
        // `set_write_timeout` called" is not askable — but *which deadline applies* is, and that is the question the two
        // sources raise. Without this, the override could be stored and never consulted and nothing would notice.
        let (dialer, _peer) = connected();
        let mut link = link_with_timeout(dialer, LOCAL, PEER, std::time::Duration::from_secs(30));

        assert_eq!(
            link.write_deadline(),
            Some(std::time::Duration::from_secs(30)),
            "the negotiated one"
        );
        link.set_write_timeout(Some(std::time::Duration::from_millis(250)));
        assert_eq!(
            link.write_deadline(),
            Some(std::time::Duration::from_millis(250)),
            "the caller's"
        );
        // And `None` puts the negotiated one back rather than removing every deadline — the same reading
        // `set_read_timeout` has.
        link.set_write_timeout(None);
        assert_eq!(
            link.write_deadline(),
            Some(std::time::Duration::from_secs(30))
        );
    }

    // ── A peer that stops reading ─────────────────────────────────────────────────────────────────
    //
    // ★ The socket-based version of this test is gone, and what replaced it is above: `a_pipe_that_is_full_stops_the_writer`
    // uses a 4 KiB pipe so the bound is the **fixture's** rather than the operating system's. The version that remains below
    // tests the other direction — a peer that is **gone** rather than busy — and needs a real socket, because only a closed
    // socket produces a connection reset while a dropped `MemoryStream` produces end-of-file.

    #[test]
    fn a_peer_that_is_gone_is_a_transport_failure_rather_than_a_quiet_link() {
        // ★ The other half of the distinction, and the reason it is a distinction at all. If a closed socket were also
        // reported as `TimedOut`, a caller would back off from a peer that has actually gone — waiting out a backoff schedule
        // for a link that will never carry anything again. One condition has a repair and the other does not.
        let (dialer, peer) = connected();
        let mut link = link_with_timeout(dialer, LOCAL, PEER, std::time::Duration::from_secs(5));
        drop(peer);

        // The first write after a peer closes may still be absorbed by the local buffer; the failure arrives after that.
        let block = vec![0u8; 32 * 1024];
        let mut refusal = None;
        for index in 0..64_u32 {
            match link.send_chunk(index, &block) {
                Ok(()) => continue,
                Err(error) => {
                    refusal = Some(error);
                    break;
                }
            }
        }

        match refusal {
            Some(LinkError::Transport { .. }) => {}
            Some(LinkError::TimedOut) => {
                panic!("a closed socket is not a quiet link: the peer is gone, not busy")
            }
            Some(other) => panic!("expected a transport failure, got {other:?}"),
            None => panic!("a closed peer absorbed sixty-four blocks"),
        }
    }

    #[test]
    fn two_links_exchange_an_envelope_over_memory_rather_than_a_socket() {
        // ★ The seam, proved by the only thing that can prove it: a link that was never near a socket.
        //
        // `04 §11` records that the design's end-to-end tests were unwritable because `PeerLink` held a concrete
        // `TcpStream` while `synra-testkit`'s `MemoryTransport` moves decoded frames — two layers, no seam. This is the
        // seam, and this test is the smallest thing that shows it carries a real envelope through the real framing, with the
        // real checks (the target is ours, the sender is the peer) applied on the way.
        let (here, there) = MemoryStream::pair();
        let mut sender = link_with_stream(here, LOCAL, PEER);
        let mut receiver = link_with_stream(there, PEER, LOCAL);

        sender
            .send(&envelope(LOCAL, PEER, "_plugin.chat.text"))
            .expect("sends over memory");
        let received = receiver.receive().expect("receives over memory");

        assert_eq!(received.event.as_str(), "_plugin.chat.text");
        assert_eq!(received.from, device(LOCAL));
        assert_eq!(received.target, device(PEER));
        // And the counters the report is built from moved, so this went through the same path a socket does.
        assert_eq!(sender.sent(), 1);
        assert_eq!(receiver.received(), 1);
    }

    #[test]
    fn a_memory_reader_with_nothing_to_read_reports_a_quiet_link_rather_than_waiting() {
        // ★ The deadline, over memory. A fixture that blocked forever when nothing had been written would make every
        // test that reads before writing hang — and would make `is_a_timeout`'s distinction untestable, because the
        // distinction is exactly "nothing arrived yet" against "the connection is broken".
        let (here, _there) = MemoryStream::pair();
        let mut link = link_with_stream(here, LOCAL, PEER);
        link.set_read_timeout(Some(std::time::Duration::from_millis(20)));

        let started = std::time::Instant::now();
        let refused = link.receive().expect_err("nothing was written");

        match refused {
            LinkError::TimedOut => {}
            other => panic!("a quiet memory link is not {other:?}"),
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "it waited {:?}, which is not a deadline",
            started.elapsed()
        );
    }

    #[test]
    fn dropping_one_end_stops_the_other_rather_than_leaving_it_waiting() {
        // The third property a socket has and a `Vec` does not: a closed peer is visible. The unwrap is what would hang if
        // the close did not wake the reader.
        let (here, there) = MemoryStream::pair();
        let mut link = link_with_stream(here, LOCAL, PEER);
        drop(there);

        assert!(matches!(link.receive(), Err(LinkError::Closed)));
    }

    #[test]
    fn a_pipe_that_is_full_stops_the_writer_without_waiting_for_a_socket_buffer_to_fill() {
        // ★ What the seam buys over a socket, in one test.
        //
        // `a_peer_that_stops_reading_is_told_rather_than_waited_for` reaches the same behaviour by writing into a real
        // socket until the operating system's buffer fills — which is slow, depends on how that machine is configured, and
        // has to send megabytes to get there. A pipe that is **4 KiB wide** reaches it in microseconds and reaches it the
        // same way on every machine, because the bound is this fixture's rather than the kernel's.
        //
        // The deadline is one millisecond, so "the write stopped" means "its deadline passed" rather than "the operating
        // system eventually gave up".
        let (here, _there) = MemoryStream::pair_with_capacity(4 * 1024);
        let mut link = link_with_stream(here, LOCAL, PEER);
        link.set_write_timeout(Some(std::time::Duration::from_millis(1)));

        let started = std::time::Instant::now();
        let refused = link
            .send_chunk(0, &[0u8; 8 * 1024])
            .expect_err("the pipe holds four");

        // ★ `TimedOut` and not `Transport`: the reader is alive and not reading, which is the distinction rounds 83 and 84
        // built. A caller backs off from this one and reconnects from the other.
        assert!(matches!(refused, LinkError::TimedOut), "{refused:?}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "it waited {:?}, which is not a deadline",
            started.elapsed()
        );
    }

    #[test]
    fn the_same_narrow_pipe_carries_everything_when_somebody_reads() {
        // ★ The control for the test above, and the reason it is not just "a small pipe fails": the same 4 KiB pipe
        // delivers a block twice its width intact once a reader is taking bytes. Without this, a fixture that refused
        // everything would pass the other test.
        let (here, there) = MemoryStream::pair_with_capacity(4 * 1024);
        let mut sender = link_with_stream(here, LOCAL, PEER);
        let mut receiver = link_with_stream(there, PEER, LOCAL);
        sender.set_write_timeout(Some(std::time::Duration::from_millis(500)));
        receiver.set_read_timeout(Some(std::time::Duration::from_millis(500)));

        // Eight kibibytes through a four-kibibyte pipe, from another thread: the writer cannot finish until the reader
        // starts, which is exactly what a bounded pipe is for.
        let payload = vec![7u8; 8 * 1024];
        let writer = std::thread::spawn(move || {
            sender.send_chunk(0, &payload).expect("sends");
            sender
        });

        // ★ A block arrives on the block plane, so `receive` — which is the control plane and refuses anything else —
        // is the wrong door and said so: `Unexpected { found: "chunk" }`. `receive_inbound` is the sum of both planes.
        match receiver.receive_inbound().expect("receives") {
            Inbound::Block { chunk_id, data } => {
                assert_eq!(chunk_id, 0);
                assert_eq!(
                    data.len(),
                    8 * 1024,
                    "the whole block, through a pipe half its width"
                );
                assert!(data.iter().all(|byte| *byte == 7));
            }
            other => panic!("expected a block, got {other:?}"),
        }
        let sender = writer.join().expect("the writer finished");
        assert_eq!(sender.sent(), 1);
        assert_eq!(receiver.received(), 1);
    }

    /// A link over anything that carries bytes.
    fn link_with_stream(stream: impl LinkStream + 'static, local: &str, peer: &str) -> PeerLink {
        PeerLink::new(
            stream,
            device(local),
            device(peer),
            agreed(),
            Flags::no_timeout(),
        )
    }

    fn link(stream: TcpStream, local: &str, peer: &str) -> PeerLink {
        PeerLink::new(
            stream,
            device(local),
            device(peer),
            agreed(),
            Flags::no_timeout(),
        )
    }

    /// An envelope from `from` to `target`.
    fn envelope(from: &str, target: &str, event: &str) -> Envelope {
        Envelope::outbound(
            OutboundSpec {
                event: EventName::parse(event).expect("a valid event name"),
                target: device(target),
                from: device(from),
                trace_id: TraceId::new(),
                sent_at_ms: 0,
                ttl_ms: Some(60_000),
            },
            None::<&serde_json::Value>,
        )
        .expect("builds")
    }

    // ── Envelopes in both directions ──────────────────────────────────────────────────────────────

    #[test]
    fn an_envelope_travels_from_one_link_to_the_other() {
        // The whole point: a socket whose handshake is done becomes a link that carries messages.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        sender
            .send(&envelope(PEER, LOCAL, "device.ping"))
            .expect("sends");
        let got = receiver.receive().expect("receives");

        assert_eq!(got.event.as_str(), "device.ping");
        assert_eq!(got.from, device(PEER));
        assert_eq!(got.target, device(LOCAL));
        assert_eq!(sender.sent(), 1);
        assert_eq!(receiver.received(), 1);
    }

    #[test]
    fn a_link_with_a_recorder_counts_the_payload_bytes_it_moves() {
        // ★ The byte counters live on the link because the link is what holds the payloads; the host counts frames and
        // cannot add a number it never took. Payload bytes, not wire bytes: the frame header is the transport's accounting,
        // and "how much did this device move" is the question the counter exists to answer.
        use synra_observe::metrics::Value;

        let (a, b) = connected();
        let sender_metrics = Arc::new(synra_observe::metrics::RingRecorder::new());
        let receiver_metrics = Arc::new(synra_observe::metrics::RingRecorder::new());
        let mut sender = link(a, PEER, LOCAL).with_metrics(Arc::clone(&sender_metrics));
        let mut receiver = link(b, LOCAL, PEER).with_metrics(Arc::clone(&receiver_metrics));

        // The envelope helper carries no payload, so a block is what proves the counters move — and it proves it for both
        // directions, which are separate series.
        sender
            .send(&envelope(PEER, LOCAL, "device.ping"))
            .expect("sends");
        let _ = receiver.receive().expect("receives");
        sender.send_chunk(0, &[1, 2, 3, 4]).expect("sends a block");
        let _ = receiver.receive_inbound().expect("receives a block");

        assert_eq!(
            sender_metrics.snapshot().get("bytes_sent_total"),
            Some(&Value::Counter(4))
        );
        assert_eq!(
            receiver_metrics.snapshot().get("bytes_received_total"),
            Some(&Value::Counter(4))
        );
        // ★ And the frame counters, by event: the half that used to be counted in `Host::send`/`listener`, and therefore
        // only for frames that passed through one. Both directions are asserted here because the link is now the one
        // place they are taken.
        assert_eq!(
            sender_metrics
                .snapshot()
                .get("frames_sent_total{event=device.ping}"),
            Some(&Value::Counter(1))
        );
        assert_eq!(
            receiver_metrics
                .snapshot()
                .get("frames_received_total{event=device.ping}"),
            Some(&Value::Counter(1))
        );
    }

    #[test]
    fn several_envelopes_arrive_in_order() {
        // A link is one socket and one stream, so order is the transport's — and a link that reordered would be one a
        // session could not use for a conversation.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        for event in ["device.first", "device.second", "device.third"] {
            sender.send(&envelope(PEER, LOCAL, event)).expect("sends");
        }
        let events: Vec<String> = (0..3)
            .map(|_| {
                receiver
                    .receive()
                    .expect("receives")
                    .event
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            events,
            vec!["device.first", "device.second", "device.third"]
        );
    }

    #[test]
    fn a_payload_survives_the_round_trip() {
        // The payload is a `RawValue` the kernel checks without parsing, so it has to arrive byte for byte.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        let payload = serde_json::json!({"nested": {"list": [1, 2, 3]}, "text": "héllo"});
        let mut message = envelope(PEER, LOCAL, "device.ping");
        message.payload = Some(serde_json::value::to_raw_value(&payload).expect("raw"));

        sender.send(&message).expect("sends");
        let got = receiver.receive().expect("receives");

        let got_payload = got.payload.expect("a payload");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(got_payload.get()).expect("parses"),
            payload
        );
    }

    // ── The checks a socket cannot make ───────────────────────────────────────────────────────────

    #[test]
    fn an_envelope_claiming_another_sender_is_refused() {
        // ★ The check only a link can make. The peer **is** the sender, so an envelope whose `from` is a different device
        // is a peer speaking for a device it is not — and without this, any paired device could send an intent that
        // appears to come from one the user trusts more.
        let (a, b) = connected();
        // The socket on `a` carries `OTHER`: that is who the receiver believes is on the other end, decided when the link
        // was built from the handshake. So an envelope claiming to be from `PEER` is a forgery *by this link's own
        // terms* — and the two versions of this test that failed were ones where the fixture had accidentally made the
        // envelope legitimate.
        let mut liar = link(a, OTHER, LOCAL);
        let mut receiver = link(b, LOCAL, OTHER);

        let forged = envelope(PEER, LOCAL, "device.ping");
        liar.send(&forged).expect("sends");

        match receiver.receive() {
            Err(LinkError::Envelope { why }) => {
                assert!(why.contains(&device(PEER).to_string()), "{why}");
                assert!(why.contains(&device(OTHER).to_string()), "{why}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And nothing was counted as received, because nothing was.
        assert_eq!(receiver.received(), 0);
    }

    #[test]
    fn an_envelope_addressed_elsewhere_is_refused() {
        // A peer that sends one for another device is either misconfigured or probing, and either way this link is not
        // the one to route it.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        sender
            .send(&envelope(PEER, OTHER, "device.ping"))
            .expect("sends");
        assert!(matches!(
            receiver.receive(),
            Err(LinkError::Envelope { .. })
        ));
    }

    #[test]
    fn a_block_travels_from_one_link_to_the_other() {
        // ★ The data plane, which the link did not carry until now: a `ChunkFrame` is a different frame kind from an
        // envelope, and a reader that understood only envelopes refused it.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        sender.send_chunk(7, b"block bytes").expect("sends");
        match receiver.receive_inbound().expect("receives") {
            Inbound::Block { chunk_id, data } => {
                assert_eq!(chunk_id, 7);
                assert_eq!(&data[..], b"block bytes");
            }
            other => panic!("expected a block, got {other:?}"),
        }
        assert_eq!(sender.sent(), 1);
        assert_eq!(receiver.received(), 1);
    }

    #[test]
    fn the_two_planes_interleave_without_confusing_each_other() {
        // ★ What a transfer actually looks like on the wire: a control message, blocks, another control message. A reader
        // that handled one plane but not the other would fail at the first block *or* at the first envelope after one.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        sender
            .send(&envelope(PEER, LOCAL, "file.transfer.request"))
            .expect("sends");
        sender.send_chunk(0, b"first").expect("sends");
        sender.send_chunk(1, b"second").expect("sends");
        sender
            .send(&envelope(PEER, LOCAL, "file.transfer.complete"))
            .expect("sends");

        let mut seen = Vec::new();
        for _ in 0..4 {
            match receiver.receive_inbound().expect("receives") {
                Inbound::Envelope(envelope) => {
                    seen.push(format!("event:{}", envelope.event.as_str()));
                }
                Inbound::Block { chunk_id, data } => {
                    seen.push(format!(
                        "block:{chunk_id}:{}",
                        String::from_utf8_lossy(&data)
                    ));
                }
            }
        }
        assert_eq!(
            seen,
            vec![
                "event:file.transfer.request",
                "block:0:first",
                "block:1:second",
                "event:file.transfer.complete",
            ]
        );
    }

    #[test]
    fn a_caller_that_asked_for_an_envelope_is_told_about_a_block() {
        // ★ `receive` refuses a block rather than dropping it. Dropping would lose part of a file silently, and the caller
        // that wanted only envelopes is one that has nowhere to put it.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        sender.send_chunk(0, b"data").expect("sends");
        match receiver.receive() {
            Err(LinkError::Unexpected { found }) => assert_eq!(found, "chunk"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_block_too_large_for_a_frame_is_refused() {
        // The ceiling is the protocol's, and the refusal happens before anything is written rather than after.
        let (a, _b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let too_big = vec![0u8; synra_protocol::limits::MAX_CHUNK_LEN + 1];
        assert!(sender.send_chunk(0, &too_big).is_err());
        // And the ceiling itself is accepted, because an off-by-one here would refuse a block the protocol allows.
        let at_limit = vec![0u8; synra_protocol::limits::MAX_CHUNK_LEN];
        assert!(sender.send_chunk(0, &at_limit).is_ok());
    }

    #[test]
    fn a_ping_between_two_blocks_is_still_answered_invisibly() {
        // The heartbeat stays the link's business on the data plane too: a caller reading blocks should never see one.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        sender.send_chunk(0, b"before").expect("sends");
        sender.ping().expect("sends");
        sender.send_chunk(1, b"after").expect("sends");

        match receiver.receive_inbound().expect("first") {
            Inbound::Block { chunk_id, .. } => assert_eq!(chunk_id, 0),
            other => panic!("expected a block, got {other:?}"),
        }
        match receiver.receive_inbound().expect("second") {
            Inbound::Block { chunk_id, .. } => {
                assert_eq!(chunk_id, 1, "the ping was not swallowed")
            }
            other => panic!("expected a block, got {other:?}"),
        }
        // Exactly the two blocks were counted; the heartbeat is not a message.
        assert_eq!(receiver.received(), 2);
    }

    #[test]
    fn a_full_size_block_survives_the_round_trip() {
        // ★ The size a real transfer uses, which is the size that found a bug: a 256 KiB block is far more than one socket
        // read, so it arrives in pieces. An earlier `read_frame` treated a socket timeout **between** two of those pieces
        // as a broken link and threw the buffered bytes away — so a 300 KB file arrived byte-for-byte while both ends
        // reported a timeout.
        // ★ `production()` rather than `no_timeout()`, because the timeout is the thing under test: a block larger than one
        // socket read sits in the buffer across several reads, and a timeout between two of them must not abandon it.
        let (a, b) = connected();
        let mut sender = PeerLink::new(
            a,
            device(LOCAL),
            device(PEER),
            agreed(),
            Flags::production(),
        );
        let mut receiver = PeerLink::new(
            b,
            device(PEER),
            device(LOCAL),
            agreed(),
            Flags::production(),
        );

        let first = vec![7u8; synra_protocol::limits::MAX_CHUNK_LEN];
        let second = vec![9u8; 37_856];

        let writer = std::thread::spawn(move || {
            sender.send_chunk(0, &first).expect("sends the first");
            sender.send_chunk(1, &second).expect("sends the second");
            sender
        });

        let mut seen = Vec::new();
        for _ in 0..2 {
            match receiver.receive_inbound().expect("receives a block") {
                Inbound::Block { chunk_id, data } => seen.push((chunk_id, data)),
                other => panic!("expected a block, got {other:?}"),
            }
        }
        let sender = writer.join().expect("the writer finished");

        assert_eq!(seen[0].0, 0);
        assert_eq!(seen[0].1.len(), synra_protocol::limits::MAX_CHUNK_LEN);
        assert!(seen[0].1.iter().all(|byte| *byte == 7));
        assert_eq!(seen[1].0, 1);
        assert_eq!(seen[1].1.len(), 37_856);
        assert!(seen[1].1.iter().all(|byte| *byte == 9));
        assert_eq!(sender.sent(), 2);
    }

    #[test]
    fn a_frame_that_is_not_an_envelope_is_refused() {
        // A `Hello` after the handshake is a peer that has lost track of where it is, and a `Bye` is one saying goodbye —
        // neither is a message this reader carries. ★ A `Chunk` used to be in this list, and is not any more: the data
        // plane travels here now, and a block is refused by `receive` specifically rather than as an unknown frame.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        // A `Hello` needs its own body: the protocol pairs each kind with a variant, and an empty one is refused by the
        // encoder rather than by the link.
        let hello = Frame {
            kind: FrameKind::Hello,
            flags: 0,
            body: FrameBody::Hello(Bytes::from_static(b"{}")),
        };
        sender.send_frame(&hello).expect("sends");
        match receiver.receive() {
            Err(LinkError::Unexpected { found }) => assert_eq!(found, "hello"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_malformed_envelope_is_refused_rather_than_panicking() {
        // The frame is well formed and its contents are not, which is the case a peer controls.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        let frame = Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(b"{not json")),
        };
        sender.send_frame(&frame).expect("sends");
        assert!(matches!(
            receiver.receive(),
            Err(LinkError::Envelope { .. })
        ));
    }

    #[test]
    fn an_envelope_that_is_not_utf8_is_refused() {
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        let frame = Frame {
            kind: FrameKind::Envelope,
            flags: 0,
            body: FrameBody::Envelope(Bytes::from_static(&[0xff, 0xfe, 0xfd])),
        };
        sender.send_frame(&frame).expect("sends");
        match receiver.receive() {
            Err(LinkError::Envelope { why }) => assert!(why.contains("text"), "{why}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // ── Heartbeats ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_ping_is_answered_without_the_caller_seeing_it() {
        // ★ A caller that had to handle a `Ping` would be one that could forget to — and the consequence is a peer that
        // concludes the link is dead while it is working. A heartbeat is the link's own business.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        sender.ping().expect("sends");
        // The receiver first answers the ping, then gets the envelope that follows it.
        sender
            .send(&envelope(PEER, LOCAL, "device.ping"))
            .expect("sends");

        let got = receiver.receive().expect("receives");
        assert_eq!(got.event.as_str(), "device.ping");
        // Only the envelope counted, because a heartbeat is not a message the session has anything to do with.
        assert_eq!(receiver.received(), 1);

        // And the pong came back, which the sender reads as a frame it can ignore.
        let mut decoder = FrameDecoder::new();
        let mut buffer = [0u8; 1024];
        let read = sender.stream.read(&mut buffer).expect("reads");
        decoder
            .push_slice(buffer.get(..read).expect("a chunk"))
            .expect("the frame is well formed");
        let frame = decoder.next_frame().expect("no error").expect("a frame");
        assert_eq!(frame.kind, FrameKind::Pong);
    }

    #[test]
    fn a_frame_the_decoder_refuses_ends_the_link() {
        // ★ A1 says a structural problem closes the link. The decoder side of that was already tested
        // (`frame.rs`: an unknown kind poisons, and a poisoned decoder refuses further use). What was missing is the
        // other half: that the **link** stops, rather than carrying on in a state where every later read fails for a
        // reason that has nothing to do with what the caller did.
        //
        // Without this, the sentence in the design document was supported by a code reading and not by a test — which is
        // the same gap `code review + test` is written to close.
        let (a, b) = connected();
        let mut a = a;

        // ★ The bytes are written straight onto the socket rather than through `send_frame`, and that is the point.
        // `send_frame` refuses this frame first — the encoder validates the kind and body pair and answers
        // `BodyKindMismatch` — so a test built on the sender could only ever prove that the *encoder* is careful.
        // A peer is not the encoder: it is whatever is on the other end, so the only honest way to test the receiving
        // half is to produce bytes no compliant sender would.
        //
        // The layout is the documented one: `u32 BE length` (4 = kind + flags + two body bytes), then an unknown
        // kind byte `0xff`, then flags, then a two-byte body.
        use std::io::Write;
        a.write_all(&[0x00, 0x00, 0x00, 0x04, 0xff, 0x00, b'{', b'}'])
            .expect("writes");

        let mut _sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        let first = receiver.receive();
        assert!(
            matches!(
                first,
                Err(LinkError::Frame(_)) | Err(LinkError::Unexpected { .. })
            ),
            "an unknown frame kind was accepted: {first:?}"
        );

        // And the link does not come back: a second read is refused rather than returning whatever happens to be next.
        let second = receiver.receive();
        assert!(
            second.is_err(),
            "the link carried on after a refused frame: {second:?}"
        );
    }

    #[test]
    fn a_bye_ends_the_link() {
        // The peer saying goodbye is the ordinary end, and a caller reads it as closed rather than as a fault.
        let (a, b) = connected();
        let mut sender = link(a, PEER, LOCAL);
        let mut receiver = link(b, LOCAL, PEER);

        sender.bye("done").expect("sends");
        assert!(matches!(receiver.receive(), Err(LinkError::Closed)));
    }

    #[test]
    fn a_peer_that_hangs_up_is_reported_as_closed() {
        // The ordinary shape of a user who closed a laptop. On Windows this arrives as a reset rather than a clean
        // end-of-file, which is why the check is on the error rather than on the read count alone.
        let (a, b) = connected();
        let mut receiver = link(b, LOCAL, PEER);
        drop(a);

        assert!(matches!(receiver.receive(), Err(LinkError::Closed)));
    }

    // ── What the link knows ───────────────────────────────────────────────────────────────────────

    #[test]
    fn the_link_knows_both_identifiers_and_what_was_agreed() {
        let (a, _b) = connected();
        let link = link(a, LOCAL, PEER);
        assert_eq!(link.local(), device(LOCAL));
        assert_eq!(link.peer(), device(PEER));
        assert!(link.supports(synra_protocol::handshake::Feature::EventStream));
        assert!(!link.supports(synra_protocol::handshake::Feature::ClipboardSync));
        assert_eq!(link.sent(), 0);
        assert_eq!(link.received(), 0);
    }

    #[test]
    fn a_link_with_a_missing_required_feature_is_still_made() {
        // The link is built from an `Agreed` rather than deciding for itself: a caller that wants to refuse a link with
        // a missing requirement does so before building it, and one that built it anyway can still ask.
        let (a, _b) = connected();
        let broken = synra_protocol::handshake::Agreed {
            common: Vec::new(),
            missing_required: vec![synra_protocol::handshake::Feature::TransferResume],
        };
        let link = PeerLink::new(a, device(LOCAL), device(PEER), broken, Flags::no_timeout());
        assert!(!link.agreed().is_usable());
    }

    // ── Errors ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            LinkError::Transport {
                why: "reset".to_owned(),
            },
            LinkError::Closed,
            LinkError::Frame(FrameError::Poisoned),
            LinkError::Unexpected {
                found: "chunk".to_owned(),
            },
            LinkError::Envelope {
                why: "not for us".to_owned(),
            },
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 10, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn a_handshake_failure_becomes_the_matching_link_failure() {
        // A handshake's transport failure and a link's are the same condition seen at different moments, so a caller does
        // not have to handle two spellings of "the connection broke".
        assert!(matches!(
            LinkError::from(HandshakeError::Transport {
                why: "x".to_owned()
            }),
            LinkError::Transport { .. }
        ));
        assert!(matches!(
            LinkError::from(HandshakeError::Closed),
            LinkError::Closed
        ));
        assert!(matches!(
            LinkError::from(HandshakeError::Frame(FrameError::Poisoned)),
            LinkError::Frame(_)
        ));
        assert!(matches!(
            LinkError::from(HandshakeError::VersionMismatch { theirs: 2, ours: 1 }),
            LinkError::Envelope { .. }
        ));
    }
}
