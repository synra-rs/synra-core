use super::receive::is_a_timeout;
use super::*;

impl PeerLink {
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
    pub(super) fn write_frame(&mut self, encoded: &[u8]) -> Result<(), LinkError> {
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
        let payload_len = envelope
            .payload
            .as_ref()
            .map_or(0, |payload| payload.get().len());
        self.count_bytes("bytes_sent_total", payload_len);
        // ★ The debug tap sees the frame that actually went out, not the one the caller asked to send: a failed write
        // returns above and produces no line, which is what a reader comparing both ends needs.
        self.trace_sent(envelope.event.as_str(), payload_len);
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
        if synra_observe::wire::is_installed() {
            synra_observe::wire::emit(&synra_observe::wire::WireEvent::sent(
                self.peer.to_string(),
                format!("chunk #{chunk_id}"),
                data.len(),
            ));
        }
        Ok(())
    }
}
