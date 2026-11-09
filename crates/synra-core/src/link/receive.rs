use super::*;

impl PeerLink {
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
        let deadline = self
            .read_timeout_override
            .or(self.flags.timeout)
            .and_then(|timeout| std::time::Instant::now().checked_add(timeout));
        loop {
            let frame = self.read_frame(deadline)?;
            match frame.kind {
                FrameKind::Envelope => {
                    let envelope = self.parse_envelope(&frame)?;
                    self.received = self.received.saturating_add(1);
                    self.count_frame("frames_received_total", envelope.event.as_str());
                    let received_len = envelope
                        .payload
                        .as_ref()
                        .map_or(0, |payload| payload.get().len());
                    self.count_bytes("bytes_received_total", received_len);
                    self.trace_received(envelope.event.as_str(), received_len);
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
                    if synra_observe::wire::is_installed() {
                        synra_observe::wire::emit(&synra_observe::wire::WireEvent::received(
                            self.peer.to_string(),
                            format!("chunk #{}", chunk.chunk_id),
                            chunk.data.len(),
                        ));
                    }
                    return Ok(Inbound::Block {
                        chunk_id: chunk.chunk_id,
                        data: chunk.data,
                    });
                }
                FrameKind::Ping => {
                    self.trace_received("ping", 0);
                    let previous = self.write_timeout_override;
                    if let Some(deadline) = deadline {
                        let remaining =
                            deadline.saturating_duration_since(std::time::Instant::now());
                        if remaining.is_zero() {
                            return Err(LinkError::TimedOut);
                        }
                        self.write_timeout_override =
                            Some(remaining.min(self.write_deadline().unwrap_or(remaining)));
                    }
                    let result = self.pong();
                    self.write_timeout_override = previous;
                    result?;
                    self.trace_sent("pong", 0);
                }
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

    pub(super) fn send_frame(&mut self, frame: &Frame) -> Result<(), LinkError> {
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

    /// Saves caller overrides while a bounded business operation temporarily narrows them.
    pub(crate) const fn timeout_overrides(
        &self,
    ) -> (Option<std::time::Duration>, Option<std::time::Duration>) {
        (self.read_timeout_override, self.write_timeout_override)
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
    fn read_frame(&mut self, deadline: Option<std::time::Instant>) -> Result<Frame, LinkError> {
        if let Some(timeout) = self.read_timeout_override.or(self.flags.timeout) {
            self.stream.set_read_deadline(timeout)?;
        }

        let mut buffer = [0u8; 8 * 1024];
        loop {
            // This check also covers frames prefetched by Hello or an earlier read.
            self.stream.authorize(self.local, self.peer)?;
            if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(LinkError::TimedOut);
                }
                self.stream.set_read_deadline(remaining)?;
            }
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
pub(crate) fn is_a_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}
