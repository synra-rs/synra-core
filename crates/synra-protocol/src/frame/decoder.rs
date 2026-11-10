//! Incremental frame decoding and poisoning behavior.

use bytes::{Bytes, BytesMut};

use super::{Frame, FrameError, FrameKind, FRAME_HEADER_LEN, MAX_FRAME_LEN};
use super::validation::{build_body, validate_declared, validate_shape};

/// A validated frame header.
#[derive(Debug, Clone, Copy)]
struct Header {
    declared: u32,
    kind_byte: u8,
    flags: u8,
}

impl Header {
    /// Body length implied by the declared length.
    ///
    /// `validate_declared` has already established `declared >= 2`, so this cannot underflow.
    const fn body_len(self) -> usize {
        (self.declared - 2) as usize
    }
}

/// Reads a header without indexing, returning `None` if six bytes are not present.
fn read_header(bytes: &Bytes) -> Option<Header> {
    let [l0, l1, l2, l3, kind_byte, flags] = bytes.first_chunk::<{ FRAME_HEADER_LEN }>()?;
    Some(Header {
        declared: u32::from_be_bytes([*l0, *l1, *l2, *l3]),
        kind_byte: *kind_byte,
        flags: *flags,
    })
}

/// Turns a whole-frame region into a typed frame.
fn build_frame(region: &Bytes, header: Header) -> Result<Frame, FrameError> {
    let kind = FrameKind::from_u8(header.kind_byte)?;
    validate_shape(kind, header.body_len())?;

    // Skip the header. `slice` is O(1), so the body is still the same allocation.
    let body = build_body(kind, region.slice(FRAME_HEADER_LEN..))?;

    Ok(Frame { kind, flags: header.flags, body })
}

/// Incremental decoder.
///
/// Feed it bytes with [`Self::push`], read frames with [`Self::next_frame`], drop the last read with
/// [`Self::recycle`]. Every error is a link-closing condition; after one the decoder is poisoned.
///
/// # Buffer behaviour
///
/// A read that contains whole frames is sliced, not copied. A frame split across reads is copied
/// into `scratch`, which is reused: [`Self::recycle`] resets its length without freeing or zeroing
/// the allocation.
#[derive(Debug)]
pub struct FrameDecoder {
    /// The most recent read, kept so whole frames can be sliced out of it.
    head: Option<Bytes>,
    /// Holds a frame that is waiting for the rest of its bytes.
    scratch: BytesMut,
    /// Set on the first error. Once set, every operation returns [`FrameError::Poisoned`].
    poisoned: bool,
    /// Largest frame this decoder accepts, so a test or a host can lower it.
    max_frame: u32,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    /// A decoder with the standard ceiling.
    #[must_use]
    pub fn new() -> Self {
        Self {
            head: None,
            scratch: BytesMut::with_capacity(8 * 1024),
            poisoned: false,
            max_frame: MAX_FRAME_LEN,
        }
    }

    /// A decoder with a lowered ceiling, for tests and for hosts that want a smaller limit.
    #[must_use]
    pub fn with_max_frame(max_frame: u32) -> Self {
        Self { max_frame, ..Self::new() }
    }

    /// Whether an earlier operation failed.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Bytes buffered but not yet consumed.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.scratch.len() + self.head.as_ref().map_or(0, Bytes::len)
    }

    /// Appends received bytes.
    ///
    /// Takes `&Bytes` rather than `&[u8]` so a caller can hand over a socket read without a
    /// conversion. When the read contains whole frames — the common case — they are sliced straight
    /// out of it, so the fast path copies nothing at all. Only a frame split across reads is copied,
    /// into the scratch buffer, because it has to be held somewhere until the rest arrives.
    ///
    /// # Errors
    ///
    /// [`FrameError::Poisoned`] if the decoder has already failed.
    pub fn push(&mut self, input: &Bytes) -> Result<(), FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }

        // Carry-over wins.
        //
        // While anything is left over from an earlier read, new bytes must join *it* rather than
        // replace it: the stream is ordered, so a partial frame has to be completed before a later
        // frame can be looked at. Assigning `head` instead would silently drop the partial frame's
        // first bytes, which shows up later as a length read from the middle of a message.
        if self.head.as_ref().is_some_and(|head| !head.is_empty()) || !self.scratch.is_empty() {
            self.absorb_into_scratch(input);
        }
        else {
            self.head = Some(input.clone());
        }
        Ok(())
    }

    /// Moves whatever remains in `head` into `scratch`, then appends `input`.
    fn absorb_into_scratch(&mut self, input: &Bytes) {
        if let Some(rest) = self.head.take()
            && !rest.is_empty()
        {
            self.scratch.extend_from_slice(&rest);
        }
        self.scratch.extend_from_slice(input);
    }

    /// Appends bytes from a slice, for tests and callers without a [`Bytes`].
    ///
    /// # Errors
    ///
    /// As [`Self::push`].
    pub fn push_slice(&mut self, input: &[u8]) -> Result<(), FrameError> {
        self.push(&Bytes::copy_from_slice(input))
    }

    /// Returns the next complete frame, or `None` if more bytes are needed.
    ///
    /// On `Err` the decoder is poisoned and the caller must close the link.
    ///
    /// # Errors
    ///
    /// Any [`FrameError`] variant.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.poisoned {
            return Err(FrameError::Poisoned);
        }

        // The scratch buffer holds a frame that arrived in pieces, plus anything queued behind it.
        // It is drained before the head is touched, because the stream is ordered.
        if !self.scratch.is_empty() {
            return self.advance_scratch();
        }

        let Some(head) = self.head.clone() else {
            return Ok(None);
        };

        if head.len() < FRAME_HEADER_LEN {
            // Too short for a header. Move it to scratch, because a `Bytes` cannot be extended.
            self.scratch.extend_from_slice(&head);
            self.head = None;
            return Ok(None);
        }

        let Some(header) = read_header(&head) else {
            return Ok(None);
        };

        // The declared length is validated before waiting for the body, so a peer cannot make us
        // buffer an arbitrarily large frame: a claim above the ceiling is refused the moment the
        // header arrives, rather than after the memory has been committed.
        if let Err(error) = validate_declared(header.declared, self.max_frame) {
            return Err(self.poison(error));
        }

        let total = FRAME_HEADER_LEN + header.body_len();
        if head.len() < total {
            // Valid header, incomplete body. Keep what arrived and wait.
            self.scratch.extend_from_slice(&head);
            self.head = None;
            return Ok(None);
        }

        // The fast path: a whole frame is present, so it is sliced rather than copied.
        self.head = Some(head.slice(total..));
        match build_frame(&head.slice(..total), header) {
            Ok(frame) => Ok(Some(frame)),
            Err(error) => Err(self.poison(error)),
        }
    }

    /// Consumes one frame from the scratch buffer, if a whole one is present.
    fn advance_scratch(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.scratch.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        // A `Bytes` view for header reading, so the borrow does not conflict with the later
        // `split_to`. `clone().freeze()` is O(1): it shares the allocation.
        let view = self.scratch.clone().freeze();
        let Some(header) = read_header(&view) else {
            return Ok(None);
        };

        if let Err(error) = validate_declared(header.declared, self.max_frame) {
            return Err(self.poison(error));
        }

        let total = FRAME_HEADER_LEN + header.body_len();
        if self.scratch.len() < total {
            return Ok(None);
        }

        // `split_to` advances an offset; `freeze` makes the result a shared slice, so the frame body
        // borrows the scratch allocation rather than a copy of it.
        let frame_region = self.scratch.split_to(total).freeze();

        // Once the scratch buffer is drained, stop using it entirely and go back to slicing the
        // head. Following this rule in `push` as well is what keeps the two in step: a drained
        // scratch means "the next read may go straight to head".
        if self.scratch.is_empty() {
            self.scratch = BytesMut::with_capacity(8 * 1024);
        }

        match build_frame(&frame_region, header) {
            Ok(frame) => Ok(Some(frame)),
            Err(error) => Err(self.poison(error)),
        }
    }

    /// Marks the decoder unusable and returns the error unchanged.
    fn poison(&mut self, error: FrameError) -> FrameError {
        self.poisoned = true;
        self.head = None;
        error
    }

    /// Drops the reference to the last read and clears the scratch length.
    ///
    /// Keeps the scratch allocation so the next partial frame reuses it, and does not zero it: the
    /// bytes are about to be overwritten.
    pub fn recycle(&mut self) {
        self.scratch.clear();
        self.head = None;
    }

    /// Frees both buffers and marks the decoder unusable, for a link being torn down.
    ///
    /// Poisoning on release is deliberate: a decoder belonging to a dead link must not be handed to
    /// a new one, because leftover bytes from the old stream would be read as the new stream's first
    /// frame.
    pub fn release(&mut self) {
        self.scratch = BytesMut::new();
        self.head = None;
        self.poisoned = true;
    }
}




