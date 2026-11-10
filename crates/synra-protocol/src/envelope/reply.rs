//! The routing facts needed to build a reply after the request bytes are gone.

use crate::ids::{DeviceId, RequestId, TraceId};

use super::Envelope;

/// What a reply needs to know, when the request's own bytes are no longer at hand.
///
/// ★ **Why this is a value rather than the request envelope.**
///
/// The side that answers is often not the side that read the request: in the daemon's case the bytes were consumed by a
/// transfer that has already landed, and what survives is these four facts. A constructor that demanded the original
/// envelope would make every reader keep one — including a payload it has no use for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyContext {
    /// The request this answers.
    pub request_id: RequestId,
    /// Who the answer is for.
    pub target: DeviceId,
    /// Who it is from.
    pub from: DeviceId,
    /// The trace the question belonged to.
    pub trace_id: TraceId,
    /// How long the question was interesting for.
    pub ttl_ms: Option<u32>,
}

impl ReplyContext {
    /// The facts a reply needs, taken from the request and this device's own identity.
    ///
    /// ★ `local` is a parameter rather than a field read off the request, and that is the whole reason this is a
    /// function: **who is answering** is never in the question. A version of this that took only the request would set
    /// `from` to the *asker* — a reply addressed from the device it is addressed to.
    #[must_use]
    pub const fn of(request: &Envelope, local: DeviceId) -> Self {
        Self {
            request_id: request.request_id,
            target: request.from,
            from: local,
            trace_id: request.trace_id,
            ttl_ms: request.ttl_ms,
        }
    }
}

