use crate::ids::{DeviceId, RequestId};
use super::PlatformKind;

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionState {
    /// Started, not finished.
    Open,
    /// Finished successfully.
    Succeeded,
    /// Finished unsuccessfully.
    Failed,
    /// Bounded out.
    Expired,
    /// Abandoned by one side.
    Cancelled,
}

impl SessionState {
    /// Whether this is an end state, after which nothing more happens.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Open)
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Tracks which requests are outstanding, so a reply can be matched and a duplicate recognised.
///
/// A small bounded set rather than a record of everything ever sent: what matters is the recent past,
/// and an unbounded list of outstanding requests is a memory leak with a slow fuse.
#[derive(Debug)]
pub struct OutstandingRequests {
    entries: Vec<(RequestId, i64)>,
    capacity: usize,
    window_ms: i64,
}

impl OutstandingRequests {
    /// Tracks up to `capacity` requests within `window_ms`.
    #[must_use]
    pub fn new(capacity: usize, window_ms: i64) -> Self {
        Self { entries: Vec::new(), capacity: capacity.max(1), window_ms }
    }

    /// Records a request as sent, at `now_ms`.
    ///
    /// When full, the oldest entry is dropped: the newest requests are the ones whose replies have
    /// not yet had time to arrive.
    pub fn insert(&mut self, request: RequestId, now_ms: i64) {
        self.expire(now_ms);
        if self.entries.len() >= self.capacity {
            // `remove(0)` is O(n), but n is a small constant and this happens only when the list is
            // full — never on the reply path, which runs per frame.
            self.entries.remove(0);
        }
        self.entries.push((request, now_ms));
    }

    /// Whether a request is still outstanding.
    #[must_use]
    pub fn contains(&self, request: &RequestId) -> bool {
        self.entries.iter().any(|(id, _)| id == request)
    }

    /// Forgets a request, once its reply has arrived.
    pub fn remove(&mut self, request: &RequestId) {
        self.entries.retain(|(id, _)| id != request);
    }

    /// Drops entries older than the window.
    pub fn expire(&mut self, now_ms: i64) {
        let window = self.window_ms;
        self.entries
            .retain(|(_, at)| now_ms.saturating_sub(*at) <= window);
    }

    /// How many requests are outstanding.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is outstanding.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A device's own view of one peer.
///
/// Only the fields the protocol layer needs. The richer "device card" belongs to the kernel, and is
/// derived from this rather than stored beside it — two places holding the same state is how they
/// come to disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSnapshot {
    /// The peer's id.
    pub device_id: DeviceId,
    /// Whether this host has a pairing record for it.
    pub paired: bool,
    /// The last name it reported.
    pub display_name: String,
    /// Which platform it runs.
    pub platform: PlatformKind,
}
