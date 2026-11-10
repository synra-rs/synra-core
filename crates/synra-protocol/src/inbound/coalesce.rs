use crate::envelope::Envelope;

use crate::event::builtin;

use super::Inbound;

/// Newest-wins buffer for high-frequency events.
///
/// Coalescing keeps the *current* state rather than a queue of history. A consumer that has fallen
/// behind wants to know where the transfer is now, not where it was twenty reports ago.
///
/// Only events whose name is on [`coalescable_names`] are joined; everything else is passed through
/// in order. Coalescing a business event would silently drop it, which is a different thing from
/// dropping a stale progress report.
#[derive(Debug, Default)]
pub struct CoalesceBuffer {
    /// Waiting messages, in arrival order. An envelope already carries its own event name, so a
    /// separate key would be a second copy of the same fact — and two copies of one fact is how they
    /// come to disagree.
    pending: Vec<Envelope>,
}

impl CoalesceBuffer {
    /// An empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self { pending: Vec::new() }
    }

    /// Adds a message, replacing any earlier one with the same event name.
    ///
    /// Returns `true` if it superseded an earlier message, so the caller can tell that one was
    /// dropped in favour of newer information.
    pub fn push(&mut self, inbound: Inbound) -> bool {
        let event = inbound.event().clone();
        let envelope = inbound.into_envelope();

        if !coalescable_names().contains(&event.as_str()) {
            // Not coalescable: kept as its own entry, in arrival order.
            self.pending.push(envelope);
            return false;
        }

        // Replaced in place, so the entry keeps its original position in the queue. Moving it to the
        // end would reorder it behind events that arrived later but matter less.
        for existing in &mut self.pending {
            if existing.event == event {
                *existing = envelope;
                return true;
            }
        }
        self.pending.push(envelope);
        false
    }

    /// How many messages are waiting.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Takes everything, leaving the buffer empty.
    pub fn drain(&mut self) -> Vec<Envelope> {
        core::mem::take(&mut self.pending)
    }
}

impl Inbound {
    /// Consumes the message and returns the envelope.
    #[must_use]
    pub fn into_envelope(self) -> Envelope {
        match self {
            Self::Transport { envelope, .. }
            | Self::Kernel { envelope, .. }
            | Self::Builtin { envelope, .. }
            | Self::DataPlane { envelope, .. }
            | Self::Plugin { envelope, .. }
            | Self::Unknown { envelope, .. } => *envelope,
        }
    }
}

/// The event names that may be coalesced.
///
/// A closed list. See the module docs for why nothing else belongs on it.
#[must_use]
pub const fn coalescable_names() -> &'static [&'static str] {
    &[builtin::TRANSFER_PROGRESS, builtin::NETWORK_CHANGED]
}
