//! What the pool knows about one instance, and the limits it holds it to.

use core::time::Duration;

use super::policy::InstancePolicy;
/// One instance's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceRecord {
    /// The handle.
    pub handle: u64,
    /// The conversation it is bound to, for a stateful plugin.
    pub conversation: Option<String>,
    /// Whether a call is in progress.
    pub busy: bool,
    /// How many calls it has served, which is one input to recycling.
    pub calls: u64,
    /// When it was created, as a monotonic millisecond count.
    pub created_ms: u64,
    /// When it last served a call.
    pub last_used_ms: u64,
}

impl InstanceRecord {
    /// Whether it may be handed to a caller asking about `conversation`.
    pub(super) fn serves(&self, policy: InstancePolicy, conversation: Option<&str>) -> bool {
        if self.busy {
            return false;
        }
        match policy {
            InstancePolicy::Stateless => true,
            // A stateful instance with no conversation has never been used, so it may take one. One that has a
            // conversation serves only that conversation, which is the whole point of the policy.
            InstancePolicy::Stateful => match (&self.conversation, conversation) {
                (None, _) => true,
                (Some(bound), Some(wanted)) => bound == wanted,
                (Some(_), None) => false,
            },
        }
    }
}

/// How many calls an instance may serve before it is recycled.
///
/// A Wasm instance accumulates whatever the plugin's allocator does not return. Recycling on a call count bounds
/// that in a way the plugin cannot influence, and — unlike a memory threshold — it is cheap to check.
pub const RECYCLE_AFTER_CALLS: u64 = 10_000;

/// How long an idle instance is kept before it is recycled.
///
/// Five minutes: long enough that a plugin used intermittently keeps its compiled instance, short enough that a
/// plugin nobody is using stops holding memory.
pub const IDLE_EVICT_AFTER: Duration = Duration::from_secs(300);
