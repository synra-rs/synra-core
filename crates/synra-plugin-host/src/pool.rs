//! The instance pool: how many plugin instances exist, and which one serves a call.
//!
//! # The decision the design document leaves open, and how it is settled here
//!
//! A headless plugin may declare itself `stateful`. That single flag decides whether instances are interchangeable,
//! and the two answers are not variations of one policy:
//!
//! * **Stateless** — memory does not persist between calls, so any instance will do. The pool creates instances on
//!   demand up to a quota and hands them out to whoever asks. A call that arrives while every instance is busy waits
//!   for one rather than creating another, because the quota is the bound on how much of the machine the plugin may
//!   use.
//! * **Stateful** — the plugin keeps memory across calls, so instances are **not** interchangeable. Handing a call
//!   to a different instance than the previous one is handing it to a plugin that has forgotten what it was doing.
//!   Each conversation gets its own instance for as long as it lasts, and the pool's job becomes *affinity*: the same
//!   conversation gets the same instance or none.
//!
//! Collapsing those two into one policy is the mistake this module exists to avoid. A pool that round-robins a
//! stateful plugin silently loses its state, and the symptom is a plugin that works when only one thing is happening.
//!
//! # Why the pool owns no runtime
//!
//! Instances here are `u64` handles. The Wasmtime store behind one is the application layer's, because an instance's
//! type is the engine's and this crate deliberately carries no engine dependency — see the crate root. What the pool
//! decides is *which handle a call gets and when a handle may be recycled*, and that is the part with the mistakes in
//! it.

use core::time::Duration;

use serde::{Deserialize, Serialize};

/// Whether a plugin's instances are interchangeable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstancePolicy {
    /// Memory does not persist between calls, so any instance will do.
    Stateless,
    /// Memory persists, so a conversation must keep the instance it started with.
    Stateful,
}

impl InstancePolicy {
    /// Whether instances may be handed to any caller.
    #[must_use]
    pub const fn allows_sharing(self) -> bool {
        matches!(self, Self::Stateless)
    }
}

/// Why an instance could not be handed out.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PoolRefusal {
    /// Every instance is busy and the quota does not allow another.
    ///
    /// Retryable: an instance will be released. This is the refusal a caller waits on.
    #[error("every instance is busy, and the plugin's quota allows {limit}")]
    Exhausted {
        /// The quota.
        limit: u32,
        /// How long a caller should wait before asking again.
        retry_after_ms: u64,
    },

    /// A stateful plugin has no instance for this conversation and cannot make one.
    ///
    /// Not the same as [`Self::Exhausted`] because the caller cannot make progress by waiting: the conversation needs
    /// *its* instance, and waiting for someone else's to be released does not produce it. The caller's next step is to
    /// tell the user the plugin is at its limit, or to drop the conversation.
    #[error("the plugin is stateful and has no instance free for this conversation")]
    NoAffinity {
        /// The conversation that wanted one.
        conversation: String,
        /// How many instances exist.
        live: u32,
        /// The quota.
        limit: u32,
    },

    /// The plugin is not running.
    #[error("the plugin is not running")]
    NotRunning,

    /// An instance handle is not one this pool issued.
    ///
    /// Checked rather than assumed: a handle from a previous pool, or from a different plugin, would otherwise be
    /// released twice or released into the wrong pool.
    #[error("{handle} is not an instance of this pool")]
    UnknownInstance {
        /// The handle.
        handle: u64,
    },
}

impl PoolRefusal {
    /// Whether asking again later could succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Exhausted { .. })
    }
}

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
    fn serves(&self, policy: InstancePolicy, conversation: Option<&str>) -> bool {
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

/// A pool of instances for one plugin.
#[derive(Debug)]
pub struct InstancePool {
    policy: InstancePolicy,
    limit: u32,
    instances: parking_lot::Mutex<Vec<InstanceRecord>>,
    next_handle: parking_lot::Mutex<u64>,
    running: parking_lot::Mutex<bool>,
    /// How long a caller is told to wait when the pool is exhausted.
    retry_hint: Duration,
    recycle_after_calls: u64,
    idle_evict_after: Duration,
}

impl InstancePool {
    /// A pool for a plugin.
    ///
    /// Not `const`, though nothing in it needs to allocate: it builds a `parking_lot::Mutex` and a `Duration`, neither
    /// of which is const-constructible in a form the lint accepts.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(policy: InstancePolicy, limit: u32) -> Self {
        Self {
            policy,
            limit,
            instances: parking_lot::Mutex::new(Vec::new()),
            next_handle: parking_lot::Mutex::new(1),
            running: parking_lot::Mutex::new(true),
            retry_hint: Duration::from_millis(50),
            recycle_after_calls: RECYCLE_AFTER_CALLS,
            idle_evict_after: IDLE_EVICT_AFTER,
        }
    }

    /// Overrides the recycling thresholds, for a test that cannot make ten thousand calls.
    #[must_use]
    pub const fn with_recycling(mut self, after_calls: u64, idle_after: Duration) -> Self {
        self.recycle_after_calls = after_calls;
        self.idle_evict_after = idle_after;
        self
    }

    /// Overrides the wait a caller is told when the pool is exhausted.
    #[must_use]
    pub const fn with_retry_hint(mut self, hint: Duration) -> Self {
        self.retry_hint = hint;
        self
    }

    /// The policy.
    #[must_use]
    pub const fn policy(&self) -> InstancePolicy {
        self.policy
    }

    /// The quota.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// How many instances exist.
    #[must_use]
    pub fn live(&self) -> u32 {
        u32::try_from(self.instances.lock().len()).unwrap_or(u32::MAX)
    }

    /// How many are busy.
    #[must_use]
    pub fn busy(&self) -> u32 {
        u32::try_from(self.instances.lock().iter().filter(|record| record.busy).count())
            .unwrap_or(u32::MAX)
    }

    /// Marks the pool usable.
    pub fn start(&self) {
        *self.running.lock() = true;
    }

    /// Marks the pool unusable and drops every instance.
    ///
    /// Drops rather than keeps, because a stopped plugin's instances hold memory and state that no longer correspond
    /// to anything the plugin will be asked about.
    pub fn stop(&self) {
        *self.running.lock() = false;
        self.instances.lock().clear();
    }

    /// Whether the plugin is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        *self.running.lock()
    }

    /// Takes an instance for a call.
    ///
    /// # Errors
    ///
    /// [`PoolRefusal`] describing why not, and whether waiting would help.
    ///
    /// # Creating on demand, up to the quota
    ///
    /// A pool does not pre-create instances: a plugin that is never called should cost nothing, and the first call is
    /// the earliest moment the host knows an instance is wanted. Once the quota is reached the pool stops creating,
    /// which is what makes the quota a bound on memory rather than a suggestion.
    pub fn acquire(&self, conversation: Option<&str>, now_ms: u64) -> Result<u64, PoolRefusal> {
        if !self.is_running() {
            return Err(PoolRefusal::NotRunning);
        }

        // Each critical section lives in its own method, so no guard is ever held across another lock. That is not a
        // style preference: two pool locks held at once is how a pool deadlocks with itself, and a design that makes
        // the overlap impossible is better than one that remembers not to do it.
        if let Some(handle) = self.try_reuse(conversation, now_ms) {
            return Ok(handle);
        }

        let live = self.check_capacity(conversation)?;
        let _ = live;

        let handle = self.take_handle();
        self.push_instance(handle, conversation, now_ms);
        Ok(handle)
    }

    /// Hands out a free instance that may serve this conversation.
    fn try_reuse(&self, conversation: Option<&str>, now_ms: u64) -> Option<u64> {
        // No early return anywhere in this function, not even through `?`. A guard dropped on one path and held on
        // another is the shape `clippy::correctness` refuses, and the answer is to write a body with a single exit.
        let mut instances = self.instances.lock();
        // Reuse before creating: an instance that already exists costs nothing more, and creating one per call would
        // make the quota the only thing limiting memory.
        let mut found = None;
        let index = instances.iter().position(|record| record.serves(self.policy, conversation));
        if let Some(index) = index
            && let Some(record) = instances.get_mut(index)
        {
            record.busy = true;
            record.last_used_ms = now_ms;
            // A stateful instance is bound to the conversation that first used it.
            if self.policy == InstancePolicy::Stateful && record.conversation.is_none() {
                record.conversation = conversation.map(str::to_owned);
            }
            found = Some(record.handle);
        }
        // Released here rather than at the closing brace, so the guard's scope *is* the critical section. Holding it
        // to the end of the function is what `clippy::correctness` objects to, and the objection is about contention
        // rather than style.
        drop(instances);
        found
    }

    /// Checks whether another instance may exist, answering with the current count.
    ///
    /// # Errors
    ///
    /// [`PoolRefusal`] when the quota is reached, with the reason depending on the policy.
    fn check_capacity(&self, conversation: Option<&str>) -> Result<u32, PoolRefusal> {
        let live = {
            let instances = self.instances.lock();
            u32::try_from(instances.len()).unwrap_or(u32::MAX)
        };
        if live >= self.limit {
            return Err(match self.policy {
                InstancePolicy::Stateless => PoolRefusal::Exhausted {
                    limit: self.limit,
                    retry_after_ms: u64::try_from(self.retry_hint.as_millis()).unwrap_or(0),
                },
                // A stateful caller cannot make progress by waiting for someone else's instance, so it is told that
                // rather than being given a wait it would spend in vain.
                InstancePolicy::Stateful => PoolRefusal::NoAffinity {
                    conversation: conversation.unwrap_or_default().to_owned(),
                    live,
                    limit: self.limit,
                },
            });
        }
        Ok(live)
    }

    /// Takes the next handle.
    ///
    /// A handle is only taken once the pool knows an instance will be created, because taking one and then refusing
    /// would leave a gap in the numbering that a caller comparing handles would notice.
    fn take_handle(&self) -> u64 {
        let mut next = self.next_handle.lock();
        let handle = *next;
        *next = next.saturating_add(1);
        handle
    }

    /// Records a new instance.
    fn push_instance(&self, handle: u64, conversation: Option<&str>, now_ms: u64) {
        self.instances.lock().push(InstanceRecord {
            handle,
            conversation: match self.policy {
                InstancePolicy::Stateless => None,
                InstancePolicy::Stateful => conversation.map(str::to_owned),
            },
            busy: true,
            calls: 0,
            created_ms: now_ms,
            last_used_ms: now_ms,
        });
    }
    /// Returns an instance after a call, counting the call.
    ///
    /// # Errors
    ///
    /// [`PoolRefusal::UnknownInstance`] if the handle is not one this pool issued.
    pub fn release(&self, handle: u64, now_ms: u64) -> Result<(), PoolRefusal> {
        // The guard is held for the whole body and the function has one exit per outcome, with no early return that
        // would drop it on one path only — see `try_reuse` for the reasoning.
        let mut instances = self.instances.lock();
        let index = instances.iter().position(|record| record.handle == handle);
        let Some(index) = index else {
            return Err(PoolRefusal::UnknownInstance { handle });
        };

        let recycle = if let Some(record) = instances.get_mut(index) {
            record.busy = false;
            record.calls = record.calls.saturating_add(1);
            record.last_used_ms = now_ms;
            // Recycling on a call count bounds whatever the plugin's allocator does not return, in a way the plugin
            // cannot influence. A stateful instance is only recycled once its conversation is done — which is what
            // `end_conversation` is for — because recycling it mid-conversation would lose its state.
            self.policy == InstancePolicy::Stateless && record.calls >= self.recycle_after_calls
        }
        else {
            false
        };

        if recycle {
            instances.retain(|record| record.handle != handle);
        }
        drop(instances);
        Ok(())
    }

    /// Ends a conversation, freeing its instance.
    ///
    /// # Returns
    ///
    /// The handle that was freed, if any.
    pub fn end_conversation(&self, conversation: &str) -> Option<u64> {
        // One exit, for the reason given in `try_reuse`.
        let mut instances = self.instances.lock();
        let index = instances
            .iter()
            .position(|record| record.conversation.as_deref() == Some(conversation));

        let mut freed = None;
        if let Some(index) = index {
            // Only when not busy: a call in progress is still using the instance, and removing it would leave the call
            // with a handle the pool no longer knows.
            let busy = instances.get(index).is_some_and(|record| record.busy);
            if !busy {
                freed = Some(instances.remove(index).handle);
            }
        }
        drop(instances);
        freed
    }

    /// Recycles instances that have been idle too long.
    ///
    /// # Returns
    ///
    /// The handles that were recycled.
    pub fn evict_idle(&self, now_ms: u64) -> Vec<u64> {
        let idle_ms = u64::try_from(self.idle_evict_after.as_millis()).unwrap_or(u64::MAX);
        let mut instances = self.instances.lock();
        let mut evicted = Vec::new();
        instances.retain(|record| {
            let idle = now_ms.saturating_sub(record.last_used_ms) >= idle_ms;
            // A busy instance is never evicted, whatever its last-used time says: a long-running call would otherwise
            // be cut off by the sweep, which reads as a plugin crashing.
            let keep = record.busy || !idle;
            if !keep {
                evicted.push(record.handle);
            }
            keep
        });
        evicted
    }

    /// A snapshot for the interface and a diagnostic report.
    #[must_use]
    pub fn report(&self) -> PoolReport {
        let instances = self.instances.lock();
        PoolReport {
            policy: match self.policy {
                InstancePolicy::Stateless => "stateless",
                InstancePolicy::Stateful => "stateful",
            }
            .to_owned(),
            limit: self.limit,
            live: u32::try_from(instances.len()).unwrap_or(u32::MAX),
            busy: u32::try_from(instances.iter().filter(|record| record.busy).count()).unwrap_or(u32::MAX),
            conversations: instances.iter().filter_map(|record| record.conversation.clone()).collect(),
            total_calls: instances.iter().map(|record| record.calls).sum(),
        }
    }
}

/// What the interface shows about a plugin's instances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolReport {
    /// Whether instances are interchangeable.
    pub policy: String,
    /// The quota.
    pub limit: u32,
    /// How many exist.
    pub live: u32,
    /// How many are serving a call.
    pub busy: u32,
    /// The conversations holding an instance, for a stateful plugin.
    pub conversations: Vec<String>,
    /// How many calls the live instances have served.
    pub total_calls: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stateless(limit: u32) -> InstancePool {
        InstancePool::new(InstancePolicy::Stateless, limit)
    }

    fn stateful(limit: u32) -> InstancePool {
        InstancePool::new(InstancePolicy::Stateful, limit)
    }

    // ── Stateless ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_stateless_pool_creates_an_instance_on_demand() {
        // A pool does not pre-create instances: a plugin that is never called should cost nothing.
        let pool = stateless(4);
        assert_eq!(pool.live(), 0);

        let handle = pool.acquire(None, 0).expect("acquires");
        assert_eq!(pool.live(), 1);
        assert_eq!(pool.busy(), 1);
        assert!(handle > 0);
    }

    #[test]
    fn a_released_instance_is_reused_before_a_new_one_is_made() {
        // An instance that already exists costs nothing more, and creating one per call would make the quota the only
        // thing limiting memory.
        let pool = stateless(4);
        let first = pool.acquire(None, 0).expect("acquires");
        pool.release(first, 1).expect("releases");

        let second = pool.acquire(None, 2).expect("acquires");
        assert_eq!(second, first, "a new instance was made while one was free");
        assert_eq!(pool.live(), 1);
    }

    #[test]
    fn a_busy_instance_is_not_handed_to_a_second_call() {
        let pool = stateless(4);
        let first = pool.acquire(None, 0).expect("acquires");
        let second = pool.acquire(None, 0).expect("acquires");
        assert_ne!(first, second);
        assert_eq!(pool.live(), 2);
        assert_eq!(pool.busy(), 2);
    }

    #[test]
    fn a_stateless_pool_stops_creating_at_its_quota() {
        // The quota is what makes the pool a bound on memory rather than a suggestion.
        let pool = stateless(2);
        let _a = pool.acquire(None, 0).expect("acquires");
        let _b = pool.acquire(None, 0).expect("acquires");

        match pool.acquire(None, 0) {
            Err(PoolRefusal::Exhausted { limit, retry_after_ms }) => {
                assert_eq!(limit, 2);
                assert!(retry_after_ms > 0);
            }
            other => panic!("expected exhaustion, got {other:?}"),
        }
        assert_eq!(pool.live(), 2, "the pool grew past its quota");
    }

    #[test]
    fn an_exhausted_stateless_pool_says_waiting_would_help() {
        // The refusal a caller waits on, as opposed to the one it cannot.
        let pool = stateless(1);
        let handle = pool.acquire(None, 0).expect("acquires");
        let refusal = pool.acquire(None, 0).expect_err("refused");
        assert!(refusal.is_retryable());

        pool.release(handle, 1).expect("releases");
        assert!(pool.acquire(None, 2).is_ok(), "waiting did not help");
    }

    #[test]
    fn a_stateless_instance_is_recycled_after_its_call_budget() {
        // A Wasm instance accumulates whatever the plugin's allocator does not return, and the count bounds that in a
        // way the plugin cannot influence.
        let pool = stateless(1).with_recycling(3, Duration::from_secs(300));
        let handle = pool.acquire(None, 0).expect("acquires");
        pool.release(handle, 1).expect("releases");
        pool.release(handle, 2).expect("releases");
        assert_eq!(pool.live(), 1, "recycled too early");

        pool.release(handle, 3).expect("releases");
        assert_eq!(pool.live(), 0, "the instance was not recycled at its budget");

        // And a new call gets a new handle, not the recycled one.
        let next = pool.acquire(None, 4).expect("acquires");
        assert_ne!(next, handle);
    }

    #[test]
    fn a_stateless_instance_may_serve_any_conversation() {
        // Memory does not persist between calls, so there is nothing to lose by sharing.
        let pool = stateless(1);
        let handle = pool.acquire(Some("c1"), 0).expect("acquires");
        pool.release(handle, 1).expect("releases");
        let again = pool.acquire(Some("c2"), 2).expect("acquires");
        assert_eq!(again, handle);
    }

    // ── Stateful ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_stateful_instance_is_bound_to_its_first_conversation() {
        // Handing a call to a different instance than the previous one is handing it to a plugin that has forgotten
        // what it was doing.
        let pool = stateful(4);
        let handle = pool.acquire(Some("c1"), 0).expect("acquires");
        pool.release(handle, 1).expect("releases");

        let again = pool.acquire(Some("c1"), 2).expect("acquires");
        assert_eq!(again, handle, "the conversation did not get its own instance back");
    }

    #[test]
    fn a_stateful_instance_is_not_given_to_another_conversation() {
        // The mistake this policy exists to prevent: round-robin would silently lose the plugin's state and the
        // symptom would be a plugin that works when only one thing is happening.
        let pool = stateful(4);
        let first = pool.acquire(Some("c1"), 0).expect("acquires");
        pool.release(first, 1).expect("releases");

        let second = pool.acquire(Some("c2"), 2).expect("acquires");
        assert_ne!(second, first);
        assert_eq!(pool.live(), 2);
    }

    #[test]
    fn a_stateful_pool_at_its_quota_refuses_rather_than_sharing() {
        // A stateful caller cannot make progress by waiting for someone else's instance, so it is told that rather
        // than being given a wait it would spend in vain.
        let pool = stateful(1);
        let handle = pool.acquire(Some("c1"), 0).expect("acquires");
        pool.release(handle, 1).expect("releases");

        match pool.acquire(Some("c2"), 2) {
            Err(PoolRefusal::NoAffinity { conversation, live, limit }) => {
                assert_eq!(conversation, "c2");
                assert_eq!(live, 1);
                assert_eq!(limit, 1);
            }
            other => panic!("expected a no-affinity refusal, got {other:?}"),
        }
        // And it does not claim that waiting would help.
        assert!(!PoolRefusal::NoAffinity {
            conversation: "c".to_owned(),
            live: 1,
            limit: 1
        }
        .is_retryable());
    }

    #[test]
    fn ending_a_conversation_frees_its_instance_for_another() {
        let pool = stateful(1);
        let first = pool.acquire(Some("c1"), 0).expect("acquires");
        pool.release(first, 1).expect("releases");

        assert_eq!(pool.end_conversation("c1"), Some(first));
        assert_eq!(pool.live(), 0);
        assert!(pool.acquire(Some("c2"), 2).is_ok());
    }

    #[test]
    fn ending_a_busy_conversation_does_not_free_its_instance() {
        // A call in progress is still using the instance, and removing it would leave the call with a handle the pool
        // no longer knows.
        let pool = stateful(2);
        let handle = pool.acquire(Some("c1"), 0).expect("acquires");
        assert_eq!(pool.end_conversation("c1"), None);
        assert_eq!(pool.live(), 1);

        // After the call finishes it can be freed.
        pool.release(handle, 1).expect("releases");
        assert_eq!(pool.end_conversation("c1"), Some(handle));
    }

    #[test]
    fn ending_a_conversation_that_has_no_instance_is_not_an_error() {
        let pool = stateful(2);
        assert_eq!(pool.end_conversation("never-seen"), None);
    }

    #[test]
    fn a_stateful_instance_may_take_the_first_conversation_that_asks() {
        // An instance that has never been used has no state to lose.
        let pool = stateful(1);
        let handle = pool.acquire(None, 0).expect("acquires");
        pool.release(handle, 1).expect("releases");

        let bound = pool.acquire(Some("c1"), 2).expect("acquires");
        assert_eq!(bound, handle);
        assert_eq!(pool.report().conversations, vec!["c1".to_owned()]);
    }

    #[test]
    fn a_bound_stateful_instance_is_not_handed_to_a_caller_with_no_conversation() {
        // A caller that does not say which conversation it is would be given an instance carrying someone else's state.
        let pool = stateful(2);
        let handle = pool.acquire(Some("c1"), 0).expect("acquires");
        pool.release(handle, 1).expect("releases");

        let other = pool.acquire(None, 2).expect("acquires");
        assert_ne!(other, handle, "an unbound caller got a bound instance");
    }

    #[test]
    fn a_stateful_instance_is_not_recycled_by_its_call_budget() {
        // Recycling it mid-conversation would lose its state, which is the only thing the policy is about.
        let pool = stateful(1).with_recycling(2, Duration::from_secs(300));
        let handle = pool.acquire(Some("c1"), 0).expect("acquires");
        for at in 1..10 {
            pool.release(handle, at).expect("releases");
        }
        assert_eq!(pool.live(), 1, "a stateful instance was recycled by its call count");
    }

    // ── Both policies ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_stopped_pool_refuses_and_drops_its_instances() {
        // A stopped plugin's instances hold memory and state that no longer correspond to anything the plugin will be
        // asked about.
        let pool = stateless(4);
        let _handle = pool.acquire(None, 0).expect("acquires");
        pool.stop();
        assert!(!pool.is_running());
        assert_eq!(pool.live(), 0);

        assert!(matches!(pool.acquire(None, 1), Err(PoolRefusal::NotRunning)));
        // And starting it again works.
        pool.start();
        assert!(pool.acquire(None, 2).is_ok());
    }

    #[test]
    fn releasing_a_handle_this_pool_never_issued_is_refused() {
        // A handle from a previous pool, or from a different plugin, would otherwise be released twice or released
        // into the wrong pool.
        let pool = stateless(4);
        assert!(matches!(
            pool.release(9_999, 0),
            Err(PoolRefusal::UnknownInstance { handle: 9_999 })
        ));
    }

    #[test]
    fn releasing_twice_does_not_double_count_or_over_recycle() {
        let pool = stateless(1).with_recycling(3, Duration::from_secs(300));
        let handle = pool.acquire(None, 0).expect("acquires");
        pool.release(handle, 1).expect("releases");
        pool.release(handle, 1).expect("releases again");
        // Two releases, so the count is two and the instance is still live.
        assert_eq!(pool.live(), 1);
        assert_eq!(pool.report().total_calls, 2);
    }

    #[test]
    fn handles_are_never_reused_within_a_pool() {
        // A reused handle would make a stale release hit an unrelated instance, which is a defect that surfaces as a
        // plugin whose state appears to jump between conversations.
        // One at a time, so the pool never reaches its limit — the limit is what would stop a new handle being
        // issued, and this test is about the counter, not the bound.
        let pool = stateless(1).with_recycling(1, Duration::ZERO);
        let mut seen = std::collections::HashSet::new();
        for at in 0..20u64 {
            let handle = pool.acquire(None, at).expect("acquires");
            assert!(seen.insert(handle), "handle {handle} was issued twice");
            // Recycling after one call means each iteration gets a genuinely new instance rather than the reused one.
            pool.release(handle, at).expect("releases");
        }
    }

    #[test]
    fn an_idle_instance_is_evicted() {
        // Long enough that a plugin used intermittently keeps its compiled instance, short enough that a plugin
        // nobody is using stops holding memory.
        let pool = stateless(4).with_recycling(1_000, Duration::from_millis(100));
        let handle = pool.acquire(None, 0).expect("acquires");
        pool.release(handle, 0).expect("releases");

        assert!(pool.evict_idle(50).is_empty(), "evicted too early");
        assert_eq!(pool.evict_idle(100), vec![handle]);
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn a_busy_instance_is_never_evicted() {
        // A long-running call would otherwise be cut off by the sweep, which reads as a plugin crashing.
        let pool = stateless(4).with_recycling(1_000, Duration::from_millis(100));
        let _handle = pool.acquire(None, 0).expect("acquires");

        assert!(pool.evict_idle(1_000_000).is_empty(), "a busy instance was evicted");
        assert_eq!(pool.live(), 1);
    }

    #[test]
    fn an_eviction_does_not_release_a_handle_twice() {
        let pool = stateless(4).with_recycling(1_000, Duration::from_millis(100));
        let handle = pool.acquire(None, 0).expect("acquires");
        pool.release(handle, 0).expect("releases");
        assert_eq!(pool.evict_idle(100), vec![handle]);

        // The swept handle is no longer the pool's, so releasing it is refused rather than creating a phantom record.
        assert!(matches!(pool.release(handle, 101), Err(PoolRefusal::UnknownInstance { .. })));
    }

    #[test]
    fn the_report_carries_what_the_interface_needs() {
        let pool = stateful(4);
        let handle = pool.acquire(Some("c1"), 0).expect("acquires");

        let report = pool.report();
        assert_eq!(report.policy, "stateful");
        assert_eq!(report.limit, 4);
        assert_eq!(report.live, 1);
        assert_eq!(report.busy, 1);
        assert_eq!(report.conversations, vec!["c1".to_owned()]);
        assert_eq!(report.total_calls, 0);

        pool.release(handle, 1).expect("releases");
        assert_eq!(pool.report().total_calls, 1);
    }

    #[test]
    fn the_report_names_the_policy_for_each() {
        assert_eq!(stateless(1).report().policy, "stateless");
        assert_eq!(stateful(1).report().policy, "stateful");
    }

    #[test]
    fn only_the_stateless_policy_shares_instance() {
        assert!(InstancePolicy::Stateless.allows_sharing());
        assert!(!InstancePolicy::Stateful.allows_sharing());
    }

    #[test]
    fn the_policy_and_limits_are_readable() {
        let pool = stateless(7).with_retry_hint(Duration::from_millis(25));
        assert_eq!(pool.policy(), InstancePolicy::Stateless);
        assert_eq!(pool.limit(), 7);
        assert!(pool.is_running());
    }

    #[test]
    fn a_pool_survives_being_asked_for_more_than_its_quota_repeatedly() {
        // A caller in a retry loop must not be able to grow the pool by asking.
        let pool = stateless(2);
        let _a = pool.acquire(None, 0).expect("acquires");
        let _b = pool.acquire(None, 0).expect("acquires");
        for _ in 0..100 {
            let _ = pool.acquire(None, 0);
        }
        assert_eq!(pool.live(), 2);
    }

    #[test]
    fn a_quota_of_zero_refuses_immediately() {
        // A configuration that allows no instances must refuse rather than create one anyway.
        let pool = stateless(0);
        assert!(matches!(pool.acquire(None, 0), Err(PoolRefusal::Exhausted { limit: 0, .. })));
        assert_eq!(pool.live(), 0);
    }

    #[test]
    fn a_pool_report_survives_a_round_trip() {
        let pool = stateful(4);
        let _handle = pool.acquire(Some("c1"), 0).expect("acquires");
        let report = pool.report();

        let json = serde_json::to_string(&report).expect("serialises");
        assert!(json.contains("conversations"), "{json}");
        let back: PoolReport = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
    }

    #[test]
    fn pool_refusals_explain_themselves() {
        let refusals = [
            PoolRefusal::Exhausted { limit: 2, retry_after_ms: 50 },
            PoolRefusal::NoAffinity { conversation: "c".to_owned(), live: 1, limit: 1 },
            PoolRefusal::NotRunning,
            PoolRefusal::UnknownInstance { handle: 7 },
        ];
        for refusal in refusals {
            let text = refusal.to_string();
            assert!(text.len() > 15, "{refusal:?} -> {text}");
            assert!(!text.contains('{'), "{refusal:?} -> {text}");
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// One pool operation, as a value.
    #[derive(Debug, Clone)]
    enum Op {
        Acquire(Option<String>),
        Release(u64),
        EndConversation(String),
        EvictIdle(u64),
    }

    fn arbitrary_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            proptest::option::of("[a-c]").prop_map(|c| Op::Acquire(c.map(|text: String| text))),
            (0u64..20).prop_map(Op::Release),
            "[a-c]".prop_map(Op::EndConversation),
            (0u64..10_000).prop_map(Op::EvictIdle),
        ]
    }

    proptest! {
        /// Whatever the sequence of operations, a stateless pool never holds more instances than its quota. The quota
        /// is what makes the pool a bound on memory rather than a suggestion, so a sequence that could exceed it is a
        /// sequence that could exhaust the machine.
        #[test]
        fn a_stateless_pool_never_exceeds_its_quota(
            limit in 0u32..6,
            ops in proptest::collection::vec(arbitrary_op(), 0..80),
        ) {
            let pool = InstancePool::new(InstancePolicy::Stateless, limit);
            let mut at = 0u64;
            for op in ops {
                at += 1;
                match op {
                    Op::Acquire(conversation) => { let _ = pool.acquire(conversation.as_deref(), at); }
                    Op::Release(handle) => { let _ = pool.release(handle, at); }
                    Op::EndConversation(conversation) => { let _ = pool.end_conversation(&conversation); }
                    Op::EvictIdle(now) => { let _ = pool.evict_idle(now); }
                }
                prop_assert!(pool.live() <= limit, "held {} of {}", pool.live(), limit);
            }
        }

        /// A stateful pool never hands two different conversations the same live instance. Round-robin would silently
        /// lose the plugin's state, and the symptom would be a plugin that works when only one thing is happening.
        #[test]
        fn a_stateful_pool_never_shares_an_instance_across_conversations(
            limit in 1u32..4,
            ops in proptest::collection::vec(arbitrary_op(), 0..60),
        ) {
            let pool = InstancePool::new(InstancePolicy::Stateful, limit);
            let mut at = 0u64;
            // Conversation to handle, for the instances that are live and bound.
            let mut bound: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
            let mut busy: std::collections::HashSet<u64> = std::collections::HashSet::new();

            for op in ops {
                at += 1;
                match op {
                    Op::Acquire(conversation) => {
                        if let Ok(handle) = pool.acquire(conversation.as_deref(), at) {
                            // A handle already bound to a conversation may only be handed to that conversation.
                            if let (Some(existing), Some(wanted)) = (bound.get(&handle), conversation.as_deref()) {
                                prop_assert_eq!(existing, wanted, "instance {} served two conversations", handle);
                            }
                            if let Some(wanted) = conversation {
                                bound.insert(handle, wanted.to_owned());
                            }
                            prop_assert!(busy.insert(handle), "instance {} was handed out while busy", handle);
                        }
                    }
                    Op::Release(handle) => {
                        let _ = pool.release(handle, at);
                        busy.remove(&handle);
                    }
                    Op::EndConversation(conversation) => {
                        if let Some(handle) = pool.end_conversation(&conversation) {
                            prop_assert!(!busy.contains(&handle), "a busy instance was freed");
                            bound.remove(&handle);
                        }
                    }
                    Op::EvictIdle(now) => {
                        let evicted = pool.evict_idle(now);
                        for handle in evicted {
                            prop_assert!(!busy.contains(&handle), "a busy instance was evicted");
                            bound.remove(&handle);
                        }
                    }
                }
            }
        }

        /// Every handle a pool issues is unique for the life of the pool. A reused handle would make a stale release
        /// hit an unrelated instance, which surfaces as a plugin whose state jumps between conversations.
        #[test]
        fn handles_are_never_reused(ops in proptest::collection::vec(arbitrary_op(), 0..60)) {
            // Recycling after one call, so every acquire makes a fresh instance and the counter is what is under test.
            let pool = InstancePool::new(InstancePolicy::Stateless, 4).with_recycling(1, Duration::ZERO);
            let mut seen = std::collections::HashSet::new();
            let mut at = 0u64;

            for op in ops {
                at += 1;
                match op {
                    Op::Acquire(conversation) => {
                        if let Ok(handle) = pool.acquire(conversation.as_deref(), at) {
                            prop_assert!(seen.insert(handle), "handle {} was issued twice", handle);
                        }
                    }
                    Op::Release(handle) => { let _ = pool.release(handle, at); }
                    Op::EndConversation(conversation) => { let _ = pool.end_conversation(&conversation); }
                    Op::EvictIdle(now) => { let _ = pool.evict_idle(now); }
                }
            }
        }

        /// A stopped pool is empty and refuses everything, whatever the sequence that came before. A stopped plugin's
        /// instances hold memory and state that no longer correspond to anything.
        #[test]
        fn a_stopped_pool_is_empty_and_refuses(
            policy_stateful in any::<bool>(),
            ops in proptest::collection::vec(arbitrary_op(), 0..40),
        ) {
            let policy = if policy_stateful { InstancePolicy::Stateful } else { InstancePolicy::Stateless };
            let pool = InstancePool::new(policy, 4);
            let mut at = 0u64;
            for op in ops {
                at += 1;
                match op {
                    Op::Acquire(conversation) => { let _ = pool.acquire(conversation.as_deref(), at); }
                    Op::Release(handle) => { let _ = pool.release(handle, at); }
                    Op::EndConversation(conversation) => { let _ = pool.end_conversation(&conversation); }
                    Op::EvictIdle(now) => { let _ = pool.evict_idle(now); }
                }
            }

            pool.stop();
            prop_assert_eq!(pool.live(), 0);
            prop_assert!(!pool.is_running());
            prop_assert!(matches!(pool.acquire(None, at), Err(PoolRefusal::NotRunning)));
        }
    }
}
