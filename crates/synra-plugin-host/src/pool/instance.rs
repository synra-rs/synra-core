//! The pool itself, and the report it produces.

use core::time::Duration;

use super::policy::{InstancePolicy, PoolRefusal};
use super::record::{IDLE_EVICT_AFTER, InstanceRecord, RECYCLE_AFTER_CALLS};
use serde::{Deserialize, Serialize};

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
