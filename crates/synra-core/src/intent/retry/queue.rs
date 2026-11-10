use super::*;

impl RetryQueue {
    /// An empty queue.
    #[must_use]
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            attempts: HashMap::new(),
            due: HashMap::new(),
            gave_up: HashSet::new(),
        }
    }

    /// Rebuilds the schedule from stored rows.
    ///
    /// # What is restored, and what is deliberately not
    ///
    /// The attempt count and the next due time are restored, so a restart does not send the backoff back to thirty seconds.
    /// A **given-up** row is not restored as given up: "gave up until the next start" is what the interface says, and the
    /// next start is this one. Such a row is returned in the second half of the answer for the caller to delete, and the
    /// intent gets a fresh first retry.
    ///
    /// Rows whose intent is no longer pending are returned the same way — a schedule for work that ended is not something
    /// to keep.
    #[must_use]
    pub fn restore(
        policy: RetryPolicy,
        rows: &[synra_store::IntentRetryRow],
        pending: &HashSet<IntentId>,
        now_ms: i64,
    ) -> (Self, Vec<String>) {
        let mut queue = Self::new(policy);
        let mut stale = Vec::new();
        let stored: HashMap<&str, &synra_store::IntentRetryRow> = rows
            .iter()
            .map(|row| (row.intent_id.as_str(), row))
            .collect();

        for id in pending {
            let key = id.to_string();
            match stored.get(key.as_str()) {
                Some(row) if !row.gave_up => {
                    queue.attempts.insert(*id, row.attempts.saturating_add(1));
                    // A stored time in the past is due now; `take_due` treats it that way without a special case.
                    queue.due.insert(
                        *id,
                        row.next_at_ms
                            .unwrap_or_else(|| now_ms + queue.policy.delay_ms(*id, 1)),
                    );
                }
                Some(row) => {
                    stale.push(row.intent_id.clone());
                    queue.attempts.insert(*id, 1);
                    queue
                        .due
                        .insert(*id, now_ms + queue.policy.delay_ms(*id, 1));
                }
                None => {
                    queue.attempts.insert(*id, 1);
                    queue
                        .due
                        .insert(*id, now_ms + queue.policy.delay_ms(*id, 1));
                }
            }
        }
        for row in rows {
            if !pending.iter().any(|id| id.to_string() == row.intent_id) {
                stale.push(row.intent_id.clone());
            }
        }
        (queue, stale)
    }

    /// Schedules anything new, and forgets anything that is no longer in flight.
    ///
    /// # Why the sweep is part of observing
    ///
    /// Because an intent can end for reasons this loop did not cause — the user cancelled it, the answer arrived on the
    /// listener's link, or the retention sweep dropped it. Keeping its entry would mean a due time for work that no longer
    /// exists, and the map would grow for the life of the process.
    ///
    /// # Returns
    ///
    /// The intents that had no entry, so the caller knows which rows it has to write.
    pub fn observe(
        &mut self,
        pending: impl IntoIterator<Item = IntentId>,
        now_ms: i64,
    ) -> Vec<IntentId> {
        let pending: HashSet<IntentId> = pending.into_iter().collect();
        self.attempts.retain(|id, _| pending.contains(id));
        self.due.retain(|id, _| pending.contains(id));
        self.gave_up.retain(|id| pending.contains(id));
        let mut added = Vec::new();
        for id in pending {
            if let std::collections::hash_map::Entry::Vacant(entry) = self.attempts.entry(id) {
                entry.insert(1);
                self.due.insert(id, now_ms + self.policy.delay_ms(id, 1));
                added.push(id);
            }
        }
        added
    }

    /// The ids whose wait is over, removed from the schedule.
    ///
    /// Removed rather than left: the caller is about to attempt them, and a due time that is still in the past would make the
    /// next `take_due` hand the same id out again.
    pub fn take_due(&mut self, now_ms: i64) -> Vec<IntentId> {
        let due: Vec<IntentId> = self
            .due
            .iter()
            .filter_map(|(id, at)| (*at <= now_ms).then_some(*id))
            .collect();
        for id in &due {
            self.due.remove(id);
        }
        due
    }

    /// Schedules the next attempt, or gives up when the bound is reached.
    ///
    /// Returns whether another attempt was scheduled. Giving up keeps the entry and its count: the card says "no answer
    /// after N tries", and dropping the entry at the same moment would leave the page with nothing to say.
    pub fn record_failure(&mut self, id: IntentId, now_ms: i64) -> bool {
        let attempt = self.attempts.entry(id).or_insert(0);
        *attempt = attempt.saturating_add(1);
        if *attempt > self.policy.max_attempts {
            self.gave_up.insert(id);
            return false;
        }
        self.due
            .insert(id, now_ms + self.policy.delay_ms(id, *attempt));
        true
    }

    /// Removes an intent: it was answered, or it ended.
    pub fn forget(&mut self, id: IntentId) {
        self.attempts.remove(&id);
        self.due.remove(&id);
        self.gave_up.remove(&id);
    }

    /// What the interface is told about one intent's retries, when there is anything to tell.
    ///
    /// Nothing before the first retry has failed: an intent whose first attempt is still waiting is simply `Dispatching`,
    /// and "retrying (0/8)" would describe work that has not happened yet.
    #[must_use]
    pub fn status(&self, id: IntentId) -> Option<RetryStatus> {
        let next = *self.attempts.get(&id)?;
        let attempts = next.saturating_sub(1);
        let gave_up = self.gave_up.contains(&id);
        if attempts == 0 && !gave_up {
            return None;
        }
        Some(RetryStatus {
            attempts,
            max_attempts: self.policy.max_attempts,
            gave_up,
            next_at_ms: self.due.get(&id).copied(),
        })
    }

    /// The row that preserves this intent's schedule, when it has one.
    ///
    /// `attempts` is the count of retries **already made**, which is one less than the internal next-attempt number.
    #[must_use]
    pub fn row(&self, id: IntentId) -> Option<synra_store::IntentRetryRow> {
        let next = *self.attempts.get(&id)?;
        Some(synra_store::IntentRetryRow {
            intent_id: id.to_string(),
            attempts: next.saturating_sub(1),
            next_at_ms: self.due.get(&id).copied(),
            gave_up: self.gave_up.contains(&id),
        })
    }

    /// How long until the next attempt, or [`Duration::MAX`] when nothing is waiting.
    #[must_use]
    pub fn next_wait(&self, now_ms: i64) -> Duration {
        self.due
            .values()
            .map(|at| at.saturating_sub(now_ms).max(0))
            .filter_map(|ms| u64::try_from(ms).ok())
            .min()
            .map(Duration::from_millis)
            .unwrap_or(Duration::MAX)
    }
}
