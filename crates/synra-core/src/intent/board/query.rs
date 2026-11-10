use super::*;

impl Board {
    /// The intent under an id.
    #[must_use]
    pub fn get(&self, id: IntentId) -> Option<&Intent> {
        self.intents.get(&id)
    }

    /// Every intent that has not ended, oldest first.
    ///
    /// Ordered because this is what an interface lists, and a list that reordered itself between reads would move an
    /// item while a user was looking at it.
    #[must_use]
    pub fn live(&self) -> Vec<&Intent> {
        self.order
            .iter()
            .filter_map(|id| self.intents.get(id))
            .filter(|intent| !intent.state.is_final())
            .collect()
    }

    /// How many intents are held, finished ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.intents.len()
    }

    /// Whether the board holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// The intent a repeated request already raised.
    #[must_use]
    pub fn recall(&self, origin: DeviceId, request: RequestId) -> Option<&Intent> {
        self.find_request(origin, request)
            .and_then(|id| self.intents.get(&id))
    }

    /// The intent a request was dispatched to a device under, if it is still in flight.
    ///
    /// # Why both halves of the pair
    ///
    /// Because a reply names the request it answers (`reply_to`) and the device that answered. The request alone is not
    /// enough — one device may be running several dispatches — and the device alone is not either. Only the pair says which
    /// dispatch this outcome belongs to.
    #[must_use]
    pub fn dispatched_to(&self, request: RequestId, target: DeviceId) -> Option<IntentId> {
        self.intents
            .values()
            .find(|intent| {
                matches!(
                    &intent.state,
                    IntentState::Dispatching { request_id, target: named, .. }
                        if *request_id == request && *named == target
                )
            })
            .map(|intent| intent.id)
    }

    /// Drops the finished intents a board no longer needs.
    ///
    /// # Two rules, and why both
    ///
    /// An intent that ended longer ago than `keep_for` is one no prompt will be asked about again, so it goes. And
    /// between the rest, only the most recent [`ENDED_MEMORY`](self::ENDED_MEMORY) are kept, because a device that
    /// shares things all day would otherwise hold every share it has ever seen. Both rules apply on every sweep, so a
    /// kernel that never reaches the bound still forgets what is stale — and a kernel that reaches it forgets the
    /// oldest whatever their age.
    ///
    /// Nothing that has not ended is ever dropped, however old: an intent somebody is still answering is not stale.
    ///
    /// # Returns
    ///
    /// How many were dropped, so a caller can tell whether an interface has anything to refresh.
    pub fn forget_ended_before(&mut self, now_ms: i64, keep_for: Duration) -> usize {
        let horizon =
            now_ms.saturating_sub(i64::try_from(keep_for.as_millis()).unwrap_or(i64::MAX));

        let mut ended: Vec<(i64, IntentId)> = self
            .order
            .iter()
            .filter_map(|id| self.intents.get(id))
            .filter(|intent| intent.state.is_final())
            .map(|intent| (intent.created_at_ms, intent.id))
            .collect();
        // Oldest first, so what is dropped is chosen by age rather than by the order a map happens to iterate in. The
        // identifier breaks a tie, because two intents raised in the same millisecond share an age and an order that
        // depended on the map would make a sweep drop a different one each time it ran.
        ended.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.to_string().cmp(&right.1.to_string()))
        });
        let ended: Vec<IntentId> = ended.into_iter().map(|(_, id)| id).collect();

        let stale = ended
            .iter()
            .filter(|id| {
                self.intents
                    .get(id)
                    .is_some_and(|intent| intent.created_at_ms < horizon)
            })
            .count();
        let excess = ended.len().saturating_sub(self.ended_memory);
        let doomed: Vec<IntentId> = ended.into_iter().take(stale.max(excess)).collect();

        for id in &doomed {
            let _ = self.intents.remove(id);
        }
        self.order.retain(|id| self.intents.contains_key(id));
        doomed.len()
    }

    /// How many finished intents are held.
    #[must_use]
    pub fn ended_count(&self) -> usize {
        self.intents
            .values()
            .filter(|intent| intent.state.is_final())
            .count()
    }

    /// Finds the intent a request already raised.
    pub(in crate::intent::board) fn find_request(
        &self,
        origin: DeviceId,
        request: RequestId,
    ) -> Option<IntentId> {
        self.order
            .iter()
            .filter_map(|id| self.intents.get(id))
            .find(|intent| intent.is_same_request_as(origin, request))
            .map(|intent| intent.id)
    }

    /// Moves an intent, if it is there to move.
    ///
    /// One place that writes a state, so a transition that should have been refused has one place to be refused in.
    pub(in crate::intent::board) fn set_state(
        &mut self,
        id: IntentId,
        state: IntentState,
    ) -> Option<()> {
        let intent = self.intents.get_mut(&id)?;
        intent.state = state;
        Some(())
    }
}
