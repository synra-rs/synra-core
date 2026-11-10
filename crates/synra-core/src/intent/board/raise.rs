use super::*;

impl Board {
    /// An empty board.
    #[must_use]
    pub fn new() -> Self {
        Self {
            intents: HashMap::new(),
            order: Vec::new(),
            matching_window: MATCHING_WINDOW,
            ended_memory: ENDED_MEMORY,
        }
    }

    /// An empty board with a matching window of its own.
    ///
    /// A test passes one of a millisecond; a device with many plugins passes a longer one. The default is neither.
    #[must_use]
    pub fn with_window(matching_window: Duration) -> Self {
        Self {
            matching_window,
            ..Self::new()
        }
    }

    /// The matching window.
    #[must_use]
    pub const fn matching_window(&self) -> Duration {
        self.matching_window
    }

    /// Puts an intent back on the board, as it was when the store was written.
    ///
    /// # Returns
    ///
    /// `false` when the board already holds this identifier, in which case nothing changes.
    ///
    /// # ★ Why this exists, and why it is not `raise`
    ///
    /// Restoring is not raising. `raise` mints an identifier, a trace and a deadline, and it applies the idempotency rule —
    /// all of which have already happened for an intent read back from the store. Calling it here would give a restored
    /// intent a **new** identifier, so a peer that resent the request it originally raised would be answered with a second
    /// intent and the action would run twice, and the trace would no longer match the one in every log line about it.
    ///
    /// # Why a duplicate is refused rather than overwritten
    ///
    /// Because the two are not the same intent, and the board cannot tell which one is current: a restored copy of an
    /// intent the board has already been working on would roll its state backwards, and a rollback looks exactly like
    /// progress to everything downstream. So the first one wins and the caller is told.
    pub fn restore(&mut self, intent: Intent) -> bool {
        let id = intent.id;
        if self.intents.contains_key(&id) {
            return false;
        }
        let _ = self.intents.insert(id, intent);
        // ★ Appended to `order`, which is what a sweep walks to drop the oldest finished intents. A restored intent is the
        // oldest thing on the board, and putting it at the end would make a sweep consider it last — so the caller is
        // expected to restore oldest first, which is the order `load_intents` answers in.
        self.order.push(id);
        true
    }

    /// Every intent on the board, in the order they were raised.
    ///
    /// # Why this is needed rather than iterating `live`
    ///
    /// Because persisting has to save what *changed*, and what changed may be an intent that has just ended — `live` is
    /// exactly the intents that have not. A board that could only list its live intents could not persist a result.
    #[must_use]
    pub fn all(&self) -> Vec<&Intent> {
        self.order
            .iter()
            .filter_map(|id| self.intents.get(id))
            .collect()
    }

    /// Raises an intent, or answers with the one this request already raised.
    ///
    /// # Returns
    ///
    /// `(id, trace, created)` — `created` is `false` when the same request had already been raised, which is what makes
    /// a retry after a lost answer idempotent: the second attempt gets the first attempt's intent rather than a second
    /// one that would run the action again.
    ///
    /// # Why the deadline is computed here rather than by the caller
    ///
    /// Because two places computing "now plus the window" is one place that will use a different window. The board owns
    /// the window, so it owns the arithmetic.
    pub fn raise(
        &mut self,
        source: IntentSource,
        choice: Choice,
        origin: Option<DeviceId>,
        request_id: Option<RequestId>,
        now_ms: i64,
    ) -> (IntentId, TraceId, bool) {
        self.raise_with_trace(source, choice, origin, request_id, None, now_ms)
    }

    /// Receive authenticated remote work while retaining the originating operation's trace.
    /// A duplicate keeps the original trace and outcome, even if the new envelope claims another trace.
    pub fn receive(
        &mut self,
        source: IntentSource,
        origin: DeviceId,
        request: RequestId,
        trace: TraceId,
        now_ms: i64,
    ) -> (IntentId, TraceId, bool) {
        self.raise_with_trace(
            source,
            Choice::default(),
            Some(origin),
            Some(request),
            Some(trace),
            now_ms,
        )
    }

    fn raise_with_trace(
        &mut self,
        source: IntentSource,
        choice: Choice,
        origin: Option<DeviceId>,
        request_id: Option<RequestId>,
        trace: Option<TraceId>,
        now_ms: i64,
    ) -> (IntentId, TraceId, bool) {
        // ★ The idempotency check comes before anything is created. A sender whose answer was lost resends the same
        // request, and raising a second intent would run a user's action twice — the failure this exists to prevent,
        // and the one a "did we already do this" check placed *after* creation cannot prevent.
        if let (Some(origin), Some(request)) = (origin, request_id)
            && let Some(existing) = self.find_request(origin, request)
        {
            let intent = self.intents.get(&existing);
            let trace = intent.map_or_else(TraceId::new, |intent| intent.trace);
            return (existing, trace, false);
        }

        let id = IntentId::new();
        let trace = trace.unwrap_or_default();
        let deadline = now_ms
            .saturating_add(i64::try_from(self.matching_window.as_millis()).unwrap_or(i64::MAX));
        let implied = source.implied_action();
        let state = match implied {
            // A source that named its plugin and action needs no matching: the candidate list has one entry, and
            // putting it through a matching phase would mean asking a plugin that was already told what to do.
            Some(planned) => IntentState::Dispatching {
                candidate: candidate_of(&planned),
                target: source.named_target().unwrap_or_default(),
                request_id: request_id.unwrap_or_default(),
            },
            None => IntentState::Matching {
                deadline_ms: deadline,
                candidates: Vec::new(),
            },
        };

        let intent = Intent {
            id,
            trace,
            source,
            state,
            choice,
            created_at_ms: now_ms,
            request_id,
            origin,
        };
        let _ = self.intents.insert(id, intent);
        self.order.push(id);
        (id, trace, true)
    }
}
