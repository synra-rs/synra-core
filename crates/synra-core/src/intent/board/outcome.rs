use super::*;

impl Board {
    /// Records the outcome a device reported.
    ///
    /// # Errors
    ///
    /// [`IntentError::Unknown`] when there is no such intent. An outcome for an intent this board has forgotten is
    /// **not** an error at the protocol level — it is a late answer, and the caller logs it.
    pub fn conclude(
        &mut self,
        id: IntentId,
        outcome: Result<serde_json::Value, SynraError>,
        elapsed_ms: u64,
    ) -> Result<IntentState, IntentError> {
        let intent = self
            .intents
            .get(&id)
            .ok_or(IntentError::Unknown { intent_id: id })?;
        if intent.state.is_final() {
            return Ok(intent.state.clone());
        }
        let next = match outcome {
            Ok(result) => IntentState::Succeeded { result, elapsed_ms },
            Err(error) => IntentState::Failed { error, elapsed_ms },
        };
        let _ = self.set_state(id, next);
        self.intents
            .get(&id)
            .map(|intent| intent.state.clone())
            .ok_or(IntentError::Unknown { intent_id: id })
    }

    /// Ends an intent because its admission refused it.
    pub fn refuse(&mut self, id: IntentId, refusal: AdmissionRefusal) -> Option<IntentState> {
        let _ = self.set_state(id, IntentState::Refused { refusal });
        self.intents.get(&id).map(|intent| intent.state.clone())
    }

    /// Ends an intent nobody answered in time.
    pub fn time_out(&mut self, id: IntentId) -> Option<IntentState> {
        let after = self.matching_window;
        let _ = self.set_state(id, IntentState::TimedOut { after });
        self.intents.get(&id).map(|intent| intent.state.clone())
    }

    /// Ends a dispatched intent whose answer can no longer arrive.
    ///
    /// # Why this is not [`Board::time_out`]
    ///
    /// Because `time_out` is the matching window's ending: it moves any intent into `TimedOut` after the window in which
    /// candidates could arrive. This one is about **work sent to another device**, and it must only move work that is
    /// still `Dispatching` — calling it on a finished intent would roll a real outcome back to "nobody answered", which is
    /// the one thing a late answer must never do.
    ///
    /// `after` is how long the device waited, not the matching window: the two timeouts are different questions.
    pub fn expire_dispatch(&mut self, id: IntentId, after: Duration) -> Option<IntentState> {
        let intent = self.intents.get(&id)?;
        if !intent.state.is_running() {
            return Some(intent.state.clone());
        }
        let _ = self.set_state(id, IntentState::TimedOut { after });
        self.intents.get(&id).map(|intent| intent.state.clone())
    }

    /// Ends an intent a user or a policy stopped.
    pub fn cancel(
        &mut self,
        id: IntentId,
        reason: impl Into<String>,
    ) -> Result<IntentState, IntentError> {
        let intent = self
            .intents
            .get(&id)
            .ok_or(IntentError::Unknown { intent_id: id })?;
        let ended = intent.state.is_final();
        if ended {
            let state = intent.state.clone();
            // Cancelling something that already ended is not an error: the user asked for it to stop and it has
            // stopped. Refusing would make a race between the two a message about an invalid state.
            return Ok(state);
        }
        let _ = self.set_state(
            id,
            IntentState::Cancelled {
                reason: reason.into(),
            },
        );
        self.intents
            .get(&id)
            .map(|intent| intent.state.clone())
            .ok_or(IntentError::Unknown { intent_id: id })
    }
}
