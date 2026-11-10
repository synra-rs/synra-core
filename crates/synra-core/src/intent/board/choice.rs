use super::*;

impl Board {
    /// Picks a candidate the user was shown.
    ///
    /// # Errors
    ///
    /// [`IntentError::NotACandidate`] when the named plugin and action are not on the list. Checked rather than
    /// trusted: a choice arrives from an interface, and acting on one that was never shown would run something the user
    /// did not choose.
    pub fn choose(
        &mut self,
        id: IntentId,
        choice: &CandidateChoice,
    ) -> Result<IntentState, IntentError> {
        let intent = self
            .intents
            .get(&id)
            .ok_or(IntentError::Unknown { intent_id: id })?;
        let found = intent
            .state
            .candidates()
            .iter()
            .find(|candidate| {
                candidate.plugin_id == choice.plugin_id && candidate.planned.action == choice.action
            })
            .cloned()
            .ok_or_else(|| IntentError::NotACandidate {
                plugin_id: choice.plugin_id.to_string(),
                action: choice.action.clone(),
            })?;

        let target = found
            .suggested_target
            .or_else(|| intent.source.named_target());
        match target {
            Some(target) => {
                let _ = self.set_state(
                    id,
                    IntentState::Confirming {
                        candidate: found,
                        target,
                    },
                );
            }
            None => {
                let _ = self.set_state(
                    id,
                    IntentState::Choosing {
                        candidates: vec![found],
                    },
                );
            }
        }
        self.intents
            .get(&id)
            .map(|intent| intent.state.clone())
            .ok_or(IntentError::Unknown { intent_id: id })
    }

    /// Answers "where should this run?" for an intent that asked.
    ///
    /// # ★ Why this method had to exist
    ///
    /// Because `Choosing` is reached for **two different questions** — "which plugin?" when several claimed the share,
    /// and "where?" when the one that claimed it named no device — and only the first had a method. A targetless
    /// candidate left the intent in a state nothing could advance: `choose` puts a candidate with no suggested target
    /// straight back into `Choosing`, and `confirm` refuses anything that is not `Confirming`. The intent was reachable
    /// and could not be moved, which meant an action could be proposed and never performed.
    ///
    /// # Why this refuses an ambiguous choice rather than taking the first candidate
    ///
    /// Because with two candidates the question being asked is "which plugin", and attaching a device to one the user has
    /// not picked would answer a question they were not asked — and would do it by silently choosing for them. Which is
    /// also why the two questions sharing one state is a weakness rather than a design: the state alone does not say what
    /// is being asked, so this method has to infer it from the candidate count.
    ///
    /// # Errors
    ///
    /// [`IntentError::Unknown`] when there is no such intent, and [`IntentError::WrongState`] when the intent is not
    /// waiting to be decided or is waiting with more than one candidate.
    pub fn aim(&mut self, id: IntentId, target: DeviceId) -> Result<IntentState, IntentError> {
        let intent = self
            .intents
            .get(&id)
            .ok_or(IntentError::Unknown { intent_id: id })?;
        let IntentState::Choosing { candidates } = &intent.state else {
            return Err(IntentError::WrongState {
                attempted: "aim",
                current: intent.state.kind(),
            });
        };
        // A slice pattern rather than `candidates[0]`: the workspace forbids indexing, and the shape check is the
        // refusal this method means to give.
        let candidate = match candidates.as_slice() {
            [only] => only.clone(),
            _ => {
                return Err(IntentError::WrongState {
                    attempted: "aim",
                    current: "choosing between several candidates, so the question is which plugin rather than which device",
                });
            }
        };
        // ★ And it must not already have answered the question itself.
        //
        // A candidate that suggested a device is one whose plugin said *where*; the intent is in `Choosing` only because
        // the user's setting asked them to confirm **which** plugin (`Choice::AlwaysAsk`, or more than one claimant
        // earlier in the pass). Letting a caller aim there would replace the plugin's own suggestion with a device the
        // caller chose — so a share the plugin meant to send to a phone could be run on this laptop, by a client that
        // answered a question nobody asked it.
        if let Some(suggested) = candidate.suggested_target {
            return Err(IntentError::WrongState {
                attempted: "aim",
                current: if suggested == target {
                    "the candidate already suggested that device, so nothing needs answering"
                } else {
                    "the candidate already suggested a device, so the question is which plugin rather than which device"
                },
            });
        }
        let _ = self.set_state(id, IntentState::Confirming { candidate, target });
        self.intents
            .get(&id)
            .map(|intent| intent.state.clone())
            .ok_or(IntentError::Unknown { intent_id: id })
    }

    /// Confirms a candidate and a target, producing the dispatch.
    ///
    /// # Returns
    ///
    /// The candidate and the envelope id the caller must send under. The id is minted **once** and kept on the intent,
    /// so a retry after a lost answer reuses it: a fresh id on a retry is a second request as far as the receiving
    /// side's idempotency cache is concerned, which is the same as running the action twice.
    ///
    /// # Errors
    ///
    /// [`IntentError::WrongState`] when the intent is not waiting to be confirmed, and [`IntentError::Unknown`] when
    /// there is no such intent.
    pub fn confirm(&mut self, id: IntentId) -> Result<(IntentCandidate, RequestId), IntentError> {
        let intent = self
            .intents
            .get(&id)
            .ok_or(IntentError::Unknown { intent_id: id })?;
        let IntentState::Confirming { candidate, target } = &intent.state else {
            return Err(IntentError::WrongState {
                attempted: "confirm",
                current: intent.state.kind(),
            });
        };
        let candidate = candidate.clone();
        let target = *target;
        // Reused rather than reminted, which is what makes a resend idempotent.
        let request_id = intent.request_id.unwrap_or_else(RequestId::new);
        let _ = self.set_state(
            id,
            IntentState::Dispatching {
                candidate: candidate.clone(),
                target,
                request_id,
            },
        );
        Ok((candidate, request_id))
    }
}
