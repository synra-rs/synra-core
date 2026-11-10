use super::*;

impl Board {
    /// Adds a plugin's answer to an intent that is still matching.
    ///
    /// # Returns
    ///
    /// Whether it was kept. A candidate arriving after the window closed is **dropped** rather than added: a list that
    /// grew after the user started reading it is a prompt whose meaning changed under them.
    pub fn offer(&mut self, id: IntentId, candidate: IntentCandidate) -> bool {
        let Some(intent) = self.intents.get_mut(&id) else {
            return false;
        };
        let IntentState::Matching { candidates, .. } = &mut intent.state else {
            return false;
        };

        // A second answer from the same plugin supersedes the first rather than joining it: one plugin has not offered
        // two choices, it has described one twice.
        if let Some(slot) = candidates
            .iter_mut()
            .find(|existing| candidate.supersedes(existing))
        {
            *slot = candidate;
            return true;
        }
        candidates.push(candidate);
        true
    }

    /// Closes the matching window, if it has closed.
    ///
    /// # Returns
    ///
    /// What the intent became, or `None` when it is not matching or the window is still open. Called by whoever owns a
    /// timer, and safe to call repeatedly: a board with nothing to settle does nothing.
    ///
    /// # The three endings of a matching phase
    ///
    /// No candidate is [`IntentState::NoHandler`] — a fact about what is installed, and the user's next step is to
    /// install something. One or more candidates and a [`Choice`] that says to ask is [`IntentState::Choosing`]. And
    /// anything else with a candidate is decided now, which is the automatic path the design document makes the default.
    pub fn settle(&mut self, id: IntentId, now_ms: i64) -> Option<IntentState> {
        let choice = self.intents.get(&id)?.choice;
        let planned = {
            let intent = self.intents.get(&id)?;
            let IntentState::Matching {
                deadline_ms,
                candidates,
            } = &intent.state
            else {
                return None;
            };
            if now_ms < *deadline_ms {
                return None;
            }
            let candidates = candidates.clone();
            if candidates.is_empty() {
                let _ = self.set_state(id, IntentState::NoHandler);
                return self.intents.get(&id).map(|intent| intent.state.clone());
            }
            let ask = match choice {
                Choice::AlwaysAsk => true,
                Choice::AskWhenAmbiguous => candidates.len() > 1,
                // ★ Automatic is not "pick the first". It is "pick the only one", and with two candidates the user is
                // asked exactly as they would be under `AskWhenAmbiguous`: a plugin cannot make itself the silent
                // answer by being installed first.
                Choice::Automatic => candidates.len() > 1,
                Choice::Never => false,
            };
            if ask {
                let _ = self.set_state(id, IntentState::Choosing { candidates });
                return self.intents.get(&id).map(|intent| intent.state.clone());
            }
            candidates.first().cloned()
        };

        match planned {
            Some(candidate) => {
                let target = candidate.suggested_target.or_else(|| {
                    self.intents
                        .get(&id)
                        .and_then(|intent| intent.source.named_target())
                });
                let next = match target {
                    // A candidate with a device in mind goes straight to confirmation, which is the state that shows
                    // the user what is about to happen on another machine.
                    Some(target) => IntentState::Confirming { candidate, target },
                    // And a candidate without one is a choice about *where*, which is the user's.
                    None => IntentState::Choosing {
                        candidates: vec![candidate],
                    },
                };
                let _ = self.set_state(id, next);
                self.intents.get(&id).map(|intent| intent.state.clone())
            }
            None => None,
        }
    }
}
