use super::{MatchReport, Misbehaviour, Proposal, CAN_HANDLE_BUDGET_MS};
use crate::dispatch::plugins::{PluginSet, PluginSetError};
use crate::intent::Board;
use synra_protocol::ids::PluginId;

/// Asks loaded plugins whether they can handle one share.
pub struct Matcher<'a> {
    set: &'a mut PluginSet,
    fuel: Option<u64>,
    memory_growth: Option<u64>,
    budget_ms: u64,
}

impl<'a> Matcher<'a> {
    /// A matcher that asks under the default budget.
    #[must_use]
    pub const fn new(set: &'a mut PluginSet) -> Self {
        Self {
            set,
            fuel: None,
            memory_growth: None,
            budget_ms: CAN_HANDLE_BUDGET_MS,
        }
    }

    /// A matcher with an explicit fuel limit per call.
    ///
    /// # Why fuel is opt-in rather than a default
    ///
    /// Because a limit that is always on and set generously is a limit that has never been chosen, and a limit set
    /// tightly fails plugins that are merely large. A caller that has measured its plugins sets this; one that has not
    /// leaves it off and gets the wall clock, which is the limit that cannot be evaded anyway.
    #[must_use]
    pub const fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel = Some(fuel);
        self
    }

    /// The budget one call will run under.
    #[must_use]
    pub const fn budget(&self) -> synra_plugin_host::CallBudget {
        synra_plugin_host::CallBudget {
            fuel: self.fuel,
            timeout: Some(std::time::Duration::from_millis(self.budget_ms)),
            max_memory_growth: self.memory_growth,
        }
    }

    /// Asks every loaded plugin about one share and gives the answers to the board.
    ///
    /// `item_json` is the shared item as JSON, which is what the contract's `can-handle` takes.
    pub fn match_share(
        &mut self,
        board: &mut Board,
        intent_id: synra_protocol::ids::IntentId,
        item_json: &str,
        now_ms: i64,
    ) -> MatchReport {
        let mut report = MatchReport::default();
        let work = synra_plugin_host::Work::CanHandle {
            item_json: item_json.to_owned(),
        };
        let budget = self.budget();

        // ★ Snapshot the ids before asking anyone. A plugin's own host call can install or remove a plugin, and
        // iterating the set while a call mutates it is the kind of bug that reproduces on a user's machine and nowhere
        // else. A plugin installed mid-pass answers on the next share, which is a delay, rather than this.
        for id in self.set.ids() {
            let Some(version) = self.set.version(&id).map(ToOwned::to_owned) else {
                continue;
            };
            report.asked = report.asked.saturating_add(1);
            let now = now_ms.max(0) as u64;
            match self.set.call(&id, &work, budget, now) {
                Ok(outcome) => {
                    self.take_answer(&id, version, outcome, board, intent_id, &mut report)
                }
                Err(PluginSetError::AtInstanceLimit { .. }) => {
                    // At its limit, not broken: this is not a misbehaviour and must not count as one, or a busy plugin
                    // would be degraded for being busy.
                }
                Err(error) => report.misbehaved.push(Misbehaviour {
                    plugin_id: id.clone(),
                    detail: error.to_string(),
                }),
            }
        }
        report
    }

    /// Turns one call outcome into an offer, a decline, or a note in the report.
    fn take_answer(
        &mut self,
        id: &PluginId,
        version: String,
        outcome: synra_plugin_host::CallOutcome,
        board: &mut Board,
        intent_id: synra_protocol::ids::IntentId,
        report: &mut MatchReport,
    ) {
        if outcome.is_misbehaviour() {
            report.misbehaved.push(Misbehaviour {
                plugin_id: id.clone(),
                detail: outcome.as_str().to_owned(),
            });
            return;
        }
        let synra_plugin_host::CallOutcome::Ok(payload) = outcome else {
            // `Failed` is the plugin reporting an error it handled. It is recorded and the pass continues.
            report.misbehaved.push(Misbehaviour {
                plugin_id: id.clone(),
                detail: "failed".to_owned(),
            });
            return;
        };
        match serde_json::from_str::<Proposal>(&payload) {
            Ok(proposal) => match proposal.into_candidate(id.clone(), version) {
                Some(candidate) => {
                    report.handled = report.handled.saturating_add(1);
                    if board.offer(intent_id, candidate) {
                        report.offered = report.offered.saturating_add(1);
                    }
                }
                None => report.declined = report.declined.saturating_add(1),
            },
            Err(error) => report.misbehaved.push(Misbehaviour {
                plugin_id: id.clone(),
                detail: format!("can-handle returned {error}"),
            }),
        }
    }
}
