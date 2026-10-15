//! Asking every loaded plugin what it can do with a share, and putting the answers on the board.
//!
//! # What one matching pass does
//!
//! The design document's step 3 (`07-core-kernel.md` §6.2) in full: ask each plugin that declares a share handler
//! whether this share is its business, under a budget, and give every answer to the [`Board`]. The board then decides
//! what the answers mean — when to stop asking, whether to prompt — and this file does not second-guess it.
//!
//! # Why one plugin's failure does not stop the others
//!
//! Because a share with nine plugins installed is matched by nine independent calls, and one of them trapping, timing
//! out or answering with nonsense must not cost the user the other eight. Each failure is recorded in the [`MatchReport`]
//! instead of being propagated, so the difference between "nothing can handle this" and "everything that could have
//! handle this failed" stays visible — the first is a fact about what is installed, the second is a bug report.
//!
//! # Why declining is not a failure
//!
//! Because `can-handle` returning `{"handled": false}` is the common answer and the correct one. Counting declines as
//! errors would put every share in front of a plugin author as an error report, which is the fastest way to teach them
//! that the log is noise.
//!
//! # Why this runs on one thread and says so
//!
//! Because a [`PluginInstance`] is mutable state and two callers sharing one is a data race by construction. The engine
//! already has a thread pool for this ([`synra_plugin_host::WasmExecutor`]); this type is the logic that runs inside
//! it, and it takes `&mut PluginSet` so that a caller cannot accidentally run two of them over one set.

use serde::Deserialize;

use synra_protocol::ids::{DeviceId, PluginId};

use crate::intent::{Board, IntentCandidate, PlannedAction};

use super::plugins::{PluginSet, PluginSetError};

/// What one plugin said it could do.
///
/// # Why this is deserialized and not trusted as a `Value`
///
/// Because a plugin that returns a title of the wrong type should be recorded as a plugin that answered wrongly, and
/// walking a `serde_json::Value` to find that out would be this crate re-deriving serde's error messages one branch at
/// a time. `handled` is required and the rest defaults, so a plugin that says only "yes" is not a parse failure — it is
/// a plugin with nothing to show in the prompt, and [`Proposal::into_candidate`] gives it a title from its id rather
/// than dropping it. Dropping it would mean a plugin that works perfectly is invisible because it wrote a short answer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct Proposal {
    /// Whether this share is the plugin's business.
    pub handled: bool,
    /// What it proposes to do, defaulting to `share` because the only entry point that asks is the share entry point.
    #[serde(default = "share_action")]
    pub action: String,
    /// One line for the prompt.
    #[serde(default)]
    pub title: String,
    /// Optional second line.
    #[serde(default)]
    pub detail: Option<String>,
    /// The capabilities the action needs, which the gate checks before anything runs.
    #[serde(default)]
    pub required: Vec<String>,
    /// What `execute` should be given.
    ///
    /// ★ **Without this, `execute` could not know what to act on.**
    ///
    /// `can-handle` is handed the shared item and `execute` is not — the contract is
    /// `execute(action: string, args-json: string)` — so a plugin that answered "yes, I can open this" was called with
    /// `("open", "null")` and had no way to learn *which* link. The action could be proposed and never performed, which
    /// is why this field exists rather than a fourth parameter on `execute`.
    ///
    /// # Why the plugin supplies this rather than the host
    ///
    /// Because only the plugin knows what its own action needs. "Open this link" wants the URL and nothing else; "add to
    /// reading list" wants the URL and the title; a file share wants a transfer id. A host that decided would be guessing
    /// at every plugin's interface. Here the plugin copies whatever it needs out of the item it was already given, and the
    /// host carries it across unchanged — it does not read, interpret or filter the contents.
    ///
    /// # Why this is not a way to smuggle anything past the gate
    ///
    /// Because the args go back to the plugin that wrote them, and the gate judges capabilities rather than arguments. A
    /// plugin cannot escalate by lying to itself, and the item it copied from is one the host already handed it.
    ///
    /// Absent means `null`, which is exactly what every plugin received before this field existed — an older plugin that
    /// does not send `args` behaves as it did.
    #[serde(default)]
    pub args: serde_json::Value,
    /// Where it suggests running, when it has an opinion.
    #[serde(default)]
    pub target: Option<DeviceId>,
}

/// The action name a proposal means when it did not name one.
fn share_action() -> String {
    "share".to_owned()
}

impl Proposal {
    /// Turns this into a candidate, or `None` when the plugin declined.
    ///
    /// # Why a declining plugin still needs a title field to be valid
    ///
    /// Because `handled: false` is the answer to "is this yours" and it carries no other information. A plugin that
    /// declines is a plugin that works, so it is read the same way as one that accepts — no error, no warning.
    #[must_use]
    pub fn into_candidate(self, plugin_id: PluginId, version: String) -> Option<IntentCandidate> {
        if !self.handled {
            return None;
        }
        let action = self.action;
        let title = if self.title.is_empty() {
            plugin_id.as_str().to_owned()
        } else {
            self.title
        };
        let planned = PlannedAction {
            plugin_id: plugin_id.clone(),
            action,
            // ★ Carried through from the plugin's own answer rather than overwritten. This line used to be
            // `Value::Null`, which meant `execute` was always called with `null` — see `Proposal::args`.
            args: self.args,
        };
        Some(IntentCandidate {
            plugin_id,
            plugin_version: version,
            planned,
            required_caps: self.required,
            suggested_target: self.target,
            title,
            detail: self.detail,
        })
    }
}

/// What one plugin said that was not an answer the board could use.
///
/// # Why these are kept whole rather than counted
///
/// Because "the manifest says it has a share handler and it answered with `not json`" is a bug report that names the
/// plugin, and a counter that only said `failures: 2` would make somebody reproduce it by hand across every install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Misbehaviour {
    /// Which plugin.
    pub plugin_id: PluginId,
    /// What the host saw: `trap`, `timeout`, `fuel-exhausted`, or the engine's own reason.
    pub detail: String,
}

/// What a matching pass did.
///
/// # Why this is a report and not just a count
///
/// Because the two interesting outcomes look identical from outside. A share that matched nothing because nothing is
/// installed and a share that matched nothing because everything crashed both produce an empty candidate list, and a user
/// cannot tell them apart — but a maintainer can, immediately, from this.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchReport {
    /// How many plugins were asked.
    pub asked: u32,
    /// How many said yes.
    pub handled: u32,
    /// How many said no.
    pub declined: u32,
    /// How many the board kept. Less than `handled` means the window closed mid-pass.
    pub offered: u32,
    /// Which plugins did not answer usably, and why.
    pub misbehaved: Vec<Misbehaviour>,
}

impl MatchReport {
    /// Whether at least one candidate reached the board.
    #[must_use]
    pub const fn matched(&self) -> bool {
        self.offered > 0
    }

    /// Whether every plugin that was asked failed.
    ///
    /// Distinguishable from "nothing was installed" on purpose — see [`MatchReport`].
    #[must_use]
    pub const fn all_misbehaved(&self) -> bool {
        self.asked > 0 && self.misbehaved.len() >= self.asked as usize
    }
}

/// The budget one `can-handle` call gets.
///
/// # Why the window and the per-call budget are different numbers
///
/// Because they answer different questions. 50 ms bounds one plugin; the board's window bounds the whole pass so that a
/// prompt appears while the user is still looking at what they shared. Giving every plugin the whole window would make a
/// device with nine plugins feel broken for as long as nine slow plugins can last.
pub const CAN_HANDLE_BUDGET_MS: u64 = 50;

/// Asks plugins about a share.
#[derive(Debug)]
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
