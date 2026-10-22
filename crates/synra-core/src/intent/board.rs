//! The board: every intent this kernel is in the middle of, and what may happen to each.
//!
//! # The four decisions this type owns
//!
//! | Decision | Where |
//! | --- | --- |
//! | When asking plugins stops | the deadline in [`IntentState::Matching`], closed by [`Board::settle`] |
//! | Whether a user is interrupted | [`Board::settle`] against the intent's [`Choice`] |
//! | Whether a repeated request runs twice | [`Board::recall`], keyed on the sender *and* the request id |
//! | What a candidate may become | [`Board::choose`] and [`Board::confirm`], each checking the candidate is one the user was shown |
//!
//! # Why the deadline is not a timer
//!
//! Nothing here sleeps. A board is a value with a clock passed in — every method that cares takes `now_ms` — so the
//! sequence "ask, wait, settle" is a test that runs in microseconds instead of one that waits for a timeout. The timer
//! that calls [`Board::settle`] belongs to whoever owns a runtime, and it is the only part of this that cannot be
//! tested by a value.
//!
//! # Why an intent is never removed when it ends
//!
//! Because two readers need it afterwards: the interface, which shows what happened, and [`Board::recall`], which
//! answers a repeated request with the outcome of the first one. The board keeps finished intents under a bound and
//! reaps the oldest, which is [`Board::forget_ended_before`] — a sweep rather than a deletion on completion, because
//! the whole point of keeping them is that the answer is still wanted later.

use std::collections::HashMap;
use std::time::Duration;

use synra_protocol::ids::{DeviceId, IntentId, RequestId, TraceId};
use synra_protocol::SynraError;

use super::types::{
    Choice, Intent, IntentCandidate, IntentError, IntentSource, IntentState, PlannedAction,
};
use crate::admission::AdmissionRefusal;

/// How many finished intents are kept for a repeated request to be answered from.
///
/// A bound rather than an unbounded map, because a device that shares things all day would otherwise hold every share
/// it has ever seen. Sixty-four is roughly a day of shares on a busy phone, and the value of an entry drops off
/// sharply: a retry arrives within seconds, not hours.
pub const ENDED_MEMORY: usize = 64;

/// How long an intent may spend matching, by default.
///
/// The design document's 50ms is a plugin *call's* budget, not the matching window: a window has to cover several
/// plugins answering in sequence behind a bounded concurrency. This is the window, and it is deliberately short enough
/// that a share feels instant — a prompt that appears two seconds after a share is a prompt the user has moved on from.
pub const MATCHING_WINDOW: Duration = Duration::from_millis(400);

/// Why an intent was raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raised {
    /// The new intent's identifier.
    pub intent_id: IntentId,
    /// Its trace, so a caller can log the whole life of it.
    pub trace: TraceId,
}

/// Which candidate a user picked.
///
/// # Why a candidate and not an index
///
/// An index is only meaningful against the list it came from, and the list can change between the prompt being drawn
/// and the answer arriving — a late candidate supersedes an earlier one from the same plugin. Naming the plugin and
/// the action is stable across that, and [`Board::choose`] checks it against the list the user was actually shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateChoice {
    /// Which plugin.
    pub plugin_id: synra_protocol::ids::PluginId,
    /// Which action.
    pub action: String,
}

impl CandidateChoice {
    /// Names a candidate.
    #[must_use]
    pub fn new(plugin_id: synra_protocol::ids::PluginId, action: impl Into<String>) -> Self {
        Self { plugin_id, action: action.into() }
    }
}

/// The board.
#[derive(Debug)]
pub struct Board {
    intents: HashMap<IntentId, Intent>,
    /// The order intents were raised in, so a sweep can drop the oldest finished ones without sorting by a timestamp
    /// that a clock change could reorder.
    order: Vec<IntentId>,
    matching_window: Duration,
    ended_memory: usize,
}

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
        Self { matching_window, ..Self::new() }
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
        self.order.iter().filter_map(|id| self.intents.get(id)).collect()
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
        let trace = TraceId::new();
        let deadline = now_ms.saturating_add(i64::try_from(self.matching_window.as_millis()).unwrap_or(i64::MAX));
        let implied = source.implied_action();
        let state = match implied {
            // A source that named its plugin and action needs no matching: the candidate list has one entry, and
            // putting it through a matching phase would mean asking a plugin that was already told what to do.
            Some(planned) => IntentState::Dispatching {
                candidate: candidate_of(&planned),
                target: source.named_target().unwrap_or_default(),
                request_id: request_id.unwrap_or_default(),
            },
            None => IntentState::Matching { deadline_ms: deadline, candidates: Vec::new() },
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
        if let Some(slot) = candidates.iter_mut().find(|existing| candidate.supersedes(existing)) {
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
            let IntentState::Matching { deadline_ms, candidates } = &intent.state else {
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
                let target = candidate
                    .suggested_target
                    .or_else(|| self.intents.get(&id).and_then(|intent| intent.source.named_target()));
                let next = match target {
                    // A candidate with a device in mind goes straight to confirmation, which is the state that shows
                    // the user what is about to happen on another machine.
                    Some(target) => IntentState::Confirming { candidate, target },
                    // And a candidate without one is a choice about *where*, which is the user's.
                    None => IntentState::Choosing { candidates: vec![candidate] },
                };
                let _ = self.set_state(id, next);
                self.intents.get(&id).map(|intent| intent.state.clone())
            }
            None => None,
        }
    }

    /// Picks a candidate the user was shown.
    ///
    /// # Errors
    ///
    /// [`IntentError::NotACandidate`] when the named plugin and action are not on the list. Checked rather than
    /// trusted: a choice arrives from an interface, and acting on one that was never shown would run something the user
    /// did not choose.
    pub fn choose(&mut self, id: IntentId, choice: &CandidateChoice) -> Result<IntentState, IntentError> {
        let intent = self.intents.get(&id).ok_or(IntentError::Unknown { intent_id: id })?;
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
                let _ = self.set_state(id, IntentState::Confirming { candidate: found, target });
            }
            None => {
                let _ = self.set_state(id, IntentState::Choosing { candidates: vec![found] });
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
        let intent = self.intents.get(&id).ok_or(IntentError::Unknown { intent_id: id })?;
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
        let intent = self.intents.get(&id).ok_or(IntentError::Unknown { intent_id: id })?;
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
            IntentState::Dispatching { candidate: candidate.clone(), target, request_id },
        );
        Ok((candidate, request_id))
    }

    /// Records the outcome a device reported.
    ///
    /// # Errors
    ///
    /// [`IntentError::Unknown`] when there is no such intent. An outcome for an intent this board has forgotten is
    /// **not** an error at the protocol level — it is a late answer, and the caller logs it.
    pub fn conclude(&mut self, id: IntentId, ok: bool, result: &str, error: Option<SynraError>, elapsed_ms: u64) -> Result<IntentState, IntentError> {
        let intent = self.intents.get(&id).ok_or(IntentError::Unknown { intent_id: id })?;
        if intent.state.is_final() {
            // A second outcome for an intent that already ended. Kept as the first answer: a device that reports
            // success and then failure has not changed what happened.
            return Ok(intent.state.clone());
        }
        let next = if ok {
            IntentState::Succeeded {
                // A payload that does not parse is stored as a JSON string rather than refused: the action *succeeded*,
                // and turning a formatting problem into a failure would report the wrong thing to the user.
                result: serde_json::from_str(result)
                    .unwrap_or_else(|_| serde_json::Value::String(result.to_owned())),
                elapsed_ms,
            }
        } else {
            IntentState::Failed {
                error: error.unwrap_or_else(|| SynraError::new(synra_protocol::error::ErrorCode::Internal, result)),
                elapsed_ms,
            }
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
    pub fn cancel(&mut self, id: IntentId, reason: impl Into<String>) -> Result<IntentState, IntentError> {
        let intent = self.intents.get(&id).ok_or(IntentError::Unknown { intent_id: id })?;
        let ended = intent.state.is_final();
        if ended {
            let state = intent.state.clone();
            // Cancelling something that already ended is not an error: the user asked for it to stop and it has
            // stopped. Refusing would make a race between the two a message about an invalid state.
            return Ok(state);
        }
        let _ = self.set_state(id, IntentState::Cancelled { reason: reason.into() });
        self.intents
            .get(&id)
            .map(|intent| intent.state.clone())
            .ok_or(IntentError::Unknown { intent_id: id })
    }

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
        self.find_request(origin, request).and_then(|id| self.intents.get(&id))
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
        let horizon = now_ms.saturating_sub(i64::try_from(keep_for.as_millis()).unwrap_or(i64::MAX));

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
            left.0.cmp(&right.0).then_with(|| left.1.to_string().cmp(&right.1.to_string()))
        });
        let ended: Vec<IntentId> = ended.into_iter().map(|(_, id)| id).collect();

        let stale = ended
            .iter()
            .filter(|id| self.intents.get(id).is_some_and(|intent| intent.created_at_ms < horizon))
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
        self.intents.values().filter(|intent| intent.state.is_final()).count()
    }

    /// Finds the intent a request already raised.
    fn find_request(&self, origin: DeviceId, request: RequestId) -> Option<IntentId> {
        self.order
            .iter()
            .filter_map(|id| self.intents.get(id))
            .find(|intent| intent.is_same_request_as(origin, request))
            .map(|intent| intent.id)
    }

    /// Moves an intent, if it is there to move.
    ///
    /// One place that writes a state, so a transition that should have been refused has one place to be refused in.
    fn set_state(&mut self, id: IntentId, state: IntentState) -> Option<()> {
        let intent = self.intents.get_mut(&id)?;
        intent.state = state;
        Some(())
    }
}

impl Default for Board {
    fn default() -> Self {
        Self::new()
    }
}

/// A candidate for an action a source named outright.
///
/// The version is empty because nothing was asked: no plugin answered, so there is no version to record. A dispatch
/// built from this carries no version claim rather than one invented here.
fn candidate_of(planned: &PlannedAction) -> IntentCandidate {
    IntentCandidate {
        plugin_id: planned.plugin_id.clone(),
        plugin_version: String::new(),
        planned: planned.clone(),
        required_caps: Vec::new(),
        suggested_target: None,
        title: planned.action.clone(),
        detail: None,
    }
}
