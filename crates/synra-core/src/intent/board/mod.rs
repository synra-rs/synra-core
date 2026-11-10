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

use synra_protocol::SynraError;
use synra_protocol::ids::{DeviceId, IntentId, RequestId, TraceId};

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
        Self {
            plugin_id,
            action: action.into(),
        }
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

mod choice;
mod matching;
mod outcome;
mod query;
mod raise;

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
