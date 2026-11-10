use std::collections::VecDeque;

use super::*;

const NOW: i64 = 1_000;

/// A host that answers from a script and records what the runner told it.
struct Fake {
    pending: Vec<IntentId>,
    outcomes: VecDeque<Attempt>,
    changes: Vec<(
        IntentId,
        Option<synra_store::IntentRetryRow>,
        Option<RetryStatus>,
    )>,
    attempts: usize,
}

impl RetryHost for Fake {
    fn pending(&mut self) -> Vec<IntentId> {
        std::mem::take(&mut self.pending)
    }

    fn attempt(&mut self, _id: IntentId) -> Attempt {
        self.attempts += 1;
        self.outcomes.pop_front().unwrap_or(Attempt::Answered)
    }

    fn changed(
        &mut self,
        id: IntentId,
        row: Option<synra_store::IntentRetryRow>,
        status: Option<RetryStatus>,
    ) {
        self.changes.push((id, row, status));
    }
}

mod backoff;
mod persistence;
