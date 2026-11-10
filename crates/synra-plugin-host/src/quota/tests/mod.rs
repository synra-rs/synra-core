//! Quota enforcement, escalation and reporting tests.

use super::{Budget, Quota};

fn budget() -> Budget {
    Budget::new(Quota::default())
}

/// A budget whose host-call bucket never refills, so every call after the burst is refused.
///
/// Written as a named helper because the tests below are all about the escalation ladder, and a rate that refilled
/// between calls would make them about the token bucket instead: with a default refill of 500 per second, eleven
/// milliseconds of "elapsed" time is a whole token back, and the ladder would never move.
fn refusal_budget() -> Budget {
    Budget::new(refusal_quota())
}

/// The quota `refusal_budget` was built from, for asserting what is in force.
fn refusal_quota() -> Quota {
    Quota { host_calls_burst: 1, host_calls_per_sec: 0, ..Quota::default() }
}

mod buckets;
mod limits;
mod rates;
mod escalation;
mod reporting;
mod traps;
