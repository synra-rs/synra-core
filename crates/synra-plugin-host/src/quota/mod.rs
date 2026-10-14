//! What a plugin may spend, and what happens when it overspends.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds three separable things: what is counted and how much is allowed, the buckets and windows those
//! limits are enforced with, and the budget that ties a plugin's overspending to its health. In one file the
//! three-hundred-line `impl Budget` sat below four hundred lines of type definitions.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `limits` | what is rate-limited, how much is allowed, and the refusal to serve |
//! | `ledger` | the token bucket, the refusals that persist, and the window arithmetic |
//! | `budget` | the budget, the health it reaches, and the report it produces |

mod limits;
mod ledger;
mod budget;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod proptests;

pub use budget::{
    Budget, DEGRADE_AFTER_WINDOWS, FAULT_AFTER_WINDOWS, Health, PERSISTENCE_WINDOW,
    PERSISTENT_REFUSALS, QuotaReport, window_number,
};
pub use ledger::{RateLimited, StaticRefusal, TokenBucket};
pub use limits::{Quota, RateKind};

#[cfg(test)]
pub(crate) use budget::in_window;
