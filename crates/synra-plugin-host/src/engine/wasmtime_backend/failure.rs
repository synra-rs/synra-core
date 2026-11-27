//! Classify runtime failures from the typed causes carried by Wasmtime.

use std::fmt::Write as _;

use wasmtime::Trap;

use super::store::{EffectiveBudget, GrowthRefusal, MemoryCeilingExceeded};
use crate::{CallError, engine::CallOutcome};

pub(super) fn classify(
    error: &wasmtime::Error,
    budget: EffectiveBudget,
    growth_refusal: Option<&GrowthRefusal>,
) -> CallOutcome {
    if let Some(error) = error.downcast_ref::<MemoryCeilingExceeded>() {
        return CallOutcome::MemoryExceeded {
            limit: u64::try_from(error.limit).unwrap_or(u64::MAX),
        };
    }
    match (error.downcast_ref::<Trap>(), budget.fuel, budget.timeout) {
        (Some(Trap::OutOfFuel), Some(fuel), _) => return CallOutcome::FuelExhausted { fuel },
        (Some(Trap::Interrupt), _, Some(after)) => return CallOutcome::Timeout { after },
        _ => {}
    }

    // Non-result WIT imports trap on a host refusal. Keep that category so the caller retires the instance.
    let mut detail = error.downcast_ref::<CallError>().map_or_else(
        || format!("{error:#}"),
        |failure| format!("host call failed: {failure}"),
    );
    if let Some(refusal) = growth_refusal {
        let _ = write!(
            detail,
            "\nA memory growth request was also refused: {refusal}"
        );
    }
    CallOutcome::Trap { detail }
}
