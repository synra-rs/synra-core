//! Availability and concrete level authorization for the WIT logging function.

use std::borrow::Cow;

use serde::Deserialize;
use synra_capability::{Capability, CapabilitySet, Domain};

use super::CallError;

const LEVELS: &[(&str, &str)] = &[
    ("trace", "log:trace"),
    ("debug", "log:debug"),
    ("info", "log:info"),
    ("warn", "log:warn"),
    ("error", "log:error"),
];

pub(crate) fn available(grants: &CapabilitySet) -> bool {
    grants.iter().any(|grant| {
        if grant.domain() != Domain::Log {
            return false;
        }
        match grant.as_str() {
            "log:*" | "log:**" => true,
            text if grant.is_exact() => LEVELS.iter().any(|(_, name)| text == *name),
            // Preserve the shared matcher for less common multi-segment patterns.
            _ => LEVELS.iter().any(|(_, name)| {
                Capability::parse(name).is_ok_and(|capability| grant.matches(&capability))
            }),
        }
    })
}

#[derive(Deserialize)]
struct Request<'a> {
    #[serde(borrow)]
    level: Cow<'a, str>,
}

pub(super) fn authorize(grants: &CapabilitySet, argument: &str) -> Result<(), CallError> {
    let request: Request<'_> = serde_json::from_str(argument)
        .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
    let capability = required(&request.level)?;
    if grants.grants(&capability) {
        Ok(())
    } else {
        Err(CallError::denied(capability.as_str(), grants))
    }
}

fn required(level: &str) -> Result<Capability, CallError> {
    let (_, name) = LEVELS
        .iter()
        .find(|(supported, _)| *supported == level)
        .ok_or_else(|| {
            CallError::new(
                CallError::BAD_ARGUMENT,
                "log requires a concrete WIT log level",
            )
        })?;
    Capability::parse(name)
        .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))
}
