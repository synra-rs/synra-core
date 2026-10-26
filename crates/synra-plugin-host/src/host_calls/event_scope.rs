//! Import availability and concrete event-name authority for event emission.

use std::borrow::Cow;

use serde::Deserialize;
use synra_capability::{Capability, CapabilitySet};
use synra_protocol::PluginId;

use super::{CallError, HostCalls};

pub(crate) fn available(grants: &CapabilitySet) -> bool {
    let Ok(family) = Capability::parse("event:emit:*") else {
        return false;
    };
    grants
        .iter()
        .any(|grant| family.matches(grant) || grant.matches(&family))
}

#[derive(Deserialize)]
struct Request<'a> {
    #[serde(borrow)]
    event: Cow<'a, str>,
}

pub(super) fn authorize(
    grants: &CapabilitySet,
    plugin: &PluginId,
    argument: &str,
) -> Result<(), CallError> {
    let request: Request<'_> = serde_json::from_str(argument)
        .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
    // Ownership is independent of grants: even a wildcard cannot impersonate another package.
    HostCalls::check_emittable(plugin, &request.event)?;
    let capability = Capability::parse(&format!("event:emit:{}", request.event))
        .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
    if grants.grants(&capability) {
        Ok(())
    } else {
        Err(CallError::denied(capability.as_str(), grants))
    }
}
