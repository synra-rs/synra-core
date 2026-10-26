//! Import families and concrete authority for device sends and cross-plugin calls.

use std::borrow::Cow;

use serde::Deserialize;
use synra_capability::{Capability, CapabilitySet};
use synra_protocol::{DeviceId, PluginId};

use super::CallError;

pub(crate) const DEVICE_FAMILY: &str = "device:send:*";
pub(crate) const ACTION_FAMILY: &str = "action:invoke:*:*";
pub(crate) const DECLARE_FAMILY: &str = "action:declare:*";

/// Import availability is only a family check; every call checks its concrete arguments.
pub(crate) fn available(grants: &CapabilitySet, family: &str) -> bool {
    let Ok(family) = Capability::parse(family) else {
        return false;
    };
    grants
        .iter()
        .any(|grant| family.matches(grant) || grant.matches(&family))
}

#[derive(Deserialize)]
struct DeviceRequest<'a> {
    #[serde(borrow)]
    target: Cow<'a, str>,
}

#[derive(Deserialize)]
struct ActionRequest<'a> {
    #[serde(borrow)]
    plugin: Cow<'a, str>,
    #[serde(borrow)]
    name: Cow<'a, str>,
}

#[derive(Deserialize)]
struct DeclareRequest<'a> {
    #[serde(borrow)]
    name: Cow<'a, str>,
}

pub(super) fn declare(grants: &CapabilitySet, argument: &str) -> Result<(), CallError> {
    require_family(grants, DECLARE_FAMILY)?;
    let request: DeclareRequest<'_> = serde_json::from_str(argument).map_err(bad_argument)?;
    synra_plugin_api::manifest::validate_action_name(&request.name).map_err(bad_argument)?;
    require(grants, &format!("action:declare:{}", request.name))
}

pub(super) fn device(grants: &CapabilitySet, argument: &str) -> Result<(), CallError> {
    // A caller without any send authority gets a permission refusal, even for malformed arguments.
    require_family(grants, DEVICE_FAMILY)?;
    let request: DeviceRequest<'_> = serde_json::from_str(argument).map_err(bad_argument)?;
    let target: DeviceId = request.target.parse().map_err(bad_argument)?;
    if target.to_string() != request.target {
        return Err(CallError::new(
            CallError::BAD_ARGUMENT,
            "target must be a canonical device UUID",
        ));
    }
    require(grants, &format!("device:send:{}", request.target))
}

pub(super) fn action(grants: &CapabilitySet, argument: &str) -> Result<(), CallError> {
    require_family(grants, ACTION_FAMILY)?;
    let request: ActionRequest<'_> = serde_json::from_str(argument).map_err(bad_argument)?;
    PluginId::parse(&request.plugin).map_err(bad_argument)?;
    synra_plugin_api::manifest::validate_action_name(&request.name).map_err(bad_argument)?;
    require(
        grants,
        &format!("action:invoke:{}:{}", request.plugin, request.name),
    )
}

fn require_family(grants: &CapabilitySet, family: &str) -> Result<(), CallError> {
    if available(grants, family) {
        Ok(())
    } else {
        Err(CallError::denied(family, grants))
    }
}

fn require(grants: &CapabilitySet, text: &str) -> Result<(), CallError> {
    let capability = Capability::parse(text).map_err(bad_argument)?;
    if grants.grants(&capability) {
        Ok(())
    } else {
        Err(CallError::denied(text, grants))
    }
}

fn bad_argument(error: impl std::fmt::Display) -> CallError {
    CallError::new(CallError::BAD_ARGUMENT, error.to_string())
}

#[cfg(test)]
mod tests;
