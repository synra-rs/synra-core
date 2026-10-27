//! Cached immutable routing metadata, with fresh persisted consent on every use.

use super::{EventService, context::Execution, refusal};
use std::{collections::HashMap, sync::Arc};
use synra_capability::{Capability, CapabilitySet};
use synra_plugin_api::{Manifest, ManifestContext, ValidationLevel, payload::PayloadSchema};
use synra_protocol::{ErrorCode, SynraError, inbound::HandlePattern};

pub(super) struct Policy {
    generation: synra_protocol::RequestId,
    events: HashMap<String, Option<PayloadSchema>>,
    handles: Vec<(HandlePattern, Option<PayloadSchema>)>,
}

impl Policy {
    pub(super) fn emitted(
        &self,
        event: &str,
        payload: &serde_json::Value,
    ) -> Result<(), SynraError> {
        let schema = self.events.get(event).ok_or_else(|| {
            refusal(
                ErrorCode::InvalidArgument,
                "the running plugin did not declare this event",
                "undeclaredEvent",
            )
        })?;
        if let Some(schema) = schema {
            schema
                .validate(payload)
                .map_err(|error| payload_error(&error))?;
        }
        Ok(())
    }

    pub(super) fn accepts(&self, event: &str, payload: &serde_json::Value) -> bool {
        self.handles.iter().any(|(pattern, condition)| {
            pattern.matches(event)
                && condition
                    .as_ref()
                    .is_none_or(|schema| schema.validate(payload).is_ok())
        })
    }
}

impl EventService {
    pub(super) fn policy(
        &self,
        execution: &Execution,
    ) -> Result<(Arc<Policy>, CapabilitySet), SynraError> {
        let cached = {
            let state = self.state.lock();
            state
                .policies
                .iter()
                .find(|policy| policy.generation == execution.generation)
                .cloned()
        };
        let (decisions, manifest) = {
            let db = self.db.lock();
            if !db
                .plugin_is_allowed(execution.plugin.as_str())
                .map_err(storage)?
            {
                return Err(refusal(
                    ErrorCode::CapabilityDenied,
                    "this plugin is not enabled and trusted",
                    "pluginDisabled",
                ));
            }
            let active = db
                .active_plugin_version(execution.plugin.as_str())
                .map_err(storage)?;
            if active
                .as_ref()
                .is_none_or(|(version, _)| version != &execution.version)
            {
                return Err(refusal(
                    ErrorCode::CapabilityDenied,
                    "the installed version no longer matches this execution",
                    "versionChanged",
                ));
            }
            let decisions = db
                .plugin_grants(execution.plugin.as_str())
                .map_err(storage)?;
            let manifest = if cached.is_none() {
                Some(
                    db.active_plugin_manifest(execution.plugin.as_str(), &execution.version)
                        .map_err(storage)?
                        .ok_or_else(|| {
                            refusal(
                                ErrorCode::CapabilityDenied,
                                "the installed manifest is missing",
                                "manifestMissing",
                            )
                        })?,
                )
            } else {
                None
            };
            (decisions, manifest)
        };
        let mut grants = CapabilitySet::new();
        for row in decisions {
            if row.manifest_digest != execution.manifest_digest {
                return Err(refusal(
                    ErrorCode::CapabilityDenied,
                    "the plugin changed after consent",
                    "consentChanged",
                ));
            }
            let capability = Capability::parse(&row.capability).map_err(invalid)?;
            if row.granted {
                grants.insert(capability).map_err(invalid)?;
            }
        }
        if let Some(policy) = cached {
            return Ok((policy, grants));
        }
        let text = manifest.ok_or_else(|| {
            refusal(
                ErrorCode::Internal,
                "event metadata is unavailable",
                "manifestMissing",
            )
        })?;
        if text.len() > 1024 * 1024 {
            return Err(refusal(
                ErrorCode::PayloadTooLarge,
                "the installed manifest exceeds its byte budget",
                "manifestTooLarge",
            ));
        }
        if synra_plugin_api::manifest_digest(&text) != execution.manifest_digest {
            return Err(refusal(
                ErrorCode::CapabilityDenied,
                "the installed manifest does not match the running code",
                "manifestChanged",
            ));
        }
        let manifest = Manifest::from_json(&text).map_err(invalid)?;
        // Reject the routing count before compiling any of its payload schemas.
        if manifest.events.len() > 16 || manifest.handles.len() > 16 {
            return Err(refusal(
                ErrorCode::PayloadTooLarge,
                "a plugin may declare at most sixteen event types and sixteen handlers",
                "routingLimit",
            ));
        }
        manifest
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .map_err(invalid)?;
        if manifest.id != execution.plugin
            || manifest.version != execution.version
            || manifest.runtime.headless.is_none()
        {
            return Err(refusal(
                ErrorCode::CapabilityDenied,
                "event metadata names a different execution",
                "manifestChanged",
            ));
        }
        let mut events = HashMap::new();
        for declaration in manifest.events {
            let schema = declaration
                .payload
                .as_ref()
                .map(PayloadSchema::compile)
                .transpose()
                .map_err(invalid)?;
            events.insert(declaration.name, schema);
        }
        let mut handles = Vec::new();
        for handle in manifest.handles {
            let pattern = HandlePattern::parse(&handle.event).map_err(invalid)?;
            let condition = handle
                .conditions
                .as_ref()
                .map(|value| {
                    if !value.is_object() {
                        return Err(refusal(
                            ErrorCode::InvalidArgument,
                            "an event match condition must be an object",
                            "badCondition",
                        ));
                    }
                    PayloadSchema::compile(&condition_schema(value, 0)?).map_err(invalid)
                })
                .transpose()?;
            handles.push((pattern, condition));
        }
        let policy = Arc::new(Policy {
            generation: execution.generation,
            events,
            handles,
        });
        let mut state = self.state.lock();
        if state.policies.len() >= 32 {
            state.policies.pop_front();
        }
        state.policies.push_back(Arc::clone(&policy));
        drop(state);
        Ok((policy, grants))
    }
}

fn condition_schema(
    value: &serde_json::Value,
    depth: usize,
) -> Result<serde_json::Value, SynraError> {
    if depth > 16 {
        return Err(refusal(
            ErrorCode::PayloadTooLarge,
            "the event condition exceeds its depth budget",
            "badCondition",
        ));
    }
    if let Some(object) = value.as_object() {
        let mut properties = serde_json::Map::new();
        for (name, value) in object {
            properties.insert(name.clone(), condition_schema(value, depth + 1)?);
        }
        Ok(
            serde_json::json!({"type":"object","required":object.keys().collect::<Vec<_>>(),"properties":properties}),
        )
    } else {
        Ok(serde_json::json!({"const":value}))
    }
}

pub(super) fn require(grants: &CapabilitySet, name: &str) -> Result<(), SynraError> {
    let capability = Capability::parse(name).map_err(invalid)?;
    if grants.contains(&capability) {
        Ok(())
    } else {
        Err(SynraError::capability_denied(name))
    }
}

pub(super) fn invalid(error: impl std::fmt::Display) -> SynraError {
    refusal(
        ErrorCode::InvalidArgument,
        error.to_string(),
        "invalidEvent",
    )
}
pub(super) fn payload_error(error: &synra_plugin_api::payload::PayloadError) -> SynraError {
    let code = if matches!(error, synra_plugin_api::payload::PayloadError::TooLarge) {
        ErrorCode::PayloadTooLarge
    } else {
        ErrorCode::InvalidArgument
    };
    refusal(code, error.to_string(), "invalidPayload")
}
pub(super) fn storage(_error: impl std::fmt::Display) -> SynraError {
    refusal(
        ErrorCode::Internal,
        "event policy could not be read from storage",
        "storageFailure",
    )
}
