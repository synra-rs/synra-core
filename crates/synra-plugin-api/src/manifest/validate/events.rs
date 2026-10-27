use std::collections::HashSet;

use crate::manifest::error::ManifestError;
use crate::manifest::types::Manifest;

impl Manifest {
    /// The event declarations and their payload schemas.
    pub(super) fn check_events(&self) -> Result<(), ManifestError> {
        let namespace = self.event_namespace();
        let mut names = HashSet::new();

        for event in &self.events {
            if !names.insert(event.name.as_str()) {
                return Err(ManifestError::DuplicateName {
                    kind: "event",
                    name: event.name.clone(),
                });
            }

            // The namespace check is the one that stops a plugin emitting under another plugin's name. Without
            // it, a receiving side sees a legitimate name and routes it: one plugin impersonating another, with
            // nothing in any log to say so.
            if !event.name.starts_with(&namespace) || event.name.len() <= namespace.len() {
                return Err(ManifestError::ForeignEventNamespace {
                    name: event.name.clone(),
                    namespace,
                });
            }

            synra_protocol::event::EventName::parse(&event.name).map_err(|error| {
                ManifestError::BadEventName {
                    name: event.name.clone(),
                    reason: error.to_string(),
                }
            })?;

            if let Some(payload) = &event.payload {
                check_payload_schema(&event.name, payload)?;
            }
        }
        Ok(())
    }

    /// The `handles` entries.
    pub(super) fn check_handles(&self) -> Result<(), ManifestError> {
        for handle in &self.handles {
            // Receiving another package's event does not impersonate its emitter. The actual
            // receive grant is checked again at delivery, independently of this routing selector.
            let entry = handle.event.as_str();
            let known = synra_protocol::event::builtin::ALL.contains(&entry)
                || synra_protocol::event::events::ALL.contains(&entry);
            let namespace = entry.starts_with(synra_protocol::event::SYSTEM_PREFIX)
                || entry.starts_with("device.")
                || entry.starts_with("_plugin.");
            let acceptable = known
                || (namespace && synra_protocol::inbound::HandlePattern::parse(entry).is_ok());
            if !acceptable {
                return Err(ManifestError::BadHandle { event: handle.event.clone() });
            }
        }
        Ok(())
    }
}

/// Compile using the same bounded validator that event delivery uses.
fn check_payload_schema(name: &str, payload: &serde_json::Value) -> Result<(), ManifestError> {
    crate::payload::PayloadSchema::compile(payload)
        .map(|_| ())
        .map_err(|error| ManifestError::BadPayloadSchema {
            name: name.to_owned(),
            detail: error.to_string(),
        })
}
