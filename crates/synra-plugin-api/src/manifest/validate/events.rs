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
        let declared: HashSet<&str> = self.events.iter().map(|event| event.name.as_str()).collect();
        let namespace = self.event_namespace();

        for handle in &self.handles {
            // Four things an entry may be, and the order matters only for the message:
            //
            // 1. a known host event,
            // 2. one of this plugin's own declared names,
            // 3. a pattern in the host's namespace, which covers host events a newer build defines,
            // 4. a pattern in this plugin's own namespace, which is what a plugin uses to catch its own family.
            //
            // A pattern anywhere else is a subscription to a plugin that is not this one, or to a name that can
            // never exist — and a plugin that silently never receives anything is the hardest kind of bug to
            // find. `HandlePattern::parse` alone is not enough to tell: it validates the character class, so
            // `nonsense` is a legal pattern and a meaningless subscription.
            let entry = handle.event.as_str();
            let is_known_host_event = synra_protocol::event::builtin::ALL.contains(&entry)
                || synra_protocol::event::events::ALL.contains(&entry);
            let is_own_event = declared.contains(entry);
            let is_host_pattern =
                entry.starts_with(synra_protocol::event::SYSTEM_PREFIX) || entry.starts_with("device.");
            let is_own_pattern = entry.starts_with(&namespace);
            let is_legal_pattern = synra_protocol::inbound::HandlePattern::parse(entry).is_ok();

            let acceptable = is_known_host_event
                || is_own_event
                || ((is_host_pattern || is_own_pattern) && is_legal_pattern);

            if !acceptable {
                return Err(ManifestError::BadHandle { event: handle.event.clone() });
            }
        }
        Ok(())
    }
}

/// Checks an event's payload schema is one the host can enforce.
///
/// The rules are about what the *host* can do, not about JSON Schema in general. A payload is validated on
/// every inbound message, so the validator is deliberately small: no `$ref` to follow, no `format` needing a
/// library, no regex to run, and every bound a literal. A schema using something outside that subset is
/// refused rather than partially honoured, because a partial check is a promise the receiving side believes.
fn check_payload_schema(name: &str, payload: &serde_json::Value) -> Result<(), ManifestError> {
    let bad = |detail: &str| ManifestError::BadPayloadSchema {
        name: name.to_owned(),
        detail: detail.to_owned(),
    };

    let Some(object) = payload.as_object() else {
        return Err(bad("a payload schema must be a JSON object"));
    };

    // A top-level object, because a payload that is not an object cannot carry named fields and the wire
    // format's `payload` is an object everywhere else.
    match object.get("type").and_then(|value| value.as_str()) {
        Some("object") => {}
        Some(other) => return Err(bad(&format!("a payload schema must have type `object`, not {other:?}"))),
        None => {
            // `properties` without `type` is a common shorthand, and accepting it would mean two spellings of
            // one schema that the validator would have to keep in step.
            if object.contains_key("properties") {
                return Err(bad("a payload schema with `properties` must also say `type: object`"));
            }
            return Err(bad("a payload schema must say `type: object`"));
        }
    }

    walk_schema(&bad, payload, 0)?;
    Ok(())
}

/// Walks a schema, rejecting anything the host's validator cannot enforce.
fn walk_schema(bad: &impl Fn(&str) -> ManifestError, node: &serde_json::Value, depth: usize) -> Result<(), ManifestError> {
    // A schema is data, so it can be nested arbitrarily. Bounded because the loader walks it on every install
    // and a deeply nested one is either a mistake or an attempt to make the walk expensive.
    const MAX_DEPTH: usize = 16;
    if depth > MAX_DEPTH {
        return Err(bad(&format!("a payload schema nests deeper than {MAX_DEPTH} levels")));
    }

    match node {
        serde_json::Value::Object(object) => {
            for key in ["$ref", "format", "pattern", "patternProperties", "unevaluatedProperties"] {
                if object.contains_key(key) {
                    // `$ref` would need an external document, `format` a library, `pattern` a regex engine.
                    // Each is a validator the host does not have, so honouring the rest of the schema while
                    // ignoring it would be a partial check reported as a complete one.
                    return Err(bad(&format!("`{key}` is not supported in a payload schema")));
                }
            }

            // Numeric bounds must be literal numbers, so the validator never has to resolve anything.
            for key in ["maxLength", "minLength", "maximum", "minimum", "maxItems", "minItems"] {
                if let Some(value) = object.get(key)
                    && !value.is_number()
                {
                    return Err(bad(&format!("`{key}` must be a number")));
                }
            }

            // A string without a `maxLength` is a string whose length the host cannot bound, which makes it a
            // string the payload validator cannot promise anything about.
            if object.get("type").and_then(|value| value.as_str()) == Some("string")
                && !object.contains_key("maxLength")
            {
                return Err(bad("a string property must declare `maxLength`"));
            }

            for (key, value) in object {
                walk_schema(bad, value, depth + 1)?;
                let _ = key;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                walk_schema(bad, item, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
