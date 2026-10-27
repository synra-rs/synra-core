//! Bounded, reusable validation of declared event payloads without external schema resolution.

use serde_json::Value;

/// Maximum encoded event payload or schema size.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum nesting in a schema or payload.
pub const MAX_DEPTH: usize = 16;
/// Maximum schema nodes inspected before compilation.
pub const MAX_SCHEMA_NODES: usize = 1024;
/// Maximum payload nodes inspected before validation.
pub const MAX_PAYLOAD_NODES: usize = 4096;

/// A schema or payload could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// The schema cannot be enforced by this host.
    #[error("{0}")]
    Unusable(String),
    /// Data exceeds the bounded validator's size or complexity limit.
    #[error("the event schema or payload exceeds its size or complexity limit")]
    TooLarge,
    /// The payload does not satisfy the declared schema. Its values are never echoed.
    #[error("the event payload does not match its schema at {path}")]
    Invalid {
        /// JSON pointer to the invalid field.
        path: String,
    },
}

/// An immutable schema compiled once and reused for event delivery.
pub struct PayloadSchema {
    validator: jsonschema::Validator,
}

impl PayloadSchema {
    /// Compile a bounded object schema using JSON Schema draft 2020-12.
    ///
    /// # Errors
    /// External references, patterns, formats, unbounded string schemas and invalid schemas are refused.
    pub fn compile(schema: &Value) -> Result<Self, PayloadError> {
        let object = schema
            .as_object()
            .ok_or_else(|| unusable("a payload schema must be a JSON object"))?;
        match object.get("type").and_then(Value::as_str) {
            Some("object") => {}
            Some(_) => return Err(unusable("a payload schema must have type `object`")),
            None if object.contains_key("properties") => {
                return Err(unusable(
                    "a payload schema with `properties` must also say `type: object`",
                ));
            }
            None => return Err(unusable("a payload schema must say `type: object`")),
        }
        let mut nodes = 0;
        check_schema(schema, 0, &mut nodes)?;
        check_schema_rules(schema)?;
        check_encoded_size(schema)?;
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(schema)
            .map_err(|error| unusable(&error.to_string()))?;
        Ok(Self { validator })
    }

    /// Validate a payload without copying its values into an error message.
    ///
    /// # Errors
    /// Oversized, overly complex or schema-invalid payloads are refused.
    pub fn validate(&self, value: &Value) -> Result<(), PayloadError> {
        check_budget(value)?;
        self.validator
            .validate(value)
            .map_err(|error| PayloadError::Invalid {
                path: error.instance_path().to_string(),
            })
    }
}

/// Check event complexity and serialized byte limits even when no payload schema was declared.
///
/// # Errors
/// Data exceeding an event budget is refused before delivery or schema validation.
pub fn check_budget(value: &Value) -> Result<(), PayloadError> {
    let mut nodes = 0;
    check_value(value, 0, &mut nodes)?;
    check_encoded_size(value)
}

fn unusable(message: &str) -> PayloadError {
    PayloadError::Unusable(message.to_owned())
}

/// Count serialized bytes into a bounded sink instead of allocating another copy of the JSON.
fn check_encoded_size(value: &Value) -> Result<(), PayloadError> {
    struct Limit(usize);
    impl std::io::Write for Limit {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.saturating_add(bytes.len()) > MAX_PAYLOAD_BYTES {
                return Err(std::io::Error::other("event JSON exceeds its byte budget"));
            }
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(&mut Limit(0), value).map_err(|_| PayloadError::TooLarge)
}

fn check_schema(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), PayloadError> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_SCHEMA_NODES {
        return Err(PayloadError::TooLarge);
    }
    match value {
        Value::Object(object) => {
            for nested in object.values() {
                check_schema(nested, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            for nested in array {
                check_schema(nested, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.len() > MAX_PAYLOAD_BYTES => {
            return Err(PayloadError::TooLarge);
        }
        _ => {}
    }
    Ok(())
}

// Only schema positions interpret keywords. Property names, const, enum and annotations are data.
fn check_schema_rules(schema: &Value) -> Result<(), PayloadError> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    for key in [
        "$ref",
        "$dynamicRef",
        "$recursiveRef",
        "format",
        "pattern",
        "patternProperties",
        "unevaluatedProperties",
    ] {
        if object.contains_key(key) {
            return Err(unusable(&format!(
                "`{key}` is not supported in a payload schema"
            )));
        }
    }
    for key in [
        "maxLength",
        "minLength",
        "maximum",
        "minimum",
        "maxItems",
        "minItems",
    ] {
        if object.get(key).is_some_and(|value| !value.is_number()) {
            return Err(unusable(&format!("`{key}` must be a number")));
        }
    }
    let string_type = object.get("type").is_some_and(|value| {
        value.as_str() == Some("string")
            || value
                .as_array()
                .is_some_and(|types| types.iter().any(|value| value.as_str() == Some("string")))
    });
    if string_type && !object.contains_key("maxLength") {
        return Err(unusable("a string property must declare `maxLength`"));
    }
    for key in ["properties", "$defs", "definitions", "dependentSchemas"] {
        if let Some(map) = object.get(key).and_then(Value::as_object) {
            for value in map.values() {
                check_schema_rules(value)?;
            }
        }
    }
    for key in [
        "items",
        "contains",
        "additionalProperties",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "contentSchema",
        "unevaluatedItems",
    ] {
        if let Some(value) = object.get(key) {
            check_schema_rules(value)?;
        }
    }
    for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(array) = object.get(key).and_then(Value::as_array) {
            for value in array {
                check_schema_rules(value)?;
            }
        }
    }
    Ok(())
}

fn check_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), PayloadError> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_PAYLOAD_NODES {
        return Err(PayloadError::TooLarge);
    }
    match value {
        Value::Object(object) => {
            if object.len() > 128 {
                return Err(PayloadError::TooLarge);
            }
            for (key, nested) in object {
                if key.len() > MAX_PAYLOAD_BYTES {
                    return Err(PayloadError::TooLarge);
                }
                check_value(nested, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            if array.len() > 256 {
                return Err(PayloadError::TooLarge);
            }
            for nested in array {
                check_value(nested, depth + 1, nodes)?;
            }
        }
        Value::String(text) if text.len() > MAX_PAYLOAD_BYTES => {
            return Err(PayloadError::TooLarge);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests;
