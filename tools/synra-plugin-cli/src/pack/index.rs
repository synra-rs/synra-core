//! Merges packed versions into the static registry index.

/// Adds one version to a static index, keeping the versions it already lists.
///
/// # Errors
///
/// A sentence when the existing document is not JSON or is not the index shape. Overwriting a file this tool cannot read
/// would lose every version it did not write.
pub(super) fn merge_index(
    existing: Option<&str>,
    name: &str,
    version: &str,
    tarball: &str,
    manifest: &serde_json::Value,
    publisher: Option<(&str, &str)>,
) -> Result<String, String> {
    let mut document = match existing {
        Some(text) => serde_json::from_str::<serde_json::Value>(text)
            .map_err(|error| format!("the index is not JSON: {error}"))?,
        None => serde_json::json!({ "name": name, "versions": [], "publishers": {} }),
    };
    let Some(object) = document.as_object_mut() else {
        return Err("the index is not a JSON object".to_owned());
    };
    object.insert("name".to_owned(), serde_json::json!(name));
    object.insert("latest".to_owned(), serde_json::json!(version));

    let mut publishers = object
        .remove("publishers")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    if let Some((id, fingerprint)) = publisher {
        publishers.insert(id.to_owned(), serde_json::json!(fingerprint));
    }
    object.insert("publishers".to_owned(), serde_json::Value::Object(publishers));

    let mut versions = object
        .remove("versions")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let entry = serde_json::json!({
        "version": version,
        "tarball": tarball,
        "manifest": manifest,
    });
    match versions
        .iter()
        .position(|listed| listed.get("version").and_then(serde_json::Value::as_str) == Some(version))
    {
        // Re-packing a version replaces its entry rather than listing it twice: the parser refuses duplicates, and a
        // second tarball for one version is not a history.
        Some(index) => {
            if let Some(slot) = versions.get_mut(index) {
                *slot = entry;
            }
        }
        None => versions.push(entry),
    }
    object.insert("versions".to_owned(), serde_json::Value::Array(versions));

    serde_json::to_string_pretty(&document).map_err(|error| format!("the index could not be written: {error}"))
}
