/// One device, as a row.
pub(super) fn render_device(value: &serde_json::Value) -> String {
    let id = value
        .get("deviceId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let name = value
        .get("displayName")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let online = value
        .get("online")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let paired = value
        .get("paired")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    format!(
        "{id}  {name}  {}",
        match (paired, online) {
            (true, true) => "paired, online",
            (true, false) => "paired, offline",
            (false, true) => "not paired",
            (false, false) => "not paired, offline",
        }
    )
}

/// The devices report, as a person reads it.
///
/// # Why this device is printed first
///
/// Because it is the answer to the question a user has when the list is empty: *which device am I even on?* That
/// identifier is what every peer has recorded against them, and reading it out is how a pairing problem is diagnosed.
/// A list that showed only the other devices would leave the one fact the user can act on unsaid.
///
/// # Why an empty list says which kind of empty it is
///
/// Because "nothing is paired" and "nothing was found" are different situations with different next steps — one needs a
/// pairing, the other needs the other device to be switched on. A single "no devices" would leave the user to guess.
pub(super) fn render_devices(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();

    if let Some(this) = value.get("self") {
        let name = this
            .get("displayName")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        let id = this
            .get("deviceId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        let platform = this
            .get("platform")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        out.push(format!("this device  {name} ({platform})"));
        out.push(format!("  {id}"));
    }

    let empty = |list: Option<&Vec<serde_json::Value>>| list.is_none_or(Vec::is_empty);
    let paired = value.get("paired").and_then(serde_json::Value::as_array);
    if empty(paired) {
        out.push("paired       none".to_owned());
    } else {
        out.push("paired".to_owned());
        for row in paired.into_iter().flatten() {
            let name = row
                .get("displayName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let id = row
                .get("deviceId")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            // The session state is what separates "recorded once" from "reachable now", and a user deciding what to do
            // needs the second. Absent means there is no session at all, which is a third thing.
            let state = row
                .get("linkState")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("no session");
            let blocked = row
                .get("blocked")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let suffix = if blocked { ", blocked" } else { "" };
            out.push(format!("  {name}  {state}{suffix}"));
            out.push(format!("    {id}"));
        }
    }

    // ★ Only present when the caller asked for it. A report that always printed this section would make a user who did
    // not ask wonder what the unapproved devices are doing in their list.
    if value
        .get("includeUnpaired")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        let found = value.get("found").and_then(serde_json::Value::as_array);
        if empty(found) {
            out.push("found        none on this network".to_owned());
        } else {
            out.push("found on this network".to_owned());
            for row in found.into_iter().flatten() {
                let name = row
                    .get("displayName")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let address = row
                    .get("address")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let trust = row
                    .get("trust")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                out.push(format!("  {name}  {address}  {trust}"));
            }
        }
    }

    out
}
