use synra_control::Response;

use super::devices::{render_device, render_devices};
use super::{Shape, plugin_updates, publishers};

/// Turns a kernel's response into output.
///
/// # Why a refusal is not a transport error
///
/// A refusal is the kernel answering: it is a result, and a script reads its code. A transport error is the absence of
/// an answer, and a script reads the exit code. Collapsing them would make "the device is offline" indistinguishable
/// from "no kernel is running", which are the two things a user most needs to tell apart.
#[must_use]
pub fn outcome_of(response: &Response, shape: Shape) -> crate::session::CommandOutcome {
    use crate::session::CommandOutcome;

    match response {
        Response::Ok { value }
            if value
                .get("failures")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|failures| !failures.is_empty()) =>
        {
            CommandOutcome::json_failure(pretty(value))
        }
        Response::Ok { value } => match shape {
            Shape::Json => CommandOutcome::json(pretty(value)),
            Shape::Prose => CommandOutcome::Lines(prose(value)),
        },
        Response::Failed { code, message, .. } => {
            // The same shape for both output modes, so a caller that asked for JSON gets JSON *and* a non-zero exit
            // code rather than having to tell prose from JSON to know which happened.
            CommandOutcome::json_failure(
                serde_json::json!({ "code": code, "message": message }).to_string(),
            )
        }
        Response::Hello { version, kernel } => {
            CommandOutcome::Lines(vec![format!("kernel {kernel}, protocol {version}")])
        }
        // ★ `non_exhaustive` means an arm for a shape this build does not know is required even in the crate that
        // declares it — and that requirement is the point: a response the kernel gained is one a client must decide
        // about rather than one that falls through to nothing. Here the decision is to print it, because a client older
        // than its kernel must still show the answer rather than an empty screen.
        other => CommandOutcome::Lines(vec![format!("{other:?}")]),
    }
}

/// The JSON a script reads.
fn pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// A short summary for a person.
///
/// # Why this falls back to JSON
///
/// A build of the client that does not know a command's shape must still print the answer rather than nothing. The
/// fallback is the JSON, which is ugly and complete — and complete is what a user filing a bug report needs.
fn prose(value: &serde_json::Value) -> Vec<String> {
    if let Some(lines) = publishers::render(value) {
        return lines;
    }
    if let Some(lines) = plugin_updates::render(value) {
        return lines;
    }
    // ★ The removal's report, as a sentence: it is the one answer whose point is what happened to the user's data, and a
    // JSON blob would make them read a field name to learn whether their settings were deleted.
    if let Some(bytes) = value.get("bytesFreed").and_then(serde_json::Value::as_u64) {
        let id = value
            .get("pluginId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        let kept = value
            .get("dataKept")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let mut sentence = format!(
            "removed {id}; {bytes} bytes freed; {}",
            if kept {
                "its data was kept"
            } else {
                "its data was deleted"
            }
        );
        // ★ Files the operating system would not let go are part of the answer. A loaded engine keeps its wasm file open
        // on Windows; the plugin is gone from the list, and a user who is not told which path survived goes looking.
        let leftovers: Vec<&str> = value
            .get("leftovers")
            .and_then(serde_json::Value::as_array)
            .map(|paths| paths.iter().filter_map(serde_json::Value::as_str).collect())
            .unwrap_or_default();
        if !leftovers.is_empty() {
            sentence.push_str(&format!("; could not remove {}", leftovers.join(", ")));
        }
        return vec![sentence];
    }
    if let Some(lines) = value.get("lines").and_then(serde_json::Value::as_array) {
        let mut rendered: Vec<String> = lines.iter().map(render_line).collect();
        // ★ A log that is behind must not look like a quiet kernel. Both numbers are zero in the ordinary case, so the
        // sentence appears only when the writer had to choose between blocking the product and losing a line.
        let dropped = value
            .get("dropped")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let errors = value
            .get("writeErrors")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if dropped > 0 || errors > 0 {
            let mut sentence = format!(
                "the logger dropped {dropped} line(s) and could not write {errors} on its way to the file"
            );
            // ★ The failure's own words, when the daemon kept them. A count tells the user something is wrong; this tells
            // them whether to free space, restore a directory, or look at permissions.
            if let Some(detail) = value
                .get("lastWriteError")
                .and_then(serde_json::Value::as_str)
            {
                sentence.push_str(&format!("; the last failure was: {detail}"));
            }
            rendered.push(sentence);
        }
        return rendered;
    }
    if let Some(plugins) = value.get("plugins").and_then(serde_json::Value::as_array) {
        if plugins.is_empty() {
            return vec!["no plugins are installed".to_owned()];
        }
        return plugins.iter().map(render_plugin).collect();
    }
    // ★ The devices report has three sources, and the renderer keeps them apart for the same reason the kernel does: a
    // paired device is one the user decided about, and a device merely heard on the network is an unauthenticated
    // datagram. A list that merged them would present the second as the first.
    if value.get("paired").is_some() && value.get("found").is_some() {
        return render_devices(value);
    }
    if let Some(state) = value.get("state").and_then(serde_json::Value::as_str) {
        let mut out = vec![format!("kernel {state}")];
        if let Some(version) = value.get("version").and_then(serde_json::Value::as_str) {
            out.push(format!("  version      {version}"));
        }
        if let Some(dir) = value.get("dataDir").and_then(serde_json::Value::as_str) {
            out.push(format!("  data         {dir}"));
        }
        if let Some(ports) = value
            .get("transportPort")
            .and_then(serde_json::Value::as_u64)
        {
            out.push(format!("  transport    {ports}"));
        }
        if let Some(uptime) = value.get("uptimeMs").and_then(serde_json::Value::as_u64) {
            out.push(format!("  uptime       {}s", uptime / 1_000));
        }
        // The schema version against what this build understands, because the two disagreeing is the one database
        // problem a user can see coming rather than discover.
        if let Some(schema) = value
            .get("schemaVersion")
            .and_then(serde_json::Value::as_u64)
        {
            let known = value
                .get("schemaKnown")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            out.push(format!(
                "  schema       {schema} (this build knows {known})"
            ));
        }
        // ★ The missing layers are printed, because `status` is the command a user runs to find out what is going on
        // and a summary that hid them would leave them wondering why the next command refuses.
        if let Some(missing) = value
            .get("notImplemented")
            .and_then(serde_json::Value::as_array)
        {
            let names: Vec<&str> = missing
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect();
            if !names.is_empty() {
                out.push(format!("  not built    {}", names.join(", ")));
            }
        }
        return out;
    }
    if let Some(devices) = value.get("devices").and_then(serde_json::Value::as_array) {
        if devices.is_empty() {
            return vec!["no devices".to_owned()];
        }
        return devices.iter().map(render_device).collect();
    }
    vec![pretty(value)]
}

/// One log line, as it is.
fn render_line(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| pretty(value), ToOwned::to_owned)
}

/// One plugin, as a row.
fn render_plugin(value: &serde_json::Value) -> String {
    let id = value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    if let Some(problem) = value.get("problem").and_then(serde_json::Value::as_str) {
        return format!("{id}  ({problem})");
    }
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let title = value
        .get("title")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    format!("{id}  {version}  {title}")
}

#[cfg(test)]
mod tests;
