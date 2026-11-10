/// The one clock: milliseconds since the epoch, as the store reads it.
///
/// Read from `std` rather than from the budget, because the audit entry and a device's `last_seen_ms` have to be
/// comparable — two clocks would make a plugin's call appear to have happened before the device it addressed.
pub(crate) fn clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

/// A JSON array of strings.
///
/// Written by hand rather than through `serde_json`, because the values are already strings the host produced and the
/// only transformation is escaping — and a `serde_json::Value` round trip for a list of names would be a parse of
/// something that was never text.
pub(crate) fn json_array(values: &[String]) -> String {
    let body: Vec<String> = values.iter().map(|value| json_string(value)).collect();
    format!("[{}]", body.join(","))
}

/// A JSON string, escaped.
pub(crate) fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", other as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// The device list, as the JSON the contract's `list<device-target>` becomes.
pub(crate) fn json_devices(devices: &[(String, String, String)]) -> String {
    let body: Vec<String> = devices
        .iter()
        .map(|(id, name, kind)| {
            format!(
                "{{\"id\":{},\"name\":{},\"kind\":{}}}",
                json_string(id),
                json_string(name),
                json_string(kind)
            )
        })
        .collect();
    format!("[{}]", body.join(","))
}
