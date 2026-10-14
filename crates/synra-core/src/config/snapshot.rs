use serde_json::Value;

/// The bag and the list, as the boundary carries them.
///
/// # Why this is a second type rather than the IPC one
///
/// `synra-ipc`'s `ConfigSnapshot` is the *wire* shape and carries serde attributes that belong to the wire — camelCase
/// field names, omitted empty lists. This is what the kernel computes, and the daemon maps one to the other. Sharing
/// one type would put the wire's serialisation decisions inside the kernel and make a protocol change a kernel change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    /// Every setting, defaults filled in, keyed by its dotted path.
    pub values: Value,
    /// Which keys came from an override rather than a default.
    pub overridden: Vec<String>,
}
