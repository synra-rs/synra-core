//! What the diagnostics screen shows about sessions.
/// What the diagnostics screen shows about sessions.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionReport {
    /// How many sessions are live.
    pub live: usize,
    /// How many have been issued since start-up.
    pub issued: u64,
    /// Which plugins hold one.
    pub plugins: Vec<String>,
    /// How many pages have reported themselves ready.
    pub ready: usize,
}
