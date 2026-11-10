use super::Runtime;

impl Runtime {
    /// The counters, as the recorder's own snapshot.
    ///
    /// # Why this serialises rather than shapes
    ///
    /// Because the recorder's snapshot already derives serialization, so the daemon reports the exact series shape its
    /// metrics recorder produces without maintaining a second representation.
    pub(super) fn metrics_value(&self) -> serde_json::Value {
        serde_json::to_value(self.metrics.snapshot()).unwrap_or(serde_json::Value::Null)
    }
}
