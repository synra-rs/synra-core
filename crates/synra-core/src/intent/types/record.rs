use super::*;

/// An intent, with everything known about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// Identifies it for its whole life, and travels with the dispatch.
    pub id: IntentId,
    /// Follows it across devices and into logs.
    pub trace: TraceId,
    /// What asked for it.
    pub source: IntentSource,
    /// Where it is.
    pub state: IntentState,
    /// How much attention it may need.
    pub choice: Choice,
    /// When it was raised, in signed milliseconds since the epoch.
    pub created_at_ms: i64,
    /// The envelope id a dispatch carries, once there is one.
    pub request_id: Option<RequestId>,
    /// Which device it came from, when it came over a link.
    ///
    /// Part of the idempotency key: two devices may both pick the same identifier, and the same device may send the
    /// same request twice because its answer was lost.
    pub origin: Option<DeviceId>,
}

impl Intent {
    /// Whether this intent's action is the same one another request names.
    ///
    /// # Why the whole triple and not the request id alone
    ///
    /// A request id is chosen by the sender, and two senders choose independently: the same id from two devices is two
    /// requests. Comparing all three is what makes "have I already done this?" a question with an answer.
    #[must_use]
    pub fn is_same_request_as(&self, origin: DeviceId, request: RequestId) -> bool {
        self.origin == Some(origin) && self.request_id == Some(request)
    }
}
