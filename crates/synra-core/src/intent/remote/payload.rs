use super::*;
use crate::intent::IntentState;

/// What a device is asked to run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Invoke {
    /// The plugin that offered to handle it.
    pub plugin_id: PluginId,
    /// The version that offered, so the far side can refuse a mismatch rather than run a different build's action.
    pub plugin_version: String,
    /// What it proposed to do.
    pub action: String,
    /// Its own arguments, as the plugin proposed them.
    ///
    /// Carried rather than recomputed: a `can-handle` that proposed opening a particular URL is the whole of what the
    /// user chose, and a receiver that re-derived it from the share would be guessing at what the sender was shown.
    pub args: serde_json::Value,
}

/// What the device that ran it reports back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvokeResult {
    /// The action succeeded. JSON remains JSON rather than being embedded in another string.
    Succeeded {
        /// The returned value.
        result: serde_json::Value,
        /// Execution time on the device that ran it.
        #[serde(rename = "elapsedMs")]
        elapsed_ms: u64,
    },
    /// The action failed with its complete error, including diagnostics and trace.
    Failed {
        /// The structured failure.
        error: SynraError,
        /// Execution time on the device that ran it.
        #[serde(rename = "elapsedMs")]
        elapsed_ms: u64,
    },
}

impl InvokeResult {
    /// Whether execution succeeded, for result counters and diagnostics.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Succeeded { .. })
    }

    /// Build the wire result from execution, parsing a successful JSON payload once.
    #[must_use]
    pub fn from_execution(outcome: Result<String, SynraError>, elapsed_ms: u64) -> Self {
        match outcome {
            Ok(payload) => Self::Succeeded {
                result: serde_json::from_str(&payload)
                    .unwrap_or(serde_json::Value::String(payload)),
                elapsed_ms,
            },
            Err(error) => Self::Failed { error, elapsed_ms },
        }
    }

    /// Extract the typed result for the intent board without serializing JSON again.
    pub fn into_outcome(self) -> (Result<serde_json::Value, SynraError>, u64) {
        match self {
            Self::Succeeded { result, elapsed_ms } => (Ok(result), elapsed_ms),
            Self::Failed { error, elapsed_ms } => (Err(error), elapsed_ms),
        }
    }

    /// Build a reply from the authoritative concluded state; other states have no execution result.
    #[must_use]
    pub fn from_state(state: IntentState) -> Option<Self> {
        match state {
            IntentState::Succeeded { result, elapsed_ms } => {
                Some(Self::Succeeded { result, elapsed_ms })
            }
            IntentState::Failed { error, elapsed_ms } => Some(Self::Failed { error, elapsed_ms }),
            _ => None,
        }
    }

    /// Fields used by the local decision view and host response adapter.
    #[must_use]
    pub fn into_parts(self) -> (bool, serde_json::Value, Option<SynraError>, u64) {
        let (outcome, elapsed_ms) = self.into_outcome();
        match outcome {
            Ok(result) => (true, result, None, elapsed_ms),
            Err(error) => (false, serde_json::Value::Null, Some(error), elapsed_ms),
        }
    }
}

/// Tells a device to stop running something it was asked to run.
///
/// # ★ Why this carries only a reason
///
/// Because the request identifier in the envelope is what names the work — "the device must be idempotent by request
/// identifier" applies to a withdrawal exactly as it does to an invocation. A payload that named the plugin and action
/// again would be a second description of the same request, and the two could disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cancel {
    /// Why, in the words of whoever withdrew it.
    pub reason: String,
}

/// The envelope a host must send to withdraw a dispatched action.
///
/// # Errors
///
/// As [`invoke`].
pub fn cancel(
    from: DeviceId,
    to: DeviceId,
    payload: &Cancel,
    request_id: RequestId,
    trace_id: TraceId,
    sent_at_ms: i64,
) -> Result<Envelope, MessageError> {
    let mut envelope = build(
        events::INTENT_CANCEL,
        from,
        to,
        payload,
        trace_id,
        sent_at_ms,
    )?;
    // ★ The identifier of the request being withdrawn, **not** a new one.
    //
    // This is the whole of how the far side knows what to stop: it raised the work under the invocation's identifier and
    // looks it up by exactly this value. A fresh identifier would name a request nobody made, the lookup would find
    // nothing, and the withdrawal would be reported as delivered while the other device carried on — which is what the
    // first version did, and what the test that withdrew from another device caught. It is a parameter rather than
    // something minted here so that a caller cannot get it wrong by omission.
    envelope.request_id = request_id;
    Ok(envelope)
}

/// Reads why a dispatched action was withdrawn.
///
/// # Errors
///
/// As [`invoke_from`].
pub fn cancel_from(envelope: &Envelope) -> Result<Cancel, MessageError> {
    read(envelope, "an intent cancellation")
}

/// The envelope a host must send so an action runs somewhere else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outbound {
    /// Which device it is for.
    pub to: DeviceId,
    /// The envelope identifier, which is also the intent's request identifier.
    ///
    /// The same value, deliberately: the request identifier is what makes a resend idempotent, and a second identifier
    /// for the same message would be a second thing for the two sides to disagree about.
    pub request_id: RequestId,
    /// What to put on the link.
    pub envelope: Envelope,
}
