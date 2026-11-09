use super::*;

/// What went wrong while routing, in the protocol's own terms.
///
/// # Why a code and not a variant per failure
///
/// Because every failure here is one a caller already has a code for: an identifier that is not one, a plugin that offered
/// nothing, an action that cannot run on this device. A bespoke enum would be a second vocabulary for the same facts, and
/// each host would translate it back into the codes below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteError {
    /// Which of the contract's codes this is.
    pub code: synra_protocol::ErrorCode,
    /// A sentence for a person, which is what a host shows.
    pub message: String,
}

impl RouteError {
    /// A failure with its code and a sentence.
    #[must_use]
    pub fn new(code: synra_protocol::ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RouteError {}

/// What a routing pass produced.
///
/// # ★ Why a struct rather than JSON
///
/// Because two hosts want different things from the same fact. The daemon renders it for a control-protocol client; the
/// desktop shell fills an `IntentSnapshot` whose fields (a device per candidate, whether it is online, when the intent
/// started) are **not in this shape at all** — so a shell handed JSON could not produce a faithful DTO and would have to
/// invent the missing fields. Typed values let each host ask for what it needs, and the JSON is one rendering among
/// possible others rather than the only way out of the library.
#[derive(Debug, Clone)]
pub struct Routed {
    /// Which intent this is, which a caller uses to answer it later.
    pub intent_id: synra_protocol::ids::IntentId,
    /// The trace this intent belongs to, for a log filter.
    pub trace: synra_protocol::ids::TraceId,
    /// Whether this call raised the intent, or found one already raised for the same request.
    pub created: bool,
    /// What stage it settled at.
    pub state: &'static str,
    /// What the plugins offered.
    pub candidates: Vec<CandidateView>,
    /// The pass's own account of itself.
    pub report: crate::dispatch::matching::MatchReport,
}

/// One way an intent could be handled.
#[derive(Debug, Clone)]
pub struct CandidateView {
    /// The plugin that answered.
    pub plugin_id: PluginId,
    /// The version that answered.
    pub plugin_version: String,
    /// What it proposes to do.
    pub action: String,
    /// Its arguments, as the plugin proposed them.
    pub args: serde_json::Value,
    /// One line for a prompt.
    pub title: String,
    /// Optional detail.
    pub detail: Option<String>,
    /// The capabilities the action needs.
    pub required_caps: Vec<String>,
    /// Where it suggested running, when it had an opinion.
    pub suggested_target: Option<DeviceId>,
}

/// What has become of an intent.
#[derive(Debug, Clone)]
pub struct IntentView {
    /// Which intent.
    pub intent_id: synra_protocol::ids::IntentId,
    /// Its trace.
    pub trace: synra_protocol::ids::TraceId,
    /// What stage it is at.
    pub state: &'static str,
    /// What the plugins offered.
    pub candidates: Vec<CandidateView>,
    /// When it was raised, in milliseconds since the epoch.
    ///
    /// ★ The snapshot used to report the moment it was **read** under this name. The board has carried the real value from
    /// the first version; not carrying it made "how long has this been running?" answer "zero", every time.
    pub created_at_ms: i64,
    /// Why it failed or was refused, when either happened.
    ///
    /// ★ The board has carried this since `IntentState::Failed` was written, and the view dropped it — so the interface's
    /// "why did it fail?" line read a field no host ever filled. A refusal carries the admission check's own sentence and
    /// code, which its type documents as "a sentence the interface can show".
    pub error: Option<synra_protocol::SynraError>,
}

/// The result of running the action a user chose.
#[derive(Debug, Clone)]
pub struct Decided {
    /// Which intent.
    pub intent_id: synra_protocol::ids::IntentId,
    /// The trace this action's steps are grouped under.
    ///
    /// ★ Carried so the log line that says what happened can be found by `synra logs --trace`: the routing line already
    /// names the trace, and a decision without it would be the one step a user cannot correlate.
    pub trace: synra_protocol::ids::TraceId,
    /// The envelope id a remote dispatch would be sent under.
    pub request_id: synra_protocol::ids::RequestId,
    /// Which plugin ran.
    pub plugin_id: PluginId,
    /// Which of its actions.
    pub action: String,
    /// Whether it succeeded.
    pub ok: bool,
    /// The returned JSON value, or null when no action succeeded.
    pub result: serde_json::Value,
    /// The complete failure reported by the plugin or its execution host.
    pub error: Option<synra_protocol::SynraError>,
    /// What stage the intent ended at.
    pub state: &'static str,
    /// The envelope a host must send, when the action runs on another device.
    ///
    /// ★ Why the library builds this and does not send it
    ///
    /// Because this crate has no transport and should not grow one — `worker`'s doc makes the same argument for storage
    /// ("this crate knows nothing about storage ... the caller owns the write"). Which link, and how, is the host's
    /// business; *what* to send is not, because the event name, the addressing and the payload shape have to be right and
    /// a host is not the only thing that will want to ask.
    ///
    /// ★ And why `ok` is then `false` rather than a third value
    ///
    /// Because there is no third value in the field. When this is `Some`, the intent is `dispatching`: nothing has run
    /// yet and its outcome arrives later as an `INTENT_RESULT`. A caller must branch on this field before reading `ok`,
    /// and [`Decided::is_dispatched`] is what says so without inspecting a string.
    pub outbound: Option<crate::intent::remote::Outbound>,
}

impl Decided {
    /// Whether the action was handed to another device rather than run here.
    ///
    /// A method rather than a comparison on `state`, because the state is a string for a JSON field and a caller that
    /// compared it to `"dispatching"` would be one keystroke from comparing it to nothing at all.
    #[must_use]
    pub const fn is_dispatched(&self) -> bool {
        self.outbound.is_some()
    }
}

/// An intent's state after a move that produces nothing else.
#[derive(Debug, Clone)]
pub struct StateChange {
    /// Which intent.
    pub intent_id: synra_protocol::ids::IntentId,
    /// What stage it is at now.
    pub state: &'static str,
    /// The envelope a host must send, when the intent had been dispatched to another device.
    ///
    /// Cancelling locally is not enough for a dispatched intent: the device that is running it has no other way to hear
    /// that the user changed their mind, and it would finish and report a result for work nobody wants.
    pub outbound: Option<crate::intent::remote::Outbound>,
}

impl CandidateView {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pluginId": self.plugin_id.as_str(),
            "pluginVersion": self.plugin_version,
            "action": self.action,
            // The plugin's own arguments, so a client can show what would be acted on — the URL a link candidate
            // would open, rather than only the sentence describing it.
            "args": self.args,
            "title": self.title,
            "detail": self.detail,
            "requiredCaps": self.required_caps,
        })
    }
}

impl Routed {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "trace": self.trace.to_string(),
            // `false` means the same request had already raised an intent. Reported rather than hidden: a caller
            // retrying after a lost answer needs to know it did not create a second one.
            "created": self.created,
            "state": self.state,
            "candidates": self.candidates.iter().map(CandidateView::to_json).collect::<Vec<_>>(),
            // ★ The pass's own report, which is what separates "nothing is installed" from "everything
            // crashed". The two look identical from a candidate list, and a user cannot tell them apart.
            "asked": self.report.asked,
            "handled": self.report.handled,
            "declined": self.report.declined,
            "offered": self.report.offered,
            "misbehaved": self.report.misbehaved.iter().map(|misbehaviour| {
                serde_json::json!({
                    "pluginId": misbehaviour.plugin_id.as_str(),
                    "detail": misbehaviour.detail,
                })
            }).collect::<Vec<_>>(),
        })
    }
}

impl IntentView {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "trace": self.trace.to_string(),
            "state": self.state,
            "createdAtMs": self.created_at_ms,
            "candidates": self.candidates.iter().map(CandidateView::to_json).collect::<Vec<_>>(),
            // `null` when there is none: a client that branches on the field has one shape to read, and `null` is the
            // answer to "why did it fail?" for an intent that has not.
            "error": self.error.as_ref().and_then(|error| serde_json::to_value(error).ok()),
        })
    }
}

impl Decided {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "trace": self.trace.to_string(),
            "requestId": self.request_id.to_string(),
            "pluginId": self.plugin_id.as_str(),
            "action": self.action,
            "ok": self.ok,
            "result": self.result,
            "error": self.error,
            "state": self.state,
            // ★ Present only when the action was handed to another device.
            //
            // Without it, `"ok": false` on a dispatched intent reads as "it did not work" — and it did not *not* work, it
            // has not happened yet. The field is the qualification, and it is emitted next to `ok` rather than instead of
            // it so a client that only knows the old shape still reads a state it can act on.
            "dispatchedTo": self.outbound.as_ref().map(|outbound| outbound.to.to_string()),
        })
    }
}

impl StateChange {
    /// The shape the control protocol carries.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "intent": self.intent_id.to_string(),
            "state": self.state,
            // ★ Present only when the intent had been dispatched and the far side is being told to stop.
            //
            // Emitted for the same reason `Decided` emits it: a client that saw only `"state": "cancelled"` would think the
            // work had stopped, when what has happened is that this side has stopped tracking it and a message is on its
            // way. The device that is running it has not been un-asked yet.
            "cancelledAt": self.outbound.as_ref().map(|outbound| outbound.to.to_string()),
        })
    }
}
