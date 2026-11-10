use serde::{Deserialize, Serialize};
use synra_capability::{Capability, Domain};
use synra_protocol::PluginId;
use synra_protocol::ids::TraceId;

/// How a gated call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum AuditOutcome {
    /// The capability was held and the call proceeded.
    Allowed,
    /// No granted capability covered the call.
    Denied,
    /// The plugin exceeded its quota.
    QuotaExceeded,
    /// The plugin called faster than its rate limit allows.
    RateLimited,
    /// The call proceeded, but the operation itself failed.
    Failed,
}

impl AuditOutcome {
    /// Whether the call was permitted.
    #[must_use]
    pub const fn was_allowed(self) -> bool {
        matches!(self, Self::Allowed | Self::Failed)
    }

    /// Whether this outcome is a refusal by the capability system rather than by the operation.
    ///
    /// The distinction drives how the interface sorts the list: refusals go to the top, because they are the
    /// entries a user is looking for.
    #[must_use]
    pub const fn is_refusal(self) -> bool {
        matches!(self, Self::Denied | Self::QuotaExceeded | Self::RateLimited)
    }

    /// The name used in the interface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::QuotaExceeded => "quota-exceeded",
            Self::RateLimited => "rate-limited",
            Self::Failed => "failed",
        }
    }

    /// The outcome a stored name refers to, when this build knows the name.
    ///
    /// # Why this lives beside `as_str`
    ///
    /// `plugin_audit.outcome` stores exactly [`AuditOutcome::as_str`], so a reader of the table has to turn that name back
    /// into an outcome to answer "was it allowed". A parser in the reader would be a second table of spellings, and the
    /// drift would show up as a row drawn with the wrong colour rather than as a compile error.
    ///
    /// An unknown name is `None` and not a guess: the caller reports the name it read, because a row whose outcome came
    /// from a newer build must not be presented as "allowed".
    #[must_use]
    pub fn from_stable_name(name: &str) -> Option<Self> {
        Some(match name {
            "allowed" => Self::Allowed,
            "denied" => Self::Denied,
            "quota-exceeded" => Self::QuotaExceeded,
            "rate-limited" => Self::RateLimited,
            "failed" => Self::Failed,
            _ => return None,
        })
    }

    /// The icon the settings screen shows.
    #[must_use]
    pub const fn marker(self) -> &'static str {
        match self {
            Self::Allowed => "ok",
            Self::Failed => "warn",
            Self::Denied | Self::QuotaExceeded | Self::RateLimited => "blocked",
        }
    }
}

/// One gated call.
///
/// See the module docs for the deliberate absence of any content field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    /// When it happened, in milliseconds since the epoch.
    pub at_ms: i64,
    /// Which plugin made the call.
    pub plugin: PluginId,
    /// The capability it was checked against.
    pub capability: Capability,
    /// How it ended.
    pub outcome: AuditOutcome,
    /// How long the call took, when it ran.
    pub elapsed_ms: Option<u64>,
    /// The trace of the action that caused the call, when there was one.
    ///
    /// # Why this is filled in by the drain rather than by the gate
    ///
    /// Because the gate runs inside the guest's call and knows which capability was checked, not which user action the
    /// call belongs to. `PluginSet::call_traced` knows both — it is the funnel every audited call goes through — and it
    /// stamps the entries when it drains them. A call with no action behind it (`can-handle` during matching, a lifecycle
    /// tick) has no trace, and `None` says so rather than inventing one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trace: Option<TraceId>,
}

impl AuditEntry {
    /// Records a call.
    #[must_use]
    pub const fn new(
        at_ms: i64,
        plugin: PluginId,
        capability: Capability,
        outcome: AuditOutcome,
        elapsed_ms: Option<u64>,
    ) -> Self {
        Self { at_ms, plugin, capability, outcome, elapsed_ms, trace: None }
    }

    /// The domain the capability belongs to, for grouping in the interface.
    #[must_use]
    pub const fn domain(&self) -> Domain {
        self.capability.domain()
    }

    /// The destination, as much of it as is safe to show.
    ///
    /// The capability's qualifier is the host, the path or the device — the part that says *where* something
    /// happened, which is the part a user is asking about. It is safe for the same reason the record is: a
    /// capability describes destinations, never contents.
    #[must_use]
    pub fn destination(&self) -> Option<&str> {
        self.capability.qualifier().first().map(synra_capability::Segment::as_str)
    }

    /// A one-line rendering, matching what the settings screen shows.
    #[must_use]
    pub fn render(&self) -> String {
        let destination = self
            .destination()
            .map(|place| format!(" -> {place}"))
            .unwrap_or_default();
        let elapsed = self
            .elapsed_ms
            .map(|ms| format!("  {ms}ms"))
            .unwrap_or_default();
        format!(
            "{:>6} {} {}{}{}",
            self.outcome.marker(),
            self.capability.prefixes().first().map_or("", synra_capability::Segment::as_str),
            self.capability.domain(),
            destination,
            elapsed
        )
    }
}
