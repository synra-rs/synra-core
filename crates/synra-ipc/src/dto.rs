//! The shapes that cross the interface.
//!
//! # A picture, not the kernel
//!
//! Every type here is plain data: no handles, no connections, no plugin instances, and no identifiers that mean
//! anything to the kernel. The interface holds a *picture* of what the kernel currently believes, and asks for a
//! new one when it needs it. That is what the design document means by "the interface does not hold connections,
//! plugin instances, or protocol details" — and it is why nothing here is a reference.
//!
//! # Why `snake_case` matters less than it looks
//!
//! The wire protocol uses `snake_case` for enum variants and `camelCase` for fields, and the interface boundary
//! follows the same split. It looks like a detail until a field named in the wrong case arrives as `undefined`,
//! which is the failure mode that produces "the plugin list is empty" with no error anywhere.
//!
//! # Snapshots and deltas
//!
//! A list is a snapshot: the interface asks once and then consumes events. That is deliberate — polling a list
//! is how an interface ends up with a different view of the world than the kernel, and the mismatch shows up as
//! a device the user can see but cannot send to.
//!
//! So each snapshot type carries everything the screen needs in one value, and the events ([`crate::command`]'s
//! neighbours in the kernel) carry what changed. The sequence number is what lets the interface notice it missed
//! one and ask for a fresh snapshot rather than drifting.

use serde::{Deserialize, Serialize};

use synra_protocol::{DeviceId, IntentId, PluginId, TransferId};

// ─────────────────────────────────────────────────────────────────────────────
// Identity
// ─────────────────────────────────────────────────────────────────────────────

/// This device, as the interface shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySnapshot {
    /// This device's identifier.
    pub device_id: DeviceId,
    /// The name other devices see.
    pub display_name: String,
    /// The platform, for an icon.
    pub platform: String,
    /// The kernel's version, for a diagnostic report.
    pub kernel_version: String,
    /// Whether the name was chosen by the user or generated.
    ///
    /// Reported because a generated name is one the user may want to change, and the interface uses it to decide
    /// whether to prompt.
    pub name_is_default: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Devices
// ─────────────────────────────────────────────────────────────────────────────

/// One device, as a card in the list.
///
/// Not `Eq`, because an in-flight transfer's progress is a fraction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCard {
    /// The device.
    pub device_id: DeviceId,
    /// The name it announced.
    pub display_name: String,
    /// Its platform.
    pub platform: String,
    /// Whether a link is open.
    pub online: bool,
    /// Whether it is paired, as opposed to merely seen.
    ///
    /// Separate from `online` because they answer different questions: a paired device that is offline is one the
    /// user can send to later, and an unpaired device that is online is one they have to pair with first.
    pub paired: bool,
    /// Whether the user has blocked it.
    pub blocked: bool,
    /// When it was last seen, in milliseconds since the epoch.
    pub last_seen_ms: i64,
    /// The address it was last reachable at, if it is not paired.
    ///
    /// Shown only for an unpaired device, because an address is how a user recognises a machine they have not
    /// paired with yet — and is noise for one they have.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// How far a transfer to it has progressed, when one is in flight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer: Option<TransferSummary>,
}

/// What the devices screen shows.
///
/// Not `Eq`, because a card may carry an in-flight transfer's progress.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesSnapshot {
    /// This device, so the screen does not need a second call.
    pub identity: IdentitySnapshot,
    /// Every device, paired ones first.
    pub devices: Vec<DeviceCard>,
    /// The scan in progress, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanning: Option<ScanState>,
}

/// Where a discovery scan has got to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanState {
    /// The scan.
    pub scan_id: String,
    /// How long it has been running, in milliseconds.
    pub elapsed_ms: u64,
    /// How long it will run for in total, so the interface can show progress.
    pub total_ms: u64,
    /// How many candidates have answered.
    pub found: u32,
}

/// What a scan should look for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScanOptions {
    /// How long to scan for, in milliseconds. The kernel clamps this to its own budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Whether to include devices that are already paired.
    pub include_paired: bool,
    /// Whether to use the network at all, or only the local machine's own records.
    ///
    /// A "show me what I already know" mode, for a device that is offline: the interface can list the paired
    /// devices without spending a scan budget.
    pub cached_only: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pairing
// ─────────────────────────────────────────────────────────────────────────────

/// A pairing request waiting on a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingPrompt {
    /// The request, for the response.
    pub request_id: String,
    /// The device asking.
    pub device_id: DeviceId,
    /// The name it claims.
    pub display_name: String,
    /// Its platform.
    pub platform: String,
    /// Its address, so the user can recognise a machine they have not paired with.
    pub address: String,
    /// The code both sides show, for the user to compare.
    ///
    /// The whole point of the prompt: a comparison the user makes is what stops a device on the same network from
    /// asking to pair in place of the one the user meant.
    pub verification_code: String,
    /// When the request stops being valid, in milliseconds since the epoch.
    pub expires_at_ms: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Intents
// ─────────────────────────────────────────────────────────────────────────────

/// What the user is trying to do, from the interface's point of view.
///
/// Internally tagged so the interface can switch on `kind`, and each variant carries only what that kind needs —
/// a share has text and a file has a path, and a single struct with both optional would let the interface send a
/// share with neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
#[non_exhaustive]
pub enum IntentSourceDto {
    /// The user shared text.
    Share {
        /// The text.
        text: String,
        /// An optional title the sharing application supplied.
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
    /// The user shared files.
    ShareFiles {
        /// The paths, as the interface received them.
        paths: Vec<String>,
    },
    /// The user asked to send the clipboard.
    Clipboard,
    /// The user invoked a plugin's action from its own page.
    PluginAction {
        /// The plugin.
        plugin_id: PluginId,
        /// The action.
        action: String,
        /// Its arguments, as JSON.
    args: serde_json::Value,
    },
}

impl IntentSourceDto {
    /// The `kind` a caller branches on, as the wire spells it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Share { .. } => "share",
            Self::ShareFiles { .. } => "shareFiles",
            Self::Clipboard => "clipboard",
            Self::PluginAction { .. } => "pluginAction",
        }
    }

    /// Whether this source carries content the user would not want in a log.
    ///
    /// The kernel records the *kind* of an intent and never its content, and the interface's diagnostics screen
    /// uses this to decide whether to say so. A share's title is user content; a plugin action's arguments are
    /// whatever the plugin decided.
    #[must_use]
    pub const fn carries_user_content(&self) -> bool {
        true
    }
}

/// Where an intent has got to.
///
/// Not `Eq`, because it may carry an [`super::IpcError`] whose parameters are a JSON value — and a JSON value
/// containing a float has no total equality. `PartialEq` is what the interface's tests need.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentSnapshot {
    /// The intent.
    pub intent_id: IntentId,
    /// What stage it is at. `snake_case`, matching the kernel's own states.
    pub state: String,
    /// The plugin the kernel chose, if it has chosen one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<PluginId>,
    /// The devices that could run it, for a chooser.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<IntentCandidate>,
    /// What the user is being asked, if anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<IntentPrompt>,
    /// Why it failed, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<super::IpcError>,
    /// When it started, in milliseconds since the epoch.
    pub started_at_ms: i64,
}

/// One way an intent could be handled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentCandidate {
    /// The plugin that would handle it.
    pub plugin_id: PluginId,
    /// The plugin's name, for the chooser.
    pub title: String,
    /// Which device would run it.
    pub device_id: DeviceId,
    /// Whether that device is reachable now.
    pub online: bool,
}

/// What the user is being asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentPrompt {
    /// The message key for the question.
    pub message: String,
    /// The values the question needs.
    pub params: serde_json::Value,
    /// What the user may choose.
    pub options: Vec<String>,
}

/// What the user decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "decision")]
#[non_exhaustive]
pub enum IntentDecisionDto {
    /// Let it proceed, on the given device.
    Accept {
        /// The device to run it on.
        device_id: DeviceId,
    },
    /// Let it proceed on whichever device the kernel chose.
    AcceptDefault,
    /// Refuse it.
    Decline {
        /// A reason the other side is told, if the user gave one.
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl IntentDecisionDto {
    /// The `decision` a caller branches on.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Accept { .. } => "accept",
            Self::AcceptDefault => "acceptDefault",
            Self::Decline { .. } => "decline",
        }
    }

    /// Whether it lets the intent proceed.
    #[must_use]
    pub const fn is_accepting(&self) -> bool {
        matches!(self, Self::Accept { .. } | Self::AcceptDefault)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Transfers
// ─────────────────────────────────────────────────────────────────────────────

/// A transfer, as a row in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSnapshot {
    /// The transfer.
    pub transfer_id: TransferId,
    /// The other device.
    pub peer_device: DeviceId,
    /// The peer's name, so the row does not need a second lookup.
    pub peer_name: String,
    /// `send` or `receive`.
    pub direction: String,
    /// `plugin-bundle` or `attachment`.
    pub kind: String,
    /// Where it is in its life. `snake_case`.
    pub state: String,
    /// The file's name, sanitised for display.
    pub file_name: String,
    /// How many bytes have moved.
    pub received_bytes: u64,
    /// How many there are in total.
    pub total_bytes: u64,
    /// How many blocks are done, for a resumable transfer.
    pub blocks_done: u32,
    /// How many there are.
    pub blocks_total: u32,
    /// Why it stopped, if it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<String>,
    /// When it started, in milliseconds since the epoch.
    pub started_at_ms: i64,
}

impl TransferSnapshot {
    /// How far along it is, from `0` to `1`.
    ///
    /// A total of zero gives `0` rather than `NaN`, because a `NaN` in a progress bar is a bar that renders at
    /// whatever width the platform's arithmetic produces.
    #[must_use]
    pub fn progress(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        // Clamped because a resumed transfer can report more received than the total it was created with — the
        // file changed size on the sender. A progress of `1.4` would render outside its bar.
        (self.received_bytes as f64 / self.total_bytes as f64).clamp(0.0, 1.0)
    }
}

/// The compact form a device card carries.
///
/// Not `Eq`: `progress` is a fraction, and a fraction has no total equality — so `PartialEq` is the strongest
/// thing this can implement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSummary {
    /// The transfer.
    pub transfer_id: TransferId,
    /// `send` or `receive`.
    pub direction: String,
    /// How far along, from `0` to `1`.
    pub progress: f64,
}

/// A file to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendFileRequest {
    /// Where it goes.
    pub to: DeviceId,
    /// The path, as the interface received it.
    pub path: String,
    /// An opaque identifier grouping this file with a conversation or an intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

/// Text to send as a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTextRequest {
    /// Where it goes.
    pub to: DeviceId,
    /// The text.
    pub text: String,
    /// What to call the file it becomes.
    pub file_name: String,
    /// An opaque identifier grouping it with a conversation or an intent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugins
// ─────────────────────────────────────────────────────────────────────────────

/// A plugin, as a card in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSnapshot {
    /// The plugin.
    pub plugin_id: PluginId,
    /// Its name.
    pub title: String,
    /// Its description, if it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Its version.
    pub version: String,
    /// Who published it.
    pub publisher: String,
    /// Whether it is enabled.
    pub enabled: bool,
    /// Where it is in its life. `snake_case`, matching the kernel's own states.
    ///
    /// The interface shows this rather than deriving a state from `enabled` and a health field: a plugin that is
    /// enabled but faulted is a state the user has to be told about, and deriving it in the interface would mean
    /// two implementations of the same rule.
    pub state: String,
    /// Whether it has both halves.
    pub hybrid: bool,
    /// How much of its quota it is using, for the settings screen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<PluginHealthDto>,
    /// The capabilities the user granted.
    #[serde(default)]
    pub granted: Vec<String>,
    /// The capabilities the user denied.
    ///
    /// `default` as well as `skip_serializing_if`, because a plugin whose every capability was granted serialises
    /// no `denied` field at all — and without the default the interface could not read back what it wrote.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied: Vec<String>,
    /// Whether an update is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateInfo>,
}

/// How a plugin is behaving, for the transparency the design document requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginHealthDto {
    /// Where it sits on the escalation ladder. `snake_case`.
    pub health: String,
    /// A message key explaining it.
    pub explanation: String,
    /// How many host calls it has made.
    pub calls_admitted: u64,
    /// How many were refused.
    pub calls_refused: u64,
    /// What it is using, by resource.
    pub usage: serde_json::Value,
}

/// An available update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    /// The version on offer.
    pub version: String,
    /// Whether its manifest asks for something the current one did not.
    ///
    /// What the interface uses to say "this update wants a new permission" rather than "an update is available":
    /// the second is a routine message and the first is a decision.
    pub needs_new_consent: bool,
    /// Which capabilities are new.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added_capabilities: Vec<String>,
}

/// A plugin in the catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogItem {
    /// The plugin's identifier.
    pub plugin_id: PluginId,
    /// Its name.
    pub title: String,
    /// Its description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The version on offer.
    pub version: String,
    /// Who published it.
    pub publisher: String,
    /// How many capabilities it asks for.
    ///
    /// A count rather than the list: the catalogue response is a search result, and a search result that carried
    /// every plugin's full permission list would be the largest thing on the wire for the least read part of it.
    pub capability_count: usize,
    /// Whether it is already installed.
    pub installed: bool,
}

/// What to search the catalogue for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogQuery {
    /// The search text.
    pub query: String,
    /// Which registry, when the user has more than one configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    /// The most results to return. The kernel clamps this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Where a plugin is being installed from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "source")]
#[non_exhaustive]
pub enum InstallSourceDto {
    /// A path the user chose.
    Path {
        /// The path.
        path: String,
    },
    /// A package from a registry.
    Registry {
        /// The plugin.
        plugin_id: PluginId,
        /// The version, or the latest when absent.
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
}

/// What to do with the plugin's data when removing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoveOptionsDto {
    /// Whether to delete the plugin's data and its sandbox.
    ///
    /// Two steps rather than one because they are different decisions: removing a plugin the user may reinstall
    /// should keep its settings, and removing one they do not trust should not.
    pub remove_data: bool,
}

/// What removing a plugin did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveReport {
    /// How many bytes of the plugin's data were freed.
    pub bytes_freed: u64,
    /// Whether the data was kept.
    pub data_kept: bool,
    /// Whatever could not be removed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub leftovers: Vec<String>,
}

/// How a plugin would be synchronised to other devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncPlanDto {
    /// The plugin.
    pub plugin_id: PluginId,
    /// The devices it would go to, and what each needs.
    pub targets: Vec<SyncTarget>,
}

/// One device a synchronisation would reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncTarget {
    /// The device.
    pub device_id: DeviceId,
    /// Its name.
    pub display_name: String,
    /// Whether it needs the artifact sent.
    pub needs_artifact: bool,
    /// What it already has, if anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Whether it can be reached now.
    pub online: bool,
}

/// What a synchronisation did.
///
/// Not `Eq`, because its failures carry an [`super::IpcError`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    /// How many devices were brought up to date.
    pub updated: u32,
    /// How many were already current.
    pub unchanged: u32,
    /// The devices that failed, with their reasons.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<SyncFailure>,
}

/// One device a synchronisation could not reach.
///
/// Not `Eq`, because it carries an [`super::IpcError`] whose parameters are a JSON value — and a JSON value
/// containing a float has no total equality.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncFailure {
    /// The device.
    pub device_id: DeviceId,
    /// Why.
    pub error: super::IpcError,
}

/// One entry from a plugin's audit trail.
///
/// There is deliberately no content field: the design document forbids payloads in an audit record, and the
/// absence of a field is what enforces it rather than a rule someone has to remember.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntryDto {
    /// When it happened.
    pub at_ms: i64,
    /// What was attempted.
    pub capability: String,
    /// Whether it was allowed.
    pub allowed: bool,
    /// Why not, when it was refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// How long the call took.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    /// The trace it belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// The configuration, as the settings screens read it.
///
/// A free-form JSON object rather than a struct with a field per setting. The reason is that the configuration
/// grows with every feature and a struct here would mean an interface release for every kernel release — so the
/// boundary carries the bag and the *screens* own their own shape, which is where the knowledge of what a
/// setting means actually lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSnapshot {
    /// Every setting, keyed by its dotted path.
    pub values: serde_json::Value,
    /// Which keys came from a file rather than the defaults, for the screen to mark.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub overridden: Vec<String>,
}

/// A change to the configuration.
///
/// Keys rather than a whole replacement, because two screens can be open and a whole-value write from one would
/// discard the other's change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfigPatch {
    /// The keys to set.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub set: serde_json::Map<String, serde_json::Value>,
    /// The keys to remove, returning them to their defaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unset: Vec<String>,
}

impl ConfigPatch {
    /// Whether it would change anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty() && self.unset.is_empty()
    }

    /// How many keys it touches.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len() + self.unset.len()
    }

    /// Whether a key is both set and unset.
    ///
    /// Refused rather than resolved by precedence: the caller meant one of the two, and picking for them produces
    /// a setting that is the opposite of what they asked for half the time.
    #[must_use]
    pub fn has_conflict(&self) -> Option<&str> {
        self.unset
            .iter()
            .find(|key| self.set.contains_key(key.as_str()))
            .map(String::as_str)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Diagnostics
// ─────────────────────────────────────────────────────────────────────────────

/// What to put in a diagnostic bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagExportOptions {
    /// Whether to include the audit trail. Default off, because it names the plugins the user runs.
    pub include_audit: bool,
    /// Whether to include debug-level log lines. Default off, because they are the most likely to contain
    /// something the user did not intend to share.
    pub include_debug_logs: bool,
    /// How many log lines to include.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_lines: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    /// A device id from a fixed string.
    ///
    /// Fixed so a round-trip test compares the *same* value rather than two fresh ones: a test that generated a new
    /// id on each side would fail while proving nothing. Built by parsing rather than from a raw UUID because the
    /// newtypes keep their inner value private, which is the point of them.
    fn fixed_device_id(text: &str) -> DeviceId {
        DeviceId::from_str(text).expect("a valid uuid")
    }

    /// A transfer id from a fixed string.
    fn fixed_transfer_id(text: &str) -> TransferId {
        TransferId::from_str(text).expect("a valid uuid")
    }

    /// A plugin id.
    ///
    /// The protocol validates a plugin id rather than accepting a bare string, so a test that wants one has to
    /// build a valid one — which is the same constraint the manifest loader has.
    fn plugin_id() -> PluginId {
        PluginId::parse("@synra-plugin/chat").expect("a valid plugin id")
    }

    /// A transfer id.
    fn transfer_id() -> TransferId {
        TransferId::new()
    }

    /// An intent id.
    fn intent_id() -> IntentId {
        IntentId::new()
    }

    fn card() -> DeviceCard {
        DeviceCard {
            device_id: DeviceId::new(),
            display_name: "My PC".to_owned(),
            platform: "linux".to_owned(),
            online: true,
            paired: true,
            blocked: false,
            last_seen_ms: 1_000,
            address: None,
            transfer: None,
        }
    }

    // ── Device cards ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_card_separates_online_from_paired() {
        // Different questions: a paired device that is offline is one the user can send to later, and an unpaired
        // device that is online is one they have to pair with first.
        let paired_offline = DeviceCard { online: false, paired: true, ..card() };
        assert!(paired_offline.paired && !paired_offline.online);

        let seen_online = DeviceCard { online: true, paired: false, ..card() };
        assert!(seen_online.online && !seen_online.paired);
    }

    #[test]
    fn an_absent_address_is_omitted_rather_than_null() {
        let json = serde_json::to_string(&card()).expect("serialises");
        assert!(!json.contains("address"), "{json}");
        assert!(!json.contains("transfer"), "{json}");
    }

    #[test]
    fn a_card_round_trips() {
        let card = DeviceCard {
            address: Some("192.168.1.5:32100".to_owned()),
            transfer: Some(TransferSummary {
                transfer_id: transfer_id(),
                direction: "send".to_owned(),
                progress: 0.25,
            }),
            ..card()
        };
        let json = serde_json::to_string(&card).expect("serialises");
        assert!(json.contains("lastSeenMs"), "{json}");
        let back: DeviceCard = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, card);
    }

    #[test]
    fn a_devices_snapshot_carries_the_identity_too() {
        // So the screen does not need a second call, which is what the design document means by a snapshot being
        // everything the screen needs in one value.
        let snapshot = DevicesSnapshot {
            identity: IdentitySnapshot {
                device_id: DeviceId::new(),
                display_name: "Laptop".to_owned(),
                platform: "linux".to_owned(),
                kernel_version: "0.1.0".to_owned(),
                name_is_default: true,
            },
            devices: vec![card()],
            scanning: None,
        };
        let json = serde_json::to_string(&snapshot).expect("serialises");
        let back: DevicesSnapshot = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, snapshot);
        // A device with no identity is one the interface cannot show a "this is you" marker for.
        assert_eq!(back.identity.device_id, snapshot.identity.device_id);
    }

    #[test]
    fn scan_options_default_to_a_short_inclusive_scan() {
        let options = ScanOptions::default();
        assert!(!options.cached_only);
        assert!(!options.include_paired);
        assert_eq!(options.timeout_ms, None);
    }

    #[test]
    fn scan_options_refuse_an_unknown_field() {
        // The boundary refuses unknown fields so a mistyped option is an error rather than a silently ignored
        // setting, which is the same rule the wire protocol's envelopes follow.
        let json = r#"{ "includePaired": true, "cachedOnly": false, "mystery": 1 }"#;
        assert!(serde_json::from_str::<ScanOptions>(json).is_err());
    }

    // ── Intents ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_intent_source_carries_only_what_its_kind_needs() {
        // A single struct with both text and paths optional would let the interface send a share with neither.
        let share = IntentSourceDto::Share { text: "hi".to_owned(), title: None };
        assert_eq!(share.kind(), "share");

        let files = IntentSourceDto::ShareFiles { paths: vec!["/a".to_owned()] };
        assert_eq!(files.kind(), "shareFiles");

        assert_eq!(IntentSourceDto::Clipboard.kind(), "clipboard");

        let action = IntentSourceDto::PluginAction {
            plugin_id: plugin_id(),
            action: "send".to_owned(),
            args: serde_json::json!({}),
        };
        assert_eq!(action.kind(), "pluginAction");
    }

    #[test]
    fn an_intent_source_is_tagged_on_the_wire() {
        let json = serde_json::to_string(&IntentSourceDto::Clipboard).expect("serialises");
        assert!(json.contains("\"kind\":\"clipboard\""), "{json}");
        let back: IntentSourceDto = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, IntentSourceDto::Clipboard);
    }

    #[test]
    fn an_absent_title_is_omitted() {
        let json = serde_json::to_string(&IntentSourceDto::Share {
            text: "hi".to_owned(),
            title: None,
        })
        .expect("serialises");
        assert!(!json.contains("title"), "{json}");
    }

    #[test]
    fn every_intent_source_carries_something_the_user_would_not_want_logged() {
        // The kernel records the kind and never the content, and this is what the diagnostics screen uses to say
        // so. A source that reported `false` here would be one the interface might echo.
        for source in [
            IntentSourceDto::Share { text: "x".to_owned(), title: None },
            IntentSourceDto::ShareFiles { paths: vec!["/a".to_owned()] },
            IntentSourceDto::Clipboard,
            IntentSourceDto::PluginAction {
                plugin_id: plugin_id(),
                action: "x".to_owned(),
                args: serde_json::json!(null),
            },
        ] {
            assert!(source.carries_user_content(), "{:?}", source.kind());
        }
    }

    #[test]
    fn a_decision_says_whether_it_accepts() {
        assert!(IntentDecisionDto::AcceptDefault.is_accepting());
        assert!(IntentDecisionDto::Accept { device_id: DeviceId::new() }.is_accepting());
        assert!(!IntentDecisionDto::Decline { reason: None }.is_accepting());
    }

    #[test]
    fn a_decision_is_tagged_on_the_wire() {
        for decision in [
            IntentDecisionDto::AcceptDefault,
            IntentDecisionDto::Decline { reason: Some("no".to_owned()) },
        ] {
            let json = serde_json::to_string(&decision).expect("serialises");
            assert!(json.contains("\"decision\""), "{json}");
            let back: IntentDecisionDto = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, decision);
        }
    }

    #[test]
    fn an_intent_snapshot_round_trips() {
        let snapshot = IntentSnapshot {
            intent_id: intent_id(),
            state: "awaiting_decision".to_owned(),
            plugin_id: Some(plugin_id()),
            candidates: vec![IntentCandidate {
                plugin_id: plugin_id(),
                title: "Chat".to_owned(),
                device_id: DeviceId::new(),
                online: true,
            }],
            prompt: Some(IntentPrompt {
                message: "intent.confirm".to_owned(),
                params: serde_json::json!({ "title": "Chat" }),
                options: vec!["accept".to_owned(), "decline".to_owned()],
            }),
            error: None,
            started_at_ms: 1_000,
        };
        let json = serde_json::to_string(&snapshot).expect("serialises");
        let back: IntentSnapshot = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, snapshot);
    }

    // ── Transfers ─────────────────────────────────────────────────────────────────────────────────

    fn transfer(received: u64, total: u64) -> TransferSnapshot {
        TransferSnapshot {
            transfer_id: fixed_transfer_id("018f2b40-0000-7000-8000-000000000001"),
            peer_device: fixed_device_id("018f2b40-0000-7000-8000-000000000002"),
            peer_name: "My PC".to_owned(),
            direction: "send".to_owned(),
            kind: "attachment".to_owned(),
            state: "transferring".to_owned(),
            file_name: "report.pdf".to_owned(),
            received_bytes: received,
            total_bytes: total,
            blocks_done: 0,
            blocks_total: 0,
            abort_reason: None,
            started_at_ms: 0,
        }
    }

    #[test]
    fn progress_is_a_fraction() {
        assert_eq!(transfer(0, 100).progress(), 0.0);
        assert_eq!(transfer(50, 100).progress(), 0.5);
        assert_eq!(transfer(100, 100).progress(), 1.0);
    }

    #[test]
    fn progress_of_an_empty_transfer_is_zero_rather_than_nan() {
        // A `NaN` in a progress bar renders at whatever width the platform's arithmetic produces.
        assert_eq!(transfer(0, 0).progress(), 0.0);
        assert!(transfer(0, 0).progress().is_finite());
    }

    #[test]
    fn progress_never_exceeds_one() {
        // A resumed transfer can report more received than the total it was created with, because the file changed
        // size on the sender. A progress of 1.4 would render outside its bar.
        assert_eq!(transfer(140, 100).progress(), 1.0);
    }

    #[test]
    fn a_transfer_round_trips() {
        let json = serde_json::to_string(&transfer(1, 2)).expect("serialises");
        assert!(json.contains("transferId"), "{json}");
        assert!(json.contains("blocksTotal"), "{json}");
        let back: TransferSnapshot = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, transfer(1, 2));
    }

    #[test]
    fn a_send_request_round_trips() {
        let request = SendFileRequest {
            to: DeviceId::new(),
            path: "/tmp/x.pdf".to_owned(),
            context_id: Some("c1".to_owned()),
        };
        let json = serde_json::to_string(&request).expect("serialises");
        assert!(json.contains("contextId"), "{json}");
        let back: SendFileRequest = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, request);
    }

    // ── Plugins ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plugin_snapshot_reports_its_state_rather_than_leaving_it_to_be_derived() {
        // A plugin that is enabled but faulted is a state the user has to be told about, and deriving it in the
        // interface would mean two implementations of the same rule.
        let plugin = PluginSnapshot {
            plugin_id: plugin_id(),
            title: "Chat".to_owned(),
            description: None,
            version: "1.0.0".to_owned(),
            publisher: "synra-official".to_owned(),
            enabled: true,
            state: "faulted".to_owned(),
            hybrid: true,
            health: None,
            granted: vec!["log:*".to_owned()],
            denied: Vec::new(),
            update: None,
        };
        assert!(plugin.enabled);
        assert_eq!(plugin.state, "faulted");

        let json = serde_json::to_string(&plugin).expect("serialises");
        let back: PluginSnapshot = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, plugin);
    }

    #[test]
    fn an_update_reports_whether_it_needs_new_consent() {
        // "An update is available" is a routine message; "this update wants a new permission" is a decision, and
        // the interface says different things for each.
        let routine = UpdateInfo {
            version: "1.0.1".to_owned(),
            needs_new_consent: false,
            added_capabilities: Vec::new(),
        };
        assert!(!routine.needs_new_consent);

        let needing = UpdateInfo {
            version: "2.0.0".to_owned(),
            needs_new_consent: true,
            added_capabilities: vec!["platform:simulate-keys".to_owned()],
        };
        assert!(needing.needs_new_consent);
        assert_eq!(needing.added_capabilities.len(), 1);
    }

    #[test]
    fn a_catalog_item_carries_a_capability_count_rather_than_the_list() {
        // The catalogue response is a search result, and a result carrying every plugin's full permission list
        // would be the largest thing on the wire for the least read part of it.
        let item = CatalogItem {
            plugin_id: plugin_id(),
            title: "Chat".to_owned(),
            description: None,
            version: "1.0.0".to_owned(),
            publisher: "synra-official".to_owned(),
            capability_count: 7,
            installed: false,
        };
        let json = serde_json::to_string(&item).expect("serialises");
        assert!(json.contains("capabilityCount"), "{json}");
        assert!(!json.contains("capabilities"), "{json}");
    }

    #[test]
    fn an_install_source_is_tagged() {
        for source in [
            InstallSourceDto::Path { path: "/tmp/x.synra".to_owned() },
            InstallSourceDto::Registry { plugin_id: plugin_id(), version: None },
        ] {
            let json = serde_json::to_string(&source).expect("serialises");
            assert!(json.contains("\"source\""), "{json}");
            let back: InstallSourceDto = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, source);
        }
    }

    #[test]
    fn an_audit_entry_has_no_field_for_content() {
        // The design document forbids payloads in an audit record, and the absence of a field is what enforces it
        // rather than a rule someone has to remember.
        let entry = AuditEntryDto {
            at_ms: 1,
            capability: "platform:open-url".to_owned(),
            allowed: false,
            reason: Some("not granted".to_owned()),
            elapsed_ms: None,
            trace_id: None,
        };
        let json = serde_json::to_string(&entry).expect("serialises");
        // Quoted, so a *field* named for content is caught and a capability whose value happens to contain the
        // word — `platform:open-url` contains `url` — is not a false positive.
        for forbidden in ["\"payload\"", "\"content\"", "\"args\"", "\"body\"", "\"url\"", "\"text\""] {
            assert!(!json.contains(forbidden), "{forbidden} appeared in {json}");
        }
    }

    #[test]
    fn a_sync_report_separates_updated_from_unchanged() {
        // The interface says different things for each: "3 devices updated" and "already up to date" are not the
        // same message.
        let report = SyncReport {
            updated: 2,
            unchanged: 1,
            failures: vec![SyncFailure {
                device_id: DeviceId::new(),
                error: super::super::IpcError::unknown(synra_protocol::ErrorCode::DeviceOffline),
            }],
        };
        let json = serde_json::to_string(&report).expect("serialises");
        assert!(json.contains("\"updated\":2"), "{json}");
        assert!(json.contains("\"unchanged\":1"), "{json}");
        let back: SyncReport = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
    }

    // ── Configuration ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_patch_sets_and_unsets_keys() {
        let mut patch = ConfigPatch::default();
        patch.set.insert("ui.theme".to_owned(), serde_json::json!("dark"));
        patch.unset.push("ui.locale".to_owned());

        assert!(!patch.is_empty());
        assert_eq!(patch.len(), 2);
        assert_eq!(patch.has_conflict(), None);
    }

    #[test]
    fn an_empty_patch_says_so() {
        // So the shell can refuse a no-op call rather than waking the kernel for it.
        assert!(ConfigPatch::default().is_empty());
        assert_eq!(ConfigPatch::default().len(), 0);
    }

    #[test]
    fn a_key_that_is_both_set_and_unset_is_reported() {
        // Refused rather than resolved by precedence: the caller meant one of the two, and picking for them
        // produces a setting that is the opposite of what they asked for half the time.
        let mut patch = ConfigPatch::default();
        patch.set.insert("ui.theme".to_owned(), serde_json::json!("dark"));
        patch.unset.push("ui.theme".to_owned());
        assert_eq!(patch.has_conflict(), Some("ui.theme"));
    }

    #[test]
    fn a_config_patch_round_trips() {
        let mut patch = ConfigPatch::default();
        patch.set.insert("a".to_owned(), serde_json::json!(1));
        patch.unset.push("b".to_owned());
        let json = serde_json::to_string(&patch).expect("serialises");
        let back: ConfigPatch = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, patch);
    }

    #[test]
    fn a_config_snapshot_carries_which_keys_were_overridden() {
        // So the settings screen can mark a value the user changed from the default.
        let snapshot = ConfigSnapshot {
            values: serde_json::json!({ "ui.theme": "dark" }),
            overridden: vec!["ui.theme".to_owned()],
        };
        let json = serde_json::to_string(&snapshot).expect("serialises");
        assert!(json.contains("overridden"), "{json}");
        let back: ConfigSnapshot = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, snapshot);
    }

    // ── Diagnostics ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_diagnostic_export_defaults_to_the_least_intrusive_bundle() {
        // The optional sections are the ones that name the plugins the user runs and the ones most likely to
        // contain something they did not intend to share.
        let options = DiagExportOptions::default();
        assert!(!options.include_audit);
        assert!(!options.include_debug_logs);
        assert_eq!(options.log_lines, None);
    }

    #[test]
    fn a_diagnostic_export_refuses_an_unknown_field() {
        // A mistyped option would otherwise silently export the defaults, which is the sort of thing a user
        // discovers by reading the file they just sent.
        let json = r#"{ "includeAudit": true, "mystery": 1 }"#;
        assert!(serde_json::from_str::<DiagExportOptions>(json).is_err());
    }

    // ── Forbidden content ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn no_snapshot_carries_a_field_named_for_content() {
        // The design document's rule, checked over the shapes rather than over one of them: a snapshot is a
        // picture, and a picture that includes the user's text is one that ends up in a diagnostic bundle.
        let snapshots: Vec<serde_json::Value> = vec![
            serde_json::to_value(DevicesSnapshot {
                identity: IdentitySnapshot {
                    device_id: DeviceId::new(),
                    display_name: "L".to_owned(),
                    platform: "linux".to_owned(),
                    kernel_version: "0".to_owned(),
                    name_is_default: false,
                },
                devices: vec![card()],
                scanning: None,
            })
            .expect("serialises"),
            serde_json::to_value(IntentSnapshot {
                intent_id: intent_id(),
                state: "pending".to_owned(),
                plugin_id: None,
                candidates: Vec::new(),
                prompt: None,
                error: None,
                started_at_ms: 0,
            })
            .expect("serialises"),
            serde_json::to_value(transfer(0, 1)).expect("serialises"),
        ];

        for value in snapshots {
            let json = serde_json::to_string(&value).expect("serialises");
            for forbidden in ["\"payload\"", "\"body\"", "\"text\"", "\"content\""] {
                assert!(!json.contains(forbidden), "{forbidden} appeared in {json}");
            }
        }
    }
}
