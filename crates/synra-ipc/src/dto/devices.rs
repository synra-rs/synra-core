//! This device, the devices it can see, and a pairing request waiting on a decision.
//!
//! # Why a card and not a device
//!
//! Because the interface shows what it can *do* with a device, not what the device is. A card carries the trust level and
//! whether a send would be accepted, so a screen does not have to derive either from a protocol state it cannot see.

use serde::{Deserialize, Serialize};

use synra_protocol::DeviceId;

use super::transfer::TransferSummary;

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
