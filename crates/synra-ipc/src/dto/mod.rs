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
//! So each snapshot type carries everything the screen needs in one value, and the events carry what changed. The
//! sequence number is what lets the interface notice it missed one and ask for a fresh snapshot rather than drifting.
//!
//! # Why this is a directory
//!
//! Because it is one subject per screen. In one file the pairing prompt sat between a device card and an intent
//! snapshot, so a reader looking for "what does the plugin list look like" scrolled past three unrelated subjects.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `devices` | this device, the device list, and the pairing prompt |
//! | `intent` | what the user is trying to do, and their decision |
//! | `transfer` | transfers, and the requests that start one |
//! | `plugin` | installed plugins, the catalog, and install reports |
//! | `config` | configuration, and the diagnostic export options |

mod config;
mod devices;
mod intent;
mod plugin;
mod transfer;

pub use config::{ConfigPatch, ConfigSnapshot, DiagExportOptions};
pub use devices::{
    DeviceCard, DevicesSnapshot, IdentitySnapshot, PairingPrompt, ScanOptions, ScanState,
};
pub use intent::{IntentCandidate, IntentDecisionDto, IntentPrompt, IntentSnapshot, IntentSourceDto};
pub use plugin::{
    AuditEntryDto, CatalogItem, CatalogQuery, CatalogSort, InstallPreviewDto, InstallReport, InstallSourceDto,
    PluginHealthDto, PluginSnapshot, PublisherDto, RemoveOptionsDto, RemoveReport, SyncFailure, SyncPlanDto,
    SyncReport, SyncTarget, UpdateInfo,
};
pub use transfer::{SendFileRequest, SendTextRequest, TransferSnapshot, TransferSummary};

#[cfg(test)]
mod tests;