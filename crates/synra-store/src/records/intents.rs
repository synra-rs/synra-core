//! Active plugin versions and persisted intent rows.

use super::{required, RowError};

/// The version of a plugin that is in effect, with the artifact it names.
///
/// # Why the artifact is a file name and not a path
///
/// Because the directory is the caller's: [`crate::Paths::plugin_dir`] decides where a plugin lives, and a row that
/// stored an absolute path would point into the wrong data directory the moment one moved. The name is joined to that
/// directory by whoever needs the bytes.
///
/// ★ **It can be empty**, and that is not a defect: a UI-only plugin has no headless artifact, and the install records
/// an empty name rather than inventing one. A caller that needs bytes has to decide what an empty name means — the sync
/// runner refuses it with a sentence rather than opening the plugin's directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveVersion {
    /// The version string.
    pub version: String,
    /// The artifact's file name inside the plugin's directory, or empty when there is no headless half.
    pub artifact: String,
    /// The artifact's digest, as the install computed it. Empty for a plugin with no artifact.
    pub digest: String,
    /// Who signed the package, when it was signed.
    pub publisher_id: Option<String>,
    /// The signing key's fingerprint, as a person reads it. `None` for an unsigned package.
    pub fingerprint: Option<String>,
}

/// One intent, as the `intents` table keeps it.
///
/// # Why this is a projection **and** a document
///
/// Because the two queries the store makes want different things. The retention sweep filters by state and time without
/// caring what an intent is, and the idempotency lookup is by the pair a peer retried under — both of those want columns.
/// Everything else about an intent is the kernel's own business, and the store has no opinion about it, so it travels as
/// the kernel serialised it.
///
/// ★ The first version of this type mapped each column to a field, and it could not round-trip: `Intent` has a trace, a
/// `Choice`, a candidate list and a dispatch's request id, and the table had room for none of them. A store that cannot
/// give back what it was handed is worse than one that keeps nothing, because the loss is quiet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentRecord {
    /// The intent's identifier, as the protocol spells it.
    pub intent_id: String,
    /// Where it got to, as the kernel spells it.
    ///
    /// Carried beside the document on purpose: the sweep compares this to a list of finished states, and a sweep that had
    /// to deserialise every row to read one field would be a sweep nobody could run on a large table.
    pub state: String,
    /// When it was raised.
    pub created_ms: i64,
    /// When it last changed.
    pub updated_ms: i64,
    /// The device that raised it, when it came over a link.
    ///
    /// The first half of the idempotency key, and `NULL` for an intent this device raised itself.
    pub origin_device: Option<String>,
    /// The request it was raised under, when it came over a link.
    ///
    /// The second half. A pair that repeats is the same intent, which is what the unique index on these two enforces.
    pub request_id: Option<String>,
    /// The intent itself, as the kernel serialised it.
    pub document: String,
}

impl IntentRecord {
    /// Builds a row from the columns `intents` declares, in its order.
    ///
    /// # Errors
    ///
    /// [`RowError::Missing`] for a `NOT NULL` column that is empty.
    pub fn from_columns(
        intent_id: Option<&str>,
        state: Option<&str>,
        created_ms: Option<i64>,
        updated_ms: Option<i64>,
        origin_device: Option<String>,
        request_id: Option<String>,
        document: Option<&str>,
    ) -> Result<Self, RowError> {
        Ok(Self {
            intent_id: required(intent_id, "intent_id")?.to_owned(),
            state: required(state, "state")?.to_owned(),
            created_ms: required(created_ms, "created_ms")?,
            updated_ms: required(updated_ms, "updated_ms")?,
            origin_device,
            request_id,
            document: required(document, "document")?.to_owned(),
        })
    }
}


