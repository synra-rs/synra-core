//! Session payloads: pairing, intent and transfer.
//!
//! A session is a conversation with a beginning and an end, and the thing that most often goes wrong
//! in one is that it never ends. A pairing request whose answer is lost, an intent whose peer was
//! suspended mid-flight, a transfer interrupted by a laptop closing — each leaves the initiator
//! waiting forever unless something bounds it.
//!
//! So every session has a timeout, and they live in one place: [`SessionTimeouts`].
//!
//! # Why the initiator must time itself out
//!
//! Every payload here is *also* protected by the peer's own timeout, and that is not enough. If the
//! only timeout is on the receiving side, an initiator whose packet was dropped before it arrived
//! waits for an answer that was never coming — no error, no log, just a spinner. Each side bounds
//! its own wait independently.

use core::fmt;
use core::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::SynraError;
use crate::ids::{DeviceId, IntentId, PluginId, RequestId, SessionId, TransferId};
use crate::limits;

/// Timeouts for every kind of session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTimeouts {
    /// How long a pairing request may wait for an answer.
    pub pairing: Duration,
    /// How long an intent may run, end to end.
    pub intent: Duration,
    /// How long a transfer may go without receiving a block before it is abandoned.
    pub transfer_idle: Duration,
    /// How long a transfer may run in total, however active it is.
    pub transfer_total: Duration,
    /// How long a finished session's result is kept, so a retry can be answered without re-running.
    pub result_cache: Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            pairing: Duration::from_secs(30),
            intent: Duration::from_secs(30),
            transfer_idle: Duration::from_secs(60),
            transfer_total: Duration::from_secs(30 * 60),
            result_cache: Duration::from_secs(5 * 60),
        }
    }
}

impl SessionTimeouts {
    /// Rejects a combination that cannot work.
    ///
    /// Checked rather than assumed because both mistakes below are silent. A result cache shorter
    /// than the dedup window means a retry re-executes work the user already waited for; an idle
    /// timeout longer than the total one means the idle check can never fire, so a stalled transfer
    /// is only caught by the total timeout — minutes later, with no progress reported in between.
    ///
    /// # Errors
    ///
    /// Describes the first inconsistency found.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.pairing.is_zero() || self.intent.is_zero() {
            return Err("pairing and intent timeouts must be non-zero, or every session hangs");
        }
        if self.transfer_total < self.transfer_idle {
            return Err("transfer_total must be at least transfer_idle, or the idle check never fires");
        }
        // A retry arrives within the dedup window, so the cached answer has to outlive it.
        if self.result_cache < limits::REQUEST_DEDUP_WINDOW {
            return Err("result_cache must cover the request dedup window, or a retry re-runs the work");
        }
        Ok(())
    }
}

/// Which platform a device runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PlatformKind {
    /// Windows, macOS or Linux.
    Desktop,
    /// Android.
    Android,
    /// iOS.
    Ios,
}

impl PlatformKind {
    /// Whether this is a mobile platform, where the host may be suspended at any moment.
    #[must_use]
    pub const fn is_mobile(self) -> bool {
        matches!(self, Self::Android | Self::Ios)
    }
}

impl fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Desktop => "desktop",
            Self::Android => "android",
            Self::Ios => "ios",
        })
    }
}

/// What a peer is told about a device during pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerProfile {
    /// The device's stable id.
    pub device_id: DeviceId,
    /// The name to show a human.
    pub display_name: String,
    /// Which platform, so the interface can pick an icon and hide what is unsupported.
    pub platform: PlatformKind,
    /// The host application's version.
    pub app_version: String,
}

impl PeerProfile {
    /// The longest display name accepted, so a peer cannot fill the interface with one string.
    pub const MAX_DISPLAY_NAME: usize = 64;

    /// Checks the profile is usable.
    ///
    /// # Errors
    ///
    /// A description of what is wrong.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.device_id.is_nil() {
            return Err("device_id must not be nil");
        }
        if self.display_name.trim().is_empty() {
            return Err("display_name must not be blank");
        }
        // Counted in characters, not bytes: a name in CJK is not "too long" in a unit the user
        // cannot see.
        if self.display_name.chars().count() > Self::MAX_DISPLAY_NAME {
            return Err("display_name is too long");
        }
        if self.app_version.trim().is_empty() {
            return Err("app_version must not be blank");
        }
        Ok(())
    }
}

/// A request to pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairRequest {
    /// Who is asking, so the receiving user sees a name rather than an id.
    pub profile: PeerProfile,
    /// Optional text to show alongside the prompt.
    ///
    /// Presentation only. It cannot change what the request means, which is why it is a hint rather
    /// than something the receiving side branches on.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user_hint: Option<String>,
}

/// The answer to a pairing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairResponse {
    /// Whether pairing was accepted.
    pub accepted: bool,
    /// Why, when it was refused. For the user, not for branching.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
    /// The token the accepting side will expect on later links, as lowercase hex.
    ///
    /// # Why the answer carries the token rather than each side deriving one
    ///
    /// The accepting side is the one that decides whether a later link is trusted, so the token has to be something it
    /// can recognise — and a value the dialer chose would be a value the dialer could choose again for a different
    /// device. Issuing it here also puts it in the same message as the acceptance, so a dialer that receives `accepted`
    /// cannot be in the state of "paired but holding no token".
    ///
    /// # Why it is optional
    ///
    /// A refusal has no token, and neither would an older build that answers a pairing request without issuing one.
    /// Absent means the pairing was recorded without a token, which later links report as needing to pair again rather
    /// than as trusted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub link_token: Option<String>,
}

impl PairResponse {
    /// An accepted answer, with the token later links must present.
    #[must_use]
    pub fn accepted(link_token: impl Into<String>) -> Self {
        Self { accepted: true, reason: None, link_token: Some(link_token.into()) }
    }

    /// A refusal with a reason.
    #[must_use]
    pub fn refused(reason: impl Into<String>) -> Self {
        Self { accepted: false, reason: Some(reason.into()), link_token: None }
    }

    /// The token a dialer should store, when the request was accepted and one was issued.
    #[must_use]
    pub fn issued_token(&self) -> Option<&str> {
        if self.accepted { self.link_token.as_deref() } else { None }
    }
}

/// Why a pairing request was refused without involving the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PairRefusal {
    /// A different pairing request is already on screen.
    ///
    /// A refusal rather than a queue: a prompt is a decision the user is in the middle of, and
    /// stacking a second one behind it means the second is answered, by default, minutes later.
    Busy,
    /// The request arrived outside a pairing window, for a device this host does not know.
    Expired,
    /// The requester is blocked.
    Blocked,
}

impl PairRefusal {
    /// The reason text a peer receives.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Expired => "expired",
            Self::Blocked => "blocked",
        }
    }
}

/// An action this device is asking another device to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentInvocation {
    /// Identifies this intent across both devices.
    pub intent_id: IntentId,
    /// Which plugin should run it.
    pub plugin_id: PluginId,
    /// Which of that plugin's actions.
    pub action: String,
    /// The action's arguments, as raw JSON.
    ///
    /// Unparsed here for the same reason an envelope's payload is: the receiving kernel validates it
    /// against the plugin's declared schema and does not need to understand it first.
    pub args: Box<RawValue>,
    /// Text the interface may show when asking the user to confirm.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display: Option<IntentDisplay>,
}

impl PartialEq for IntentInvocation {
    /// Compares `args` by value rather than by spelling: see [`crate::envelope`]'s note on why
    /// `RawValue` needs a hand-written comparison.
    fn eq(&self, other: &Self) -> bool {
        self.intent_id == other.intent_id
            && self.plugin_id == other.plugin_id
            && self.action == other.action
            && self.display == other.display
            && crate::envelope::raw_json_eq(Some(&self.args), Some(&other.args))
    }
}

impl Eq for IntentInvocation {}

/// What the interface shows while asking the user to confirm a remote action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentDisplay {
    /// One line, such as "Open this link".
    pub title: String,
    /// Optional detail, such as the URL.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
    /// Which device is asking. Shown because "who wants this" is part of the decision.
    pub source_display_name: String,
}

/// How an intent ended.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntentOutcome {
    /// Which intent this concludes.
    pub intent_id: IntentId,
    /// Whether it worked.
    pub ok: bool,
    /// The action's return value, when it succeeded and produced one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<Box<RawValue>>,
    /// The failure, when it did not.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<SynraError>,
    /// How long the action took on the remote device.
    pub elapsed_ms: u64,
}

impl PartialEq for IntentOutcome {
    fn eq(&self, other: &Self) -> bool {
        self.intent_id == other.intent_id
            && self.ok == other.ok
            && self.error == other.error
            && self.elapsed_ms == other.elapsed_ms
            && crate::envelope::raw_json_eq(self.result.as_deref(), other.result.as_deref())
    }
}

impl Eq for IntentOutcome {}

impl IntentOutcome {
    /// A successful outcome.
    #[must_use]
    pub const fn ok(intent_id: IntentId, result: Option<Box<RawValue>>, elapsed_ms: u64) -> Self {
        Self { intent_id, ok: true, result, error: None, elapsed_ms }
    }

    /// A failed outcome.
    ///
    /// An outcome is either a result or an error, never both: an interface that had to decide which
    /// of the two to believe would eventually meet a case where they disagree.
    #[must_use]
    pub const fn failed(intent_id: IntentId, error: SynraError, elapsed_ms: u64) -> Self {
        Self { intent_id, ok: false, result: None, error: Some(error), elapsed_ms }
    }

    /// Checks the shape is self-consistent.
    ///
    /// # Errors
    ///
    /// A description of what is wrong.
    pub const fn validate(&self) -> Result<(), &'static str> {
        match (self.ok, &self.error) {
            (true, Some(_)) => Err("a successful outcome must not carry an error"),
            (false, None) => Err("a failed outcome must carry an error"),
            _ => Ok(()),
        }
    }
}

/// The kind of a transfer, so the receiver knows where the bytes go before they arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum TransferKind {
    /// A plugin's artifact, being synchronised for installation.
    PluginBundle,
    /// A file a user or a plugin is sending.
    Attachment,
}

/// The digest algorithms this protocol accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256, the only one currently accepted.
    Sha256,
}

impl DigestAlgorithm {
    /// The prefix used in the wire form.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }

    /// The length the base64 value must have for this algorithm.
    const fn encoded_len(self) -> usize {
        match self {
            // 32 bytes, base64 without padding.
            Self::Sha256 => 43,
        }
    }
}

/// A subresource-integrity style digest: an algorithm and a base64 value.
///
/// One type rather than a bare string so the algorithm is never implicit. A digest whose algorithm
/// has to be inferred is one that will eventually be checked with the wrong one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SriDigest {
    algorithm: DigestAlgorithm,
    encoded: String,
}

impl SriDigest {
    /// Builds a digest from an algorithm and a base64 value.
    ///
    /// # Errors
    ///
    /// A description if the value is not the right length for the algorithm, or is not base64.
    pub fn new(algorithm: DigestAlgorithm, encoded: impl Into<String>) -> Result<Self, &'static str> {
        let encoded = encoded.into();
        if encoded.len() != algorithm.encoded_len() {
            return Err("digest has the wrong length for its algorithm");
        }
        // Base64 without padding: standard alphabet, and `=` is not expected here.
        if !encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '/')
        {
            return Err("digest is not base64");
        }
        Ok(Self { algorithm, encoded })
    }

    /// Which algorithm this digest uses.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// The base64 value, without the algorithm prefix.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Display for SriDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.algorithm.prefix(), self.encoded)
    }
}

impl TryFrom<String> for SriDigest {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let (prefix, encoded) = value
            .split_once('-')
            .ok_or("a digest must be `algorithm-base64`")?;
        let algorithm = match prefix {
            "sha256" => DigestAlgorithm::Sha256,
            _ => return Err("unknown digest algorithm"),
        };
        Self::new(algorithm, encoded)
    }
}

impl From<SriDigest> for String {
    fn from(value: SriDigest) -> Self {
        value.to_string()
    }
}

/// What a transfer carries, beyond its bytes.
///
/// A tagged enum so the receiver can reject a transfer whose metadata it does not understand
/// *before* accepting megabytes of data.
///
/// `rename_all_fields` rather than `rename_all`: the latter renames the *variants*, and the fields
/// inside each variant would keep their Rust names and go out as `plugin_id` where the protocol says
/// `pluginId`. Both attributes are needed, and the difference is invisible until a peer rejects the
/// message.
///
/// `deny_unknown_fields` is deliberately absent. It cannot be combined with `flatten` — the
/// enclosing [`TransferRequest`] flattens this enum — so a stray field here is ignored rather than
/// refused. The cost is accepted because the metadata is a hint about where bytes go, not a
/// capability: a field this version does not know cannot change what the receiver does with them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", rename_all_fields = "camelCase", tag = "metaKind")]
#[non_exhaustive]
pub enum TransferMeta {
    /// A plugin artifact on its way to be installed.
    #[serde(rename = "plugin-bundle")]
    PluginBundle {
        /// Which plugin.
        plugin_id: PluginId,
        /// Which version.
        version: String,
    },
    /// A file, with optional presentation details.
    #[serde(rename = "attachment")]
    Attachment {
        /// Suggested file name. Sanitised by the receiver before it is used on disk.
        file_name: String,
        /// Declared MIME type, if the sender knows it.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        mime_type: Option<String>,
        /// An opaque id grouping this file with an intent or a conversation.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        context_id: Option<String>,
    },
}

/// Proposes a transfer.
///
/// Note the absent `deny_unknown_fields`: serde cannot combine it with `flatten`, and the flattened
/// metadata needs to sit at the top level so a receiver sees one flat object rather than a nested
/// one it would have to unwrap before knowing whether the transfer is even for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferRequest {
    /// Identifies this transfer across both devices.
    pub transfer_id: TransferId,
    /// What kind of thing is being sent.
    pub kind: TransferKind,
    /// Total size in bytes.
    pub byte_length: u64,
    /// How the sender will split it. The receiver checks the sender keeps its word.
    pub chunk_size: u32,
    /// Digest of the whole object, checked before the transfer counts as successful.
    pub digest: SriDigest,
    /// Groups transfers that belong to one logical sync.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sync_session_id: Option<SessionId>,
    /// Kind-specific metadata.
    #[serde(flatten)]
    pub meta: TransferMeta,
}

/// One plugin as a peer describes it.
///
/// # Why this is not `synra_core::plugin_sync::RemoteState`
///
/// Because the wire has to be describable without the kernel: `RemoteState` is the kernel's opinion of a peer's plugin, and a
/// protocol type that leaned on it would make the protocol depend on the implementation it exists to describe. The mapping is
/// the kernel's, one field at a time, and it is the only place the two can disagree — which is why it is a mapping rather than
/// a `From`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginSummary {
    /// Which plugin.
    pub plugin_id: PluginId,
    /// The version this device has, if any.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub version: Option<String>,
    /// The digest of its artifact, if this device has one.
    ///
    /// The comparison that matters: two devices may hold the same version string with different bytes, and comparing versions
    /// alone would call that "already synchronised".
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub digest: Option<String>,
    /// Whether it is running there.
    pub active: bool,
}

/// What a device answers when another asks what plugins it has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginList {
    /// Every plugin the answering device knows about, by identifier.
    pub plugins: Vec<PluginSummary>,
}
/// Which blocks the receiver has, as a bitmap.
///
/// A bitmap rather than a list of indices: a list of a hundred thousand indices is a hundred
/// thousand numbers, and the same information in bits is twelve kilobytes. It also makes "which
/// blocks am I missing" a bitwise operation rather than a set difference.
///
/// # Bit order
///
/// Little-endian *within each byte*: block `n` lives in byte `n / 8`, at bit `n % 8`, with bit 0 the
/// least significant. Chosen so that comparing two bitmaps is a plain `u8` operation per byte.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProgressBitmap {
    bytes: Vec<u8>,
    /// Total blocks the transfer comprises, so trailing padding bits are never mistaken for blocks.
    total_blocks: u32,
}

impl ProgressBitmap {
    /// A bitmap for a transfer of `total_blocks` blocks, with none received.
    #[must_use]
    pub fn empty(total_blocks: u32) -> Self {
        let byte_len = total_blocks.div_ceil(8) as usize;
        Self { bytes: vec![0; byte_len], total_blocks }
    }

    /// A bitmap with every block marked received.
    #[must_use]
    pub fn full(total_blocks: u32) -> Self {
        let mut bitmap = Self::empty(total_blocks);
        for block in 0..total_blocks {
            bitmap.set(block);
        }
        bitmap
    }

    /// Total blocks this bitmap covers.
    #[must_use]
    pub const fn total_blocks(&self) -> u32 {
        self.total_blocks
    }

    /// Marks a block received. A block beyond the total is ignored.
    pub fn set(&mut self, block: u32) {
        if block >= self.total_blocks {
            return;
        }
        let index = (block / 8) as usize;
        let bit = (block % 8) as u8;
        if let Some(byte) = self.bytes.get_mut(index) {
            *byte |= 1 << bit;
        }
    }

    /// Whether a block has been received.
    #[must_use]
    pub fn contains(&self, block: u32) -> bool {
        if block >= self.total_blocks {
            return false;
        }
        let index = (block / 8) as usize;
        let bit = (block % 8) as u8;
        self.bytes.get(index).is_some_and(|byte| byte & (1 << bit) != 0)
    }

    /// How many blocks have been received.
    #[must_use]
    pub fn received_count(&self) -> u32 {
        let full_bytes = (self.total_blocks / 8) as usize;
        let mut count: u32 = self
            .bytes
            .iter()
            .take(full_bytes)
            .map(|byte| byte.count_ones())
            .sum();

        // The partial byte needs masking, or its padding bits would be counted as blocks — and a
        // transfer would appear complete before it was.
        let remainder = self.total_blocks % 8;
        if remainder != 0
            && let Some(byte) = self.bytes.get(full_bytes)
        {
            let mask = (1u8 << remainder) - 1;
            count += (byte & mask).count_ones();
        }
        count
    }

    /// Whether every block has been received.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received_count() == self.total_blocks
    }

    /// The blocks still missing, in ascending order.
    ///
    /// What a sender retransmits. The caller decides how many losses are worth patching: a transfer
    /// that has lost most of its blocks is better restarted than repaired.
    #[must_use]
    pub fn missing(&self) -> Vec<u32> {
        (0..self.total_blocks)
            .filter(|block| !self.contains(*block))
            .collect()
    }

    /// The highest block index this bitmap holds, or `None` when it holds none.
    ///
    /// # Why a sender needs this
    ///
    /// Because a report is a snapshot and names as "missing" every block still crossing the network. A block **below** the
    /// highest one the receiver holds has been passed over by an in-order reader, so it is genuinely lost and worth
    /// rewriting; one above it is merely late. Without the distinction a sender rewrites what is already in flight — a
    /// 5 MB transfer logged 54 duplicate blocks that way.
    #[must_use]
    pub fn highest(&self) -> Option<u32> {
        (0..self.total_blocks).rev().find(|block| self.contains(*block))
    }

    /// The raw bytes, for the wire.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Rebuilds a bitmap from bytes received on the wire.
    ///
    /// # Errors
    ///
    /// A description if the length disagrees with the block count, which would mean the two sides
    /// differed about the transfer's size.
    pub fn from_bytes(bytes: Vec<u8>, total_blocks: u32) -> Result<Self, &'static str> {
        let expected = total_blocks.div_ceil(8) as usize;
        if bytes.len() != expected {
            return Err("progress bitmap length does not match the block count");
        }
        Ok(Self { bytes, total_blocks })
    }
}

/// Which blocks a transfer has received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferProgress {
    /// Which transfer.
    pub transfer_id: TransferId,
    /// The bitmap, base64 on the wire.
    pub received: Vec<u8>,
    /// Total blocks, repeated so the receiver can check the two agree.
    pub total_blocks: u32,
    /// Bytes received, for a progress display that does not have to count bits.
    pub bytes_received: u64,
}

/// The sender's assertion that a transfer is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferComplete {
    /// Which transfer.
    pub transfer_id: TransferId,
    /// The digest, repeated. The receiver compares it with the one in the request rather than
    /// trusting the later message alone.
    pub digest: SriDigest,
}

/// Why a transfer ended badly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransferAbortReason {
    /// The user stopped it.
    UserCancelled,
    /// The bytes did not match the declared digest.
    DigestMismatch,
    /// The object is larger than the receiver accepts.
    TooLarge,
    /// A read or write failed.
    IoError,
    /// No progress for longer than the idle timeout.
    IdleTimeout,
    /// The transfer ran longer than the total timeout.
    TotalTimeout,
    /// The receiver declined.
    PeerRejected,
}

impl TransferAbortReason {
    /// Whether restarting could help.
    ///
    /// The distinction drives whether the interface offers a retry button: offering one for a digest
    /// mismatch would invite the user to repeat a failure that will happen again.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::IoError | Self::IdleTimeout | Self::TotalTimeout)
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserCancelled => "user_cancelled",
            Self::DigestMismatch => "digest_mismatch",
            Self::TooLarge => "too_large",
            Self::IoError => "io_error",
            Self::IdleTimeout => "idle_timeout",
            Self::TotalTimeout => "total_timeout",
            Self::PeerRejected => "peer_rejected",
        }
    }
}

/// A transfer being given up on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferAbort {
    /// Which transfer.
    pub transfer_id: TransferId,
    /// Why.
    pub reason: TransferAbortReason,
}

/// The sliding window a transfer keeps in flight.
///
/// A window rather than a block-at-a-time loop because the loop's throughput is bounded by the
/// round-trip time rather than by the link. A 5 MB object in 64 KiB blocks is eighty round trips; at
/// 2 ms each that is a sixth of a second spent waiting instead of sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferWindow {
    /// How many blocks may be unacknowledged at once.
    pub in_flight: u32,
    /// The block size in bytes.
    pub chunk_size: u32,
}

impl Default for TransferWindow {
    fn default() -> Self {
        Self { in_flight: 32, chunk_size: limits::MAX_CHUNK_LEN as u32 }
    }
}

impl TransferWindow {
    /// Checks the window and block size are usable.
    ///
    /// # Errors
    ///
    /// A description of what is wrong.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.in_flight == 0 {
            return Err("in_flight must be non-zero, or no data is ever sent");
        }
        if self.chunk_size == 0 {
            return Err("chunk_size must be non-zero");
        }
        if self.chunk_size as usize > limits::MAX_CHUNK_LEN {
            return Err("chunk_size exceeds the maximum block size");
        }
        Ok(())
    }

    /// How much data is in flight at most.
    #[must_use]
    pub const fn bytes_in_flight(&self) -> u64 {
        self.in_flight as u64 * self.chunk_size as u64
    }

    /// How many blocks an object of `byte_length` needs.
    #[must_use]
    pub const fn block_count(&self, byte_length: u64) -> u32 {
        // Rounded up: a partial trailing block is still a block, and rounding down would drop it.
        // The cast is safe because a transfer with more than 2^32 blocks is far beyond what is
        // accepted.
        byte_length.div_ceil(self.chunk_size as u64) as u32
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionState {
    /// Started, not finished.
    Open,
    /// Finished successfully.
    Succeeded,
    /// Finished unsuccessfully.
    Failed,
    /// Bounded out.
    Expired,
    /// Abandoned by one side.
    Cancelled,
}

impl SessionState {
    /// Whether this is an end state, after which nothing more happens.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Open)
    }

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Tracks which requests are outstanding, so a reply can be matched and a duplicate recognised.
///
/// A small bounded set rather than a record of everything ever sent: what matters is the recent past,
/// and an unbounded list of outstanding requests is a memory leak with a slow fuse.
#[derive(Debug)]
pub struct OutstandingRequests {
    entries: Vec<(RequestId, i64)>,
    capacity: usize,
    window_ms: i64,
}

impl OutstandingRequests {
    /// Tracks up to `capacity` requests within `window_ms`.
    #[must_use]
    pub fn new(capacity: usize, window_ms: i64) -> Self {
        Self { entries: Vec::new(), capacity: capacity.max(1), window_ms }
    }

    /// Records a request as sent, at `now_ms`.
    ///
    /// When full, the oldest entry is dropped: the newest requests are the ones whose replies have
    /// not yet had time to arrive.
    pub fn insert(&mut self, request: RequestId, now_ms: i64) {
        self.expire(now_ms);
        if self.entries.len() >= self.capacity {
            // `remove(0)` is O(n), but n is a small constant and this happens only when the list is
            // full — never on the reply path, which runs per frame.
            self.entries.remove(0);
        }
        self.entries.push((request, now_ms));
    }

    /// Whether a request is still outstanding.
    #[must_use]
    pub fn contains(&self, request: &RequestId) -> bool {
        self.entries.iter().any(|(id, _)| id == request)
    }

    /// Forgets a request, once its reply has arrived.
    pub fn remove(&mut self, request: &RequestId) {
        self.entries.retain(|(id, _)| id != request);
    }

    /// Drops entries older than the window.
    pub fn expire(&mut self, now_ms: i64) {
        let window = self.window_ms;
        self.entries
            .retain(|(_, at)| now_ms.saturating_sub(*at) <= window);
    }

    /// How many requests are outstanding.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is outstanding.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A device's own view of one peer.
///
/// Only the fields the protocol layer needs. The richer "device card" belongs to the kernel, and is
/// derived from this rather than stored beside it — two places holding the same state is how they
/// come to disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSnapshot {
    /// The peer's id.
    pub device_id: DeviceId,
    /// Whether this host has a pairing record for it.
    pub paired: bool,
    /// The last name it reported.
    pub display_name: String,
    /// Which platform it runs.
    pub platform: PlatformKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> SriDigest {
        // 32 bytes of zeros, base64 without padding, is 43 'A' characters.
        SriDigest::new(DigestAlgorithm::Sha256, "A".repeat(43)).expect("valid")
    }

    fn profile() -> PeerProfile {
        PeerProfile {
            device_id: DeviceId::new(),
            display_name: "imba97's laptop".to_owned(),
            platform: PlatformKind::Desktop,
            app_version: "1.0.0".to_owned(),
        }
    }

    #[test]
    fn default_timeouts_are_self_consistent() {
        assert_eq!(SessionTimeouts::default().validate(), Ok(()));
    }

    #[test]
    fn a_result_cache_shorter_than_the_dedup_window_is_refused() {
        let timeouts = SessionTimeouts {
            result_cache: limits::REQUEST_DEDUP_WINDOW - Duration::from_secs(1),
            ..SessionTimeouts::default()
        };
        assert!(timeouts.validate().is_err());
    }

    #[test]
    fn an_idle_timeout_longer_than_the_total_is_refused() {
        let timeouts = SessionTimeouts {
            transfer_idle: Duration::from_secs(3600),
            transfer_total: Duration::from_secs(60),
            ..SessionTimeouts::default()
        };
        assert!(timeouts.validate().is_err());
    }

    #[test]
    fn zero_session_timeouts_are_refused() {
        for timeouts in [
            SessionTimeouts { pairing: Duration::ZERO, ..SessionTimeouts::default() },
            SessionTimeouts { intent: Duration::ZERO, ..SessionTimeouts::default() },
        ] {
            assert!(timeouts.validate().is_err());
        }
    }

    #[test]
    fn a_profile_needs_a_usable_name() {
        let mut profile = profile();
        assert_eq!(profile.validate(), Ok(()));

        profile.display_name = "   ".to_owned();
        assert!(profile.validate().is_err());

        profile.display_name = "x".repeat(PeerProfile::MAX_DISPLAY_NAME + 1);
        assert!(profile.validate().is_err());

        // Counted in characters: a CJK name of the same character count is accepted.
        profile.display_name = "电".repeat(PeerProfile::MAX_DISPLAY_NAME);
        assert_eq!(profile.validate(), Ok(()));

        profile.app_version = String::new();
        assert!(profile.validate().is_err());
    }

    #[test]
    fn pairing_payloads_round_trip() {
        let request = PairRequest {
            profile: profile(),
            user_hint: Some("at the desk".to_owned()),
        };
        let json = serde_json::to_string(&request).expect("serialises");
        assert!(json.contains("displayName"), "{json}");
        assert!(json.contains("deviceId"), "{json}");
        let back: PairRequest = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, request);

        use crate::handshake::LinkToken;

        let response = PairResponse::refused(PairRefusal::Busy.as_str());
        let json = serde_json::to_string(&response).expect("serialises");
        assert!(!json.contains("null"), "an absent reason must be omitted: {json}");
        assert!(
            !json.contains("linkToken"),
            "a refusal issues no token, and an absent token must be omitted: {json}"
        );

        // An acceptance carries the token later links present, in the same message as the acceptance. That pairing is
        // what stops a dialer reaching the state of "paired but holding nothing to present".
        let accepted = PairResponse::accepted("aa".repeat(LinkToken::LEN));
        let json = serde_json::to_string(&accepted).expect("serialises");
        assert!(json.contains("linkToken"), "{json}");
        let back: PairResponse = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back.issued_token(), accepted.issued_token());

        // And a refusal never hands one out, even if a field somehow carried one.
        let with_token = PairResponse {
            accepted: false,
            reason: None,
            link_token: Some("aa".repeat(LinkToken::LEN)),
        };
        assert_eq!(with_token.issued_token(), None, "a refusal must not issue a token");
    }

    #[test]
    fn an_intent_invocation_round_trips_with_its_raw_args() {
        let invocation = IntentInvocation {
            intent_id: IntentId::new(),
            plugin_id: PluginId::parse("@synra-plugin/github-bridge").expect("valid"),
            action: "open-url".to_owned(),
            args: serde_json::value::to_raw_value(&serde_json::json!({ "url": "https://example.com" }))
                .expect("raw"),
            display: Some(IntentDisplay {
                title: "Open this link".to_owned(),
                detail: Some("https://example.com".to_owned()),
                source_display_name: "phone".to_owned(),
            }),
        };

        let json = serde_json::to_string(&invocation).expect("serialises");
        let back: IntentInvocation = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, invocation);
        // The args stay text until somebody reads them.
        assert!(invocation.args.get().contains("example.com"));
    }

    #[test]
    fn an_outcome_is_either_a_result_or_an_error() {
        let intent = IntentId::new();
        assert_eq!(IntentOutcome::ok(intent, None, 12).validate(), Ok(()));
        assert_eq!(
            IntentOutcome::failed(intent, SynraError::unsupported("x"), 5).validate(),
            Ok(())
        );

        // Both at once is refused: an interface that had to choose which to believe would
        // eventually meet a case where they disagree.
        let contradictory = IntentOutcome {
            intent_id: intent,
            ok: true,
            result: None,
            error: Some(SynraError::unsupported("x")),
            elapsed_ms: 5,
        };
        assert!(contradictory.validate().is_err());

        // And a failure with no error tells the user nothing.
        let mute = IntentOutcome {
            intent_id: intent,
            ok: false,
            result: None,
            error: None,
            elapsed_ms: 5,
        };
        assert!(mute.validate().is_err());
    }

    #[test]
    fn a_transfer_request_round_trips_with_flattened_metadata() {
        let request = TransferRequest {
            transfer_id: TransferId::new(),
            kind: TransferKind::PluginBundle,
            byte_length: 1024,
            chunk_size: 256,
            digest: digest(),
            sync_session_id: None,
            meta: TransferMeta::PluginBundle {
                plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
                version: "1.2.0".to_owned(),
            },
        };

        let json = serde_json::to_string(&request).expect("serialises");
        // `flatten` lifts the metadata's own fields to the top level, tagged so a reader knows which
        // variant it is without inferring it from which fields happen to be present.
        assert!(json.contains("\"metaKind\":\"plugin-bundle\""), "{json}");
        assert!(json.contains("\"pluginId\""), "{json}");

        let back: TransferRequest = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, request);
    }

    #[test]
    fn an_attachment_metadata_round_trips() {
        let request = TransferRequest {
            transfer_id: TransferId::new(),
            kind: TransferKind::Attachment,
            byte_length: 10,
            chunk_size: 4,
            digest: digest(),
            sync_session_id: Some(SessionId::new()),
            meta: TransferMeta::Attachment {
                file_name: "report.pdf".to_owned(),
                mime_type: Some("application/pdf".to_owned()),
                context_id: None,
            },
        };

        let json = serde_json::to_string(&request).expect("serialises");
        let back: TransferRequest = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, request);
    }

    #[test]
    fn an_unknown_transfer_kind_is_refused_rather_than_ignored() {
        // A receiver that accepted an unknown kind would have to guess where to put the bytes.
        let json = r#"{"transferId":"0193abcd-0000-7000-8000-000000000000","kind":"mystery",
            "byteLength":1,"chunkSize":1,"digest":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "metaKind":"attachment","fileName":"x"}"#;
        assert!(serde_json::from_str::<TransferRequest>(json).is_err());
    }

    #[test]
    fn a_digest_carries_its_algorithm() {
        let digest = digest();
        assert_eq!(digest.algorithm(), DigestAlgorithm::Sha256);
        assert_eq!(digest.to_string().len(), "sha256-".len() + 43);

        // A digest whose algorithm has to be inferred is one that will eventually be checked with
        // the wrong one, so an unknown prefix is refused.
        assert!(SriDigest::try_from("md5-abc".to_owned()).is_err());
        assert!(SriDigest::try_from("noprefix".to_owned()).is_err());
        assert!(SriDigest::try_from("sha256-tooshort".to_owned()).is_err());
        assert!(SriDigest::try_from(format!("sha256-{}", "!".repeat(43))).is_err());

        let json = serde_json::to_string(&digest).expect("serialises");
        let back: SriDigest = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, digest);
    }

    #[test]
    fn a_progress_bitmap_counts_only_real_blocks() {
        // 10 blocks occupy two bytes, and the second byte's six padding bits must not count as
        // received blocks — otherwise a transfer would look complete before it was.
        let mut bitmap = ProgressBitmap::empty(10);
        assert_eq!(bitmap.received_count(), 0);
        assert!(!bitmap.is_complete());

        bitmap.set(0);
        bitmap.set(9);
        assert_eq!(bitmap.received_count(), 2);
        assert!(bitmap.contains(0));
        assert!(bitmap.contains(9));
        assert!(!bitmap.contains(5));

        // Out-of-range writes are ignored rather than panicking.
        bitmap.set(10);
        bitmap.set(u32::MAX);
        assert_eq!(bitmap.received_count(), 2);
        assert!(!bitmap.contains(10));
    }

    #[test]
    fn a_full_bitmap_is_complete_at_every_boundary() {
        // The byte boundary is where a bit-packing off-by-one hides.
        for total in [0u32, 1, 7, 8, 9, 15, 16, 17, 1000] {
            let bitmap = ProgressBitmap::full(total);
            assert!(bitmap.is_complete(), "total {total}");
            assert_eq!(bitmap.received_count(), total, "total {total}");
            assert!(bitmap.missing().is_empty(), "total {total}");
        }
    }

    #[test]
    fn missing_blocks_are_reported_in_order() {
        let mut bitmap = ProgressBitmap::empty(5);
        bitmap.set(1);
        bitmap.set(3);
        assert_eq!(bitmap.missing(), vec![0, 2, 4]);
    }

    #[test]
    fn a_bitmap_survives_a_trip_through_bytes() {
        let mut bitmap = ProgressBitmap::empty(20);
        for block in [1, 2, 7, 8, 19] {
            bitmap.set(block);
        }

        let restored =
            ProgressBitmap::from_bytes(bitmap.as_bytes().to_vec(), 20).expect("round trips");
        assert_eq!(restored, bitmap);
        assert_eq!(restored.received_count(), 5);

        // A length that disagrees with the block count means the two sides differ about the
        // transfer's size, which is not something to guess about.
        assert!(ProgressBitmap::from_bytes(vec![0; 3], 1000).is_err());
    }

    #[test]
    fn progress_reports_round_trip() {
        let mut bitmap = ProgressBitmap::empty(8);
        bitmap.set(0);
        let progress = TransferProgress {
            transfer_id: TransferId::new(),
            received: bitmap.as_bytes().to_vec(),
            total_blocks: 8,
            bytes_received: 64,
        };

        let json = serde_json::to_string(&progress).expect("serialises");
        let back: TransferProgress = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, progress);
    }

    #[test]
    fn abort_reasons_agree_with_their_retryability() {
        assert!(TransferAbortReason::IoError.is_retryable());
        assert!(TransferAbortReason::IdleTimeout.is_retryable());
        assert!(!TransferAbortReason::DigestMismatch.is_retryable());
        assert!(!TransferAbortReason::UserCancelled.is_retryable());

        for reason in [
            TransferAbortReason::UserCancelled,
            TransferAbortReason::DigestMismatch,
            TransferAbortReason::TooLarge,
            TransferAbortReason::IoError,
            TransferAbortReason::IdleTimeout,
            TransferAbortReason::TotalTimeout,
            TransferAbortReason::PeerRejected,
        ] {
            let json = serde_json::to_string(&reason).expect("serialises");
            assert_eq!(json, format!("\"{}\"", reason.as_str()));
            let back: TransferAbortReason = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, reason);
        }
    }

    #[test]
    fn a_transfer_window_computes_its_block_count() {
        let window = TransferWindow { in_flight: 32, chunk_size: 256 * 1024 };
        assert_eq!(window.validate(), Ok(()));
        assert_eq!(window.bytes_in_flight(), 32 * 256 * 1024);

        assert_eq!(window.block_count(0), 0);
        assert_eq!(window.block_count(1), 1);
        assert_eq!(window.block_count(256 * 1024), 1);
        assert_eq!(window.block_count(256 * 1024 + 1), 2);
    }

    #[test]
    fn a_degenerate_transfer_window_is_refused() {
        assert!(TransferWindow { in_flight: 0, chunk_size: 1024 }.validate().is_err());
        assert!(TransferWindow { in_flight: 1, chunk_size: 0 }.validate().is_err());
        assert!(
            TransferWindow { in_flight: 1, chunk_size: limits::MAX_CHUNK_LEN as u32 + 1 }
                .validate()
                .is_err()
        );
    }

    #[test]
    fn session_states_know_which_are_terminal() {
        assert!(!SessionState::Open.is_terminal());
        for state in [
            SessionState::Succeeded,
            SessionState::Failed,
            SessionState::Expired,
            SessionState::Cancelled,
        ] {
            assert!(state.is_terminal(), "{state:?}");
        }
    }

    #[test]
    fn outstanding_requests_forget_what_has_expired() {
        let mut outstanding = OutstandingRequests::new(4, 1_000);
        let first = RequestId::new();
        outstanding.insert(first, 0);
        assert!(outstanding.contains(&first));

        outstanding.expire(999);
        assert!(outstanding.contains(&first));

        outstanding.expire(1_001);
        assert!(!outstanding.contains(&first));
        assert!(outstanding.is_empty());
    }

    #[test]
    fn outstanding_requests_stay_bounded() {
        // A record that grows without limit is a memory leak with a slow fuse.
        let mut outstanding = OutstandingRequests::new(2, 1_000_000);
        let ids: Vec<_> = (0..5).map(|_| RequestId::new()).collect();
        for (at, id) in ids.iter().enumerate() {
            outstanding.insert(*id, at as i64);
        }
        assert_eq!(outstanding.len(), 2);
        // The oldest are dropped: the newest requests are the ones whose replies have not yet had
        // time to arrive.
        assert!(!outstanding.contains(&ids[0]));
        assert!(outstanding.contains(&ids[4]));
    }

    #[test]
    fn a_answered_request_stops_being_outstanding() {
        let mut outstanding = OutstandingRequests::new(4, 1_000_000);
        let id = RequestId::new();
        outstanding.insert(id, 0);
        assert!(outstanding.contains(&id));

        outstanding.remove(&id);
        assert!(!outstanding.contains(&id));
        assert!(outstanding.is_empty());
    }

    #[test]
    fn platform_kinds_report_mobility() {
        assert!(!PlatformKind::Desktop.is_mobile());
        assert!(PlatformKind::Android.is_mobile());
        assert!(PlatformKind::Ios.is_mobile());
        assert_eq!(PlatformKind::Desktop.to_string(), "desktop");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A bitmap built by setting blocks individually reports exactly those blocks. Bit packing
        /// is where an off-by-one hides, so this exercises boundaries as well as the middle.
        #[test]
        fn a_bitmap_reports_exactly_what_was_set(
            total in 1u32..200,
            blocks in proptest::collection::vec(0u32..400, 0..40),
        ) {
            let mut bitmap = ProgressBitmap::empty(total);
            let mut expected = std::collections::BTreeSet::new();
            for block in &blocks {
                bitmap.set(*block);
                if *block < total {
                    expected.insert(*block);
                }
            }

            prop_assert_eq!(bitmap.received_count(), expected.len() as u32);
            for block in 0..total {
                prop_assert_eq!(bitmap.contains(block), expected.contains(&block));
            }
            prop_assert_eq!(bitmap.is_complete(), expected.len() as u32 == total);
        }

        /// The block count is the ceiling of the division, never the floor. Rounding down would
        /// silently drop a trailing partial block.
        #[test]
        fn block_count_always_covers_every_byte(
            byte_length in 0u64..10_000_000,
            chunk_size in 1u32..(limits::MAX_CHUNK_LEN as u32),
        ) {
            let window = TransferWindow { in_flight: 1, chunk_size };
            let blocks = u64::from(window.block_count(byte_length));
            prop_assert!(blocks * u64::from(chunk_size) >= byte_length);
            if blocks > 0 {
                prop_assert!((blocks - 1) * u64::from(chunk_size) < byte_length);
            }
        }

        /// A digest built from a well-formed pair survives the wire; anything else is refused.
        #[test]
        fn digests_are_strict(value in "[A-Za-z0-9+/]{0,60}") {
            let built = SriDigest::new(DigestAlgorithm::Sha256, value.clone());
            if value.len() == 43 {
                let digest = built.expect("43 base64 characters is a sha256 digest");
                let back = SriDigest::try_from(digest.to_string()).expect("round trips");
                prop_assert_eq!(back, digest);
            }
            else {
                prop_assert!(built.is_err());
            }
        }
    }
}

    #[test]
    fn a_pairing_response_without_a_token_still_decodes() {
        // A build that answers a pairing request without issuing a token — an older one, or a refusal — must remain
        // readable. `deny_unknown_fields` rejects fields this build does not know, so the field being `default` is what
        // keeps the two directions apart: a missing field is fine, an unknown one is not.
        let older = r#"{"accepted":true}"#;
        let response: PairResponse = serde_json::from_str(older).expect("an absent token decodes");
        assert!(response.accepted);
        assert_eq!(response.link_token, None);
        assert_eq!(response.issued_token(), None, "nothing was issued, so nothing may be presented");

        // And a response that carries one round trips.
        use crate::handshake::LinkToken;
        let token = LinkToken::from_bytes([0x7f; LinkToken::LEN]).to_hex();
        let json = format!(r#"{{"accepted":true,"linkToken":"{token}"}}"#);
        let response: PairResponse = serde_json::from_str(&json).expect("decodes");
        assert_eq!(response.issued_token(), Some(token.as_str()));
    }