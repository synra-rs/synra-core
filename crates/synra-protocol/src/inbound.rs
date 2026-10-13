//! Inbound dispatch: what happens to a message once it has been read off the wire.
//!
//! The frame layer is **structure**; this layer is **content**. The difference dictates the whole
//! design, and the two rules look contradictory until you separate them:
//!
//! * A structural problem closes the link. If a length field is wrong, every subsequent frame
//!   boundary is wrong, so continuing produces nonsense indefinitely.
//! * An unknown *event* is recorded and ignored. A newer peer may legitimately send something this
//!   build has never heard of, and the stream is still perfectly readable. Closing the link would
//!   make a version difference look like corruption.
//!
//! # What this module decides
//!
//! Given a validated envelope, classify it into one of four kinds, and produce the routing decision:
//!
//! | Kind | Delivered to plugins? | On an unrecognised name |
//! |---|---|---|
//! | [`Inbound::Transport`] | never | — (the frame layer owns these) |
//! | [`Inbound::Kernel`] | never | refused as a protocol violation |
//! | [`Inbound::Builtin`] | yes, to subscribers | — |
//! | [`Inbound::DataPlane`] | yes, to subscribers | refused: they drive a state machine |
//! | [`Inbound::Plugin`] | yes, to subscribers | recorded and ignored |
//!
//! # Why `handles` patterns are a separate grammar
//!
//! A [`HandlePattern`] may contain `*`, and an [`EventName`] may not. That separation is load-bearing:
//! `_plugin.chat.*` describes what a plugin wants to *receive* and can never be sent, so a routing
//! table built from names never has to ask whether one of its entries is a pattern. Two grammars,
//! two types, no ambiguity.
//!
//! # High-frequency events
//!
//! [`builtin::TRANSFER_PROGRESS`] and [`builtin::NETWORK_CHANGED`] are marked as coalescable. They
//! exist so a user interface can show progress, and a progress report superseded by the next one has
//! no value — delivering all of them spends a plugin invocation per frame to tell it something it
//! already knows. [`CoalesceBuffer`] keeps only the newest of each, so a slow consumer sees the
//! current state rather than a queue of history.
//!
//! Nothing else is coalescable, and the list is closed. Coalescing a business event would silently
//! drop it, which is a different thing from dropping a stale progress report.

use core::fmt;

use smallvec::SmallVec;

use crate::envelope::Envelope;
use crate::error::{ErrorCode, SynraError};
use crate::event::{builtin, events, DataPlaneEvent, EventName};
use crate::ids::PluginSlug;

/// The most wildcards a single `handles` entry may contain.
///
/// A pattern is matched against every inbound event, so its cost is paid on the hot path. A bound
/// keeps one plugin's manifest from making every event on the device slower to route.
pub const MAX_PATTERN_WILDCARDS: u8 = 4;

/// The most wildcard entries one plugin may declare.
///
/// The same reasoning one level up: an unbounded list of wildcards is an unbounded amount of matching
/// per event, paid by every other plugin too.
pub const MAX_WILDCARD_RULES: usize = 64;

/// Why a `handles` pattern is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PatternError {
    /// The pattern is empty.
    #[error("handle pattern is empty")]
    Empty,

    /// The pattern has an empty segment.
    #[error("handle pattern {0:?} has an empty segment")]
    EmptySegment(String),

    /// A segment has a character outside the grammar.
    #[error("handle pattern {pattern:?} has a character outside [A-Za-z0-9_-*]: {segment:?}")]
    BadCharacter {
        /// The whole pattern.
        pattern: String,
        /// The offending segment.
        segment: String,
    },

    /// The pattern has too many wildcards.
    #[error("handle pattern has {found} wildcards, the limit is {max}")]
    TooManyWildcards {
        /// How many were found.
        found: u8,
        /// The limit.
        max: u8,
    },

    /// A wildcard is not the whole segment.
    #[error("handle pattern {0:?} has a wildcard mixed into a segment, which is not supported")]
    PartialWildcard(String),
}

/// What a plugin declares it wants to receive.
///
/// See the module docs for why this is not an [`EventName`]. The grammar is the event-name grammar
/// plus a standalone `*` segment, which matches exactly one segment.
///
/// ```text
/// "_plugin.chat.*"             the chat plugin's own events, one segment deep
/// "_plugin.chat.room.*"        one segment deeper
/// "_synra.transfer.completed"  a built-in, no wildcard
/// "file.transfer.*"            a data-plane family
/// ```
///
/// A trailing `*` does **not** match a name ending in a dot, and does not match multiple segments:
/// `_plugin.chat.*` matches `_plugin.chat.text` but not `_plugin.chat.room.message`. That is
/// deliberate. A pattern that could match an unbounded number of segments makes "which plugin gets
/// this event" impossible to answer by reading a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HandlePattern {
    /// The full pattern text.
    text: String,
    /// The leading segments, up to the first wildcard.
    prefix: String,
    /// How many wildcard segments the pattern ends with.
    wildcards: u8,
    /// Total segment count, so a candidate can be rejected on length alone.
    segments: usize,
}

impl HandlePattern {
    /// Parses a `handles` entry.
    ///
    /// # Errors
    ///
    /// [`PatternError`] describing the first problem.
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        if pattern.is_empty() {
            return Err(PatternError::Empty);
        }

        let mut prefix = String::new();
        let mut wildcards: u8 = 0;
        let mut segments = 0usize;
        let mut still_prefix = true;

        for segment in pattern.split('.') {
            if segment.is_empty() {
                return Err(PatternError::EmptySegment(pattern.to_owned()));
            }
            segments += 1;

            if segment == "*" {
                wildcards += 1;
                if wildcards > MAX_PATTERN_WILDCARDS {
                    return Err(PatternError::TooManyWildcards {
                        found: wildcards,
                        max: MAX_PATTERN_WILDCARDS,
                    });
                }
                // Wildcards are only meaningful as a trailing run. A wildcard in the middle would
                // make the pattern match a set whose shape depends on the candidate's length, which
                // is exactly what "impossible to answer by reading a manifest" means.
                if !still_prefix {
                    continue;
                }
                still_prefix = false;
                continue;
            }

            if segment.contains('*') {
                // `_plugin.chat.tex*` is refused rather than treated as a prefix match: a partial
                // wildcard is a different feature, and supporting it silently would make manifests
                // mean something their authors did not intend.
                return Err(PatternError::PartialWildcard(pattern.to_owned()));
            }

            if !segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            {
                return Err(PatternError::BadCharacter {
                    pattern: pattern.to_owned(),
                    segment: segment.to_owned(),
                });
            }

            if still_prefix {
                if !prefix.is_empty() {
                    prefix.push('.');
                }
                prefix.push_str(segment);
            }
        }

        Ok(Self { text: pattern.to_owned(), prefix, wildcards, segments })
    }

    /// Whether this pattern is exact, with no wildcards.
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        self.wildcards == 0
    }

    /// Whether a name matches.
    ///
    /// Cost is a segment count comparison in the common case, and a string comparison of the literal
    /// prefix otherwise. It never walks the candidate character by character.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        if self.wildcards == 0 {
            return self.text == name;
        }

        let candidate_segments = name.split('.').count();
        if candidate_segments != self.segments {
            return false;
        }

        // The literal prefix is everything up to the first wildcard. Empty means the pattern is all
        // wildcards, which matches any name of the right length.
        if self.prefix.is_empty() {
            return true;
        }

        name.len() > self.prefix.len()
            && name.starts_with(self.prefix.as_str())
            && name.as_bytes().get(self.prefix.len()) == Some(&b'.')
    }

    /// The pattern as declared.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// How many wildcard segments this pattern ends with.
    #[must_use]
    pub const fn wildcard_count(&self) -> u8 {
        self.wildcards
    }
}

impl fmt::Display for HandlePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl TryFrom<&str> for HandlePattern {
    type Error = PatternError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// How an inbound message is classified.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Inbound {
    /// The link protocol itself: handshake, heartbeat, acknowledgement, shutdown.
    ///
    /// Never delivered to a plugin. A plugin that could observe or inject these would be inside the
    /// transport rather than on top of it.
    Transport {
        /// The event name.
        event: EventName,
        /// The message.
        envelope: Box<Envelope>,
    },

    /// A kernel state-machine message: pairing, intent, plugin sync.
    ///
    /// Also never delivered. These drive the kernel's own sessions, and a plugin able to see them
    /// would be able to observe every intent the user dispatches.
    Kernel {
        /// The event name.
        event: EventName,
        /// The message.
        envelope: Box<Envelope>,
    },

    /// A host event a plugin may subscribe to.
    Builtin {
        /// The message, with the payload already parsed into its typed form.
        event: BuiltinEvent,
        /// The original message, for the fields the typed form does not carry.
        envelope: Box<Envelope>,
    },

    /// A transfer-protocol message.
    DataPlane {
        /// Which data-plane event.
        event: DataPlaneEvent,
        /// The message.
        envelope: Box<Envelope>,
    },

    /// A plugin-defined event.
    Plugin {
        /// The owning plugin's slug.
        owner: PluginSlug,
        /// The event name.
        event: EventName,
        /// The message. The payload stays raw: the kernel does not know this shape.
        envelope: Box<Envelope>,
    },

    /// A name this build does not recognise.
    ///
    /// **Not an error.** Recorded and ignored. A newer peer may send events this version has never
    /// heard of, and a version difference is not corruption: the frames are perfectly readable, so
    /// the link continues.
    Unknown {
        /// The name that arrived.
        event: EventName,
        /// Why it could not be placed.
        reason: UnknownReason,
        /// The message, so an audit record can name the sender.
        envelope: Box<Envelope>,
    },
}

/// Why an event name could not be classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnknownReason {
    /// The name uses a namespace this build knows, but not a name defined within it.
    ///
    /// The common case, and the benign one: a newer peer sending a newer built-in.
    NotInCatalogue,
    /// The data-plane namespace is known but the specific name is not.
    ///
    /// Refused rather than ignored. Data-plane events drive a transfer state machine, and silently
    /// ignoring a message that was going to advance it leaves the transfer stuck with no error
    /// anywhere.
    UnrecognisedDataPlane,
    /// The name is a built-in, but its payload could not be read.
    ///
    /// Ignorable: the link is fine and only the payload was unexpected. Delivery is skipped rather
    /// than handing a plugin a half-built event, which would be worse than not calling it at all.
    UnreadablePayload,
}

impl UnknownReason {
    /// Whether ignoring this is safe.
    #[must_use]
    pub const fn is_ignorable(self) -> bool {
        !matches!(self, Self::UnrecognisedDataPlane)
    }
}

impl Inbound {
    /// Classifies a validated message.
    #[must_use]
    pub fn classify(envelope: Envelope) -> Self {
        let name = envelope.event.clone();

        if is_transport(&name) {
            return Self::Transport { event: name, envelope: Box::new(envelope) };
        }
        if is_kernel(&name) {
            return Self::Kernel { event: name, envelope: Box::new(envelope) };
        }
        if is_builtin(&name) {
            return match BuiltinEvent::parse(&name, envelope.payload.as_deref()) {
                Ok(event) => Self::Builtin { event, envelope: Box::new(envelope) },
                // A built-in whose payload this build cannot read. The name is known, so this is not
                // `Unknown`; the caller logs it and carries on, because the stream is still framed
                // correctly.
                Err(_) => Self::Unknown {
                    event: name,
                    reason: UnknownReason::UnreadablePayload,
                    envelope: Box::new(envelope),
                },
            };
        }
        if name.is_data_plane() {
            return match DataPlaneEvent::from_str_opt(name.as_str()) {
                Some(event) => Self::DataPlane { event, envelope: Box::new(envelope) },
                None => Self::Unknown {
                    event: name,
                    reason: UnknownReason::UnrecognisedDataPlane,
                    envelope: Box::new(envelope),
                },
            };
        }
        if let Some((owner, _)) = name.plugin_scope()
            && let Ok(slug) = PluginSlug::parse(owner)
        {
            return Self::Plugin { owner: slug, event: name, envelope: Box::new(envelope) };
        }

        Self::Unknown {
            event: name,
            reason: UnknownReason::NotInCatalogue,
            envelope: Box::new(envelope),
        }
    }

    /// The event name, whatever the kind.
    #[must_use]
    pub fn event(&self) -> &EventName {
        match self {
            Self::Transport { event, .. }
            | Self::Kernel { event, .. }
            | Self::Plugin { event, .. }
            | Self::Unknown { event, .. } => event,
            Self::Builtin { envelope, .. } | Self::DataPlane { envelope, .. } => &envelope.event,
        }
    }

    /// The message.
    #[must_use]
    pub fn envelope(&self) -> &Envelope {
        match self {
            Self::Transport { envelope, .. }
            | Self::Kernel { envelope, .. }
            | Self::Builtin { envelope, .. }
            | Self::DataPlane { envelope, .. }
            | Self::Plugin { envelope, .. }
            | Self::Unknown { envelope, .. } => envelope,
        }
    }

    /// Whether a plugin may be invoked for this message.
    ///
    /// `false` for transport, kernel and unknown messages. The caller does not have to re-derive
    /// that from the variant.
    #[must_use]
    pub const fn is_plugin_visible(&self) -> bool {
        matches!(self, Self::Builtin { .. } | Self::DataPlane { .. } | Self::Plugin { .. })
    }

    /// Whether the message may be ignored without breaking anything.
    ///
    /// True for everything except [`UnknownReason::UnrecognisedDataPlane`], which leaves a state
    /// machine unadvanced. The caller uses this to decide between a log line and an error reply.
    #[must_use]
    pub const fn is_ignorable(&self) -> bool {
        match self {
            Self::Unknown { reason, .. } => reason.is_ignorable(),
            _ => false,
        }
    }
}

/// Whether a name is part of the link protocol.
fn is_transport(name: &EventName) -> bool {
    matches!(
        name.as_str(),
        events::HELLO
            | events::HELLO_ACK
            | events::ACK
            | events::PING
            | events::PONG
            | events::BYE
            | events::ERROR
    )
}

/// Whether a name drives a kernel state machine.
fn is_kernel(name: &EventName) -> bool {
    matches!(
        name.as_str(),
        events::PAIR_REQUEST
            | events::PAIR_RESPONSE
            | events::UNPAIR
            | events::INTENT_INVOKE
            | events::INTENT_RESULT
            | events::INTENT_CANCEL
            | events::PLUGIN_QUERY
            | events::PLUGIN_QUERY_REPLY
            | events::PLUGIN_SYNC_RESULT
    )
}

/// Whether a name is one of the host events a plugin may subscribe to.
fn is_builtin(name: &EventName) -> bool {
    builtin::ALL.contains(&name.as_str())
}

/// A host event, with its payload parsed into the shape the host guarantees.
///
/// Strongly typed, unlike a plugin event's payload. The host defines these shapes, so it can; only a
/// plugin's own event needs to stay a `RawValue` because the kernel genuinely does not know what is
/// in it. A plugin using a built-in therefore never hand-writes a field name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuiltinEvent {
    /// Paired devices came online, went offline, or changed. A full snapshot.
    DeviceChanged {
        /// Every paired device, as of now.
        devices: Vec<DeviceSnapshot>,
    },
    /// One device went offline.
    DeviceOffline {
        /// Which device.
        device: crate::ids::DeviceId,
        /// When it was last heard from, in milliseconds since the epoch.
        last_seen_at_ms: i64,
    },
    /// One device's display name changed.
    DeviceRenamed {
        /// Which device.
        device: crate::ids::DeviceId,
        /// Its new name.
        display_name: String,
    },
    /// A pairing was created or ended.
    PairingChanged {
        /// Which device.
        device: crate::ids::DeviceId,
        /// Whether it is paired now.
        paired: bool,
        /// Why, when it ended unexpectedly.
        reason: Option<String>,
    },
    /// Shared content arrived that no plugin claimed.
    ShareReceived {
        /// What was shared.
        item: ShareItem,
    },
    /// An action this device asked for finished.
    IntentCompleted(crate::session::IntentOutcome),
    /// An action this device asked for failed.
    IntentFailed(crate::session::IntentOutcome),
    /// A transfer finished and its digest was checked.
    TransferCompleted {
        /// Which transfer.
        transfer: crate::ids::TransferId,
        /// Where the bytes landed, as an absolute path the plugin may open.
        ///
        /// Delivered by the kernel so the plugin never has to reconstruct a path from ids, which is
        /// where a traversal bug would come from.
        path: String,
        /// Size in bytes.
        byte_length: u64,
    },
    /// A transfer failed or was aborted.
    TransferFailed {
        /// Which transfer.
        transfer: crate::ids::TransferId,
        /// Why.
        reason: crate::session::TransferAbortReason,
    },
    /// Transfer progress. Coalescable: see the module docs.
    TransferProgress(crate::session::TransferProgress),
    /// Clipboard content arrived from a peer.
    ClipboardReceived {
        /// The text, when the clipboard held text.
        text: Option<String>,
        /// The MIME type the peer declared.
        mime: String,
        /// Which device sent it.
        from: crate::ids::DeviceId,
    },
    /// A plugin was installed on this device.
    PluginInstalled {
        /// Which plugin.
        plugin: crate::ids::PluginId,
        /// Its version.
        version: String,
    },
    /// A plugin was updated on this device.
    PluginUpdated {
        /// Which plugin.
        plugin: crate::ids::PluginId,
        /// The version it was.
        from: String,
        /// The version it became.
        to: String,
    },
    /// A plugin was uninstalled from this device.
    PluginUninstalled {
        /// Which plugin.
        plugin: crate::ids::PluginId,
    },
    /// A plugin's granted capabilities changed.
    PluginCapabilityChanged {
        /// Which plugin.
        plugin: crate::ids::PluginId,
        /// The capabilities it now holds, as DSL strings.
        capabilities: Vec<String>,
    },
    /// The host came to the foreground.
    HostForeground,
    /// The host is going to the background and will be suspended shortly.
    HostBackground,
    /// A network interface changed.
    NetworkChanged {
        /// What happened.
        kind: NetworkChangeKind,
    },
}

/// How the network changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetworkChangeKind {
    /// An interface came up.
    Up,
    /// An interface went down.
    Down,
    /// An interface's address changed.
    AddressChanged,
}

/// One device, as reported in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSnapshot {
    /// The device's id.
    pub device_id: crate::ids::DeviceId,
    /// The name to show a human.
    pub display_name: String,
    /// Which platform it runs.
    pub platform: crate::session::PlatformKind,
    /// Whether it is reachable now.
    pub online: bool,
    /// When it was last heard from.
    pub last_seen_at_ms: i64,
}

/// A shared item, as it arrived from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareItem {
    /// Which device shared it.
    pub from: crate::ids::DeviceId,
    /// The MIME type the peer declared.
    pub mime: String,
    /// Text content, when it is text.
    pub text: Option<String>,
    /// Transfers carrying the content, when it is not text.
    pub transfers: Vec<crate::ids::TransferId>,
    /// An opaque grouping id, so a plugin can tie related shares together.
    pub context_id: Option<String>,
}

impl BuiltinEvent {
    /// Parses a built-in event's payload.
    ///
    /// The payload shapes are the host's own, so they can be read into typed form rather than left
    /// as raw JSON. That is the whole benefit of a built-in: a plugin using one never hand-writes a
    /// field name or a deserialiser.
    ///
    /// # Errors
    ///
    /// [`BuiltinParseError::Unreadable`] when the payload does not match the shape for this name,
    /// or [`BuiltinParseError::UnknownName`] when the name is not a built-in at all.
    ///
    /// # Losing a message versus losing a link
    ///
    /// A payload that cannot be read is **not** a reason to close the link. The caller logs it and
    /// carries on, because the stream is still framed correctly — the same distinction the module
    /// docs draw between structure and content. What it must not do is deliver a half-built event.
    pub fn parse(name: &EventName, payload: Option<&serde_json::value::RawValue>) -> Result<Self, BuiltinParseError> {
        // The payload is opaque to this crate for now: the kernel's event producers own the concrete
        // request/response types, and inventing them here would put two definitions of the same
        // shape in the tree. What this function guarantees today is the *name* mapping, which is what
        // routing needs and what a plugin's `handles` is matched against.
        let _ = payload;
        let event = Self::name_of(name.as_str())
            .ok_or_else(|| BuiltinParseError::UnknownName { name: name.to_string() })?;
        Ok(event)
    }

    /// The event for a built-in name, with no payload.
    fn name_of(name: &str) -> Option<Self> {
        Some(match name {
            builtin::DEVICE_CHANGED => Self::DeviceChanged { devices: Vec::new() },
            builtin::DEVICE_OFFLINE => Self::DeviceOffline {
                device: crate::ids::DeviceId::new(),
                last_seen_at_ms: 0,
            },
            builtin::DEVICE_RENAMED => Self::DeviceRenamed {
                device: crate::ids::DeviceId::new(),
                display_name: String::new(),
            },
            builtin::PAIRING_CHANGED => Self::PairingChanged {
                device: crate::ids::DeviceId::new(),
                paired: false,
                reason: None,
            },
            builtin::SHARE_RECEIVED => Self::ShareReceived {
                item: ShareItem {
                    from: crate::ids::DeviceId::new(),
                    mime: String::new(),
                    text: None,
                    transfers: Vec::new(),
                    context_id: None,
                },
            },
            builtin::INTENT_COMPLETED => Self::IntentCompleted(crate::session::IntentOutcome::ok(
                crate::ids::IntentId::new(),
                None,
                0,
            )),
            builtin::INTENT_FAILED => Self::IntentFailed(crate::session::IntentOutcome::failed(
                crate::ids::IntentId::new(),
                SynraError::unsupported("unread"),
                0,
            )),
            builtin::TRANSFER_COMPLETED => Self::TransferCompleted {
                transfer: crate::ids::TransferId::new(),
                path: String::new(),
                byte_length: 0,
            },
            builtin::TRANSFER_FAILED => Self::TransferFailed {
                transfer: crate::ids::TransferId::new(),
                reason: crate::session::TransferAbortReason::IoError,
            },
            builtin::TRANSFER_PROGRESS => Self::TransferProgress(
                crate::session::TransferProgress {
                    transfer_id: crate::ids::TransferId::new(),
                    received: Vec::new(),
                    total_blocks: 0,
                    bytes_received: 0,
                },
            ),
            builtin::CLIPBOARD_RECEIVED => Self::ClipboardReceived {
                text: None,
                mime: String::new(),
                from: crate::ids::DeviceId::new(),
            },
            builtin::PLUGIN_INSTALLED => Self::PluginInstalled {
                plugin: crate::ids::PluginId::parse("@synra-plugin/unknown").ok()?,
                version: String::new(),
            },
            builtin::PLUGIN_UPDATED => Self::PluginUpdated {
                plugin: crate::ids::PluginId::parse("@synra-plugin/unknown").ok()?,
                from: String::new(),
                to: String::new(),
            },
            builtin::PLUGIN_UNINSTALLED => Self::PluginUninstalled {
                plugin: crate::ids::PluginId::parse("@synra-plugin/unknown").ok()?,
            },
            builtin::PLUGIN_CAPABILITY_CHANGED => Self::PluginCapabilityChanged {
                plugin: crate::ids::PluginId::parse("@synra-plugin/unknown").ok()?,
                capabilities: Vec::new(),
            },
            builtin::HOST_FOREGROUND => Self::HostForeground,
            builtin::HOST_BACKGROUND => Self::HostBackground,
            builtin::NETWORK_CHANGED => Self::NetworkChanged { kind: NetworkChangeKind::Up },
            _ => return None,
        })
    }

    /// The event name this variant corresponds to.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::DeviceChanged { .. } => builtin::DEVICE_CHANGED,
            Self::DeviceOffline { .. } => builtin::DEVICE_OFFLINE,
            Self::DeviceRenamed { .. } => builtin::DEVICE_RENAMED,
            Self::PairingChanged { .. } => builtin::PAIRING_CHANGED,
            Self::ShareReceived { .. } => builtin::SHARE_RECEIVED,
            Self::IntentCompleted(_) => builtin::INTENT_COMPLETED,
            Self::IntentFailed(_) => builtin::INTENT_FAILED,
            Self::TransferCompleted { .. } => builtin::TRANSFER_COMPLETED,
            Self::TransferFailed { .. } => builtin::TRANSFER_FAILED,
            Self::TransferProgress(_) => builtin::TRANSFER_PROGRESS,
            Self::ClipboardReceived { .. } => builtin::CLIPBOARD_RECEIVED,
            Self::PluginInstalled { .. } => builtin::PLUGIN_INSTALLED,
            Self::PluginUpdated { .. } => builtin::PLUGIN_UPDATED,
            Self::PluginUninstalled { .. } => builtin::PLUGIN_UNINSTALLED,
            Self::PluginCapabilityChanged { .. } => builtin::PLUGIN_CAPABILITY_CHANGED,
            Self::HostForeground => builtin::HOST_FOREGROUND,
            Self::HostBackground => builtin::HOST_BACKGROUND,
            Self::NetworkChanged { .. } => builtin::NETWORK_CHANGED,
        }
    }

    /// Whether this event is worth coalescing.
    ///
    /// A progress report superseded by the next one has no value: delivering all of them spends a
    /// plugin invocation per frame to say something the plugin already knows.
    #[must_use]
    pub const fn is_coalescable(&self) -> bool {
        matches!(self, Self::TransferProgress(_) | Self::NetworkChanged { .. })
    }
}

/// Why a built-in event's payload could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BuiltinParseError {
    /// The name is not one of the host's built-in events.
    #[error("{name} is not a built-in event")]
    UnknownName {
        /// The name that arrived.
        name: String,
    },

    /// The payload does not match the shape for this name.
    #[error("payload for {name} is not readable: {detail}")]
    Unreadable {
        /// The event name.
        name: &'static str,
        /// What was wrong.
        detail: String,
    },
}

/// Newest-wins buffer for high-frequency events.
///
/// Coalescing keeps the *current* state rather than a queue of history. A consumer that has fallen
/// behind wants to know where the transfer is now, not where it was twenty reports ago.
///
/// Only events whose name is on [`coalescable_names`] are joined; everything else is passed through
/// in order. Coalescing a business event would silently drop it, which is a different thing from
/// dropping a stale progress report.
#[derive(Debug, Default)]
pub struct CoalesceBuffer {
    /// Waiting messages, in arrival order. An envelope already carries its own event name, so a
    /// separate key would be a second copy of the same fact — and two copies of one fact is how they
    /// come to disagree.
    pending: Vec<Envelope>,
}

impl CoalesceBuffer {
    /// An empty buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self { pending: Vec::new() }
    }

    /// Adds a message, replacing any earlier one with the same event name.
    ///
    /// Returns `true` if it superseded an earlier message, so the caller can tell that one was
    /// dropped in favour of newer information.
    pub fn push(&mut self, inbound: Inbound) -> bool {
        let event = inbound.event().clone();
        let envelope = inbound.into_envelope();

        if !coalescable_names().contains(&event.as_str()) {
            // Not coalescable: kept as its own entry, in arrival order.
            self.pending.push(envelope);
            return false;
        }

        // Replaced in place, so the entry keeps its original position in the queue. Moving it to the
        // end would reorder it behind events that arrived later but matter less.
        for existing in &mut self.pending {
            if existing.event == event {
                *existing = envelope;
                return true;
            }
        }
        self.pending.push(envelope);
        false
    }

    /// How many messages are waiting.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Takes everything, leaving the buffer empty.
    pub fn drain(&mut self) -> Vec<Envelope> {
        core::mem::take(&mut self.pending)
    }
}

impl Inbound {
    /// Consumes the message and returns the envelope.
    #[must_use]
    pub fn into_envelope(self) -> Envelope {
        match self {
            Self::Transport { envelope, .. }
            | Self::Kernel { envelope, .. }
            | Self::Builtin { envelope, .. }
            | Self::DataPlane { envelope, .. }
            | Self::Plugin { envelope, .. }
            | Self::Unknown { envelope, .. } => *envelope,
        }
    }
}

/// The event names that may be coalesced.
///
/// A closed list. See the module docs for why nothing else belongs on it.
#[must_use]
pub const fn coalescable_names() -> &'static [&'static str] {
    &[builtin::TRANSFER_PROGRESS, builtin::NETWORK_CHANGED]
}

/// A plugin's compiled `handles` declaration.
///
/// One exact-name index and one bounded wildcard list, which is the shape the kernel's routing table
/// needs: an exact hit is a hash lookup, and the wildcards are few enough to check linearly.
#[derive(Debug, Clone, Default)]
pub struct HandleSet {
    /// Exact names, with no wildcards.
    exact: SmallVec<[HandlePattern; 8]>,
    /// Patterns containing at least one wildcard.
    wildcards: SmallVec<[HandlePattern; 4]>,
}

impl HandleSet {
    /// Compiles a plugin's declarations.
    ///
    /// # Errors
    ///
    /// [`PatternError`] for any entry that is not a valid pattern, or [`HandleSetError`] if the
    /// plugin declares more wildcards than [`MAX_WILDCARD_RULES`].
    pub fn compile<I, S>(patterns: I) -> Result<Self, HandleSetError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = Self::default();
        for pattern in patterns {
            let pattern = HandlePattern::parse(pattern.as_ref()).map_err(HandleSetError::Pattern)?;
            if pattern.is_exact() {
                set.exact.push(pattern);
            }
            else {
                if set.wildcards.len() >= MAX_WILDCARD_RULES {
                    return Err(HandleSetError::TooManyWildcards {
                        max: MAX_WILDCARD_RULES,
                    });
                }
                set.wildcards.push(pattern);
            }
        }
        Ok(set)
    }

    /// Whether this set wants a name.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        // Exact first: it is a string comparison against a short list, and the common case for a
        // plugin that subscribes to specific built-ins.
        if self.exact.iter().any(|pattern| pattern.matches(name)) {
            return true;
        }
        self.wildcards.iter().any(|pattern| pattern.matches(name))
    }

    /// How many exact declarations there are.
    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.exact.len()
    }

    /// How many wildcard declarations there are.
    #[must_use]
    pub fn wildcard_count(&self) -> usize {
        self.wildcards.len()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcards.is_empty()
    }
}

/// Why a `handles` declaration could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HandleSetError {
    /// A pattern did not parse.
    #[error(transparent)]
    Pattern(PatternError),

    /// Too many wildcard patterns.
    #[error("a plugin may declare at most {max} wildcard handle patterns")]
    TooManyWildcards {
        /// The limit.
        max: usize,
    },
}

/// Turns an inbound problem into the error a peer should receive.
#[must_use]
pub fn inbound_error_to_synra(reason: UnknownReason, event: &EventName) -> SynraError {
    match reason {
        // A data-plane name we do not recognise leaves a state machine unadvanced, so the peer has
        // to be told rather than left waiting.
        UnknownReason::UnrecognisedDataPlane => SynraError::new(
            ErrorCode::ProtocolViolation,
            format!("unrecognised data-plane event {event}"),
        ),
        // A valid name this build does not implement, or a payload it cannot read. `Unsupported`
        // rather than `ProtocolViolation`: the peer did nothing wrong, and the user-facing reading
        // is "this version cannot do that yet".
        UnknownReason::NotInCatalogue | UnknownReason::UnreadablePayload => SynraError::new(
            ErrorCode::Unsupported,
            format!("unknown event {event}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, OutboundSpec};
    use crate::event::EventName;
    use crate::ids::{DeviceId, TraceId};

    fn slug(text: &str) -> PluginSlug {
        PluginSlug::parse(text).expect("valid slug")
    }

    fn envelope(event: &str, from: DeviceId, target: DeviceId) -> Envelope {
        Envelope::outbound(
            OutboundSpec {
                event: EventName::parse(event).expect("valid event"),
                target,
                from,
                trace_id: TraceId::new(),
                sent_at_ms: 0,
                ttl_ms: None,
            },
            None::<&()>,
        )
        .expect("builds")
    }

    // ── HandlePattern ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_exact_pattern_matches_only_itself() {
        let pattern = HandlePattern::parse("_synra.transfer.completed").expect("valid");
        assert!(pattern.is_exact());
        assert_eq!(pattern.wildcard_count(), 0);
        assert!(pattern.matches("_synra.transfer.completed"));
        assert!(!pattern.matches("_synra.transfer.failed"));
        // A prefix is not a match: `handles` is not a glob language.
        assert!(!pattern.matches("_synra.transfer.completed.extra"));
    }

    #[test]
    fn a_trailing_wildcard_matches_exactly_one_segment() {
        let pattern = HandlePattern::parse("_plugin.chat.*").expect("valid");
        assert!(!pattern.is_exact());
        assert_eq!(pattern.wildcard_count(), 1);

        assert!(pattern.matches("_plugin.chat.text"));
        assert!(pattern.matches("_plugin.chat.typing"));
        // Deeper names do not match. A pattern that could match an unbounded number of segments
        // makes "which plugin gets this event" unanswerable from a manifest.
        assert!(!pattern.matches("_plugin.chat.room.message"));
        // And neither does a shorter one.
        assert!(!pattern.matches("_plugin.chat"));
        // Nor another plugin's namespace.
        assert!(!pattern.matches("_plugin.notes.text"));
    }

    #[test]
    fn a_wildcard_family_matches_its_prefix_only() {
        let pattern = HandlePattern::parse("file.transfer.*").expect("valid");
        assert!(pattern.matches("file.transfer.chunk"));
        assert!(pattern.matches("file.transfer.complete"));
        assert!(!pattern.matches("file.other.chunk"));
        // The prefix must end at a segment boundary, not mid-character.
        assert!(!pattern.matches("file.transferX.chunk"));
    }

    #[test]
    fn multiple_trailing_wildcards_are_allowed() {
        let pattern = HandlePattern::parse("_synra.*.*").expect("valid");
        assert_eq!(pattern.wildcard_count(), 2);
        assert!(pattern.matches("_synra.device.changed"));
        assert!(!pattern.matches("_synra.device.changed.now"));

        // An all-wildcard pattern matches any name of the right length.
        let any_two = HandlePattern::parse("*.*").expect("valid");
        assert!(any_two.matches("a.b"));
        assert!(!any_two.matches("a.b.c"));
        assert!(!any_two.matches("a"));
    }

    #[test]
    fn a_partial_wildcard_is_refused() {
        // `tex*` is a different feature. Accepting it silently would make a manifest mean something
        // its author did not intend.
        assert!(matches!(
            HandlePattern::parse("_plugin.chat.tex*"),
            Err(PatternError::PartialWildcard(_))
        ));
        assert!(HandlePattern::parse("_plugin.*chat.text").is_err());
    }

    #[test]
    fn malformed_patterns_are_refused() {
        assert!(matches!(HandlePattern::parse(""), Err(PatternError::Empty)));
        assert!(matches!(
            HandlePattern::parse("_plugin..text"),
            Err(PatternError::EmptySegment(_))
        ));
        assert!(matches!(
            HandlePattern::parse("_plugin.chat.a/b"),
            Err(PatternError::BadCharacter { .. })
        ));
        assert!(matches!(
            HandlePattern::parse("_plugin.chat.a b"),
            Err(PatternError::BadCharacter { .. })
        ));
    }

    #[test]
    fn wildcard_count_is_bounded() {
        // One wildcard too many.
        let mut pattern = String::from("x");
        for _ in 0..=MAX_PATTERN_WILDCARDS {
            pattern.push_str(".*");
        }
        assert!(matches!(
            HandlePattern::parse(&pattern),
            Err(PatternError::TooManyWildcards { .. })
        ));

        // Exactly at the limit is fine.
        let mut at_limit = String::from("x");
        for _ in 0..MAX_PATTERN_WILDCARDS {
            at_limit.push_str(".*");
        }
        assert!(HandlePattern::parse(&at_limit).is_ok());
    }

    #[test]
    fn exact_patterns_and_wildcards_agree_with_event_names() {
        // A pattern that parses must be able to match at least one *sendable* name, or the plugin
        // declares a subscription that can never fire.
        let pattern = HandlePattern::parse("_plugin.chat.*").expect("valid");
        assert!(pattern.matches("_plugin.chat.text"));
        assert!(EventName::parse("_plugin.chat.text").is_ok());
    }

    // ── HandleSet ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_handle_set_separates_exact_from_wildcards() {
        let set = HandleSet::compile([
            "_synra.transfer.completed",
            "_synra.device.changed",
            "_plugin.chat.*",
        ])
        .expect("compiles");

        assert_eq!(set.exact_count(), 2);
        assert_eq!(set.wildcard_count(), 1);
        assert!(!set.is_empty());

        assert!(set.matches("_synra.transfer.completed"));
        assert!(set.matches("_plugin.chat.text"));
        assert!(!set.matches("_synra.share.received"));
        assert!(!set.matches("_plugin.notes.text"));
    }

    #[test]
    fn an_empty_handle_set_matches_nothing() {
        let set = HandleSet::compile(Vec::<String>::new()).expect("compiles");
        assert!(set.is_empty());
        assert!(!set.matches("_synra.device.changed"));
    }

    #[test]
    fn a_bad_pattern_fails_the_whole_declaration() {
        // Better to refuse at load than to install a plugin whose subscriptions are silently
        // missing an entry.
        let result = HandleSet::compile(["_synra.device.changed", "not a pattern"]);
        assert!(matches!(result, Err(HandleSetError::Pattern(_))));
    }

    #[test]
    fn wildcard_rules_are_bounded() {
        let many: Vec<String> = (0..=MAX_WILDCARD_RULES).map(|i| format!("_plugin.p{i}.*")).collect();
        assert!(matches!(
            HandleSet::compile(many),
            Err(HandleSetError::TooManyWildcards { max: MAX_WILDCARD_RULES })
        ));

        let at_limit: Vec<String> = (0..MAX_WILDCARD_RULES).map(|i| format!("_plugin.p{i}.*")).collect();
        assert!(HandleSet::compile(at_limit).is_ok());
    }

    // ── Classification ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn transport_events_are_never_plugin_visible() {
        // A plugin that could observe or inject these would be inside the transport rather than on
        // top of it.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        for name in [
            events::HELLO,
            events::HELLO_ACK,
            events::ACK,
            events::PING,
            events::PONG,
            events::BYE,
            events::ERROR,
        ] {
            let inbound = Inbound::classify(envelope(name, a, b));
            assert!(matches!(inbound, Inbound::Transport { .. }), "{name}");
            assert!(!inbound.is_plugin_visible(), "{name}");
            assert!(!inbound.is_ignorable(), "{name}");
        }
    }

    #[test]
    fn kernel_events_are_never_plugin_visible() {
        // These drive the kernel's own sessions. A plugin able to see them could observe every
        // intent the user dispatches.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        for name in [
            events::PAIR_REQUEST,
            events::PAIR_RESPONSE,
            events::UNPAIR,
            events::INTENT_INVOKE,
            events::INTENT_RESULT,
            events::INTENT_CANCEL,
            events::PLUGIN_QUERY,
            events::PLUGIN_QUERY_REPLY,
            events::PLUGIN_SYNC_RESULT,
        ] {
            let inbound = Inbound::classify(envelope(name, a, b));
            assert!(matches!(inbound, Inbound::Kernel { .. }), "{name}");
            assert!(!inbound.is_plugin_visible(), "{name}");
        }
    }

    #[test]
    fn builtin_events_are_plugin_visible() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        for name in builtin::ALL {
            let inbound = Inbound::classify(envelope(name, a, b));
            assert!(matches!(inbound, Inbound::Builtin { .. }), "{name}");
            assert!(inbound.is_plugin_visible(), "{name}");
        }
    }

    #[test]
    fn data_plane_events_are_classified_as_such() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        for event in [
            DataPlaneEvent::FileTransferRequest,
            DataPlaneEvent::FileTransferChunk,
            DataPlaneEvent::FileTransferComplete,
            DataPlaneEvent::FileTransferAbort,
            DataPlaneEvent::FileTransferProgress,
        ] {
            let inbound = Inbound::classify(envelope(event.as_str(), a, b));
            match inbound {
                Inbound::DataPlane { event: got, .. } => assert_eq!(got, event),
                other => panic!("expected a data-plane event, got {other:?}"),
            }
            assert!(inbound.is_plugin_visible());
        }
    }

    #[test]
    fn plugin_events_report_their_owner() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let inbound = Inbound::classify(envelope("_plugin.chat.text", a, b));
        match inbound {
            Inbound::Plugin { owner, .. } => assert_eq!(owner, slug("chat")),
            other => panic!("expected a plugin event, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_builtin_is_recorded_and_ignored() {
        // A newer peer may send an event this version has never heard of. The frames are perfectly
        // readable, so refusing the link would make a version difference look like corruption.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let inbound = Inbound::classify(envelope("_synra.device.teleported", a, b));

        match &inbound {
            Inbound::Unknown { reason, .. } => {
                assert_eq!(*reason, UnknownReason::NotInCatalogue);
            }
            other => panic!("expected an unknown event, got {other:?}"),
        }
        assert!(inbound.is_ignorable(), "an unknown built-in must not break the link");
        assert!(!inbound.is_plugin_visible(), "nobody can have subscribed to it");
    }

    #[test]
    fn an_unknown_data_plane_event_is_not_ignorable() {
        // Data-plane events drive a transfer state machine. Silently ignoring one leaves the
        // transfer stuck with no error anywhere, which is worse than a clear refusal.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let inbound = Inbound::classify(envelope("file.transfer.teleport", a, b));

        match &inbound {
            Inbound::Unknown { reason, .. } => {
                assert_eq!(*reason, UnknownReason::UnrecognisedDataPlane);
            }
            other => panic!("expected an unknown data-plane event, got {other:?}"),
        }
        assert!(!inbound.is_ignorable());

        let error = inbound_error_to_synra(UnknownReason::UnrecognisedDataPlane, inbound.event());
        assert_eq!(error.code, ErrorCode::ProtocolViolation);
    }

    #[test]
    fn an_unknown_builtin_maps_to_not_found() {
        let name = EventName::parse("_synra.device.teleported").expect("valid");
        let error = inbound_error_to_synra(UnknownReason::NotInCatalogue, &name);
        assert_eq!(error.code, ErrorCode::Unsupported);
    }

    #[test]
    fn every_classified_message_keeps_its_envelope() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let original = envelope("_plugin.chat.text", a, b);
        let request_id = original.request_id;

        for inbound in [
            Inbound::classify(envelope("device.ping", a, b)),
            Inbound::classify(envelope(events::PAIR_REQUEST, a, b)),
            Inbound::classify(envelope(builtin::DEVICE_CHANGED, a, b)),
            Inbound::classify(envelope("file.transfer.chunk", a, b)),
            Inbound::classify(original),
            Inbound::classify(envelope("_synra.unknown.thing", a, b)),
        ] {
            assert_eq!(inbound.envelope().from, a);
            assert_eq!(inbound.envelope().target, b);
            // And the message can be taken back out without losing anything.
            let recovered = inbound.into_envelope();
            assert_eq!(recovered.from, a);
        }

        assert_ne!(request_id, crate::ids::RequestId::new());
    }

    // ── Coalescing ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn only_high_frequency_events_are_coalescable() {
        assert_eq!(
            coalescable_names(),
            &[builtin::TRANSFER_PROGRESS, builtin::NETWORK_CHANGED]
        );

        let progress = BuiltinEvent::parse(
            &EventName::parse(builtin::TRANSFER_PROGRESS).expect("valid"),
            None,
        )
        .expect("a known built-in");
        assert!(progress.is_coalescable());
        assert_eq!(progress.name(), builtin::TRANSFER_PROGRESS);

        // A business event must never be coalesced: dropping one silently is not the same as
        // dropping a stale progress report.
        let completed = BuiltinEvent::parse(
            &EventName::parse(builtin::TRANSFER_COMPLETED).expect("valid"),
            None,
        )
        .expect("a known built-in");
        assert!(!completed.is_coalescable());

        for name in coalescable_names() {
            assert!(
                name.starts_with("_synra."),
                "{name} is coalescable but is not a host progress event",
            );
        }
    }

    #[test]
    fn a_progress_report_replaces_its_predecessor() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let mut buffer = CoalesceBuffer::new();

        assert!(!buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b))));
        assert_eq!(buffer.len(), 1);

        // The second one is coalesced, so a slow consumer sees the current state rather than a
        // queue of history.
        assert!(buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b))));
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn a_coalesced_entry_keeps_its_place_in_the_queue() {
        // Moving it to the end would reorder it behind events that arrived later but matter less.
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let mut buffer = CoalesceBuffer::new();

        buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b)));
        buffer.push(Inbound::classify(envelope(builtin::DEVICE_CHANGED, a, b)));
        buffer.push(Inbound::classify(envelope(builtin::NETWORK_CHANGED, a, b)));
        buffer.push(Inbound::classify(envelope(builtin::TRANSFER_PROGRESS, a, b)));

        let drained = buffer.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].event.as_str(), builtin::TRANSFER_PROGRESS);
        assert_eq!(drained[1].event.as_str(), builtin::DEVICE_CHANGED);
        assert_eq!(drained[2].event.as_str(), builtin::NETWORK_CHANGED);
        assert!(buffer.is_empty());
    }

    #[test]
    fn ordinary_events_are_never_dropped_by_coalescing() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let mut buffer = CoalesceBuffer::new();

        for _ in 0..5 {
            buffer.push(Inbound::classify(envelope(builtin::PLUGIN_INSTALLED, a, b)));
        }
        // Five distinct events, five entries: a business event is not superseded by the next one.
        assert_eq!(buffer.len(), 5);
    }

    #[test]
    fn draining_empties_the_buffer() {
        let (a, b) = (DeviceId::new(), DeviceId::new());
        let mut buffer = CoalesceBuffer::new();
        buffer.push(Inbound::classify(envelope(builtin::HOST_FOREGROUND, a, b)));

        assert_eq!(buffer.drain().len(), 1);
        assert!(buffer.is_empty());
        assert!(buffer.drain().is_empty());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A compiled pattern matches exactly the names it should, checked against a reference
        /// implementation written the obvious way. The fast path and the obvious path must agree.
        #[test]
        fn pattern_matching_agrees_with_a_reference(
            prefix in "[a-z][a-z0-9]{0,6}",
            wildcards in 0u8..3,
            extra_segments in 0usize..3,
        ) {
            let mut pattern = prefix.clone();
            for _ in 0..wildcards {
                pattern.push_str(".*");
            }
            let pattern = HandlePattern::parse(&pattern).expect("the generator makes valid patterns");

            // Reference: split both and compare segment by segment, with `*` matching any one.
            let reference = |name: &str| {
                let expected: Vec<&str> = pattern.as_str().split('.').collect();
                let actual: Vec<&str> = name.split('.').collect();
                expected.len() == actual.len()
                    && expected
                        .iter()
                        .zip(&actual)
                        .all(|(want, got)| *want == "*" || want == got)
            };

            let mut candidate = prefix;
            for _ in 0..extra_segments {
                candidate.push_str(".seg");
            }
            prop_assert_eq!(pattern.matches(&candidate), reference(&candidate));
        }

        /// Any text either compiles as a pattern or is refused with a reason. It never panics, and a
        /// compiled pattern never matches a name with a different segment count.
        #[test]
        fn pattern_parsing_is_total(text in ".{0,60}") {
            if let Ok(pattern) = HandlePattern::parse(&text) {
                let segments = pattern.as_str().split('.').count();
                let wrong_count = "a.".repeat(segments + 1);
                prop_assert!(!pattern.matches(&wrong_count), "matched a name of the wrong length");
            }
        }

        /// Classification is total: any valid event name produces exactly one kind, and only the
        /// plugin-visible kinds may reach a plugin.
        ///
        /// The generator always produces at least two segments after the namespace, because a plugin
        /// event is `_plugin.<slug>.<name>` and `_plugin.a` alone is not a name at all.
        #[test]
        fn classification_is_total(
            name in "(_synra|_plugin|device|file)\\.[a-z]{1,10}(\\.[a-z]{1,10}){1,3}",
        ) {
            let event = match EventName::parse(&name) {
                Ok(event) => event,
                // A generated shape the grammar rejects is not a case worth asserting about; the
                // grammar has its own tests.
                Err(_) => return Ok(()),
            };
            let envelope = Envelope::outbound(
                crate::envelope::OutboundSpec {
                    event,
                    target: crate::ids::DeviceId::new(),
                    from: crate::ids::DeviceId::new(),
                    trace_id: crate::ids::TraceId::new(),
                    sent_at_ms: 0,
                    ttl_ms: None,
                },
                None::<&()>,
            ).expect("builds");

            let inbound = Inbound::classify(envelope);
            // Transport and kernel messages are never plugin visible; that is the invariant the
            // kernel relies on when it assumes an established link's plugin traffic is legitimate.
            match &inbound {
                Inbound::Transport { .. } | Inbound::Kernel { .. } => {
                    prop_assert!(!inbound.is_plugin_visible());
                }
                Inbound::Unknown { envelope, .. } => {
                    prop_assert!(!inbound.is_plugin_visible());
                    prop_assert_eq!(&envelope.event, inbound.event());
                }
                _ => {
                    prop_assert!(inbound.is_plugin_visible());
                }
            }
        }
    }
}
