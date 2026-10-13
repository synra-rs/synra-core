//! Event names: the grammar, the catalogue, and what a plugin is allowed to emit.
//!
//! # Two kinds of event, and why the line matters
//!
//! * **Built-in events** are the host's. Their names are defined here, their payload shapes are
//!   defined by the host, and they describe *capabilities* — "a device came online", "a transfer
//!   finished and its digest checked out", "a share arrived that no plugin claimed".
//! * **Plugin events** are an author's. They live under `_plugin.<slug>.`, and the plugin declares
//!   their payload shape in its manifest.
//!
//! The host does not try to guess what a plugin's events mean. It cannot: the whole point of a
//! plugin is that it knows something the host does not. So the host reports what happened, and the
//! plugin decides what it means.
//!
//! # The namespace rule is enforced, not documented
//!
//! [`EventName::plugin`] only accepts the slug it is given, and [`EventName::plugin_scope`] tells a
//! caller whether a name belongs to a plugin and which one. A plugin that could emit
//! `_plugin.someone-else.thing` could impersonate another plugin, so the check lives in the type
//! rather than in a convention someone has to remember.
//!
//! # Names are interned elsewhere
//!
//! Comparison here is by string, which is correct but not free. Routing does not use it: the host
//! resolves a name to a small integer once and looks that up thereafter, so the per-frame cost is an
//! array index rather than a string compare. See `design-docs/04-wire-protocol.md` §6.8.
use core::fmt;

use compact_str::CompactString;
use serde::{Deserialize, Serialize};

use crate::ids::PluginSlug;

/// Prefix for host-defined events.
pub const SYSTEM_PREFIX: &str = "_synra.";

/// Prefix for plugin-defined events.
pub const PLUGIN_PREFIX: &str = "_plugin.";

/// Prefix reserved for events that never leave the process.
pub const INTERNAL_PREFIX: &str = "synra.internal.";

/// Length limit for an event name, generous enough for a nested plugin name.
pub const MAX_EVENT_NAME_LEN: usize = 128;

/// Why an event name is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EventNameError {
    /// The name is empty.
    #[error("event name is empty")]
    Empty,

    /// The name is longer than [`MAX_EVENT_NAME_LEN`].
    #[error("event name is {len} bytes, the limit is {max}")]
    TooLong {
        /// Observed length.
        len: usize,
        /// The limit.
        max: usize,
    },

    /// The name carries no segment after its prefix, or has an empty one.
    #[error("malformed event name: {0}")]
    Malformed(String),

    /// A plugin tried to emit under a namespace that is not its own.
    #[error("plugin {attempted} may not emit under {actual}")]
    ForeignNamespace {
        /// The slug found in the name.
        actual: String,
        /// The slug of the plugin that tried.
        attempted: String,
    },

    /// A plugin attempted to emit a host event that is not on the allowed list.
    #[error("plugins may not emit {0}")]
    ReservedForHost(String),
}

/// A validated event name, in one of three namespaces plus the bare data-plane form.
///
/// The only ways to obtain one are [`EventName::parse`], [`EventName::system`],
/// [`EventName::plugin`] and [`EventName::internal`], so a value of this type is always well formed.
/// Deserialisation goes through the same validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EventName(CompactString);

impl EventName {
    /// Parses any event name, checking its grammar.
    ///
    /// # Errors
    ///
    /// [`EventNameError::Empty`], [`EventNameError::TooLong`] or [`EventNameError::Malformed`].
    pub fn parse(name: &str) -> Result<Self, EventNameError> {
        if name.is_empty() {
            return Err(EventNameError::Empty);
        }
        if name.len() > MAX_EVENT_NAME_LEN {
            return Err(EventNameError::TooLong { len: name.len(), max: MAX_EVENT_NAME_LEN });
        }

        if let Some(rest) = name.strip_prefix(PLUGIN_PREFIX) {
            let (slug, logical) = rest.split_once('.').ok_or_else(|| {
                EventNameError::Malformed("a plugin event needs a slug and a name".to_owned())
            })?;
            PluginSlug::parse(slug).map_err(|error| EventNameError::Malformed(error.to_string()))?;
            validate_segments(logical)?;
            return Ok(Self(CompactString::from(name)));
        }

        if let Some(rest) = name.strip_prefix(SYSTEM_PREFIX) {
            validate_segments(rest)?;
            return Ok(Self(CompactString::from(name)));
        }

        if let Some(rest) = name.strip_prefix(INTERNAL_PREFIX) {
            validate_segments(rest)?;
            return Ok(Self(CompactString::from(name)));
        }

        // `_synra.` and `_plugin.` are checked before this, so what remains is the kernel's own
        // bare namespaces: `device.*` for link and session control, `file.transfer.*` for the data
        // plane.
        //
        // The prefix list is closed on purpose. Without it, any dotted string would be a valid event
        // name, which sounds permissive and is actually worse: a typo in a constant, or a name
        // arriving from a peer, would be silently accepted as an event nobody handles. The
        // `Unknown` bucket in the inbound dispatcher is for *valid* names this version does not
        // recognise, not for arbitrary text.
        const DATA_PLANE_PREFIXES: &[&str] = &["device.", "file.transfer."];
        if let Some(prefix) = DATA_PLANE_PREFIXES.iter().find(|p| name.starts_with(**p)) {
            let logical = &name[prefix.len()..];
            validate_segments(logical)?;
            return Ok(Self(CompactString::from(name)));
        }

        Err(EventNameError::Malformed(format!(
            "event name {name:?} is not in a known namespace \
             (_synra., _plugin., synra.internal., device., file.transfer.)"
        )))
    }

    /// Builds a host event under `_synra.`.
    ///
    /// # Errors
    ///
    /// [`EventNameError::Malformed`] if `logical` is empty or has an empty segment.
    pub fn system(logical: &str) -> Result<Self, EventNameError> {
        validate_segments(logical)?;
        Self::parse(&format!("{SYSTEM_PREFIX}{logical}"))
    }

    /// Builds an event in a plugin's own namespace.
    ///
    /// # Errors
    ///
    /// [`EventNameError::Malformed`] if `logical` is empty or has an empty segment.
    pub fn plugin(slug: &PluginSlug, logical: &str) -> Result<Self, EventNameError> {
        validate_segments(logical)?;
        Self::parse(&format!("{PLUGIN_PREFIX}{slug}.{logical}"))
    }

    /// Builds an event that stays inside the process.
    ///
    /// # Errors
    ///
    /// [`EventNameError::Malformed`] if `logical` is empty or has an empty segment.
    pub fn internal(logical: &str) -> Result<Self, EventNameError> {
        validate_segments(logical)?;
        Self::parse(&format!("{INTERNAL_PREFIX}{logical}"))
    }

    /// The name as it appears on the wire.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether this is a host event under `_synra.`.
    ///
    /// Carries no payload contract of its own: the host defines what each one means.
    #[must_use]
    pub fn is_system(&self) -> bool {
        self.0.starts_with(SYSTEM_PREFIX)
    }

    /// Whether this is part of the link and session protocol itself (`device.*`).
    ///
    /// Separate from [`Self::is_system`] because these are never delivered to a plugin: they are the
    /// mechanism by which links exist, and a plugin that could observe or inject them would be
    /// inside the transport rather than on top of it.
    #[must_use]
    pub fn is_transport(&self) -> bool {
        self.0.starts_with("device.")
    }

    /// Whether this is a plugin event.
    #[must_use]
    pub fn is_plugin(&self) -> bool {
        self.0.starts_with(PLUGIN_PREFIX)
    }

    /// Whether this never leaves the process.
    #[must_use]
    pub fn is_internal(&self) -> bool {
        self.0.starts_with(INTERNAL_PREFIX)
    }

    /// Whether this is a data-plane event, such as `file.transfer.chunk`.
    ///
    /// The kernel's own payload-carrying protocol: transfers, and nothing else. `device.*` is
    /// transport rather than data plane, and `_plugin.*` belongs to an author.
    #[must_use]
    pub fn is_data_plane(&self) -> bool {
        self.0.starts_with("file.transfer.")
    }

    /// The owning plugin's slug and the event's own name, for a plugin event.
    #[must_use]
    pub fn plugin_scope(&self) -> Option<(&str, &str)> {
        let rest = self.0.strip_prefix(PLUGIN_PREFIX)?;
        rest.split_once('.')
    }

    /// Checks this name may be emitted by the plugin with `slug`.
    ///
    /// The host calls this on every outbound plugin event. It is the difference between "plugins
    /// have their own namespace" being true and it being a sentence in a document.
    ///
    /// # Errors
    ///
    /// [`EventNameError::ForeignNamespace`] if the name belongs to another plugin,
    /// [`EventNameError::ReservedForHost`] if it is a host event a plugin may not send.
    pub fn check_emittable_by(&self, slug: &PluginSlug) -> Result<(), EventNameError> {
        if let Some((owner, _)) = self.plugin_scope() {
            if owner == slug.as_str() {
                return Ok(());
            }
            return Err(EventNameError::ForeignNamespace {
                actual: owner.to_owned(),
                attempted: slug.to_string(),
            });
        }

        if PLUGIN_EMITTABLE.contains(&self.as_str()) {
            return Ok(());
        }

        Err(EventNameError::ReservedForHost(self.0.to_string()))
    }
}

impl fmt::Display for EventName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for EventName {
    type Error = EventNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<EventName> for String {
    fn from(value: EventName) -> Self {
        value.0.into_string()
    }
}

/// Rejects an empty logical name, or one with an empty or malformed segment.
///
/// Each dot-separated segment must be `[A-Za-z0-9_-]+`.
///
/// Requiring a known character set keeps an event name from ever being usable as something else — a
/// path, a shell argument, a URL fragment — if some later code passes one along to another system.
///
/// # No wildcards
///
/// `*` is deliberately **not** allowed here. It belongs to `handles` patterns, which describe what a
/// plugin wants to receive, and a pattern is not a name: nothing can be *sent* as `_plugin.chat.*`.
/// Keeping the two grammars apart means an [`EventName`] is always something a peer could
/// legitimately have sent, so a routing table built from names never has to ask whether an entry is
/// a pattern. [`crate::inbound::HandlePattern`] is the grammar that accepts wildcards.
fn validate_segments(logical: &str) -> Result<(), EventNameError> {
    if logical.is_empty() {
        return Err(EventNameError::Malformed("empty event name".to_owned()));
    }

    for segment in logical.split('.') {
        if segment.is_empty() {
            return Err(EventNameError::Malformed(format!(
                "event name {logical:?} has an empty segment"
            )));
        }
        let valid = segment
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
        if !valid {
            return Err(EventNameError::Malformed(format!(
                "event name {logical:?} has a character outside [A-Za-z0-9_-]"
            )));
        }
    }

    Ok(())
}

/// Host events consumed by the kernel's own state machines.
///
/// Never delivered to a plugin: these *are* the protocol, and exposing them would let a plugin
/// interfere with link establishment or pairing.
pub mod events {
    /// Opens a link. Carries the handshake body.
    pub const HELLO: &str = "device.hello";
    /// Accepts a link.
    pub const HELLO_ACK: &str = "device.hello.ack";
    /// Acknowledges a reliable message.
    pub const ACK: &str = "device.ack";
    /// Heartbeat.
    pub const PING: &str = "device.ping";
    /// Heartbeat reply.
    pub const PONG: &str = "device.pong";
    /// Closes a link deliberately.
    pub const BYE: &str = "device.bye";
    /// Reports a protocol-level failure, as distinct from a business failure.
    pub const ERROR: &str = "device.error";

    /// Asks to pair.
    pub const PAIR_REQUEST: &str = "device.pairing.request";
    /// Answers a pairing request.
    pub const PAIR_RESPONSE: &str = "device.pairing.response";
    /// Ends a pairing.
    pub const UNPAIR: &str = "device.pairing.unpair";
    /// Asks a device to run an action.
    pub const INTENT_INVOKE: &str = "_synra.intent.invoke";
    /// Reports an action's outcome.
    pub const INTENT_RESULT: &str = "_synra.intent.result";
    /// Withdraws an action.
    pub const INTENT_CANCEL: &str = "_synra.intent.cancel";

    /// Asks a peer which version of a plugin it has.
    pub const PLUGIN_QUERY: &str = "_synra.plugin.query";
    /// Answers a plugin query.
    pub const PLUGIN_QUERY_REPLY: &str = "_synra.plugin.query.reply";
    /// Reports the result of a plugin sync.
    pub const PLUGIN_SYNC_RESULT: &str = "_synra.plugin.sync.result";
}

/// Built-in events a plugin may subscribe to.
///
/// These are the host's capability surface. A plugin declares the ones it wants in its manifest's
/// `handles`, and receives only those.
pub mod builtin {
    /// Paired devices came online, went offline, or changed. The payload is a full snapshot.
    pub const DEVICE_CHANGED: &str = "_synra.device.changed";
    /// One device went offline.
    pub const DEVICE_OFFLINE: &str = "_synra.device.offline";
    /// One device's display name changed.
    pub const DEVICE_RENAMED: &str = "_synra.device.renamed";
    /// A pairing was created or ended.
    pub const PAIRING_CHANGED: &str = "_synra.pairing.changed";

    /// Shared content arrived that **no plugin claimed**.
    ///
    /// Deliberately not sent when a plugin does claim the content: a plugin that handles a share
    /// already learns about it through the match path, and waking every fallback plugin on every
    /// share would be work for nothing.
    pub const SHARE_RECEIVED: &str = "_synra.share.received";
    /// An action this device asked for finished successfully.
    pub const INTENT_COMPLETED: &str = "_synra.intent.completed";
    /// An action this device asked for failed.
    pub const INTENT_FAILED: &str = "_synra.intent.failed";

    /// A transfer finished, and its digest was checked.
    ///
    /// The digest check happens before this is sent, so a plugin acting on the file never has to ask
    /// whether the bytes are intact.
    pub const TRANSFER_COMPLETED: &str = "_synra.transfer.completed";
    /// A transfer failed or was aborted.
    pub const TRANSFER_FAILED: &str = "_synra.transfer.failed";
    /// Transfer progress. High frequency; a plugin must opt in explicitly.
    pub const TRANSFER_PROGRESS: &str = "_synra.transfer.progress";

    /// Clipboard content arrived from a peer.
    pub const CLIPBOARD_RECEIVED: &str = "_synra.clipboard.received";

    /// A plugin was installed on this device.
    pub const PLUGIN_INSTALLED: &str = "_synra.plugin.installed";
    /// A plugin was updated on this device.
    pub const PLUGIN_UPDATED: &str = "_synra.plugin.updated";
    /// A plugin was uninstalled from this device.
    pub const PLUGIN_UNINSTALLED: &str = "_synra.plugin.uninstalled";
    /// A plugin's granted capabilities changed.
    pub const PLUGIN_CAPABILITY_CHANGED: &str = "_synra.plugin.capability-changed";

    /// The host came to the foreground, after being suspended.
    pub const HOST_FOREGROUND: &str = "_synra.host.foreground";
    /// The host is going to the background and will be suspended shortly.
    pub const HOST_BACKGROUND: &str = "_synra.host.background";
    /// A network interface came up, went down, or changed.
    pub const NETWORK_CHANGED: &str = "_synra.network.changed";

    /// Every built-in name, so routing, the catalogue tests and the exhaustiveness guard all read
    /// from one list.
    ///
    /// A name missing here is never classified as a built-in, so it would be treated as unknown and
    /// silently not delivered to any subscriber — a failure with no error anywhere.
    pub const ALL: &[&str] = &[
        DEVICE_CHANGED,
        DEVICE_OFFLINE,
        DEVICE_RENAMED,
        PAIRING_CHANGED,
        SHARE_RECEIVED,
        INTENT_COMPLETED,
        INTENT_FAILED,
        TRANSFER_COMPLETED,
        TRANSFER_FAILED,
        TRANSFER_PROGRESS,
        CLIPBOARD_RECEIVED,
        PLUGIN_INSTALLED,
        PLUGIN_UPDATED,
        PLUGIN_UNINSTALLED,
        PLUGIN_CAPABILITY_CHANGED,
        HOST_FOREGROUND,
        HOST_BACKGROUND,
        NETWORK_CHANGED,
    ];
}

/// Host events a plugin **is** allowed to emit.
///
/// A short list on purpose. Every entry is a way for a plugin to ask the host to act on its behalf,
/// so each needs a reason why the plugin cannot achieve the same thing through its ordinary
/// capability surface. Growing this list grows the surface on which a plugin can speak for the host.
pub const PLUGIN_EMITTABLE: &[&str] = &[
    // Ask the host to produce a diagnostic bundle, for a "report a problem" button.
    "_synra.diagnostics.request",
    // Ask the user to grant more capabilities, for a "request permission" button.
    "_synra.plugin.capability-request",
];

/// Events that do not trigger an automatic acknowledgement.
///
/// Everything else is acknowledged, so a sender can tell the difference between "the peer took it"
/// and "it went into a socket buffer somewhere". The exceptions are the events that are themselves
/// part of the reliability machinery, or that are already periodic: acknowledging a heartbeat would
/// produce an endless exchange.
pub const NO_AUTO_ACK: &[&str] = &[
    events::HELLO,
    events::HELLO_ACK,
    events::ACK,
    events::PING,
    events::PONG,
    events::BYE,
    events::ERROR,
];

/// Whether a message waits for an acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckPolicy {
    /// Do not wait. For heartbeats, and for progress that is worthless once superseded.
    FireAndForget,
    /// Wait for the peer's acknowledgement. The default, and what every business event uses.
    Await,
}

/// The acknowledgement policy for an event name.
///
/// A function of the *event*, never of the link's direction. Deciding it by direction produces an
/// undocumented asymmetry — reliable one way, best-effort the other — and the failure it causes is a
/// message that disappears with no error anywhere.
#[must_use]
pub fn ack_policy(event: &EventName) -> AckPolicy {
    if NO_AUTO_ACK.contains(&event.as_str()) {
        AckPolicy::FireAndForget
    }
    else {
        AckPolicy::Await
    }
}

/// Events on the data plane: the kernel's own transfer protocol.
///
/// Bare names, with no `_synra.` prefix, and **not emittable by a plugin**. `file.transfer.*` is a
/// kernel capability — chunking, windowing, digest checking, resumption — and a plugin that could
/// emit these directly would be able to drive the user's transfer state machine from outside it.
/// Plugins use the `transfer` API instead, which goes through the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DataPlaneEvent {
    /// Proposes a transfer.
    FileTransferRequest,
    /// One block of data.
    FileTransferChunk,
    /// The sender is done; the receiver should verify and finalise.
    FileTransferComplete,
    /// Either side is giving up.
    FileTransferAbort,
    /// The receiver reports which blocks it has.
    FileTransferProgress,
}

impl DataPlaneEvent {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileTransferRequest => "file.transfer.request",
            Self::FileTransferChunk => "file.transfer.chunk",
            Self::FileTransferComplete => "file.transfer.complete",
            Self::FileTransferAbort => "file.transfer.abort",
            Self::FileTransferProgress => "file.transfer.progress",
        }
    }

    /// Parses a wire name.
    ///
    /// Returns `None` for anything outside this set.
    #[must_use]
    pub fn from_str_opt(name: &str) -> Option<Self> {
        match name {
            "file.transfer.request" => Some(Self::FileTransferRequest),
            "file.transfer.chunk" => Some(Self::FileTransferChunk),
            "file.transfer.complete" => Some(Self::FileTransferComplete),
            "file.transfer.abort" => Some(Self::FileTransferAbort),
            "file.transfer.progress" => Some(Self::FileTransferProgress),
            _ => None,
        }
    }
}

impl fmt::Display for DataPlaneEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn slug(text: &str) -> PluginSlug {
        PluginSlug::parse(text).expect("valid slug")
    }

    #[test]
    fn host_events_parse_and_are_recognised() {
        let name = EventName::parse(events::PAIR_REQUEST).expect("valid");
        assert!(name.is_transport(), "device.* is the link protocol");
        assert!(!name.is_system(), "only _synra.* is the host event namespace");
        assert!(!name.is_plugin());
        assert!(!name.is_data_plane());
        assert_eq!(name.plugin_scope(), None);
        assert_eq!(name.as_str(), "device.pairing.request");
    }

    #[test]
    fn data_plane_names_are_bare() {
        let name = EventName::parse("file.transfer.chunk").expect("valid");
        assert!(name.is_data_plane());
        assert!(!name.is_system());
        assert!(!name.is_plugin());
    }

    #[test]
    fn plugin_events_expose_their_owner() {
        let name = EventName::parse("_plugin.chat.text").expect("valid");
        assert!(name.is_plugin());
        assert_eq!(name.plugin_scope(), Some(("chat", "text")));
        // Dotted logical names nest, and still report the owner correctly.
        let nested = EventName::parse("_plugin.chat.room.message").expect("valid");
        assert_eq!(nested.plugin_scope(), Some(("chat", "room.message")));
    }

    #[rstest]
    #[case("")]
    #[case("device..ping")]
    #[case("_synra.")]
    #[case("_synra..x")]
    #[case("synra.internal.")]
    #[case("_plugin.chat")]
    #[case("_plugin..text")]
    #[case("_plugin.Chat.text")]
    #[case("_plugin.chat.")]
    fn malformed_names_are_rejected(#[case] name: &str) {
        assert!(EventName::parse(name).is_err(), "{name:?} should not parse");
    }

    #[test]
    fn names_have_a_length_limit() {
        let long = "a".repeat(MAX_EVENT_NAME_LEN + 1);
        assert!(matches!(
            EventName::parse(&long),
            Err(EventNameError::TooLong { .. })
        ));
    }

    #[test]
    fn a_wildcard_is_not_a_sendable_event_name() {
        // `*` belongs to `handles` patterns, which describe what a plugin wants to receive. A
        // pattern is not a name: nothing can be sent as `_plugin.chat.*`. Keeping the two grammars
        // apart means an `EventName` is always something a peer could legitimately have sent.
        for pattern in ["_plugin.chat.*", "_synra.*", "file.*", "*"] {
            assert!(
                EventName::parse(pattern).is_err(),
                "{pattern:?} is a pattern, not a name",
            );
        }
        // The matching grammar accepts them; see `inbound::HandlePattern`.
        assert!(crate::inbound::HandlePattern::parse("_plugin.chat.*").is_ok());
    }

    #[test]
    fn characters_outside_the_grammar_are_refused() {
        // A name that could be read as a path, a shell argument or a URL fragment is refused, so a
        // name can never be passed to another system and mean something there.
        for name in ["_plugin.chat.a/b", "device.pi ng", "device.ping;rm", "a..b"] {
            assert!(EventName::parse(name).is_err(), "{name:?} should not parse");
        }
    }

    #[test]
    fn constructors_produce_the_expected_shape() {
        assert_eq!(
            EventName::system("device.changed").expect("valid").as_str(),
            "_synra.device.changed"
        );
        assert_eq!(
            EventName::plugin(&slug("chat"), "text").expect("valid").as_str(),
            "_plugin.chat.text"
        );
        assert_eq!(
            EventName::internal("host.boot").expect("valid").as_str(),
            "synra.internal.host.boot"
        );
        assert!(EventName::internal("host.boot").expect("valid").is_internal());
    }

    #[test]
    fn a_plugin_may_emit_its_own_events() {
        let chat = slug("chat");
        let name = EventName::plugin(&chat, "text").expect("valid");
        assert_eq!(name.check_emittable_by(&chat), Ok(()));
    }

    #[test]
    fn a_plugin_may_not_emit_another_plugins_events() {
        // The difference between "plugins have their own namespace" being true and being a sentence
        // in a document.
        let chat = slug("chat");
        let notes = slug("notes");
        let name = EventName::plugin(&chat, "text").expect("valid");

        assert!(matches!(
            name.check_emittable_by(&notes),
            Err(EventNameError::ForeignNamespace { actual, attempted })
                if actual == "chat" && attempted == "notes"
        ));
    }

    #[test]
    fn a_plugin_may_not_emit_host_events_by_default() {
        let chat = slug("chat");
        for reserved in [
            events::PAIR_REQUEST,
            events::INTENT_INVOKE,
            builtin::TRANSFER_COMPLETED,
            "file.transfer.chunk",
        ] {
            let name = EventName::parse(reserved).expect("valid");
            assert!(
                matches!(
                    name.check_emittable_by(&chat),
                    Err(EventNameError::ReservedForHost(_))
                ),
                "{reserved} should be reserved for the host",
            );
        }
    }

    #[test]
    fn only_the_whitelisted_host_events_are_plugin_emittable() {
        let chat = slug("chat");
        for allowed in PLUGIN_EMITTABLE {
            let name = EventName::parse(allowed).expect("valid");
            assert_eq!(name.check_emittable_by(&chat), Ok(()), "{allowed} should be allowed");
        }
    }

    #[test]
    fn ack_policy_lives_on_the_event_not_on_the_direction() {
        // Reliability must not depend on who dialled. This is the regression guard: the function
        // takes only an event name, so there is no direction available to consult.
        let ack = |name: &str| ack_policy(&EventName::parse(name).expect("valid"));

        assert_eq!(ack(events::PING), AckPolicy::FireAndForget);
        assert_eq!(ack(events::PONG), AckPolicy::FireAndForget);
        assert_eq!(ack(events::HELLO), AckPolicy::FireAndForget);
        assert_eq!(ack(events::BYE), AckPolicy::FireAndForget);

        // Everything a user would notice losing.
        assert_eq!(ack(events::PAIR_REQUEST), AckPolicy::Await);
        assert_eq!(ack(events::INTENT_INVOKE), AckPolicy::Await);
        assert_eq!(ack("_plugin.chat.text"), AckPolicy::Await);
        assert_eq!(ack(builtin::TRANSFER_COMPLETED), AckPolicy::Await);
    }

    #[test]
    fn no_auto_ack_contains_only_transport_events() {
        // An exception list that grew to include a business event would silently make that event
        // unreliable, with no test failing and no log line.
        for name in NO_AUTO_ACK {
            assert!(
                name.starts_with("device."),
                "{name} is not a transport event; the ack policy should not exempt it",
            );
        }
    }

    #[test]
    fn data_plane_events_round_trip_through_their_names() {
        for event in [
            DataPlaneEvent::FileTransferRequest,
            DataPlaneEvent::FileTransferChunk,
            DataPlaneEvent::FileTransferComplete,
            DataPlaneEvent::FileTransferAbort,
            DataPlaneEvent::FileTransferProgress,
        ] {
            assert_eq!(DataPlaneEvent::from_str_opt(event.as_str()), Some(event));
            assert_eq!(event.to_string(), event.as_str());
            let name = EventName::parse(event.as_str()).expect("valid");
            assert!(name.is_data_plane(), "{name} should be data plane");
        }

        assert_eq!(DataPlaneEvent::from_str_opt("file.transfer.nope"), None);
        assert_eq!(DataPlaneEvent::from_str_opt("device.ping"), None);
    }

    /// Every name this crate defines, in one list so the tests below can check all of them.
    const ALL_DEFINED: &[&str] = &[
        builtin::DEVICE_CHANGED,
        builtin::DEVICE_OFFLINE,
        builtin::DEVICE_RENAMED,
        builtin::PAIRING_CHANGED,
        builtin::SHARE_RECEIVED,
        builtin::INTENT_COMPLETED,
        builtin::INTENT_FAILED,
        builtin::TRANSFER_COMPLETED,
        builtin::TRANSFER_FAILED,
        builtin::TRANSFER_PROGRESS,
        builtin::CLIPBOARD_RECEIVED,
        builtin::PLUGIN_INSTALLED,
        builtin::PLUGIN_UPDATED,
        builtin::PLUGIN_UNINSTALLED,
        builtin::PLUGIN_CAPABILITY_CHANGED,
        builtin::HOST_FOREGROUND,
        builtin::HOST_BACKGROUND,
        builtin::NETWORK_CHANGED,
        events::HELLO,
        events::HELLO_ACK,
        events::ACK,
        events::PING,
        events::PONG,
        events::BYE,
        events::ERROR,
        events::PAIR_REQUEST,
        events::PAIR_RESPONSE,
        events::UNPAIR,
        events::INTENT_INVOKE,
        events::INTENT_RESULT,
        events::INTENT_CANCEL,
        events::PLUGIN_QUERY,
        events::PLUGIN_QUERY_REPLY,
        events::PLUGIN_SYNC_RESULT,
    ];

    #[test]
    fn every_defined_name_is_valid_and_unique() {
        // A typo in a constant would otherwise only surface when a plugin failed to subscribe.
        let mut seen = std::collections::HashSet::new();
        for name in ALL_DEFINED {
            assert!(seen.insert(name), "duplicate event name: {name}");
            assert!(EventName::parse(name).is_ok(), "{name} does not parse");
        }
    }

    #[test]
    fn transport_events_the_kernel_owns_are_never_plugin_subscribable() {
        // A built-in outside `_synra.` would be indistinguishable from a data-plane name, and a
        // plugin subscribing to it would be subscribing to the kernel's own link protocol.
        for name in [
            builtin::DEVICE_CHANGED,
            builtin::SHARE_RECEIVED,
            builtin::TRANSFER_COMPLETED,
            builtin::PLUGIN_INSTALLED,
            builtin::HOST_FOREGROUND,
            builtin::NETWORK_CHANGED,
        ] {
            assert!(name.starts_with(SYSTEM_PREFIX), "{name} is not under {SYSTEM_PREFIX}");
        }
    }

    #[test]
    fn plugin_emittable_names_are_valid_event_names() {
        for name in PLUGIN_EMITTABLE {
            assert!(EventName::parse(name).is_ok(), "{name} does not parse");
        }
    }

    #[test]
    fn events_round_trip_through_json_as_bare_strings() {
        let name = EventName::parse("_plugin.chat.text").expect("valid");
        let json = serde_json::to_string(&name).expect("serialises");
        assert_eq!(json, "\"_plugin.chat.text\"");

        let back: EventName = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, name);

        // An invalid name must not deserialise: validation on the way in means a value of this type
        // is always well formed.
        assert!(serde_json::from_str::<EventName>("\"not a name\"").is_err());
    }

    #[test]
    fn display_matches_the_wire_form() {
        let name = EventName::parse(builtin::DEVICE_CHANGED).expect("valid");
        assert_eq!(name.to_string(), builtin::DEVICE_CHANGED);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn slug_text() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9-]{0,20}".prop_map(|text| {
            let trimmed = text.trim_end_matches('-');
            if trimmed.is_empty() { "a".to_owned() } else { trimmed.to_owned() }
        })
    }

    fn logical_text() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z][a-z0-9]{0,8}", 1..4).prop_map(|parts| parts.join("."))
    }

    proptest! {
        /// Anything a constructor accepts parses back to itself and reports the owner it was given.
        #[test]
        fn plugin_events_name_their_owner(slug in slug_text(), logical in logical_text()) {
            let slug = PluginSlug::parse(&slug).expect("the generator produces valid slugs");
            let name = EventName::plugin(&slug, &logical).expect("builds");
            prop_assert!(name.is_plugin());
            prop_assert_eq!(name.plugin_scope().map(|(owner, _)| owner), Some(slug.as_str()));
            prop_assert_eq!(name.check_emittable_by(&slug), Ok(()));
        }

        /// A plugin can never emit under a namespace it does not own, whatever the names are.
        #[test]
        fn foreign_namespaces_are_always_refused(
            owner in slug_text(),
            other in slug_text(),
            logical in logical_text(),
        ) {
            prop_assume!(owner != other);
            let owner = PluginSlug::parse(&owner).expect("valid");
            let other = PluginSlug::parse(&other).expect("valid");
            let name = EventName::plugin(&owner, &logical).expect("builds");
            prop_assert!(name.check_emittable_by(&other).is_err());
        }

        /// Arbitrary text either parses or is rejected. It never panics, and a parsed name survives
        /// a trip through the wire format unchanged.
        #[test]
        fn parse_is_total_and_round_trips(text in ".{0,140}") {
            if let Ok(name) = EventName::parse(&text) {
                // The wire form is the input, unchanged.
                prop_assert_eq!(name.as_str(), text.as_str());

                let json = serde_json::to_string(&name).expect("serialises");
                let back: EventName = serde_json::from_str(&json).expect("deserialises");
                prop_assert_eq!(back, name);
            }
        }
    }
}
