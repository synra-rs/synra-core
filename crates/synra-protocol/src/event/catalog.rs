//! Event catalogue, emission policy and data-plane event values.

use core::fmt;

use serde::{Deserialize, Serialize};

use super::EventName;

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
    /// Asks a device which plugins it has.
    ///
    /// Internal rather than public: the answer is a list of what somebody installed, and a plugin able to see it would learn
    /// what the user has on another machine.
    pub const PLUGIN_LIST_REQUEST: &str = "_synra.plugin.list.request";
    /// Answers which plugins this device has.
    pub const PLUGIN_LIST_RESPONSE: &str = "_synra.plugin.list.response";
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

    /// Every kernel-internal event name.
    ///
    /// A name missing here is a `handles` entry that looks like a typo rather than a subscription, so a plugin
    /// asking for it is refused at load. Reading the list from one place is what keeps the manifest validator
    /// and the inbound dispatcher agreeing about what the kernel owns.
    pub const ALL: &[&str] = &[
        HELLO,
        HELLO_ACK,
        ACK,
        PING,
        PONG,
        BYE,
        ERROR,
        INTENT_INVOKE,
        INTENT_RESULT,
        INTENT_CANCEL,
        PLUGIN_QUERY,
        PLUGIN_QUERY_REPLY,
        PLUGIN_SYNC_RESULT,
    ];
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
#[non_exhaustive]
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


