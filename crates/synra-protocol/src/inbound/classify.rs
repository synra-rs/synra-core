use crate::envelope::Envelope;
use crate::event::{builtin, events, DataPlaneEvent, EventName};
use crate::ids::PluginId;

use super::builtin_events::BuiltinEvent;

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
        /// The owning plugin's complete package id.
        owner: PluginId,
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
            && let Ok(slug) = PluginId::parse(owner)
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
        events::INTENT_INVOKE
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
