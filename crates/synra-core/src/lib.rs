//! The kernel: the domain model, the aggregates, and the orchestration that ties the other crates together.
//!
//! # The one crate that knows everything
//!
//! Every other crate in the workspace has a narrow dependency: the protocol knows nothing of storage, the storage
//! knows nothing of plugins, the plugin host knows nothing of the network. This one depends on all of them, and the
//! reason is that a decision about a cross-device action is genuinely a decision about all of them at once — is the
//! sender paired, is the plugin active, has the user granted this, can this machine do it, and has this exact request
//! already been answered.
//!
//! That is why the checks live here rather than in the plugin host. The host knows whether a capability gate opens; it
//! does not know whether the caller is a device the user paired, and putting the sequence in the host would mean the
//! host knowing about pairing.
//!
//! # What is here so far
//!
//! * [`admission`] — the eight checks an intent passes before anything runs, in the order the design document gives,
//!   with a property that an admission never leaves a requirement ungranted.
//! * [`routing`] — the event registry: names numbered once, routes resolved by table lookup, with a bounded cache for
//!   names that arrive from a peer.
//! * [`bus`] — where kernel events come from: one numbering, a bounded queue per subscriber, and a count of what was
//!   dropped so an interface that fell behind learns that it did.
//! * [`sessions`] — the links to peers: how far each has got, when a silent one is given up on, and what a reconnect
//!   does to the session it replaces.
//! * [`config`] — the settings: an open bag of named values with the defaults kept apart from the overrides, so a
//!   settings screen can mark what the user chose and a reset can restore what they did not.
//!
//! # What is deliberately not here
//!
//! No runtime, no sockets, no database handles. The kernel's pieces are pure decisions over values a caller supplies,
//! so the tests need neither a network nor a disk — and the parts that get the answers wrong are the decisions, not the
//! plumbing.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod admission;
pub mod bus;
pub mod config;
pub mod discovery;
pub mod host;
pub mod identity;
pub mod link;
pub mod messaging;
pub mod pairing;
pub mod peer;
pub mod routing;
pub mod session;
pub mod sessions;
pub mod socket;
pub mod transfer;
pub mod worker;

pub use admission::{
    AdmissionContext, AdmissionRefusal, AdmissionStep, PluginKey, admit, check, host_requirement,
};
pub use session::{
    Message, Receiving, Received, SessionError, SessionEvent, abort, classify, complete, propose,
    report_progress, send_blocks, send_file,
};
pub use transfer::{
    Absorbed as BlockAbsorbed, Block, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, ObjectDigest, TransferError,
    TransferReceiver, TransferSender, plan_blocks,
};
pub use worker::{DiscoveryService, QUERY_INTERVAL, Ticked, is_visible, run};
pub use socket::{
    DiscoverySocket, SocketError, absorb, broadcast_addresses, is_about,
};
pub use host::{Attached, Host, HostError, SharedHost, millis_reading, reading_millis, shared};
pub use discovery::{
    Absorbed, CANDIDATE_TTL, Candidate, DiscoveryTable, UNUSABLE_NAME, announced_address,
};
pub use messaging::{
    ClipboardText, MessageError, TEXT_MIME, pair_request, pair_response, text_to,
};
pub use link::{Inbound, LinkError, PeerLink};
pub use peer::{
    Flags, HandshakeError, LocalPeer, Negotiated, accept, agree, dial,
};
pub use identity::{
    DEFAULT_DISPLAY_NAME, Identity, MAX_DISPLAY_NAME_LEN, NameError, RenameError, check_display_name,
    platform_of_os,
};
pub use config::{
    Catalog, Config, ConfigError, ConfigSnapshot, Setting, SettingKey, SettingKind,
};
pub use bus::{
    Delivery, EventBus, Judgement, SequenceTracker, SubscriberId, SubscriberReport,
    SUBSCRIBER_QUEUE_CAPACITY,
};
pub use routing::{EventId, EventRegistry, RouteOutcome, RouterError};
pub use sessions::{
    ClosureReason, LinkState, PeerSession, RegistryError, RegistryEvent, SessionKey, SessionRegistry,
};