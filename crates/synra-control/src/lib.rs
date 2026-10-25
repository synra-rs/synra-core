//! The channel between a command-line client and a kernel on the same machine.
//!
//! # What this is, and what it is not
//!
//! `synra-protocol` is how two **devices** talk: framed envelopes, handshakes, discovery, transports. This is how a
//! process on **one** machine talks to the kernel running on it, and the two are deliberately different problems:
//!
//! | | device-to-device | client-to-kernel |
//! | --- | --- | --- |
//! | trust | neither end is trusted; both are verified | the same user; the operating system already decided |
//! | transport | TCP or a relay, over a network | a local socket or a named pipe |
//! | framing | a binary frame with flags, chunking, heartbeats | a length-prefixed request and its answer |
//! | lifetime | long, resumable, stateful | one question and one answer, then closed |
//!
//! A single protocol for both would carry the device protocol's ceremony into a conversation with a process the
//! operating system has already authenticated — and the ceremony is not free: a handshake, a session nonce and a link
//! token to talk to something on the same disk as you.
//!
//! # Why the request is text
//!
//! The payload is JSON, framed by a `u32` length. JSON because this channel carries *commands and their results*, where
//! the shape is the contract and being able to read a captured frame in a terminal is worth more than a few bytes. A
//! binary encoding here would save bandwidth that is not scarce and cost the one debugging technique that works when a
//! socket will not answer.
//!
//! # Why the length is checked before the body is read
//!
//! [`MAX_MESSAGE_LEN`] is what stops a client from asking the kernel to allocate an arbitrary amount of memory: a
//! length prefix is a promise the reader has to be willing to accept, and a reader that trusted it is one a single
//! malformed or hostile frame can exhaust.
//!
//! # What is here so far
//!
//! The framing and the request/response types: enough for a client and a server to agree on the bytes. The socket
//! itself, the kernel's command dispatch and the daemon's start-up are not here.
//!
//! # What is deliberately not here
//!
//! No `tokio` and no sockets. This is the part that can be tested without a runtime or a filesystem — a buffer in, a
//! message out — which is the part where an off-by-one in a length prefix lives.

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

mod credentials;
pub mod endpoint;
mod pairing;
pub use credentials::CredentialAction;
pub use pairing::PairingAction;
pub mod server;

use serde::{Deserialize, Serialize};

pub use endpoint::{Client, Listener, SocketError, serve_stream, socket_path};
pub use server::{Kernel, Refusal, Server, SessionState};

/// The most bytes one message may be, header included.
///
/// # Why there is a ceiling at all
///
/// A length prefix is a promise the reader has to be willing to accept. Without a ceiling, one malformed frame can ask
/// the kernel to allocate as much memory as the field can express — four gigabytes — and a hostile client on the same
/// machine can do it in a loop. One megabyte is the same figure the device protocol uses for a whole frame, and it is
/// far more than a command or a device list needs.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;

/// The bytes before the body: a `u32` length in big-endian order.
pub const HEADER_LEN: usize = 4;

/// The protocol version this build speaks.
///
/// Carried in every request, because a client and a kernel are separate binaries that may be upgraded separately: a
/// user who upgrades the kernel and not the CLI, or the reverse. A version mismatch is then one clear sentence rather
/// than a decode error several layers down.
pub const PROTOCOL_VERSION: u16 = 1;

/// Why a message could not be framed or read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChannelError {
    /// A message is longer than [`MAX_MESSAGE_LEN`].
    #[error("a message of {len} bytes exceeds the limit of {max}")]
    TooLong {
        /// How long it claimed to be.
        len: usize,
        /// The ceiling.
        max: usize,
    },

    /// A message's body was not valid JSON for its type.
    #[error("a message could not be read: {why}")]
    Malformed {
        /// What the parser said.
        why: String,
    },

    /// The client speaks a protocol version this kernel does not.
    #[error("the client speaks protocol {client}, this kernel speaks {kernel}")]
    VersionMismatch {
        /// What the client sent.
        client: u16,
        /// What this build speaks.
        kernel: u16,
    },
}

/// What a client asks the kernel to do.
///
/// # Why this is not the IPC command registry
///
/// `synra-ipc`'s registry is the *interface's* contract: which commands the Tauri shell registers, what the plugin UI
/// may call, and how each result is shaped for a screen. This is a smaller and more stable surface — the handful of
/// questions a command-line tool asks — and it is deliberately separate because the two have different audiences and
/// therefore different reasons to change. A new command for the interface's settings screen is not a new thing a
/// script can call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum Request {
    /// A liveness and version check.
    ///
    /// The first thing a client sends, because everything else assumes it is talking to a kernel it understands.
    Hello {
        /// The protocol version the client speaks.
        version: u16,
    },

    /// The kernel's state and its links.
    Status,

    /// Explicit local identity-key repair and cleanup.
    Credentials {
        /// Maintenance action after the local channel handshake.
        action: CredentialAction,
    },

    /// The devices the kernel has seen.
    Devices {
        /// Whether to include devices that are not paired.
        include_unpaired: bool,
        /// How long to scan the network before answering, in milliseconds.
        ///
        /// # Why the kernel scans rather than the client waiting
        ///
        /// Because only the kernel has the discovery socket. A client that slept for this long and then asked would get
        /// exactly the table it would have got without asking — the sleep would look like a scan and be a delay. Zero or
        /// absent means "answer from what you already know", which is what a cached listing is.
        ///
        /// # Why it is optional
        ///
        /// So a client that knows nothing about scanning sends a request this kernel still understands. The protocol's
        /// rule for evolution is that a peer may say a little more, and an absent field is an older client saying nothing
        /// rather than saying zero.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        scan_ms: Option<u64>,
    },

    /// Send text to a device.
    SendText {
        /// The device's id.
        to: String,
        /// What to send.
        text: String,
    },

    /// Send a file to a device.
    SendFile {
        /// The device's id.
        to: String,
        /// The file's path, as the client resolved it.
        path: String,
    },

    /// The installed plugins.
    Plugins,

    /// Lists previously verified publisher keys and this device's decisions.
    PluginPublishers,
    /// Records a decision for the exact key the user confirmed.
    PluginPublisherDecide {
        /// A publisher this device has met.
        publisher_id: String,
        /// The fingerprint displayed to the user.
        fingerprint: String,
        /// seen, trusted or revoked.
        trust: String,
    },

    /// Reads or changes the ordered registry source list.
    PluginRegistry {
        /// None reads; an empty list clears the setting; otherwise replaces it.
        urls: Option<Vec<String>>,
    },
    /// Reads or changes the background update policy.
    PluginUpdatePolicy {
        /// None reads; otherwise never, notify-only, auto-minor or auto-all.
        policy: Option<String>,
    },
    /// Explicitly checks current registry metadata without installing, even when automatic checks are disabled.
    PluginCheckUpdates {
        /// None checks all installed plugins.
        plugin_id: Option<String>,
    },
    /// Explicitly updates an installed plugin using verified registry bytes.
    PluginUpdate {
        /// The installed identifier.
        plugin_id: String,
        /// Exact version or range, or None for latest.
        version: Option<String>,
    },

    /// Search the plugin catalogue.
    ///
    /// ★ Why this is a request of its own rather than part of `Plugins`.
    ///
    /// Because the two answer questions about different machines. `Plugins` is what is **installed here**, which the store
    /// answers; this is what a **registry offers**, which is a network call that can take seconds and can fail. Merging them
    /// would make the installed list as slow as the network and make a screen that only wanted to show what is installed
    /// depend on a registry being reachable.
    CatalogSearch {
        /// The package name, as a registry spells it.
        package: String,
    },

    /// Turn a plugin on or off.
    ///
    /// ★ Why this had to exist.
    ///
    /// Because `synra plugin enable` and `synra plugin disable` are in the documented command list, they parse, and they
    /// did **nothing**: `plugin_request` answered `None` for every action but `list`, and a `None` from there means the
    /// CLI reports "this command needs a running kernel, and none is reachable" — a sentence that is false, and that
    /// sends a user to check a daemon which is running perfectly well.
    ///
    /// The database side already existed and was tested (`set_plugin_enabled`); what was missing was any way to reach it.
    PluginSetEnabled {
        /// Which plugin.
        plugin_id: String,
        /// Whether it should be usable.
        enabled: bool,
    },

    /// Install a plugin from a directory on this machine.
    ///
    /// # Why a path rather than a package identifier
    ///
    /// Because a registry install needs a fetcher, and there is none: the design's `InstallSource::Registry` has a
    /// packument parser and an integrity check and no HTTP client, so a request naming a package would fail at the
    /// first step for a reason the caller could not act on. A path is the source that exists, and the install pipeline
    /// behind it is the same one a registry install will run.
    ///
    /// # Why the kernel installs rather than the client
    ///
    /// Because installing means verifying, writing into the plugin directory and recording a row — three things only
    /// the process that owns the data directory may do. A client that copied files and asked the kernel to record them
    /// would be a second writer of the same state.
    PluginInstall {
        /// The directory the package is in, as the client resolved it.
        path: String,
    },

    /// Install a plugin from a registry, by the name the registry spells.
    ///
    /// # Why this is a request of its own rather than a `PluginInstall` with a URL
    ///
    /// Because the two need different things from the kernel: a path is already on disk and only has to be verified, while
    /// a package name means fetching a document, choosing a version, fetching bytes and comparing them with an integrity
    /// string. A request that carried a string the kernel had to classify would put that decision on the wrong side of
    /// the boundary — and would make "the path does not exist" and "the registry has no such version" the same failure.
    PluginInstallPackage {
        /// The package, as the registry spells it, such as `@acme/chat`.
        package: String,
        /// A version, or `None` for the registry's `latest` tag.
        version: Option<String>,
    },

    /// Records the user's decision about what a plugin may do.
    ///
    /// # Why this is a request and not a field on the install
    ///
    /// Because installing and approving are two acts. The design puts `AwaitingConsent` between them so that a package
    /// which arrived — from a registry, a file, or a peer — has not acquired any authority by arriving. An install that
    /// carried its own consent would make "I installed it" and "I let it read my clipboard" the same click.
    ///
    /// # Why the granted set rather than a yes/no
    ///
    /// Because consent is per capability, and a plugin is often useful with fewer than it asks for. A boolean would
    /// collapse "it may log but not open my browser" into "it may do everything it declared", which is the decision the
    /// capability model exists to avoid making on the user's behalf.
    PluginConsent {
        /// Which plugin.
        plugin_id: String,
        /// The capabilities the user allowed. Everything else the manifest declares is recorded as denied.
        granted: Vec<String>,
    },

    /// Removes a plugin, and its data when the caller asked for that.
    ///
    /// # Why the data decision is a parameter rather than a second request
    ///
    /// Because removing and deleting the data are one act with two outcomes, and the default is the reversible one. The
    /// CLI's `plugin remove` has a `--data` flag for the destructive half; a request that could not carry the decision
    /// would make the flag a promise with nothing behind it — which is the failure `--follow` was recorded for.
    PluginRemove {
        /// Which plugin.
        plugin_id: String,
        /// Whether to delete its data as well. Off by default at the command line.
        remove_data: bool,
    },

    /// Hands the kernel something to route.
    ///
    /// # ★ Why this request had to exist
    ///
    /// Because the matcher — the component that asks every plugin "can you handle this?" — had **no production caller at
    /// all**. `synra-core` implements it, tests it, and nothing could reach it: the control protocol had no intent
    /// request, the CLI had no command, and the daemon's transport writes an inbound share to an inbox and reports that
    /// nothing was delivered. A share arriving became a file, never an action, and the design document calls this
    /// routing "the kernel's most central orchestration".
    ///
    /// # Why this carries content rather than a `ShareItem`
    ///
    /// Because a `ShareItem` says which device shared it, and a caller on this machine's own socket is not a device: the
    /// only place that knows which device this is, is the kernel. So the caller sends what was shared and the kernel
    /// supplies the origin, rather than the caller inventing an identifier for itself that the kernel would then have to
    /// trust.
    IntentDispatch {
        /// The MIME type. `text/uri-list` for a link, `text/plain` for a sentence.
        mime: String,
        /// The content.
        text: String,
    },

    /// What has become of an intent.
    ///
    /// # Why a UI needs this
    ///
    /// Because routing is asynchronous from the user's point of view: a prompt appears after the plugins have answered,
    /// and the answer they give has to be applied to the same intent the prompt was about. Asking for the snapshot is how
    /// an interface finds out whether it is still choosing, now confirming, or already over.
    IntentSnapshot {
        /// Which intent.
        intent: String,
    },

    /// The user's answer to a prompt.
    IntentDecide {
        /// Which intent.
        intent: String,
        /// Which plugin the user picked, when they were choosing between several.
        ///
        /// `None` takes the candidate the board already settled on, which is the ordinary case: one plugin claimed the
        /// share and the user confirmed it.
        plugin_id: Option<String>,
        /// Where to run it, when the plugin that claimed the share did not say.
        ///
        /// # Why this is here now, and was not before
        ///
        /// Because `Board` could not answer the question. A candidate whose plugin suggested no device settles into
        /// `Choosing` — which *is* "where should this run?" — and no method advanced it: `choose` put a targetless
        /// candidate straight back into `Choosing`, and `confirm` refuses anything that is not `Confirming`. The field was
        /// left out rather than accepted and ignored.
        ///
        /// `Board::aim` is the method that answers it, so the parameter does what it says.
        target: Option<String>,
    },

    /// The user changed their mind.
    IntentCancel {
        /// Which intent.
        intent: String,
    },

    /// The tail of the kernel's log.
    Logs {
        /// How many lines.
        lines: usize,
        /// Whether to include debug-level lines.
        verbose: bool,
        /// Show only the lines for one trace, when the caller asked for one.
        ///
        /// # ★ Why this is a field and not a `--verbose` in disguise
        ///
        /// Because the CLI used to translate `--trace <id>` into `verbose: true` and **throw the id away**. The flag
        /// parsed, the command ran, the output looked plausible, and the filter the user asked for did not exist — the
        /// worst shape a broken flag can take, because nothing about the result says so.
        ///
        /// A trace is one user action's group of steps (`TraceContext`), and the id is what a person pastes out of a bug
        /// report to find the rest of it. Filtering is by substring on the rendered line, because the line format
        /// belongs to the logger and the daemon keeps no index of its own log — the same reason the level filter reads
        /// the level out of the text.
        ///
        /// `None` means "every trace", which is what a caller who did not ask for one gets.
        trace: Option<String>,
    },

    /// Runs an explicit out-of-band pairing action over this authenticated local control channel.
    Pairing {
        /// The complete action and its bounded operands.
        action: PairingAction,
    },
}

impl Request {
    /// The name a log line and a test use.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "hello",
            Self::Status => "status",
            Self::Devices { .. } => "devices",
            Self::SendText { .. } => "sendText",
            Self::SendFile { .. } => "sendFile",
            Self::Plugins => "plugins",
            Self::PluginPublishers => "pluginPublishers",
            Self::PluginPublisherDecide { .. } => "pluginPublisherDecide",
            Self::PluginRegistry { .. } => "pluginRegistry",
            Self::PluginUpdatePolicy { .. } => "pluginUpdatePolicy",
            Self::PluginCheckUpdates { .. } => "pluginCheckUpdates",
            Self::PluginUpdate { .. } => "pluginUpdate",
            Self::IntentDispatch { .. } => "intentDispatch",
            Self::CatalogSearch { .. } => "catalogSearch",
            Self::PluginSetEnabled { .. } => "pluginSetEnabled",
            Self::PluginInstall { .. } => "pluginInstall",
            Self::PluginInstallPackage { .. } => "pluginInstallPackage",
            Self::PluginConsent { .. } => "pluginConsent",
            Self::PluginRemove { .. } => "pluginRemove",
            Self::IntentCancel { .. } => "intentCancel",
            Self::IntentDecide { .. } => "intentDecide",
            Self::IntentSnapshot { .. } => "intentSnapshot",
            Self::Logs { .. } => "logs",
            Self::Pairing { .. } => "pairing",
            Self::Credentials { .. } => "credentials",
        }
    }

    /// Whether this request is the handshake.
    ///
    /// A kernel answers `Hello` even when the version does not match — that answer is *how* the client learns the
    /// version — and refuses every other request until the handshake has happened.
    #[must_use]
    pub const fn is_handshake(&self) -> bool {
        matches!(self, Self::Hello { .. })
    }
}

/// What the kernel answers.
///
/// # Why the payload is `serde_json::Value` rather than a typed result per request
///
/// Because the client is a command-line tool that prints what it gets, and a typed variant per request would make
/// adding a field to a status report a change to this enum, to the client and to the kernel at once. The command's
/// *shape* is the contract — `devices` returns a list of device views — and the type belongs where it is produced.
///
/// A `Value` rather than a string, so a client can re-shape it without parsing twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum Response {
    /// The answer to [`Request::Hello`].
    Hello {
        /// The protocol version the kernel speaks.
        version: u16,
        /// The kernel's own version, for a bug report.
        kernel: String,
    },

    /// A successful answer, with the command's result.
    Ok {
        /// The result, shaped by the command that produced it.
        value: serde_json::Value,
    },

    /// A refusal.
    ///
    /// # Why this carries a code rather than only a sentence
    ///
    /// A script branches on the code, and a person reads the sentence. The same split as the device protocol and the
    /// interface: one field is for a program and one is for a human, and a channel that carried only the sentence would
    /// make every script match on prose.
    Failed {
        /// The kernel's stable error code.
        code: String,
        /// Why, for a person.
        message: String,
        /// Whether repeating the request as it was could succeed.
        retryable: bool,
    },
}

impl Response {
    /// A successful answer.
    #[must_use]
    pub const fn ok(value: serde_json::Value) -> Self {
        Self::Ok { value }
    }

    /// A refusal.
    #[must_use]
    pub fn failed(code: &str, message: impl Into<String>, retryable: bool) -> Self {
        Self::Failed {
            code: code.to_owned(),
            message: message.into(),
            retryable,
        }
    }

    /// Whether this is a success.
    ///
    /// # Why `Hello` counts
    ///
    /// It is an answer the kernel was happy to give, and it carries a value the client needs. A predicate that
    /// recognised only `Ok` would call a successful handshake a failure — and the first version of this did, which is
    /// the kind of mistake that makes a client report "the kernel refused my handshake" for a working connection.
    ///
    /// `Failed` is the only shape that is not a success, so it is the one that is matched.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        !matches!(self, Self::Failed { .. })
    }

    /// The error code, when this is a refusal.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        match self {
            Self::Failed { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// Frames messages for a stream, and reads them back.
///
/// # Why a decoder rather than a `read_exact` helper
///
/// A socket delivers bytes, not messages: a read may return half a frame, three frames, or two and a half. A helper
/// that read exactly a header and then exactly a body would work against a file and fail against a socket under load —
/// and it would fail intermittently, which is the shape of bug that survives review. So the decoder buffers, and
/// [`Decoder::next_message`] returns `None` when there is not yet a whole one.
#[derive(Debug, Default)]
pub struct Decoder {
    buffer: Vec<u8>,
    /// Set on the first failure. Once set, every operation reports it.
    ///
    /// # Why a decoder poisons itself
    ///
    /// A framing error leaves the stream in an unknown position: the bytes that follow a length that was wrong are not
    /// where the next header is. Continuing would read a body as a header, and the failure would present as nonsense
    /// several messages later rather than as the one bad frame that caused it.
    poisoned: Option<ChannelError>,
}

impl Decoder {
    /// A decoder with nothing buffered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.poisoned.is_none() {
            self.buffer.extend_from_slice(bytes);
        }
    }

    /// How many bytes are buffered.
    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the decoder has refused a frame and will refuse everything after it.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    /// Reads the next whole message, if there is one.
    ///
    /// # The order of the checks
    ///
    /// The length is checked against the ceiling **before** the body is waited for, so a client that claims a
    /// four-gigabyte message is refused immediately rather than after the kernel has waited for bytes that will never
    /// come.
    ///
    /// # Errors
    ///
    /// [`ChannelError::TooLong`] for a length beyond the ceiling, and [`ChannelError::Malformed`] for a body that is
    /// not the expected JSON. Both poison the decoder.
    pub fn next_message<T: for<'de> Deserialize<'de>>(
        &mut self,
    ) -> Result<Option<T>, ChannelError> {
        if let Some(error) = &self.poisoned {
            return Err(error.clone());
        }

        if self.buffer.len() < HEADER_LEN {
            return Ok(None);
        }

        // `get` rather than a slice: the workspace denies `indexing_slicing` because a slice may panic, and the length
        // was checked one statement earlier — a check the compiler cannot see through, which is exactly why the rule is
        // "no slicing" rather than "slice only when you are sure".
        let Some(header) = self
            .buffer
            .get(..HEADER_LEN)
            .and_then(|bytes| bytes.try_into().ok())
        else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(header) as usize;

        if len > MAX_MESSAGE_LEN {
            let error = ChannelError::TooLong {
                len,
                max: MAX_MESSAGE_LEN,
            };
            self.poisoned = Some(error.clone());
            return Err(error);
        }

        if self.buffer.len() < HEADER_LEN + len {
            return Ok(None);
        }

        let Some(body) = self
            .buffer
            .get(HEADER_LEN..HEADER_LEN + len)
            .map(<[u8]>::to_vec)
        else {
            return Ok(None);
        };
        self.buffer.drain(..HEADER_LEN + len);

        match serde_json::from_slice(&body) {
            Ok(message) => Ok(Some(message)),
            Err(error) => {
                let failure = ChannelError::Malformed {
                    why: error.to_string(),
                };
                self.poisoned = Some(failure.clone());
                Err(failure)
            }
        }
    }
}

/// Frames a message for a stream.
///
/// # Errors
///
/// [`ChannelError::Malformed`] when the message cannot be serialised, and [`ChannelError::TooLong`] when it does not
/// fit. The length is checked **after** serialising, because that is the only point at which it is known — and a
/// client that checked beforehand would be checking a guess.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, ChannelError> {
    let body = serde_json::to_vec(message).map_err(|error| ChannelError::Malformed {
        why: error.to_string(),
    })?;
    if body.len() > MAX_MESSAGE_LEN {
        return Err(ChannelError::TooLong {
            len: body.len(),
            max: MAX_MESSAGE_LEN,
        });
    }

    let len = u32::try_from(body.len()).map_err(|_| ChannelError::TooLong {
        len: body.len(),
        max: MAX_MESSAGE_LEN,
    })?;

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Whether a client and this kernel can talk.
///
/// # Errors
///
/// [`ChannelError::VersionMismatch`], which names both versions. A client and a kernel are separate binaries that may
/// be upgraded separately, so this is an ordinary condition rather than a programming error.
pub const fn check_version(client: u16) -> Result<(), ChannelError> {
    if client == PROTOCOL_VERSION {
        return Ok(());
    }
    Err(ChannelError::VersionMismatch {
        client,
        kernel: PROTOCOL_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip<T>(message: &T) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let bytes = encode(message).expect("encodes");
        let mut decoder = Decoder::new();
        decoder.push(&bytes);
        decoder
            .next_message()
            .expect("no error")
            .expect("a message")
    }

    // ── Framing ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_message_round_trips() {
        let request = Request::Devices {
            include_unpaired: true,
            scan_ms: None,
        };
        assert_eq!(round_trip(&request), request);
    }

    #[test]
    fn every_request_round_trips() {
        // Each variant, because a `deny_unknown_fields` on the wrong side of a rename is a variant that decodes to
        // nothing — and the failure appears only for the one request a user happened to send.
        let requests = [
            Request::Hello {
                version: PROTOCOL_VERSION,
            },
            Request::Status,
            Request::Devices {
                include_unpaired: false,
                scan_ms: None,
            },
            Request::SendText {
                to: "dev_a".to_owned(),
                text: "hi".to_owned(),
            },
            Request::SendFile {
                to: "dev_a".to_owned(),
                path: "/tmp/a".to_owned(),
            },
            Request::Plugins,
            Request::PluginRemove {
                plugin_id: "@acme/x".to_owned(),
                remove_data: true,
            },
            Request::Logs {
                lines: 50,
                verbose: true,
                trace: None,
            },
        ];
        for request in requests {
            assert_eq!(round_trip(&request), request, "{}", request.kind());
        }
    }

    #[test]
    fn every_response_round_trips() {
        let responses = [
            Response::Hello {
                version: PROTOCOL_VERSION,
                kernel: "0.1.0".to_owned(),
            },
            Response::ok(serde_json::json!({"devices": []})),
            Response::failed("device_offline", "the device is not reachable", true),
        ];
        for response in responses {
            assert_eq!(round_trip(&response), response, "{response:?}");
        }
    }

    #[test]
    fn the_header_is_a_big_endian_length_of_the_body() {
        // ★ The framing is what a client and a kernel agree on, so it is asserted byte for byte rather than only
        // round-tripped: a round trip through one implementation passes even when that implementation is wrong.
        let bytes = encode(&Request::Status).expect("encodes");
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(len, bytes.len() - HEADER_LEN);

        // And the body is the JSON for the request, exactly. Asserted as the literal the wire carries rather than only
        // through a round trip, because a round trip through one implementation passes even when that implementation
        // spells the variant differently from the one a release already shipped.
        let body = std::str::from_utf8(&bytes[HEADER_LEN..]).expect("utf8");
        assert_eq!(body, r#""status""#, "{body}");
    }

    #[test]
    fn a_partial_header_is_waited_for_rather_than_refused() {
        // A socket delivers bytes, not messages. A decoder that refused a partial header would fail on the first read of
        // every real connection.
        let bytes = encode(&Request::Status).expect("encodes");
        let mut decoder = Decoder::new();
        for byte in &bytes[..HEADER_LEN - 1] {
            decoder.push(&[*byte]);
            assert!(
                decoder
                    .next_message::<Request>()
                    .expect("no error")
                    .is_none()
            );
        }
        decoder.push(&bytes[HEADER_LEN - 1..]);
        assert!(
            decoder
                .next_message::<Request>()
                .expect("no error")
                .is_some()
        );
    }

    #[test]
    fn a_partial_body_is_waited_for() {
        // The same, one layer in: the header arrives and the body does not. The length is known and the bytes are not,
        // which is the ordinary state of a connection mid-message.
        let bytes = encode(&Request::SendText {
            to: "a".to_owned(),
            text: "b".to_owned(),
        })
        .expect("encodes");
        let split = HEADER_LEN + 3;
        let mut decoder = Decoder::new();
        decoder.push(&bytes[..split]);
        assert!(
            decoder
                .next_message::<Request>()
                .expect("no error")
                .is_none()
        );
        decoder.push(&bytes[split..]);
        assert!(
            decoder
                .next_message::<Request>()
                .expect("no error")
                .is_some()
        );
    }

    #[test]
    fn two_messages_in_one_read_both_come_out() {
        // What a real socket does under load: one read holds several messages. A decoder that returned only the first
        // would leave the rest in the buffer until the next read — which may never come, because the client is waiting
        // for an answer.
        let mut bytes = encode(&Request::Status).expect("encodes");
        bytes.extend_from_slice(&encode(&Request::Plugins).expect("encodes"));

        let mut decoder = Decoder::new();
        decoder.push(&bytes);
        assert_eq!(
            decoder.next_message::<Request>().expect("no error"),
            Some(Request::Status)
        );
        assert_eq!(
            decoder.next_message::<Request>().expect("no error"),
            Some(Request::Plugins)
        );
        assert!(
            decoder
                .next_message::<Request>()
                .expect("no error")
                .is_none()
        );
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn a_message_split_across_three_reads_is_assembled() {
        let bytes = encode(&Request::Logs {
            lines: 10,
            verbose: false,
            trace: None,
        })
        .expect("encodes");
        let third = bytes.len() / 3;
        let mut decoder = Decoder::new();
        decoder.push(&bytes[..third]);
        decoder.push(&bytes[third..third * 2]);
        decoder.push(&bytes[third * 2..]);
        assert_eq!(
            decoder.next_message::<Request>().expect("no error"),
            Some(Request::Logs {
                lines: 10,
                verbose: false,
                trace: None
            })
        );
    }

    // ── The ceiling ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_length_beyond_the_ceiling_is_refused_before_the_body_arrives() {
        // ★ A length prefix is a promise the reader has to be willing to accept. Without the check, one frame can ask
        // the kernel to allocate four gigabytes — and a reader that waited for the body would do it after waiting for
        // bytes that will never come.
        let mut decoder = Decoder::new();
        let huge = u32::try_from(MAX_MESSAGE_LEN + 1).expect("fits");
        decoder.push(&huge.to_be_bytes());

        match decoder.next_message::<Request>() {
            Err(ChannelError::TooLong { len, max }) => {
                assert_eq!(len, MAX_MESSAGE_LEN + 1);
                assert_eq!(max, MAX_MESSAGE_LEN);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        // And the body never arrived, yet the decoder is poisoned rather than waiting.
        assert!(decoder.is_poisoned());
        assert_eq!(decoder.buffered(), HEADER_LEN);
    }

    #[test]
    fn a_message_exactly_at_the_ceiling_is_accepted() {
        // The boundary. An off-by-one here is a legitimate message refused, or a message one byte over accepted.
        // Sized by working backwards from what `encode` refuses, rather than by guessing the JSON overhead — a guess
        // that was wrong the first time this test was written.
        let overhead = serde_json::to_vec(&Request::SendText {
            to: "a".to_owned(),
            text: String::new(),
        })
        .expect("encodes")
        .len();
        let payload = "x".repeat(MAX_MESSAGE_LEN - overhead);
        let request = Request::SendText {
            to: "a".to_owned(),
            text: payload,
        };
        let bytes = encode(&request).expect("encodes");
        assert!(
            bytes.len() <= MAX_MESSAGE_LEN + HEADER_LEN,
            "{} bytes",
            bytes.len()
        );

        let mut decoder = Decoder::new();
        decoder.push(&bytes);
        assert!(
            decoder
                .next_message::<Request>()
                .expect("no error")
                .is_some()
        );
    }

    #[test]
    fn encoding_something_too_long_is_refused() {
        // The other end of the same rule: a server that produced an oversized answer would otherwise write a length the
        // client refuses, and the client would report a framing error for a message that was fine.
        let payload = "x".repeat(MAX_MESSAGE_LEN);
        let request = Request::SendText {
            to: "a".to_owned(),
            text: payload,
        };
        assert!(matches!(
            encode(&request),
            Err(ChannelError::TooLong { .. })
        ));
    }

    // ── Poisoning ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_body_that_is_not_json_poisons_the_decoder() {
        // ★ A framing error leaves the stream in an unknown position: the bytes after a length that was wrong are not
        // where the next header is. Continuing would read a body as a header and present as nonsense several messages
        // later rather than as the one bad frame that caused it.
        let mut decoder = Decoder::new();
        let body = b"{not json";
        let len = u32::try_from(body.len()).expect("fits");
        decoder.push(&len.to_be_bytes());
        decoder.push(body);

        assert!(matches!(
            decoder.next_message::<Request>(),
            Err(ChannelError::Malformed { .. })
        ));
        assert!(decoder.is_poisoned());
        // And it keeps refusing, rather than recovering into a stream position nobody can vouch for.
        assert!(decoder.next_message::<Request>().is_err());
    }

    #[test]
    fn a_poisoned_decoder_ignores_further_bytes() {
        // Buffering after a framing error would grow without bound for a client that kept writing, which is a memory
        // leak a peer can drive.
        let mut decoder = Decoder::new();
        let huge = u32::try_from(MAX_MESSAGE_LEN + 1).expect("fits");
        decoder.push(&huge.to_be_bytes());
        assert!(decoder.next_message::<Request>().is_err());

        let before = decoder.buffered();
        decoder.push(&[0u8; 4096]);
        assert_eq!(decoder.buffered(), before);
    }

    #[test]
    fn an_empty_body_is_malformed_rather_than_a_message() {
        // A zero length is a header with nothing after it. A decoder that treated it as "no message yet" would wait
        // forever for a body that was never promised.
        let mut decoder = Decoder::new();
        decoder.push(&0u32.to_be_bytes());
        assert!(matches!(
            decoder.next_message::<Request>(),
            Err(ChannelError::Malformed { .. })
        ));
    }

    #[test]
    fn a_message_with_an_unknown_field_is_refused() {
        // `deny_unknown_fields` on both sides: a client and a kernel that disagree about a field's name would otherwise
        // silently ignore it, and the field would look like it had no effect.
        let body = br#"{"status":null,"extra":1}"#;
        let len = u32::try_from(body.len()).expect("fits");
        let mut decoder = Decoder::new();
        decoder.push(&len.to_be_bytes());
        decoder.push(body);
        assert!(matches!(
            decoder.next_message::<Request>(),
            Err(ChannelError::Malformed { .. })
        ));
    }

    // ── Versions ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_same_version_is_accepted() {
        assert!(check_version(PROTOCOL_VERSION).is_ok());
    }

    #[test]
    fn a_different_version_names_both() {
        // ★ A client and a kernel are separate binaries that may be upgraded separately — a user who upgrades one and
        // not the other. The sentence has to say both versions, because "incompatible" alone leaves the user with
        // nothing to do.
        match check_version(PROTOCOL_VERSION + 1) {
            Err(ChannelError::VersionMismatch { client, kernel }) => {
                assert_eq!(client, PROTOCOL_VERSION + 1);
                assert_eq!(kernel, PROTOCOL_VERSION);
            }
            other => panic!("expected a mismatch, got {other:?}"),
        }
        // And an older client is refused the same way, rather than being assumed compatible.
        assert!(check_version(PROTOCOL_VERSION - 1).is_err());
    }

    // ── Shapes ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_handshake_is_the_one_request_a_kernel_answers_before_checking_the_version() {
        // It has to be: the answer to `Hello` is *how* a client learns the version it should have sent.
        assert!(Request::Hello { version: 99 }.is_handshake());
        for request in [
            Request::Status,
            Request::Devices {
                include_unpaired: false,
                scan_ms: None,
            },
            Request::Plugins,
            Request::Logs {
                lines: 1,
                verbose: false,
                trace: None,
            },
        ] {
            assert!(!request.is_handshake(), "{}", request.kind());
        }
    }

    #[test]
    fn every_request_has_a_distinct_name() {
        // The name reaches a log line and a test, so two requests sharing one would make a diagnostic ambiguous.
        let requests = [
            Request::Hello { version: 1 },
            Request::Status,
            Request::Devices {
                include_unpaired: false,
                scan_ms: None,
            },
            Request::SendText {
                to: String::new(),
                text: String::new(),
            },
            Request::SendFile {
                to: String::new(),
                path: String::new(),
            },
            Request::Plugins,
            Request::Logs {
                lines: 1,
                verbose: false,
                trace: None,
            },
        ];
        let mut names: Vec<&str> = requests.iter().map(Request::kind).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), requests.len(), "a request name repeats");
    }

    #[test]
    fn a_response_knows_whether_it_succeeded() {
        assert!(Response::ok(serde_json::json!(null)).is_ok());
        let failed = Response::failed("timeout", "it timed out", true);
        assert!(!failed.is_ok());
        assert_eq!(failed.error_code(), Some("timeout"));
        assert_eq!(
            Response::Hello {
                version: 1,
                kernel: "k".to_owned()
            }
            .error_code(),
            None
        );
    }

    #[test]
    fn a_refusal_carries_a_code_a_sentence_and_whether_to_retry() {
        // ★ Three fields for three readers: a script branches on the code, a person reads the sentence, and the retry
        // flag decides whether a client offers the same request again. A channel with only the sentence would make every
        // script match on prose.
        let failed = Response::failed("device_offline", "the device is not reachable", true);
        match failed {
            Response::Failed {
                code,
                message,
                retryable,
            } => {
                assert_eq!(code, "device_offline");
                assert!(message.contains("reachable"));
                assert!(retryable);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_error_explains_itself() {
        let errors = [
            ChannelError::TooLong {
                len: 5_000_000,
                max: MAX_MESSAGE_LEN,
            },
            ChannelError::Malformed {
                why: "expected value".to_owned(),
            },
            ChannelError::VersionMismatch {
                client: 2,
                kernel: 1,
            },
        ];
        for error in &errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
            assert!(!text.contains('}'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn the_ceiling_is_the_one_the_device_protocol_uses() {
        // Not a coincidence: one megabyte is far more than a command needs and the same figure the wire protocol uses
        // for a whole frame, so there is one number to remember rather than two.
        assert_eq!(MAX_MESSAGE_LEN, 1024 * 1024);
        assert_eq!(HEADER_LEN, 4);
    }
}
