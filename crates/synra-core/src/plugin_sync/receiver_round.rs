use super::*;

/// One round of synchronisation, as the sender sees it.
///
/// ★ **Why the three travel as one value rather than as three arguments.**
///
/// They belong together by construction: a round is about **one plugin at one version**, and a round whose declaration
/// disagreed with the package it carried would be a message nobody could act on. They also would not fit — `send_bundle`
/// was already at clippy's argument limit, and the honest answer to that is to name the thing rather than to allow the
/// lint.
///
/// ★ **Why the sender chooses the session and the receiver does not.**
///
/// A round is started by one side, and that side is the only one that can name it: two devices pushing at the same
/// moment would each invent an identifier the other has never heard of, and neither could match a result to a round.
/// The receiver's job is to repeat it back — which is what `TransferRequest::sync_session_id` carries it for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRound {
    /// Which plugin this round is about.
    pub plugin_id: PluginId,
    /// Which version is being sent.
    pub version: String,
    /// Which round it is.
    ///
    /// ★ The protocol's identifier rather than this module's [`SyncSessionId`], because this is the value that travels:
    /// `TransferRequest::sync_session_id` is an `Option<SessionId>`, and a round the other side cannot name is a round
    /// it cannot answer. The two types name the same thing; only one of them fits in a packet.
    pub session: synra_protocol::ids::SessionId,
}
