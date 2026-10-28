//! Captured connection authority retained across asynchronous business dispatch.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use parking_lot::Mutex;
use synra_net::authentication::AuthenticatedStream;
use synra_protocol::{DeviceId, RequestId, envelope::Envelope};
use synra_store::SynraDb;

use crate::{link::LinkError, peer_trust::PeerApproval};

struct State {
    db: Arc<Mutex<SynraDb>>,
    approval: PeerApproval,
    local: DeviceId,
    peer: DeviceId,
    denied: AtomicBool,
}

/// Immutable TLS identity and approval generation for deferred business work.
///
/// Obtain this from an authenticated link; loading a current database grant cannot construct it.
/// Clone it with queued work and call [`Self::authorize`] immediately before admission to execution.
/// Revocation or storage failure permanently denies every clone and its original connection. It never upgrades itself
/// to a new approval after re-pairing, and cannot be serialized into a guest or peer-supplied token.
///
/// This is an authorization context, not a connection lease or a request deadline. Callers must
/// independently bound queued work and terminate input sessions when their connection disappears.
/// Plugin identity, namespace, capability and payload checks remain the dispatcher's responsibility.
#[derive(Clone)]
pub struct RequestAuthority(Arc<State>);

impl RequestAuthority {
    pub(super) fn new(
        tls: &AuthenticatedStream,
        approval: PeerApproval,
        db: Arc<Mutex<SynraDb>>,
    ) -> Result<Self, LinkError> {
        match approval.allows(&db, tls, tls.peer_device_id()) {
            Ok(true) => Ok(Self(Arc::new(State {
                db,
                approval,
                local: tls.local_identity().device_id(),
                peer: tls.peer_device_id(),
                denied: AtomicBool::new(false),
            }))),
            Ok(false) => Err(LinkError::Unauthorized),
            Err(error) => Err(LinkError::AuthorizationUnavailable {
                why: error.to_string(),
            }),
        }
    }

    /// Actual local identity authenticated by TLS and Hello.
    #[must_use]
    pub fn local(&self) -> DeviceId {
        self.0.local
    }

    /// Actual remote identity authenticated by TLS and Hello.
    #[must_use]
    pub fn peer(&self) -> DeviceId {
        self.0.peer
    }

    /// Original durable approval generation, retained even after revocation.
    #[must_use]
    pub fn generation(&self) -> RequestId {
        self.0.approval.generation()
    }

    /// Rechecks identities and the captured durable authorization before executing a received request.
    ///
    /// This acquires a database lock only for the check and never retains it across guest or IO work.
    /// # Errors
    /// Refuses a different sender or target, revoked or replaced credentials, a changed approval
    /// generation, and unavailable authorization storage. Failure never becomes permission.
    pub fn authorize(&self, request: &Envelope) -> Result<(), LinkError> {
        self.check(request.target, request.from)
    }

    /// Rechecks captured identities for the transport and listener adapters within this crate.
    pub(crate) fn check(&self, local: DeviceId, peer: DeviceId) -> Result<(), LinkError> {
        if local != self.local() || peer != self.peer() {
            return Err(LinkError::Unauthorized);
        }
        if self.0.denied.load(Ordering::Relaxed) {
            return Err(LinkError::Unauthorized);
        }
        let result = match self.0.approval.current(&self.0.db) {
            Ok(true) => Ok(()),
            Ok(false) => Err(LinkError::Unauthorized),
            Err(error) => Err(LinkError::AuthorizationUnavailable {
                why: error.to_string(),
            }),
        };
        if result.is_err() {
            self.0.denied.store(true, Ordering::Relaxed);
        }
        result
    }

    pub(super) fn is_denied(&self) -> bool {
        self.0.denied.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for RequestAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RequestAuthority")
            .field("local", &self.local())
            .field("peer", &self.peer())
            .finish_non_exhaustive()
    }
}
