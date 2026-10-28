//! Authenticated remote admission and bounded receipt deduplication; success means queued only.

use super::{EVENT_TTL, EventService, Origin, Pending, context, policy, refusal};
use crate::{link::LinkError, peer::authenticated::RequestAuthority};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use synra_protocol::{
    DeviceId, ErrorCode, PluginId, RequestId, SynraError, envelope::Envelope, event::EventName,
};

/// Host receipt for queue admission, never evidence that any guest handler executed.
pub const REMOTE_RECEIPT_EVENT: &str = "_synra.plugin.event.admission";
/// Maximum remembered remote admissions, shared by this runtime.
pub const MAX_REMOTE_RECEIPTS: usize = 1024;
/// Volatile deduplication window; retained entries are never evicted early to make room.
pub const REMOTE_RECEIPT_TTL: Duration = Duration::from_secs(60);

/// A remote event's admission answer; execution remains observable separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum RemoteAdmission {
    /// Admitted, or an identical request was already admitted in the current deduplication window.
    Accepted,
    /// Not queued; the sender must preserve the classified refusal.
    Refused {
        /// The bounded admission refusal, without guest output or event payload.
        error: SynraError,
    },
}

pub(super) struct Receipt {
    from: DeviceId,
    request: RequestId,
    generation: RequestId,
    digest: [u8; 32],
    expires: Instant,
}

impl EventService {
    /// Admit a remote plugin event using the actual TLS identities and original approval generation.
    ///
    /// Shares local queue, byte, handler and lifetime budgets. Identical requests are deduplicated
    /// for 60 seconds in at most 1024 slots; restart clears this volatile window. No exactly-once
    /// or execution-success guarantee is implied. Sender wall clocks never determine deadlines.
    /// # Errors
    /// Refuses changed device authority, foreign local identity, non-plugin/reply frames, invalid
    /// payloads, stopping runtimes, exhausted queues and conflicting or unrememberable request IDs.
    pub fn receive_remote(
        self: &Arc<Self>,
        request: &Envelope,
        authority: &RequestAuthority,
    ) -> Result<(), SynraError> {
        authority
            .authorize(request)
            .map_err(|error| authorization(&error))?;
        let (owner, _) = request.event.plugin_scope().ok_or_else(|| {
            refusal(
                ErrorCode::InvalidArgument,
                "remote delivery requires a plugin event",
                "invalidEvent",
            )
        })?;
        if request.reply_to.is_some() {
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "a delivery request cannot be a receipt",
                "unexpectedReply",
            ));
        }
        let plugin = PluginId::parse(owner).map_err(policy::invalid)?;
        let payload = request.payload_str().unwrap_or("{}");
        if payload.len() > synra_plugin_api::payload::MAX_PAYLOAD_BYTES {
            return Err(refusal(
                ErrorCode::PayloadTooLarge,
                "the event payload exceeds its byte budget",
                "payloadTooLarge",
            ));
        }
        let value: serde_json::Value = serde_json::from_str(payload).map_err(policy::invalid)?;
        if !value.is_object() {
            return Err(refusal(
                ErrorCode::InvalidArgument,
                "an event payload must be an object",
                "invalidPayload",
            ));
        }
        synra_plugin_api::payload::check_budget(&value)
            .map_err(|error| policy::payload_error(&error))?;
        let identity = self.db.lock().identity().map_err(policy::storage)?;
        if identity.is_none_or(|identity| identity.device_id != authority.local().to_string()) {
            return Err(refusal(
                ErrorCode::CapabilityDenied,
                "event runtime and authenticated local identity differ",
                "identityMismatch",
            ));
        }
        let ttl = request.ttl_ms.map_or(EVENT_TTL, |millis| {
            Duration::from_millis(u64::from(millis)).min(EVENT_TTL)
        });
        if ttl.is_zero() {
            return Err(refusal(
                ErrorCode::Timeout,
                "the remote event has no remaining lifetime",
                "eventExpired",
            ));
        }
        let digest: [u8; 32] =
            Sha256::digest(serde_json::to_vec(request).map_err(policy::invalid)?).into();
        let now = Instant::now();
        let mut state = self.state.lock();
        if state.stopping || state.plugins.strong_count() == 0 {
            return Err(refusal(
                ErrorCode::Unsupported,
                "event delivery is not attached to this runtime",
                "workerUnavailable",
            ));
        }
        state
            .remote_receipts
            .retain(|receipt| receipt.expires > now);
        if let Some(prior) = state
            .remote_receipts
            .iter()
            .find(|receipt| receipt.from == request.from && receipt.request == request.request_id)
        {
            if prior.generation != authority.generation() {
                return Err(refusal(
                    ErrorCode::CapabilityDenied,
                    "the request belongs to another approval generation",
                    "requestAuthorityChanged",
                ));
            }
            return if prior.digest == digest {
                Ok(())
            } else {
                Err(refusal(
                    ErrorCode::InvalidArgument,
                    "the request ID was reused for different content",
                    "requestConflict",
                ))
            };
        }
        if state.remote_receipts.len() >= MAX_REMOTE_RECEIPTS {
            return Err(refusal(
                ErrorCode::RateLimited,
                "the remote receipt window is full",
                "receiptWindowFull",
            ));
        }
        let runtime = state.runtime.ok_or_else(|| {
            refusal(
                ErrorCode::Unsupported,
                "event runtime is unavailable",
                "workerUnavailable",
            )
        })?;
        self.enqueue_locked(
            &mut state,
            Pending {
                event: request.event.clone(),
                from: authority.peer(),
                source: Origin::Remote {
                    plugin,
                    authority: authority.clone(),
                    runtime,
                },
                request: request.request_id,
                trace: request.trace_id,
                payload: value,
                bytes: payload.len(),
                deadline: now + ttl,
                cause: context::Cause::root(runtime),
            },
        )?;
        state.remote_receipts.push_back(Receipt {
            from: request.from,
            request: request.request_id,
            generation: authority.generation(),
            digest,
            expires: now + REMOTE_RECEIPT_TTL,
        });
        drop(state);
        self.wake.notify_one();
        Ok(())
    }
}

/// Produce a correlated queue receipt on the authenticated requesting connection.
/// # Errors
/// Refuses malformed event names or an unencodable response. Admission failures become structured
/// refusal receipts; a missing engine is never reported as successful delivery.
pub fn answer_remote_event(
    service: Option<&Arc<EventService>>,
    request: &Envelope,
    authority: &RequestAuthority,
    now_ms: i64,
) -> Result<Envelope, SynraError> {
    let result = match service {
        Some(service) => service.receive_remote(request, authority),
        None => authority
            .authorize(request)
            .map_err(|error| authorization(&error))
            .and_then(|()| {
                Err(refusal(
                    ErrorCode::Unsupported,
                    "the host has no plugin event runtime",
                    "workerUnavailable",
                ))
            }),
    };
    let answer = match result {
        Ok(()) => RemoteAdmission::Accepted,
        Err(error) => RemoteAdmission::Refused { error },
    };
    Envelope::reply_to(
        request,
        EventName::parse(REMOTE_RECEIPT_EVENT).map_err(policy::invalid)?,
        authority.local(),
        now_ms,
        Some(&answer),
    )
    .map_err(policy::invalid)
}

pub(super) fn authorization(error: &LinkError) -> SynraError {
    let code = if matches!(error, LinkError::AuthorizationUnavailable { .. }) {
        ErrorCode::Internal
    } else {
        ErrorCode::CapabilityDenied
    };
    refusal(
        code,
        "the captured peer authorization is no longer available",
        "peerAuthorityChanged",
    )
}
