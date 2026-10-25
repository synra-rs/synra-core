//! The complete sending workflow shared by interactive and headless hosts.

use std::time::{Duration, Instant};

use synra_protocol::ids::{TraceId, TransferId};
use synra_protocol::session::{SessionTimeouts, TransferAbortReason, TransferKind};

use crate::link::{Inbound, LinkError, PeerLink};
use crate::transfer::TransferSender;

use super::super::types::{SessionError, SessionEvent};
use super::super::wire::payload_of;
use super::blocks::{propose, send_observed};
use super::control::{Control, read_control};
use super::transfer::{abort, complete};

/// The budget and correlation information for one complete transfer.
#[derive(Debug, Clone, Copy)]
pub struct SendOptions {
    /// Trace shared by the proposal, completion and abort.
    pub trace_id: TraceId,
    /// Wall-clock sample for outgoing envelopes.
    pub now_ms: i64,
    /// Monotonic deadline for the whole operation.
    pub deadline: Instant,
    /// Maximum time without a newly acknowledged block or final confirmation.
    pub idle_timeout: Duration,
}

impl SendOptions {
    /// Uses the protocol's default idle budget and the caller's total deadline.
    #[must_use]
    pub fn new(trace_id: TraceId, now_ms: i64, deadline: Instant) -> Self {
        Self {
            trace_id,
            now_ms,
            deadline,
            idle_timeout: SessionTimeouts::default().transfer_idle,
        }
    }
}

/// Proposes an already prepared object and succeeds only after a matching digest confirmation.
///
/// `progress` reports newly acknowledged blocks, including repairs, rather than socket writes.
/// Cancellation is sampled before each write and between bounded reads, including the final wait.
/// Caller timeout overrides are restored on every return; a failed write must not be retried on
/// this link because it may have left a partial frame on the wire.
///
/// # Errors
/// Returns a structured cancellation, deadline, peer abort, malformed control message, or IO error.
pub fn send_prepared(
    link: &mut PeerLink,
    sender: &mut TransferSender,
    options: SendOptions,
    cancelled: impl Fn() -> bool,
    progress: impl FnMut(u32, u32),
) -> Result<Vec<SessionEvent>, SessionError> {
    let previous = link.timeout_overrides();
    let mut context = SendContext::new(options, cancelled, progress, link.write_deadline());
    let outcome = run(link, sender, &mut context);
    if matches!(
        outcome,
        Err(SessionError::Cancelled | SessionError::TimedOut)
    ) {
        let reason = if matches!(outcome, Err(SessionError::Cancelled)) {
            TransferAbortReason::UserCancelled
        } else if Instant::now() >= options.deadline {
            TransferAbortReason::TotalTimeout
        } else {
            TransferAbortReason::IdleTimeout
        };
        // A best-effort terminal notice gets its own short budget after the operation has ended.
        link.set_write_timeout(Some(Duration::from_millis(100)));
        let _ = abort(
            link,
            sender.transfer_id(),
            reason,
            options.trace_id,
            options.now_ms,
        );
    }
    link.set_read_timeout(previous.0);
    link.set_write_timeout(previous.1);
    outcome
}

fn run(
    link: &mut PeerLink,
    sender: &mut TransferSender,
    context: &mut SendContext<impl Fn() -> bool, impl FnMut(u32, u32)>,
) -> Result<Vec<SessionEvent>, SessionError> {
    context.prepare_write(link)?;
    let mut events = vec![propose(
        link,
        sender,
        context.options.trace_id,
        context.options.now_ms,
    )?];
    events.extend(send_observed(link, sender, context)?);
    context.prepare_write(link)?;
    events.push(complete(
        link,
        sender,
        context.options.trace_id,
        context.options.now_ms,
    )?);
    loop {
        match context.read(link)? {
            Some(Control::Complete(confirmation)) => {
                check_transfer(confirmation.transfer_id, sender.transfer_id())?;
                if &confirmation.digest != sender.digest().as_sri() {
                    return Err(crate::transfer::TransferError::CompletionMismatch {
                        found: confirmation.digest.encoded().to_owned(),
                        promised: sender.digest().encoded().to_owned(),
                    }
                    .into());
                }
                break;
            }
            Some(Control::Progress(progress)) => {
                check_transfer(progress.transfer_id, sender.transfer_id())?;
            }
            Some(Control::Abort(notice)) => {
                check_transfer(notice.transfer_id, sender.transfer_id())?;
                return Err(SessionError::Aborted {
                    reason: notice.reason,
                });
            }
            None => {}
        }
    }
    events.push(SessionEvent::Verified {
        transfer_id: sender.transfer_id(),
        digest: sender.digest().encoded().to_owned(),
    });
    if sender.request().kind == TransferKind::PluginBundle {
        // Bundle installation results are distinct from the required file confirmation.
        if let Some(result) = bundle_result(link, context)? {
            events.push(SessionEvent::SyncResult { result });
        }
    }
    Ok(events)
}

fn bundle_result(
    link: &mut PeerLink,
    context: &SendContext<impl Fn() -> bool, impl FnMut(u32, u32)>,
) -> Result<Option<crate::messaging::SyncResult>, SessionError> {
    let patience = crate::peer::Flags::production()
        .timeout
        .unwrap_or(context.remaining()?);
    let deadline = Instant::now() + patience.min(context.remaining()?);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        link.set_read_timeout(Some(
            remaining
                .min(context.remaining()?)
                .min(Duration::from_millis(100)),
        ));
        let inbound = match link.receive_inbound() {
            Ok(inbound) => inbound,
            Err(LinkError::TimedOut) => continue,
            Err(LinkError::Closed) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        context.remaining()?;
        let Inbound::Envelope(envelope) = inbound else {
            return Ok(None);
        };
        if envelope.event.as_str() != synra_protocol::event::events::PLUGIN_SYNC_RESULT {
            return Ok(None);
        }
        return Ok(Some(payload_of(&envelope, "result")?));
    }
}

pub(super) fn check_transfer(found: TransferId, expected: TransferId) -> Result<(), SessionError> {
    if found != expected {
        return Err(SessionError::WrongTransfer {
            found: found.to_string(),
            expected: expected.to_string(),
        });
    }
    Ok(())
}

pub(super) struct SendContext<C, P> {
    options: SendOptions,
    cancelled: C,
    progress: P,
    last_progress: Instant,
    write_timeout: Option<Duration>,
}

impl<C: Fn() -> bool, P: FnMut(u32, u32)> SendContext<C, P> {
    pub(super) fn new(
        options: SendOptions,
        cancelled: C,
        progress: P,
        write_timeout: Option<Duration>,
    ) -> Self {
        Self {
            options,
            cancelled,
            progress,
            last_progress: Instant::now(),
            write_timeout,
        }
    }

    pub(super) fn remaining(&self) -> Result<Duration, SessionError> {
        if (self.cancelled)() {
            return Err(SessionError::Cancelled);
        }
        let now = Instant::now();
        let total = self.options.deadline.saturating_duration_since(now);
        let idle = self
            .options
            .idle_timeout
            .saturating_sub(now.duration_since(self.last_progress));
        let remaining = total.min(idle);
        if remaining.is_zero() {
            return Err(SessionError::TimedOut);
        }
        Ok(remaining)
    }

    pub(super) fn prepare_write(&self, link: &mut PeerLink) -> Result<(), SessionError> {
        let remaining = self.remaining()?;
        link.set_write_timeout(Some(remaining.min(self.write_timeout.unwrap_or(remaining))));
        Ok(())
    }

    pub(super) fn read(&self, link: &mut PeerLink) -> Result<Option<Control>, SessionError> {
        link.set_read_timeout(Some(self.remaining()?.min(Duration::from_millis(100))));
        let control = read_control(link)?;
        self.remaining()?;
        Ok(control)
    }

    pub(super) fn advanced(&mut self, done: u32, total: u32) {
        self.last_progress = Instant::now();
        (self.progress)(done, total);
    }
}
