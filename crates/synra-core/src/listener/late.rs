use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use synra_protocol::envelope::Envelope;

use crate::host::Host;
use crate::late_queue::LateQueue;

///
/// # Why this is here rather than in a host
///
/// Because the queue is written by the listener and the delivery is the listener's own dial-back; a host that had to
/// re-implement both would have a second definition of a late answer. A host's only job is to call this on a timer.
///
/// Returns what this pass did, so a caller that keeps metrics can record it without reading the directory.
pub fn retry_late(host: &Arc<Mutex<Host>>, data_dir: &Path) -> crate::late_queue::RetrySummary {
    LateQueue::in_data_dir(data_dir).retry_with(synra_store::sqlite::now_ms(), |envelope| {
        deliver_late(host, envelope)
    })
}

/// Delivers an answer to the device it is addressed to, on a new connection.
///
/// # Why a second connection is the right answer
///
/// Because the first one is gone: the sender waited its bounded time, gave up and closed. The alternative — leaving the
/// intent `dispatching` although the action succeeded — is the state this exists to remove. The event is the same
/// `INTENT_RESULT`; the origin's listener applies it with `orchestrate::apply_result`, which ignores a result for work it
/// is no longer waiting on, so a late duplicate is harmless.
///
/// The retry decision is [`crate::retry::with_retries`]: the same bound and pause the daemon uses for an ordinary send, so
/// the two paths cannot drift about how many times a listener is given.
pub(super) fn deliver_late(host: &Arc<Mutex<Host>>, envelope: &Envelope) -> Result<(), String> {
    let address = {
        let host = host.lock();
        host.address_of(envelope.target)
            // An origin this device has never seen cannot be dialled on the first attempt or the third: retrying an
            // unknown address would only make the failure slower.
            .ok_or_else(|| format!("{} has never been seen on this network", envelope.target))?
    };
    let parts = {
        let host = host.lock();
        host.dialling_parts()
    };
    let mut attempt_dial = |_attempt: usize| {
        let handshake = crate::reading_millis(synra_store::sqlite::now_ms());
        let result = crate::dial_peer(&parts.0, parts.1, address, envelope.target, handshake)
            .map_err(|error| error.to_string());
        host.lock()
            .count_late_delivery(if result.is_ok() { "delivered" } else { "retry" });
        result
    };
    let dialled =
        match crate::retry::with_retries(crate::retry::ATTEMPTS, &mut attempt_dial, |attempt| {
            // 100 ms, then 200 ms: enough for a listener that is shutting down a previous connection to come back, short
            // enough that a peer which is truly gone does not hold this thread.
            std::thread::sleep(Duration::from_millis(
                100 * (u64::try_from(attempt).unwrap_or(0) + 1),
            ));
        }) {
            Ok(dialled) => dialled,
            Err(error) => {
                host.lock().count_late_delivery("exhausted");
                return Err(error);
            }
        };
    let mut link = host
        .lock()
        // The handshake time is taken **after** the retries: the attempt that succeeded is the one whose clock matters.
        .adopt(
            dialled,
            crate::reading_millis(synra_store::sqlite::now_ms()),
        )
        .map_err(|error| error.to_string())?;
    link.send(envelope).map_err(|error| error.to_string())?;
    let _ = link.bye("late result");
    Ok(())
}
