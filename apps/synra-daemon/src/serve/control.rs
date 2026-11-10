//! Bounded control connections and their drain at daemon shutdown.

use std::sync::Arc;
use std::time::Duration;

use synra_control::Listener;

use crate::runtime::Runtime;

/// Waits for the control connections to finish, and names the ones that did not.
pub(super) fn drain_control(gate: &Arc<crate::control_gate::ControlGate>) {
    if !gate.wait_for_idle(Duration::from_secs(5)) {
        tracing::warn!(
            open = gate.active(),
            "control connections are still open at shutdown and are being abandoned"
        );
    }
}

/// Accepts and serves one control connection; `false` means the listener itself failed.
///
/// # Why this is a function
///
/// Because the loop is three decisions — admit, spawn, or report an accept failure — and `serve` has a complexity budget.
/// Named, the loop reads as "keep accepting until asked to stop", which is what it means.
pub(super) fn accept_control(
    listener: &Listener,
    gate: &Arc<crate::control_gate::ControlGate>,
    runtime: &Arc<Runtime>,
) -> bool {
    // ★ One thread per connection. The loop used to call `serve_one`, so one client at a time — which made a command that
    // waits (a remote action's answer, a pairing prompt) an outage for every other command: `status` queued behind an
    // `intent decide` for as long as the wait lasted. The socket is local and each client is a process the user started,
    // so a thread per connection is the trust boundary the one-at-a-time loop had, without the queue.
    match listener.accept() {
        Ok(stream) => {
            let Some(permit) = gate.try_enter() else {
                // ★ Closing rather than answering: a refusal needs a request to answer, and a client over the limit is not
                // one whose request is worth reading. The caller sees a transport error naming the closed connection,
                // which is the truth.
                tracing::warn!(
                    open = gate.active(),
                    "refusing a control connection: the gate is full"
                );
                drop(stream);
                return true;
            };
            let runtime = Arc::clone(runtime);
            std::thread::spawn(move || {
                // The permit is held for the connection's lifetime, so the count cannot leak on an early return.
                let _permit = permit;
                // ★ A panic inside one connection must not be invisible: without this the thread unwinds, the socket
                // closes, and `synra logs` says nothing about why. The payload is not printed — it may contain request
                // data — but the fact is recorded, and the daemon keeps serving.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    synra_control::serve_stream(stream, &*runtime)
                }));
                match outcome {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::error!(%error, "a control connection failed"),
                    Err(_) => tracing::error!("a control connection panicked"),
                }
            });
            true
        }
        Err(error) => {
            // One client's failure is not the daemon's. A transport error is reported and the loop continues, because a
            // daemon that exited on a malformed connection would be one any local process could stop.
            tracing::error!(%error, "the control listener could not accept a connection");
            // ★ It sleeps: acceptance is separate from serving now, so a permanently failing listener would spin.
            std::thread::sleep(Duration::from_millis(10));
            false
        }
    }
}
