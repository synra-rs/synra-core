use std::net::SocketAddr;

use parking_lot::Mutex;
use synra_control::Refusal;
use synra_core::{Dialled, Host};
use synra_protocol::{error::ErrorCode, ids::DeviceId};

use super::super::refusals::refusal_of;
use super::REMOTE_RESULT_WAIT;

/// Clones dialling metadata under the host lock and retries the handshake after releasing it.
pub(super) fn dial_with_retries(
    host: &Mutex<Host>,
    address: SocketAddr,
    peer: DeviceId,
    handshake_now: u64,
) -> Result<Dialled, Refusal> {
    let (config, flags) = host.lock().dialling_parts();
    synra_core::retry::with_retries(
        synra_core::retry::ATTEMPTS,
        |_| synra_core::dial_peer(&config, flags, address, peer, handshake_now)
            .map_err(|error| refusal_of(&error)),
        |attempt| {
            std::thread::sleep(std::time::Duration::from_millis(
                100 * (u64::try_from(attempt).unwrap_or(0) + 1),
            ));
        },
    )
}

/// Puts one envelope on a link, and reads the one answer the same connection carries.
///
/// # Why this is a free function
///
/// Because two things need it and only one of them has a `Runtime`: the command path, and the start-up pass that sends
/// again what a restart left in flight. The runtime owns the pieces; a resend thread owns only clones of them, and giving
/// it a whole runtime it cannot borrow would mean not resending at all.
///
/// # Returns
///
/// `Some(reply)` for an `INTENT_RESULT`, `None` when there is nothing to apply — a timeout, an unexpected event, or a
/// withdrawal that is not answered. A timeout is **not** a failed dispatch: the action may still be running over there, so
/// the intent stays dispatching and a late answer can still end it.
///
/// # Errors
///
/// [`Refusal`] for a device with no known address, a dial that never connected, or a write the link refused.
pub(in crate::runtime) fn exchange(
    host: &Mutex<Host>,
    outbound: &synra_core::intent::remote::Outbound,
    wait_for_result: bool,
) -> Result<Option<synra_protocol::envelope::Envelope>, Refusal> {
    let now = synra_store::sqlite::now_ms();
    // Resolve and read the address under the lock; dial outside it, for the reason `send_text` gives — a `dial` blocks
    // for as long as a connection takes, and a host guard living across it would make a devices listing wait for a
    // network.
    let address = {
        let host = host.lock();
        host.address_of(outbound.to).ok_or_else(|| {
            Refusal::new(
                ErrorCode::DeviceOffline,
                format!(
                    "{} cannot run this: it has not been seen on this network, so there is nowhere to send it",
                    outbound.to
                ),
            )
        })?
    };

    // ★ The handshake runs **outside** the lock, so a `devices` listing does not wait for it. `Host::dial` needs
    // `&mut self` to record the session; `dial_peer` needs only a clone of this device's record, and `adopt` records what
    // the exchange proved.
    let handshake_now = synra_core::reading_millis(now);
    let dialled = dial_with_retries(host, address, outbound.to, handshake_now)?;
    let mut guard = host.lock();
    let mut link = guard
        .adopt(dialled, handshake_now)
        .map_err(|error| refusal_of(&error))?;
    // ★ The read half of the send, under the lock that is already held; the write itself needs no host.
    guard.may_send(&link).map_err(|error| refusal_of(&error))?;
    drop(guard);
    // ★ And the write happens holding nothing, because the session layer already writes through a link without the host.
    // Only counting it needs the host again. The write and the answer are the kernel's halves so the window and the
    // daemon cannot disagree about what counts as an answer; the count sits between them because it is about a write
    // that actually happened.
    synra_core::intent::remote::send(&mut link, outbound)
        .map_err(|error| Refusal::new(error.code, error.message))?;
    host.lock().count_sent();

    // ★ An invocation is answered on **this** connection, so the answer is read before the link is closed. A sender that
    // said `bye` immediately after the write would make the request fire-and-forget: the far side runs the action and then
    // has no connection to reply on, and this side leaves the intent dispatching for ever.
    let wait = wait_for_result.then_some(REMOTE_RESULT_WAIT);
    synra_core::intent::remote::receive(&mut link, wait)
        .map_err(|error| Refusal::new(error.code, error.message))
}
