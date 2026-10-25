//! Owns temporary listeners and restricted sockets; no task/database guard spans IO.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use synra_net::authentication::PeerIdentity;
use synra_net::authentication::pairing::PairingChannel;
use synra_protocol::RequestId;
use synra_protocol::pairing::PairingPhase;

use super::{PairingService, PairingServiceError, transport};
use crate::peer_trust::PairingTask;

pub(super) enum Connection {
    Listen(TcpListener),
    Connect(SocketAddr),
}

pub(super) fn run(
    service: &PairingService,
    id: RequestId,
    peer: &PeerIdentity,
    connection: Connection,
) -> Result<(), PairingServiceError> {
    let deadline = {
        let slot = service.task.lock();
        slot.as_ref()
            .filter(|task| task.snapshot.request_id == id)
            .ok_or(PairingServiceError::NotRunning)?
            .deadline
    };
    let (socket, accepting) = match connection {
        Connection::Connect(address) => (
            TcpStream::connect_timeout(
                &address,
                remaining(service, id, deadline)?.min(synra_protocol::limits::HELLO_TIMEOUT),
            )
            .map_err(|error| transport(&error))?,
            false,
        ),
        Connection::Listen(listener) => (accept(service, id, &listener, deadline)?, true),
    };
    let cancelled = {
        let mut slot = service.task.lock();
        let task = slot
            .as_mut()
            .filter(|task| task.snapshot.request_id == id && !task.cancelled)
            .ok_or(PairingServiceError::Cancelled)?;
        task.snapshot.phase = PairingPhase::Connecting;
        let cancelled = Arc::clone(&task.cancel_signal);
        drop(slot);
        cancelled
    };
    let budget = remaining(service, id, deadline)?.min(synra_protocol::limits::HELLO_TIMEOUT);
    let mut channel = if accepting {
        PairingChannel::accept(socket, &service.credentials, peer, budget, Some(cancelled))?
    } else {
        PairingChannel::connect(socket, &service.credentials, peer, budget, Some(cancelled))?
    };
    channel.restrict_deadline(deadline);
    // Sample callbacks before the slot lock; the clock may itself inspect application state.
    let now_ms = (service.clock)();
    let task = {
        let mut slot = service.task.lock();
        let current = slot
            .as_mut()
            .filter(|task| task.snapshot.request_id == id && !task.cancelled)
            .ok_or(PairingServiceError::Cancelled)?;
        if Instant::now() >= deadline {
            return Err(PairingServiceError::TimedOut);
        }
        let task = PairingTask::begin_reserved(
            Arc::clone(&service.db),
            channel,
            &current.reservation,
            now_ms,
        )?;
        current.snapshot.phase = PairingPhase::Confirming;
        drop(slot);
        task
    };
    // Both host commands already explicitly approved their imported OOB identities.
    task.finish(true, remaining(service, id, deadline)?, || {
        (service.clock)()
    })?;
    Ok(())
}

fn accept(
    service: &PairingService,
    id: RequestId,
    listener: &TcpListener,
    deadline: Instant,
) -> Result<TcpStream, PairingServiceError> {
    loop {
        let left = remaining(service, id, deadline)?;
        match listener.accept() {
            Ok((socket, _)) => return Ok(socket),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(transport(&error)),
        }
        std::thread::sleep(left.min(Duration::from_millis(20)));
    }
}

fn remaining(
    service: &PairingService,
    id: RequestId,
    deadline: Instant,
) -> Result<Duration, PairingServiceError> {
    let cancelled = {
        let slot = service.task.lock();
        slot.as_ref()
            .filter(|task| task.snapshot.request_id == id)
            .ok_or(PairingServiceError::NotRunning)?
            .cancelled
    };
    if cancelled {
        return Err(PairingServiceError::Cancelled);
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(PairingServiceError::TimedOut);
    }
    Ok(remaining)
}
