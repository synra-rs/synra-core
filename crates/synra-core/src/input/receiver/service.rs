use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use synra_platform::pointer::Pointer;
use synra_protocol::envelope::Envelope;
use synra_protocol::ids::SessionId;

use crate::{LinkError, PeerLink};

use super::super::{wire, CONSENT_TIMEOUT, LEASE};
use super::release::Released;
use super::{Phase, Receiver, Snapshot};

impl Receiver {
    pub(in crate::input) fn serve(&self, link: &mut PeerLink, request: &Envelope) {
        if let Err(reason) = self.admit_and_run(link, request) {
            let _ = wire::send(link, wire::ERROR, &reason);
        }
    }

    fn admit_and_run(&self, link: &mut PeerLink, request: &Envelope) -> Result<(), String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("host stopped".to_owned());
        }
        if !wire::source_matches(link, request) {
            return Err("wrong input source".to_owned());
        }
        let open: wire::Open = wire::read(request)?;
        let revision = self.policy.authorize(link.peer(), &open.plugin_id, true)?;
        let snapshot = Snapshot {
            session: SessionId::new(),
            peer: link.peer(),
            peer_name: self.policy.peer_name(link.peer()),
            plugin_id: open.plugin_id.clone(),
            phase: Phase::Pending,
            reason: None,
        };
        {
            let mut state = self.state.lock();
            if state.as_ref().is_some_and(|s| s.phase != Phase::Ended) {
                return Err("pointer is busy".to_owned());
            }
            *state = Some(snapshot.clone());
        }
        self.publish();
        link.set_read_timeout(Some(Duration::from_millis(100)));
        link.set_write_timeout(Some(LEASE));
        let result = self.run(link, &open, &snapshot, revision);
        self.finish(
            snapshot.session,
            result.as_ref().err().map_or("closed", String::as_str),
        );
        result
    }

    fn current(&self, snapshot: &Snapshot, revision: i64) -> Result<(), String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("host stopped".to_owned());
        }
        if self.phase(snapshot.session) == Phase::Ended {
            return Err("stopped or declined".to_owned());
        }
        if self
            .policy
            .authorize(snapshot.peer, &snapshot.plugin_id, true)?
            != revision
        {
            return Err("permission changed".to_owned());
        }
        Ok(())
    }

    fn run(
        &self,
        link: &mut PeerLink,
        open: &wire::Open,
        snapshot: &Snapshot,
        revision: i64,
    ) -> Result<(), String> {
        let deadline = Instant::now() + CONSENT_TIMEOUT;
        loop {
            self.current(snapshot, revision)?;
            if self.phase(snapshot.session) == Phase::Allowed {
                break;
            }
            if Instant::now() >= deadline {
                return Err("consent timed out".to_owned());
            }
            match link.receive() {
                Err(LinkError::TimedOut) => {}
                Err(error) => return Err(error.to_string()),
                Ok(envelope)
                    if envelope.event.as_str() == wire::CANCEL
                        && wire::read::<SessionId>(&envelope)? == open.control_id =>
                {
                    return Err("cancelled".to_owned());
                }
                Ok(_) => return Err("unexpected input before approval".to_owned()),
            }
        }
        // Stop may expose Ended before this worker releases its buttons. A new approved
        // worker must wait for that release, without holding the consent-state lock.
        let _exclusive = self.pointer_lease.lock();
        self.current(snapshot, revision)?;
        let mut pointer = Released((self.factory)()?);
        self.current(snapshot, revision)?;
        {
            let mut state = self.state.lock();
            if let Some(current) = state
                .as_mut()
                .filter(|s| s.session == snapshot.session && s.phase == Phase::Allowed)
            {
                current.phase = Phase::Active;
            } else {
                return Err("session stopped".to_owned());
            }
        }
        self.publish();
        wire::send(
            link,
            wire::ACCEPT,
            &wire::Accepted {
                session: snapshot.session,
                generation: revision,
            },
        )?;
        self.receive_packets(link, open, snapshot, revision, pointer.0.as_mut())
    }

    fn receive_packets(
        &self,
        link: &mut PeerLink,
        open: &wire::Open,
        snapshot: &Snapshot,
        revision: i64,
        pointer: &mut dyn Pointer,
    ) -> Result<(), String> {
        let mut last = Instant::now();
        let mut sequence = 0_u64;
        let mut window = Instant::now();
        let mut count = 0;
        loop {
            self.current(snapshot, revision)?;
            if last.elapsed() >= LEASE {
                return Err("input lease expired".to_owned());
            }
            let envelope = match link.receive() {
                Err(LinkError::TimedOut) => continue,
                Err(error) => return Err(error.to_string()),
                Ok(envelope) => envelope,
            };
            if envelope.event.as_str() == wire::CANCEL
                && wire::read::<SessionId>(&envelope)? == open.control_id
            {
                return Ok(());
            }
            if last.elapsed() >= LEASE {
                return Err("input lease expired".to_owned());
            }
            if envelope.event.as_str() != wire::PACKET {
                return Err("unexpected input message".to_owned());
            }
            let packet: wire::Packet = wire::read(&envelope)?;
            if packet.session != snapshot.session
                || packet.generation != revision
                || Some(packet.sequence) != sequence.checked_add(1)
                || packet.commands.len() > 16
                || !packet.commands.iter().all(|command| command.valid())
            {
                return Err("invalid or replayed input packet".to_owned());
            }
            if window.elapsed() >= Duration::from_secs(1) {
                window = Instant::now();
                count = 0;
            }
            count += 1;
            if count > 120 {
                return Err("input rate exceeded".to_owned());
            }
            self.current(snapshot, revision)?;
            {
                // Linearize local Stop with native effects: once stop() returns no later packet can apply.
                let state = self.state.lock();
                if state
                    .as_ref()
                    .is_none_or(|s| s.session != snapshot.session || s.phase != Phase::Active)
                {
                    return Err("session stopped".to_owned());
                }
                for command in packet.commands {
                    pointer.apply(command)?;
                }
                drop(state);
            }
            sequence = packet.sequence;
            last = Instant::now();
            wire::send(link, wire::ACK, &sequence)?;
        }
    }
}
