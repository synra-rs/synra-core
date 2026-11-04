use super::{CONSENT_TIMEOUT, Client, Duration, Instant, Phase, Policy};
use crate::input::{LEASE, queue::Sample, wire};
use crate::{LinkError, PeerLink};

pub(super) fn run(client: &Client, policy: &dyn Policy) -> Result<(), String> {
    current(client, policy)?;
    let snapshot = client.state.lock().clone();
    let mut link = policy.connect(snapshot.target)?;
    current(client, policy)?;
    link.set_read_timeout(Some(Duration::from_millis(100)));
    link.set_write_timeout(Some(LEASE));
    let open = wire::Open {
        control_id: snapshot.session,
        plugin_id: client.plugin.clone(),
    };
    wire::send(&mut link, wire::OPEN, &open)?;
    let result = exchange(client, policy, &mut link);
    // Best effort only; if the socket is gone, the receiving lease still releases independently.
    let _ = wire::send(&mut link, wire::CANCEL, &snapshot.session);
    result
}

fn current(client: &Client, policy: &dyn Policy) -> Result<(), String> {
    if !client.active() {
        return Err("controller closed or hidden".to_owned());
    }
    let target = client.state.lock().target;
    if policy.authorize(target, &client.plugin, false)? != client.generation {
        return Err("permission changed".to_owned());
    }
    Ok(())
}

fn exchange(client: &Client, policy: &dyn Policy, link: &mut PeerLink) -> Result<(), String> {
    let deadline = Instant::now() + CONSENT_TIMEOUT;
    let accepted = loop {
        current(client, policy)?;
        if Instant::now() >= deadline {
            return Err("consent timed out".to_owned());
        }
        match link.receive() {
            Err(LinkError::TimedOut) => continue,
            Err(error) => return Err(error.to_string()),
            Ok(envelope) if envelope.event.as_str() == wire::ACCEPT => {
                break wire::read::<wire::Accepted>(&envelope)?;
            }
            Ok(envelope) if envelope.event.as_str() == wire::ERROR => {
                return Err(wire::read::<String>(&envelope)?);
            }
            Ok(_) => return Err("unexpected input approval".to_owned()),
        }
    };
    current(client, policy)?;
    {
        let mut state = client.state.lock();
        if state.phase != Phase::Pending {
            return Err("session stopped".to_owned());
        }
        state.phase = Phase::Active;
    }
    let mut sequence = 0_u64;
    let mut last = Instant::now();
    loop {
        current(client, policy)?;
        let sample = client.queue.pop().or_else(|| {
            (last.elapsed() >= Duration::from_millis(250)).then(|| Sample {
                commands: Vec::new(),
                at: Instant::now(),
            })
        });
        let Some(sample) = sample else {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        };
        sequence = sequence
            .checked_add(1)
            .ok_or_else(|| "input sequence exhausted".to_owned())?;
        let measured = !sample.commands.is_empty();
        let packet = wire::Packet {
            session: accepted.session,
            generation: accepted.generation,
            sequence,
            commands: sample.commands,
        };
        wire::send(link, wire::PACKET, &packet)?;
        let deadline = Instant::now() + Duration::from_millis(750);
        loop {
            current(client, policy)?;
            if Instant::now() >= deadline {
                return Err("input execution acknowledgement timed out".to_owned());
            }
            match link.receive() {
                Err(LinkError::TimedOut) => continue,
                Err(error) => return Err(error.to_string()),
                Ok(envelope)
                    if envelope.event.as_str() == wire::ACK
                        && wire::read::<u64>(&envelope)? == sequence =>
                {
                    break;
                }
                Ok(envelope) if envelope.event.as_str() == wire::ERROR => {
                    return Err(wire::read::<String>(&envelope)?);
                }
                Ok(_) => return Err("unexpected input acknowledgement".to_owned()),
            }
        }
        client.acknowledge(sequence, sample.at, measured);
        last = Instant::now();
        // A separate input budget, independent of ordinary command retries and their timeouts.
        std::thread::sleep(Duration::from_micros(16_667));
    }
}
