use std::path::PathBuf;

use synra_control::{Kernel, Refusal};
use synra_protocol::error::ErrorCode;

use super::refusals::{error_code_for, error_code_for_session, refusal_of};
use super::{Runtime, now_ms};

/// How long one file transfer may take before the daemon stops waiting.
///
/// # Why this is a ceiling and not an expectation
///
/// A file takes as long as it takes, so nothing here can be the *expected* duration. What it bounds is the worst case: a
/// peer that stops reading, a link that has gone quiet, or a receiver that never answers. Without it, one stalled transfer
/// holds a kernel thread for ever — and the protocol's own scan budget would be far too short, because that is how long a
/// *scan* listens, not how long a file takes to move.
const TRANSFER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

impl Kernel for Runtime {
    fn version(&self) -> String {
        self.version.clone()
    }

    fn status(&self) -> Result<serde_json::Value, Refusal> {
        Ok(self.status_value(now_ms()))
    }

    fn devices(&self, include_unpaired: bool, scan_ms: Option<u64>) -> Result<serde_json::Value, Refusal> {
        // ★ The scan is done **before** the table is read, and by the worker rather than here. Only the worker owns the
        // discovery socket, and a client that slept for the duration and then asked would get exactly the table it would
        // have got without asking — the sleep would look like a scan and be a delay.
        if let Some(scan_ms) = scan_ms.filter(|ms| *ms > 0) {
            self.scan(scan_ms);
        }

        // ★ Three sources, reported separately rather than merged. A paired device, a device merely heard on the network,
        // and this device are three different things to a user — and a list that put them together would present an
        // unauthenticated datagram as something the user had approved.
        let host = self.host.lock();
        let now = now_ms();

        // The paired devices come from the database, which is the recorded decision.
        let paired = self.db.paired_devices().map_err(|error| {
            Refusal::new(ErrorCode::Internal, format!("could not read the paired devices: {error}"))
        })?;
        let mut paired_list: Vec<serde_json::Value> = Vec::new();
        for row in &paired {
            // The session is the proof the device is reachable *now*, as opposed to recorded once. A user asking for
            // devices is asking what they can act on, so the two are reported together.
            let device_id: synra_protocol::ids::DeviceId = row.device_id.parse().map_err(|error| {
                Refusal::new(
                    ErrorCode::Internal,
                    format!("the stored device id {} is not a UUID: {error}", row.device_id),
                )
            })?;
            let session = host.state_of(device_id);
            paired_list.push(serde_json::json!({
                "deviceId": row.device_id,
                "displayName": row.display_name,
                "platform": row.platform,
                "blocked": row.blocked,
                "pairedAtMs": row.paired_at_ms,
                "lastSeenMs": row.last_seen_ms,
                // `null` when there is no session, which is different from a session that is closed — and the difference
                // is what tells a user whether the device is offline or was never reached.
                "linkState": session.map(|state| format!("{state:?}")),
            }));
        }

        // The candidates are what discovery heard, which is unauthenticated and therefore reported as its own list.
        let candidates: Vec<serde_json::Value> = if include_unpaired {
            host.discovery()
                .displayable(synra_core::millis_reading(now))
                .map(|candidate| {
                    serde_json::json!({
                        "deviceId": candidate.device_id.to_string(),
                        "displayName": candidate.display_name,
                        "address": candidate.address.to_string(),
                        "trust": format!("{:?}", candidate.trust),
                        "lastSeenMs": candidate.last_seen_ms,
                    })
                })
                .collect()
        }
        else {
            Vec::new()
        };

        Ok(serde_json::json!({
            // ★ Reported rather than omitted, so a client prints it. A user who runs `devices` because nothing works
            // needs to know which device they are running it *on* — that identifier is what the other end has recorded
            // against them.
            "self": {
                "deviceId": self.identity.device_id.to_string(),
                "displayName": self.identity.display_name,
                "platform": self.identity.platform,
            },
            "paired": paired_list,
            "found": candidates,
            "includeUnpaired": include_unpaired,
            "count": paired_list.len() + candidates.len(),
        }))
    }

    fn send_text(&self, to: &str, text: &str) -> Result<serde_json::Value, Refusal> {
        let now = synra_store::sqlite::now_ms();
        let trace_id = synra_protocol::ids::TraceId::new();

        // ★ The text is checked **before** the host is touched, and the order is a decision rather than a detail. An empty
        // `--text` is a mistake in the argument the user just typed; reporting it as an unknown device would send them to
        // check a device list for a mistake they made in their own sentence. The check is done by building an envelope
        // addressed to *this* device, which the protocol validates, and then throwing it away — the real one is built once
        // the device is known, so this costs one small allocation and no lock.
        synra_core::text_to(self.identity.device_id, self.identity.device_id, text, trace_id, now)
            .map_err(|error| Refusal::new(error_code_for(&error), error.to_string()))?;

        // ★ One critical section, and the handshake is **outside** it. `dial` blocks for as long as a connection takes,
        // and a `host` guard living across it would mean a `devices` listing waits for a network — which is exactly the
        // report a user runs while something is wrong. So: resolve and read the address under the lock, release it, dial,
        // and take it again to record what happened.
        let (device_id, address, from) = {
            let host = self.host.lock();
            let device_id = host.resolve(to).map_err(|error| refusal_of(&error))?;
            // Where to reach it. A device known by name but never seen has no address, which is a different answer from
            // "nothing is called that".
            let address = host.address_of(device_id).ok_or_else(|| {
                Refusal::new(
                    ErrorCode::DeviceOffline,
                    format!("{device_id} is known and has no address — it has not been seen on this network"),
                )
            })?;
            (device_id, address, host.device_id())
        };

        // The envelope is built now, addressed to the device that was resolved.
        let envelope = synra_core::text_to(from, device_id, text, trace_id, now)
            .map_err(|error| Refusal::new(error_code_for(&error), error.to_string()))?;

        let mut host = self.host.lock();
        // Dial, which is where the handshake establishes that the device on the other end really is the one asked for.
        let mut link = host
            .dial(address, None, synra_core::reading_millis(now))
            .map_err(|error| refusal_of(&error))?;
        host.send(&mut link, &envelope).map_err(|error| refusal_of(&error))?;
        drop(host);

        // The link is closed on the way out rather than kept: the daemon has nowhere to record it between requests, and a
        // link nobody is reading is one the peer sees as a connection that arrived and went silent. A session per message
        // costs a handshake; holding links open is the next piece of work and is a design decision rather than a detail.
        let _ = link.bye("message delivered");

        Ok(serde_json::json!({
            "sent": true,
            "to": device_id.to_string(),
            "bytes": text.len(),
            "traceId": trace_id.to_string(),
        }))
    }

    /// Sends a file to a device, named by identifier, display name, or `host:port`.
    ///
    /// # Errors
    ///
    /// [`Refusal`] naming what the user got wrong: the path, the device, or the transfer.
    fn send_file(&self, to: &str, path: &str) -> Result<serde_json::Value, Refusal> {
        let now = synra_store::sqlite::now_ms();
        let trace_id = synra_protocol::ids::TraceId::new();
        let source = PathBuf::from(path);

        // ★ The file is checked **before** the device is looked up, for the reason `send --text` checks the text first: a
        // path that does not exist is a mistake in the argument the user just typed, and reporting it as an unknown device
        // would send them to check a device list for a problem that is not there.
        if !source.is_file() {
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                format!("{path} is not a file this process can read"),
            ));
        }

        // The same two-step the text path uses: resolve and read the address under one lock, release it, then dial. The
        // handshake can take seconds, and a guard living across it would make a `devices` listing wait for the network.
        //
        // ★ One critical section, a `drop` and then the failures — not an expression that returns them. `?` inside a block
        // whose guard is still alive reads, to clippy's `significant_drop_in_scrutinee`, as a drop on the early-return path
        // — which is the same pattern that has bitten this workspace before.
        // ★ `--to` may be an address as well as a device, and the address is checked first because it is unambiguous by
        // construction: a device identifier and a display name are both arbitrary strings that *could* look like one, and
        // a user who typed `192.168.1.5:47100` meant the address. This is what makes a device reachable before discovery
        // has found it — which is the state every installation is in until its first scan.
        let address = match to.trim().parse::<std::net::SocketAddr>() {
            Ok(address) => address,
            Err(_) => {
                let found = {
                    let host = self.host.lock();
                    match host.resolve(to) {
                        Ok(device_id) => host.address_of(device_id).map(|address| (device_id, address)).ok_or_else(
                            || {
                                Refusal::new(
                                    ErrorCode::DeviceOffline,
                                    format!(
                                        "{device_id} is known and has no address — it has not been seen on this network"
                                    ),
                                )
                            },
                        ),
                        Err(error) => Err(refusal_of(&error)),
                    }
                };
                // The guard is gone by now: the block above ended, which is what `significant_drop_in_scrutinee` wants to
                // see rather than a `?` on an expression that still holds it.
                let (device_id, address) = found?;
                // Kept only so the report below can name the device. The handshake establishes the real identity, and the
                // link is the authority for everything after it.
                let _ = device_id;
                address
            }
        };

        let mut host = self.host.lock();
        let mut link = host
            .dial(address, None, synra_core::reading_millis(now))
            .map_err(|error| refusal_of(&error))?;
        // ★ Taken from the link rather than from what the user typed. The handshake is what established who is on the other
        // end, so an address that turned out to belong to a different device is reported as *that* device rather than as
        // the one that was expected.
        let device_id = link.peer();

        // ★ The transfer runs with a deadline, because a peer that stops reading would otherwise hold this thread for ever.
        // The protocol's own scan budget is not the right figure — a file takes as long as it takes — so this is a ceiling
        // on one transfer rather than an expected duration.
        let deadline = std::time::Instant::now() + TRANSFER_DEADLINE;
        let events = synra_core::send_file(
            &mut link,
            &source,
            synra_core::transfer::DEFAULT_CHUNK_SIZE,
            trace_id,
            now,
            deadline,
        )
        .map_err(|error| Refusal::new(error_code_for_session(&error), error.to_string()))?;
        drop(host);

        let bytes = std::fs::metadata(&source).map(|meta| meta.len()).unwrap_or(0);
        let resends = events
            .iter()
            .filter(|event| matches!(event, synra_core::SessionEvent::Resend { .. }))
            .count();
        // ★ `sent` means **the receiver confirmed it**, not "this end finished talking". Those are different claims, and
        // an end-to-end run showed the gap: the file arrived byte-for-byte while the sender reported a transport failure,
        // because it had stopped listening before the confirmation came.
        let confirmed = events
            .iter()
            .any(|event| matches!(event, synra_core::SessionEvent::Verified { .. }));

        // The link is closed rather than kept, for the reason the text path gives: the daemon has nowhere to record it
        // between requests, and a link nobody is reading is one the peer sees as a connection that arrived and went quiet.
        let _ = link.bye("file sent");

        // ★ `confirmed` is a **separate fact** from whether the bytes moved, and an end-to-end run is what showed why: a
        // 300 KB file arrived byte-for-byte with a matching digest while the sender never heard the receiver's completion.
        // Reporting that as a transfer failure would tell a user their file did not arrive when it did — and reporting it
        // as a plain success would claim knowledge this device does not have.
        //
        // So both are said. `sent` is what this device did; `confirmed` is what it heard back.
        Ok(serde_json::json!({
            "sent": true,
            "confirmed": confirmed,
            "to": device_id.to_string(),
            "bytes": bytes,
            "resendRounds": resends,
            "traceId": trace_id.to_string(),
        }))
    }

    fn plugins(&self) -> Result<serde_json::Value, Refusal> {
        self.plugins_value()
    }

    fn logs(&self, lines: usize, verbose: bool) -> Result<serde_json::Value, Refusal> {
        self.logs_value(lines, verbose)
    }

    /// Asks a device to pair, and waits for its user.
    ///
    /// # Why the host lock is released before the request is sent
    ///
    /// Because the wait is a person. `dial` blocks for a connection and the answer blocks for a decision, and a `host`
    /// guard living across either would make a `devices` listing wait for somebody else's user to make up their mind —
    /// which is exactly the command a user runs while wondering why pairing is taking so long.
    ///
    /// # Why the peer's details come from this side's own record
    ///
    /// Because nothing on the wire carries them in this direction: a `PairRequest` carries **this** device's profile, so
    /// the other user sees a name. What the asked device calls itself is what discovery heard, which is the only place
    /// either side learns it.
    ///
    /// # Errors
    ///
    /// [`Refusal`] naming what went wrong: the device, the connection, the request, or the other user's refusal.
    fn pair(&self, device: &str) -> Result<serde_json::Value, Refusal> {
        let now = synra_store::sqlite::now_ms();
        let trace_id = synra_protocol::ids::TraceId::new();

        // Read everything the exchange needs under one lock, then release it. Scoped rather than held, because `dial`
        // below is a network round trip.
        let (device_id, address, ours) = {
            let host = self.host.lock();
            let device_id = host.resolve(device).map_err(|error| refusal_of(&error))?;
            let address = host.address_of(device_id).ok_or_else(|| {
                Refusal::new(
                    ErrorCode::DeviceOffline,
                    format!("{device_id} is known and has no address — it has not been seen on this network"),
                )
            })?;
            let identity = host.identity();
            let profile = synra_protocol::session::PeerProfile {
                device_id: identity.device_id,
                display_name: identity.display_name.clone(),
                // The identity stores the operating system, because that is what it was created from; the profile the
                // protocol carries wants the coarser kind, so the conversion is the same one the host announces with.
                platform: synra_core::platform_of_os(&identity.platform),
                app_version: self.version.clone(),
            };
            // Released here rather than at the end of the block: the values above are owned, and holding the host while
            // the tuple is built would be a lock held for no reason.
            drop(host);
            (device_id, address, profile)
        };

        // What the peer calls itself, from what discovery heard. Absent means it was never announced, which is a device
        // this kernel can dial but cannot name — and a prompt that cannot name the device asking is one a user should not
        // be shown, so it is refused rather than shown as an identifier.
        let (display_name, platform) = {
            let host = self.host.lock();
            let found = host.discovery().get(device_id).map(|candidate| {
                (
                    candidate.display_name.clone(),
                    candidate.platform.unwrap_or(synra_protocol::session::PlatformKind::Desktop),
                )
            });
            drop(host);
            found.ok_or_else(|| {
                Refusal::new(
                    ErrorCode::DeviceOffline,
                    format!("{device_id} has never announced itself, so pairing with it cannot be shown to a user"),
                )
            })?
        };

        let (pairing_state, request) = synra_core::pairing::OutboundPairing::ask(
            synra_core::pairing::PairingTarget { device_id, display_name: display_name.clone(), platform },
            ours.clone(),
            synra_protocol::session::SessionTimeouts::default().pairing,
            now,
        );
        // ★ The envelope carries **this** device's profile, not the peer's: the request's whole purpose is that the other
        // user sees a name rather than an identifier. Sending theirs would ask them to pair with themselves, and the
        // record on this side would then name this device as its own peer.
        let envelope =
            synra_core::pair_request(self.identity.device_id, device_id, &ours, trace_id, now)
                .map_err(|error| Refusal::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let _ = request;

        let mut host = self.host.lock();
        let mut link = host
            .dial(address, None, synra_core::reading_millis(now))
            .map_err(|error| refusal_of(&error))?;
        // The window a person answers within, which is longer than a handshake's. Set on the socket rather than left at
        // the handshake's deadline: a prompt answered just inside the session's window must not fail because the read
        // gave up at `HELLO_TIMEOUT`.
        link.set_read_timeout(Some(synra_protocol::session::SessionTimeouts::default().pairing));
        host.send(&mut link, &envelope).map_err(|error| refusal_of(&error))?;

        // A read that times out is the window closing, which the protocol makes this side's own responsibility to
        // notice: the requesting device clears its waiting state rather than hanging for ever.
        let received = match link.receive() {
            Ok(answer) => answer,
            Err(synra_core::LinkError::TimedOut) => {
                let _ = link.bye("pairing timed out");
                drop(host);
                return Err(Refusal::new(
                    ErrorCode::DeviceOffline,
                    format!("{display_name} did not answer the pairing request in time"),
                ));
            }
            Err(synra_core::LinkError::Closed) => {
                drop(host);
                return Err(Refusal::new(
                    ErrorCode::DeviceOffline,
                    format!("{display_name} closed the link without answering"),
                ));
            }
            // Any other link failure is the connection's, not the pairing's, so it is reported as itself. Folding it into
            // "did not answer" would make a broken network read as an unanswered prompt, and the user's next step is
            // different: check the network, not the other person.
            Err(other) => {
                drop(host);
                let code = error_code_for_session(&synra_core::SessionError::Link(other.clone()));
                return Err(Refusal::new(code, other.to_string()));
            }
        };
        let _ = link.bye("pairing answered");
        drop(host);

        let response: synra_protocol::session::PairResponse =
            serde_json::from_str(received.payload_str().unwrap_or("{}")).map_err(|error| {
                Refusal::new(
                    ErrorCode::Internal,
                    format!("the pairing answer could not be read: {error}"),
                )
            })?;

        let answered = pairing_state
            .accept_answer(&response, received.request_id)
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;

        match answered {
            synra_core::pairing::Answered::Accepted { device_id, display_name, platform, link_token } => {
                self.db
                    .pair_device(
                        &device_id.to_string(),
                        &display_name,
                        &platform.to_string(),
                        "[]",
                        &link_token,
                        now,
                    )
                    .map_err(|error| {
                        Refusal::new(ErrorCode::Internal, format!("the pairing could not be recorded: {error}"))
                    })?;
                Ok(serde_json::json!({
                    "paired": true,
                    "deviceId": device_id.to_string(),
                    "displayName": display_name,
                    "traceId": trace_id.to_string(),
                }))
            }
            synra_core::pairing::Answered::Refused { reason } => Err(Refusal::new(
                ErrorCode::InvalidArgument,
                format!("{display_name} refused to pair: {reason}"),
            )),
            synra_core::pairing::Answered::TimedOut => Err(Refusal::new(
                ErrorCode::DeviceOffline,
                format!("{display_name} did not answer the pairing request in time"),
            )),
        }
    }

    /// Answers the prompt a device is waiting on.
    ///
    /// # Why a request that is not there is an error rather than a quiet success
    ///
    /// Because both ways it happens are things a caller wants to know: the prompt expired while the user was deciding, or
    /// something answered it twice. Reporting "answered" for either would tell a script its decision was carried out when
    /// the device it was about had already been released — and the user would believe they had paired.
    fn pair_answer(&self, request_id: &str, accepted: bool) -> Result<serde_json::Value, Refusal> {
        let request = request_id.parse::<synra_protocol::ids::RequestId>().map_err(|error| {
            Refusal::new(
                ErrorCode::InvalidArgument,
                format!("{request_id} is not a request id: {error}"),
            )
        })?;

        // The desk records the pairing before it builds the response, so "durable, then answered" is a property of the
        // desk rather than a hope about the order of two calls here. The record goes to the database this runtime claimed.
        let db = &self.db;
        // The store's clock, which is the signed milliseconds the column holds. `Runtime::now_ms` is unsigned for the
        // uptime arithmetic it exists for, and using it here would need a cast that could wrap after the epoch.
        let now = synra_store::sqlite::now_ms();
        let written = self
            .pairing
            .answer(request, accepted, |record| {
                db.pair_device(
                    &record.device_id.to_string(),
                    &record.display_name,
                    &record.platform.to_string(),
                    "[]",
                    &record.link_token,
                    now,
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
            })
            .ok_or_else(|| {
                Refusal::new(
                    ErrorCode::InvalidArgument,
                    format!("no pairing request is waiting under {request_id}"),
                )
            })?;

        Ok(serde_json::json!({
            "requestId": request_id,
            "accepted": written.accepted,
            "reason": written.reason,
        }))
    }
}
