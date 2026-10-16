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
        let paired = self.db().paired_devices().map_err(|error| {
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
        // report a user runs while something is wrong. So: **resolve and read the address under a short lock**, release it,
        // build the envelope, and take the lock again for the exchange.
        //
        // ★ And the second lock *is* held across the dial, the handshake and the send.
        //
        // The sentence here used to say "release it, dial, and take it again", which described the address step and
        // claimed the dial for it too. It does not: `Host::dial` takes `&mut self`, because the handshake needs this
        // device's identity and the completed session has to be recorded on the host — so the network round trip happens
        // with the registry locked, in **this** function and in three others (`send_file`, `pair`, `send_outbound`).
        //
        // That is a real cost, and it is not fixed by moving a line: it needs the host split so a handshake can be
        // performed without `&mut self` and adopted afterwards, which is a design change rather than a tidy-up. `11` §
        // records it as the open item it is; what this comment can do is stop claiming otherwise.
        // ★ And the handshake now happens **outside** the lock, which is what round 117 found was not true.
        //
        // `Host::dial` needs `&mut self` — the handshake uses this device's identity and the completed session is recorded
        // on the host — so a `devices` listing waited for a peer to finish saying `Hello`. That was not fixable by moving a
        // line: it needed the host's dial split into "handshake, needing a clone of the peer record" and "record what the
        // exchange proved, needing `&mut self`". `synra_core::dial_peer` and `Host::adopt` are those two halves, and this
        // is where they are used.
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

        let parts = {
            let host = self.host.lock();
            host.dialling_parts()
        };
        let handshake_now = synra_core::reading_millis(now);
        let dialled = synra_core::dial_peer(&parts.0, parts.1, address, None, handshake_now)
            .map_err(|error| refusal_of(&error))?;
        let mut host = self.host.lock();
        let mut link = host
            .adopt(dialled, handshake_now)
            .map_err(|error| refusal_of(&error))?;
        // ★ The read half of the send, under the lock that is already held; the write itself needs no host.
        host.may_send(&link).map_err(|error| refusal_of(&error))?;
        drop(host);
        // ★ And the write happens holding nothing, because the session layer already writes through a link
        // without the host. Only counting it needs the host again.
        link.send(&envelope).map_err(|error| refusal_of(&error.into()))?;
        self.host.lock().count_sent();

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
        self.send_a_file(to, path, None)
    }

    /// Sends a plugin bundle to a device, for installation on the other side.
    ///
    /// # Errors
    ///
    /// As [`Kernel::send_file`], plus [`ErrorCode::InvalidArgument`] for an identifier or a version this build will not
    /// put in a request.
    fn send_bundle(
        &self,
        to: &str,
        path: &str,
        plugin_id: &str,
        version: &str,
    ) -> Result<serde_json::Value, Refusal> {
        let Ok(plugin_id) = synra_protocol::ids::PluginId::try_from(plugin_id.to_owned()) else {
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                format!("{plugin_id} is not a plugin identifier"),
            ));
        };
        self.send_a_file(to, path, Some((&plugin_id, version)))
    }

    fn catalog_search(&self, package: &str) -> Result<serde_json::Value, Refusal> {
        // ★ The one kernel command that talks to the open network, and the only one whose answer can be stale. `search`
        // carries both facts in the reply rather than in a log line, because a screen has to show them.
        super::catalog::search(self, package)
    }

    fn plugins(&self) -> Result<serde_json::Value, Refusal> {
        self.plugins_value()
    }

    /// Turns a plugin on or off, and answers with the list as it now stands.
    ///
    /// """ + S + """ The write, which had no caller.
    ///
    /// `set_plugin_enabled` existed in the store, was tested, and **nothing in production called it** — so `synra plugin
    /// enable` could not have worked even if the CLI had asked. Answering with the whole list rather than the one row is
    /// deliberate: enabling a plugin changes what `plugins` reports, and a caller that had to ask twice would be one
    /// showing a stale list until it did.
    fn plugin_set_enabled(&self, plugin_id: &str, enabled: bool) -> Result<serde_json::Value, Refusal> {
        let changed = self
            .db
            .lock()
            .set_plugin_enabled(plugin_id, enabled, synra_store::sqlite::now_ms())
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        // """ + S + """ No such plugin is a refusal, and a plugin already in that state is not.
        //
        // `set_plugin_enabled` returns whether a row changed, so a second `enable` on an enabled plugin answers `false` —
        // a success with nothing to do. Reporting that as "no such plugin" would make a caller retry a typo that is not
        // there, and reporting a typo as a success would leave them believing it worked.
        let installed = self
            .db
            .lock()
            .plugin_is_installed(plugin_id)
            .unwrap_or(false);
        if !changed && !installed {
            return Err(Refusal::new(
                ErrorCode::InvalidArgument,
                format!("no plugin is installed as `{plugin_id}`"),
            ));
        }
        self.plugins_value()
    }

    fn logs(&self, lines: usize, verbose: bool, trace: Option<&str>) -> Result<serde_json::Value, Refusal> {
        self.logs_value(lines, verbose, trace)
    }

    /// Routes a share: asks the plugins, and reports what offered.
    ///
    /// ★ The method that makes the kernel do the thing the product is for. Everything it calls existed and was tested;
    /// what was missing was a way in, so the matcher had no production caller and a share that arrived became a file.
    fn intent_dispatch(&self, mime: &str, text: &str) -> Result<serde_json::Value, Refusal> {
        // ★ The origin is filled in here rather than accepted from the caller. A client on this machine's own socket is
        // not a device, so it has no identifier to send — and one it made up would be an identifier the kernel then had
        // to trust. Which device this is, is something only the kernel knows.
        let item = synra_protocol::inbound::ShareItem {
            from: self.identity.device_id,
            mime: mime.to_owned(),
            text: Some(text.to_owned()),
            transfers: Vec::new(),
            context_id: None,
        };
        let routed = crate::runtime::intent::dispatch(
            &self.plugins,
            &self.board,
            &item,
            synra_store::sqlite::now_ms(),
        );
        // ★ Recorded **before** the `?`, because that `?` is the "no plugin answered" half of the outcome.
        //
        // The design's `intents_total` is labelled by result, and a counter incremented on the success path alone would
        // count the shares something handled — which is the opposite of the question it exists for. "Why did nothing
        // answer this" is asked about the refusals.
        {
            let outcome = if routed.is_ok() { "ok" } else { "refused" };
            self.metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "intents_total",
                [("outcome".to_owned(), outcome.to_owned())],
            ));
            // ★ 「路由成功」与「有人回答」是两件事，而测试先证明了这一点：一个**空插件集**也会成功地把意图建立
            // 起来。这正是清单里 `intent_no_handler_total` 存在的理由 —— 一个没人能处理的意图和一个被处理了的
            // 意图，对用户是两种处境，而 `intents_total{outcome=ok}` 会把它们算成一件。
            //
            // `dispatch` 交回的是 JSON，所以「有没有人举手」按客户端读它的方式读：`to_json` 写 `candidates`，
            // 缺了或空了在这里是同一件事。
            if let Ok(value) = &routed {
                let nobody_offered = value
                    .get("candidates")
                    .and_then(serde_json::Value::as_array)
                    .is_none_or(Vec::is_empty);
                if nobody_offered {
                    self.metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                        "intent_no_handler_total",
                        Vec::new(),
                    ));
                }
            }
        }
        let answer = routed?;

        // ★ Written down here, from the identifier the library returned, so what is stored is whatever the board now holds
        // rather than a second opinion about it.
        //
        // The key is `intent`, not `intentId` — and the first version of this line read `intentId`, which is not a field of
        // `Routed::to_json`. `as_str()` on a missing key is `None`, so the call was simply never made: persistence that
        // silently does nothing is exactly the shape this whole path exists to remove, and it was caught by the test rather
        // than by a user whose intents kept disappearing.
        // `get` rather than indexing: a missing key is `None` either way, and an index expression is a panic waiting for
        // the day the shape changes — which is exactly how the first version of this line went wrong.
        if let Some(intent) = answer.get("intent").and_then(serde_json::Value::as_str) {
            self.checkpoint_intent(intent);
        }
        Ok(answer)
    }

    fn intent_snapshot(&self, intent: &str) -> Result<serde_json::Value, Refusal> {
        crate::runtime::intent::snapshot(&self.board, intent)
    }

    /// Applies the user's answer, and runs what they chose.
    ///
    /// ★ The one place in the daemon where a plugin's action actually runs. Everything before it — the matching pass,
    /// the board's states, the prompt — is a question; this is the answer, and it happens only for the plugin the user
    /// picked.
    fn intent_decide(
        &self,
        intent: &str,
        plugin_id: Option<&str>,
        target: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        let decided = crate::runtime::intent::decide(
            &self.plugins,
            &self.board,
            self.identity.device_id,
            intent,
            plugin_id,
            target,
            synra_store::sqlite::now_ms(),
        )?;

        // ★ The one place an intent is put on a link, and the reason the library does not do it.
        //
        // `decide` builds the envelope for a remote target and cannot send it: `synra-core` has no transport, and
        // `worker`'s doc makes the same argument for storage. So the host sends it — and sending is the whole of what was
        // missing, because `INTENT_INVOKE` had a name, a catalogue entry, an automatic-ack entry and a place in the
        // kernel-event list, and no sender anywhere in the repository.
        //
        // The order matters: the intent is already `Dispatching` with this request identifier, so a send that fails leaves
        // a recorded request the far side may still have received. Reporting the failure and leaving the state alone is
        // the honest pair — un-dispatching it would claim the message did not arrive when it may have.
        if let Some(outbound) = &decided.outbound {
            self.send_outbound(outbound)?;
        }

        // ★ After the send, not before: a send that fails leaves the intent dispatching, and what must be written down is
        // the state the caller is actually in — the far side may still have received the message.
        self.checkpoint_intent(intent);

        Ok(decided.to_json())
    }


    fn intent_cancel(&self, intent: &str) -> Result<serde_json::Value, Refusal> {
        let change = crate::runtime::intent::cancel(
            &self.board,
            self.identity.device_id,
            intent,
            "the user cancelled it",
        )?;

        // ★ A dispatched intent is running somewhere else, and cancelling it here does not stop it there.
        //
        // Without this, the other device finishes work the user withdrew and reports a result for it — and from this side
        // that looks like a cancellation that quietly did not take.
        if let Some(outbound) = &change.outbound {
            self.send_outbound(outbound)?;
        }

        self.checkpoint_intent(intent);

        Ok(change.to_json())
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

        // ★ The handshake runs **outside** the lock, so a `devices` listing does not wait for it.
        // `Host::dial` needs `&mut self` to record the session; `dial_peer` needs only a clone of this device's record,
        // and `adopt` records what the exchange proved.
        let parts = {
            let host = self.host.lock();
            host.dialling_parts()
        };
        let handshake_now = synra_core::reading_millis(now);
        let dialled = synra_core::dial_peer(&parts.0, parts.1, address, None, handshake_now)
            .map_err(|error| refusal_of(&error))?;
        let mut host = self.host.lock();
        let mut link = host
            .adopt(dialled, handshake_now)
            .map_err(|error| refusal_of(&error))?;
        // ★ The read half of the send, and then the lock goes — because what follows waits for a **person**.
        //
        // This function used to hold the host's lock across the send, the blocking read and the whole answer, with the
        // socket's deadline set to the pairing window below. So a `devices` listing waited up to that window for somebody
        // to decide whether to accept a pairing request — the exact symptom the comment at the top of `send_text` says a
        // guard across a network would cause, in its worst form: not a handshake's round trip but a human's attention.
        host.may_send(&link).map_err(|error| refusal_of(&error))?;
        drop(host);

        // The window a person answers within, which is longer than a handshake's. Set on the socket rather than left at
        // the handshake's deadline: a prompt answered just inside the session's window must not fail because the read
        // gave up at `HELLO_TIMEOUT`.
        link.set_read_timeout(Some(synra_protocol::session::SessionTimeouts::default().pairing));
        link.send(&envelope).map_err(|error| refusal_of(&error.into()))?;
        self.host.lock().count_sent();

        // A read that times out is the window closing, which the protocol makes this side's own responsibility to
        // notice: the requesting device clears its waiting state rather than hanging for ever.
        let received = match link.receive() {
            Ok(answer) => answer,
            Err(synra_core::LinkError::TimedOut) => {
                let _ = link.bye("pairing timed out");
                return Err(Refusal::new(
                    ErrorCode::DeviceOffline,
                    format!("{display_name} did not answer the pairing request in time"),
                ));
            }
            Err(synra_core::LinkError::Closed) => {
                return Err(Refusal::new(
                    ErrorCode::DeviceOffline,
                    format!("{display_name} closed the link without answering"),
                ));
            }
            // Any other link failure is the connection's, not the pairing's, so it is reported as itself. Folding it into
            // "did not answer" would make a broken network read as an unanswered prompt, and the user's next step is
            // different: check the network, not the other person.
            Err(other) => {
                let code = error_code_for_session(&synra_core::SessionError::Link(other.clone()));
                return Err(Refusal::new(code, other.to_string()));
            }
        };
        let _ = link.bye("pairing answered");

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
                self.db()
                    .pair_device(&synra_store::sqlite::Paired {
                        device_id: device_id.to_string(),
                        display_name: display_name.clone(),
                        // What the peer said it is, which the answer carried. The platform a prompt shows and the one
                        // a row records are the same fact, so it is stored rather than re-derived from the OS.
                        platform: platform.to_string(),
                        features: "[]".to_owned(),
                        link_token,
                        // The address this side dialled, which it resolved from discovery a few lines above.
                        // Recording it means a device list can show where a peer was last reached.
                        address: Some(address.to_string()),
                        paired_at_ms: now,
                    })
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
            // ★ `Answered` is `#[non_exhaustive]`: a variant added to it is a change a consumer has to be told about, and
            // a wildcard is how this side says it has no answer to give. Not reached today, and the refusal is the same
            // shape the two above use — this is a caller-side failure rather than a device that went quiet.
            _ => Err(Refusal::new(
                ErrorCode::Unsupported,
                format!("this device has no answer for the response {display_name} sent"),
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
        let db = self.db();
        // The store's clock, which is the signed milliseconds the column holds. `Runtime::now_ms` is unsigned for the
        // uptime arithmetic it exists for, and using it here would need a cast that could wrap after the epoch.
        let now = synra_store::sqlite::now_ms();
        let written = self
            .pairing
            .answer(request, accepted, |record| {
                db.pair_device(&synra_store::sqlite::Paired {
                    device_id: record.device_id.to_string(),
                    display_name: record.display_name.clone(),
                    platform: record.platform.to_string(),
                    features: "[]".to_owned(),
                    link_token: record.link_token.clone(),
                    // The address the connection observed, carried on the prompt. `None` when the request had no
                    // socket under it, which records no address rather than an empty one.
                    address: Some(record.address.clone()).filter(|address| !address.is_empty()),
                    paired_at_ms: now,
                })
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


/// What this host does that the kernel trait has no place for.
impl Runtime {

    fn send_a_file(
        &self,
        to: &str,
        path: &str,
        bundle: Option<(&synra_protocol::ids::PluginId, &str)>,
    ) -> Result<serde_json::Value, Refusal> {
        let now = synra_store::sqlite::now_ms();
        let started = std::time::Instant::now();
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

        // ★ The handshake runs **outside** the lock, so a `devices` listing does not wait for it.
        // `Host::dial` needs `&mut self` to record the session; `dial_peer` needs only a clone of this device's record,
        // and `adopt` records what the exchange proved.
        let parts = {
            let host = self.host.lock();
            host.dialling_parts()
        };
        let handshake_now = synra_core::reading_millis(now);
        let dialled = synra_core::dial_peer(&parts.0, parts.1, address, None, handshake_now)
            .map_err(|error| refusal_of(&error))?;
        let mut host = self.host.lock();
        let mut link = host
            .adopt(dialled, handshake_now)
            .map_err(|error| refusal_of(&error))?;
        // ★ Taken from the link rather than from what the user typed. The handshake is what established who is on the other
        // end, so an address that turned out to belong to a different device is reported as *that* device rather than as
        // the one that was expected.
        let device_id = link.peer();

        // ★ The transfer runs with a deadline, because a peer that stops reading would otherwise hold this thread for ever.
        // The protocol's own scan budget is not the right figure — a file takes as long as it takes — so this is a ceiling
        // on one transfer rather than an expected duration.
        let deadline = std::time::Instant::now() + TRANSFER_DEADLINE;
        // ★ The same eleven steps for both payloads: what differs is the request the sender builds, and that is
        // decided here rather than by a second copy of the validation, the dial and the report.
        let events = match bundle {
            Some((plugin_id, version)) => synra_core::send_bundle(
                &mut link,
                &source,
                plugin_id.clone(),
                version,
                trace_id,
                now,
                deadline,
            ),
            None => synra_core::send_file(
                &mut link,
                &source,
                synra_core::transfer::DEFAULT_CHUNK_SIZE,
                trace_id,
                now,
                deadline,
            ),
        }
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
        // ★ The design's `transfer_retries_total`: the one number that says what the network cost.
        //
        // Recorded only when there was a resend — a counter that always adds zero is a series nobody needs, and the
        // recorder's own guard is about cardinality rather than about empty rows.
        //
        // ★ And a note about its evidence: no test covers this line. A resend happens when a report is lost, and
        // provoking that needs a link that drops one — which the test scaffolding here does not do. The number comes
        // from `resends`, which the `Verified`/`Resend` events already produced and which the report already showed.
        if resends > 0 {
            self.metrics.counter_add(
                &synra_observe::metrics::SeriesKey::new(
                    "transfer_retries_total",
                    [(
                        "kind".to_owned(),
                        if bundle.is_some() { "bundle" } else { "attachment" }.to_owned(),
                    )],
                ),
                resends as u64,
            );
        }
        // ★ The two things the successful path can answer: how big it was, and how long it took.
        //
        // `transfers_total{outcome}` is deliberately **not** here. This method has several early returns — a path that
        // does not exist, an address that cannot be resolved, a handshake that fails — and a counter written on the
        // success path alone would count the transfers that worked and say nothing about the ones a user asks about,
        // which is the same mistake the intent counter next door exists to avoid. That one needs every exit to pass one
        // place, and this method cannot get that without restructuring a `Kernel` trait method's body — tried this round
        // and backed out, because the surgery cost more than the metric.
        self.metrics.histogram_observe(
            &synra_observe::metrics::SeriesKey::new(
                "transfer_bytes",
                [("kind".to_owned(), "attachment".to_owned())],
            ),
            bytes as f64,
        );
        self.metrics.histogram_observe(
            &synra_observe::metrics::SeriesKey::new(
                "transfer_duration_ms",
                [("kind".to_owned(), "attachment".to_owned())],
            ),
            started.elapsed().as_secs_f64() * 1_000.0,
        );
        // ★ And the sender records what the peer now holds — the other half of the mirror whose receiving side landed
        // in round 150 (`sync_records`, keyed by `(plugin_id, peer_device)`).
        //
        // ★ Only on a `Verified` event, and that is the precise test rather than a convenient one: `events` carries
        // one only when the receiver actually said it checked the file (`await_confirmation`'s answer). A transfer
        // that was sent but never confirmed must not claim the peer holds anything — a row like that would make the
        // next synchronisation believe the two ends agree.
        if let Some((plugin_id, version)) = bundle
            && let Some(digest) = events.iter().find_map(|event| match event {
                synra_core::SessionEvent::Verified { digest, .. } => Some(digest.clone()),
                _ => None,
            })
        {
            let _ = self.db().record_sync(
                plugin_id.as_str(),
                &device_id.to_string(),
                version,
                &digest,
                now,
            );
        }
        Ok(serde_json::json!({
            "sent": true,
            "confirmed": confirmed,
            "to": device_id.to_string(),
            "bytes": bytes,
            "resendRounds": resends,
            "traceId": trace_id.to_string(),
        }))
    }

        /// Puts an intent's envelope on a link to the device it names.
        ///
        /// # Errors
        ///
        /// [`Refusal`] naming what the user can act on: the device has never been seen on this network, or the link could not
        /// be established.
        fn send_outbound(&self, outbound: &synra_core::intent::remote::Outbound) -> Result<(), Refusal> {
            let now = synra_store::sqlite::now_ms();
            // Resolve and read the address under the lock; dial outside it, for the reason `send_text` gives — a `dial` blocks
            // for as long as a connection takes, and a host guard living across it would make a devices listing wait for a
            // network.
            let address = {
                let host = self.host.lock();
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

            // ★ The handshake runs **outside** the lock, so a `devices` listing does not wait for it.
            // `Host::dial` needs `&mut self` to record the session; `dial_peer` needs only a clone of this device's record,
            // and `adopt` records what the exchange proved.
            let parts = {
                let host = self.host.lock();
                host.dialling_parts()
            };
            let handshake_now = synra_core::reading_millis(now);
            let dialled = synra_core::dial_peer(&parts.0, parts.1, address, None, handshake_now)
                .map_err(|error| refusal_of(&error))?;
            let mut host = self.host.lock();
            let mut link = host
                .adopt(dialled, handshake_now)
                .map_err(|error| refusal_of(&error))?;
            // ★ The read half of the send, under the lock that is already held; the write itself needs no host.
            host.may_send(&link).map_err(|error| refusal_of(&error))?;
            drop(host);
            // ★ And the write happens holding nothing, because the session layer already writes through a link
            // without the host. Only counting it needs the host again.
            link.send(&outbound.envelope).map_err(|error| refusal_of(&error.into()))?;
            self.host.lock().count_sent();
            let _ = link.bye("intent dispatched");

            Ok(())
        }
}
