use std::path::PathBuf;

use synra_protocol::error::ErrorCode;

use super::super::refusals::{error_code_for_session, refusal_of};
use super::peer::dial_with_retries;

use synra_control::Refusal;

use super::super::Runtime;

/// How long one file transfer may take before the daemon stops waiting.
///
/// # Why this is a ceiling and not an expectation
///
/// A file takes as long as it takes, so nothing here can be the *expected* duration. What it bounds is the worst case: a
/// peer that stops reading, a link that has gone quiet, or a receiver that never answers. Without it, one stalled transfer
/// holds a kernel thread for ever — and the protocol's own scan budget would be far too short, because that is how long a
/// *scan* listens, not how long a file takes to move.
const TRANSFER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

impl Runtime {
    /// Sends a file to a device, named by identifier, display name, or `host:port`.
    ///
    /// # Errors
    ///
    /// [`Refusal`] naming what the user got wrong: the path, the device, or the transfer.
    pub(super) fn command_send_file(&self, to: &str, path: &str) -> Result<serde_json::Value, Refusal> {
        self.send_a_file(to, path, None)
    }

    /// Sends a plugin bundle to a device, for installation on the other side.
    ///
    /// # Errors
    ///
    /// As [`synra_control::Kernel::send_file`], plus [`ErrorCode::InvalidArgument`] for an identifier or a version this build will not
    /// put in a request.
    pub(super) fn command_send_bundle(
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
        // A route is not an identity: resolve the intended device before choosing its certificate pin.
        let found = {
            let host = self.host.lock();
            match host.resolve(to) {
                Ok(device_id) => host
                    .address_of(device_id)
                    .map(|address| (device_id, address))
                    .ok_or_else(|| {
                        Refusal::new(
                            ErrorCode::DeviceOffline,
                            format!("{device_id} has no known address"),
                        )
                    }),
                Err(error) => Err(refusal_of(&error)),
            }
        };
        let (device_id, address) = found?;

        // ★ The handshake runs **outside** the lock, so a `devices` listing does not wait for it.
        // `Host::dial` needs `&mut self` to record the session; `dial_peer` needs only a clone of this device's record,
        // and `adopt` records what the exchange proved.
        let handshake_now = synra_core::reading_millis(now);
        let dialled = dial_with_retries(&self.host, address, device_id, handshake_now)?;
        let mut host = self.host.lock();
        let mut link = host
            .adopt(dialled, handshake_now)
            .map_err(|error| refusal_of(&error))?;
        // ★ Taken from the link rather than from what the user typed. The handshake is what established who is on the other
        // end, so an address that turned out to belong to a different device is reported as *that* device rather than as
        // the one that was expected.
        let device_id = link.peer();
        drop(host);

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
                &synra_core::plugin_sync::SyncRound {
                    plugin_id: plugin_id.clone(),
                    version: version.to_owned(),
                    // ★ 这一侧发起，所以这一侧命名 —— 而 `SessionId::new()` 给的是一个不与任何东西相撞的
                    // 标识。它不需要写进磁盘：它的用途只是让对端的回复能对上这一轮。
                    session: synra_protocol::ids::SessionId::new(),
                },
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
        let bytes = std::fs::metadata(&source)
            .map(|meta| meta.len())
            .unwrap_or(0);
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
                        if bundle.is_some() {
                            "bundle"
                        } else {
                            "attachment"
                        }
                        .to_owned(),
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
        // ★ `kind` is the same word the retry counter and the receiver use. The first version hardcoded `attachment`,
        // so a plugin bundle's size and duration were filed under the wrong kind and the two ends disagreed about what
        // crossed the wire.
        let kind = if bundle.is_some() {
            "bundle"
        } else {
            "attachment"
        };
        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
        self.metrics.histogram_observe(
            &synra_observe::metrics::SeriesKey::new(
                "transfer_bytes",
                [("kind".to_owned(), kind.to_owned())],
            ),
            bytes as f64,
        );
        self.metrics.histogram_observe(
            &synra_observe::metrics::SeriesKey::new(
                "transfer_duration_ms",
                [("kind".to_owned(), kind.to_owned())],
            ),
            elapsed_ms,
        );
        // ★ The design's throughput, computed here rather than in the interface: the two numbers it needs are already in
        // this frame, and a reader that divided them itself would have to know whether duration was seconds or ms.
        // Zero elapsed is a clock too coarse to divide by; recording nothing is better than an infinite sample.
        if elapsed_ms > 0.0 {
            self.metrics.histogram_observe(
                &synra_observe::metrics::SeriesKey::new(
                    "transfer_throughput_bps",
                    [("kind".to_owned(), kind.to_owned())],
                ),
                bytes as f64 / (elapsed_ms / 1_000.0),
            );
        }
        // ★ And the sender records what the peer now holds — the other half of the mirror whose receiving side landed
        // in round 150 (`sync_records`, keyed by `(plugin_id, peer_device)`).
        //
        // ★ Only on a `Verified` event, and that is the precise test rather than a convenient one: `events` carries
        // one only when the receiver actually said it checked the file (`await_confirmation`'s answer). A transfer
        // that was sent but never confirmed must not claim the peer holds anything — a row like that would make the
        // next synchronisation believe the two ends agree.
        // ★ **And when the receiver also said what it installed, that is what goes in the row** — not the version this
        // side pushed. They are two different questions, and until round 172 there was no answer to the second one: a
        // peer that refused the package would still have been recorded as holding it.
        //
        // A receiver that answered `ok: false` installed nothing, and one that said `ok` without naming a version is
        // contradicting itself — so neither writes a row. That is the rule `SyncTable::apply_result` has had since
        // round 134, applied to the durable copy of the same fact.
        if let Some((plugin_id, version)) = bundle
            && let Some(digest) = events.iter().find_map(|event| match event {
                synra_core::SessionEvent::Verified { digest, .. } => Some(digest.clone()),
                _ => None,
            })
        {
            let answered = events.iter().find_map(|event| match event {
                synra_core::SessionEvent::SyncResult { result } => Some(result),
                _ => None,
            });
            // 没有回复时用推过去的那个版本（第 155 轮的判断）；有回复时用**装上的**那个。
            let held = match answered {
                Some(result) if !result.ok => None,
                Some(result) => result.installed_version.clone(),
                None => Some(version.to_owned()),
            };
            if let Some(held) = held {
                let _ = self.db().record_sync(
                    plugin_id.as_str(),
                    &device_id.to_string(),
                    &held,
                    &digest,
                    now,
                );
            }
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
}
