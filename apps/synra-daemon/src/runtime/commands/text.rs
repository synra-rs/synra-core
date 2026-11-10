use synra_protocol::error::ErrorCode;

use super::super::refusals::{error_code_for, refusal_of};
use super::peer::dial_with_retries;

use synra_control::Refusal;

use super::super::Runtime;

impl Runtime {
    pub(super) fn command_send_text(&self, to: &str, text: &str) -> Result<serde_json::Value, Refusal> {
        let now = synra_store::sqlite::now_ms();
        let trace_id = synra_protocol::ids::TraceId::new();

        // ★ The text is checked **before** the host is touched, and the order is a decision rather than a detail. An empty
        // `--text` is a mistake in the argument the user just typed; reporting it as an unknown device would send them to
        // check a device list for a mistake they made in their own sentence. The check is done by building an envelope
        // addressed to *this* device, which the protocol validates, and then throwing it away — the real one is built once
        // the device is known, so this costs one small allocation and no lock.
        synra_core::text_to(
            self.identity.device_id,
            self.identity.device_id,
            text,
            trace_id,
            now,
        )
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

        let handshake_now = synra_core::reading_millis(now);
        let dialled = dial_with_retries(&self.host, address, device_id, handshake_now)?;
        let mut host = self.host.lock();
        let mut link = host
            .adopt(dialled, handshake_now)
            .map_err(|error| refusal_of(&error))?;
        // ★ The read half of the send, under the lock that is already held; the write itself needs no host.
        host.may_send(&link).map_err(|error| refusal_of(&error))?;
        drop(host);
        // ★ And the write happens holding nothing, because the session layer already writes through a link
        // without the host. Only counting it needs the host again.
        link.send(&envelope)
            .map_err(|error| refusal_of(&error.into()))?;
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
}
