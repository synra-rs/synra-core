use super::peer::exchange;

use synra_control::Refusal;

use super::super::Runtime;

impl Runtime {
    /// Routes a share: asks the plugins, and reports what offered.
    ///
    /// ★ The method that makes the kernel do the thing the product is for. Everything it calls existed and was tested;
    /// what was missing was a way in, so the matcher had no production caller and a share that arrived became a file.
    pub(super) fn command_intent_dispatch(&self, mime: &str, text: &str) -> Result<serde_json::Value, Refusal> {
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
        let started = std::time::Instant::now();
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
            // ★ The duration is observed before the `?` too: a share the matcher refused still spent its matching time,
            // and a distribution built only from successes would answer "how slow is a share" with no failures in it.
            self.metrics.histogram_observe(
                &synra_observe::metrics::SeriesKey::new("intent_duration_ms", Vec::new()),
                started.elapsed().as_secs_f64() * 1_000.0,
            );
            let outcome = if routed.is_ok() { "ok" } else { "refused" };
            self.metrics
                .counter_inc(&synra_observe::metrics::SeriesKey::new(
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
                    self.metrics
                        .counter_inc(&synra_observe::metrics::SeriesKey::new(
                            "intent_no_handler_total",
                            Vec::new(),
                        ));
                }
            }
        }
        let answer = routed?;

        // ★ The one line in the log that names an action's trace, so `synra logs --trace <id>` has something to find.
        // The id is the one the interface now shows on the received row; the rest of this action's steps still log
        // without it, which is why this is one line and not a claim that tracing is complete.
        if let (Some(intent), Some(trace)) = (
            answer.get("intent").and_then(serde_json::Value::as_str),
            answer.get("trace").and_then(serde_json::Value::as_str),
        ) {
            tracing::info!(trace_id = trace, intent, "share routed");
        }

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

    pub(super) fn command_intent_snapshot(&self, intent: &str) -> Result<serde_json::Value, Refusal> {
        crate::runtime::intent::snapshot(&self.board, intent)
    }

    /// Applies the user's answer, and runs what they chose.
    ///
    /// ★ The one place in the daemon where a plugin's action actually runs. Everything before it — the matching pass,
    /// the board's states, the prompt — is a question; this is the answer, and it happens only for the plugin the user
    /// picked.
    pub(super) fn command_intent_decide(
        &self,
        intent: &str,
        plugin_id: Option<&str>,
        target: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        let mut decided = crate::runtime::intent::decide(
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
        if let Some(outbound) = decided.outbound.take() {
            match self.send_outbound(&outbound, true)? {
                // ★ The far side answered inside the wait, and the answer has been applied to the board. The reply
                // replaces "in flight" with what actually happened: returning `dispatching` after holding the outcome would
                // make the interface show work still running that has already finished.
                Some(result) => {
                    let (ok, payload, error, _) = result.into_parts();
                    decided.ok = ok;
                    decided.result = payload;
                    decided.error = error;
                    decided.state = self
                        .board
                        .lock()
                        .get(decided.intent_id)
                        .map_or("failed", |found| found.state.name());
                }
                // No answer in the wait. It may still be running over there, and the honest answer stays `dispatching`.
                // ★ And it is **not** retried on another connection: the receiver answers on this link or not at all, so
                // an outcome slower than the wait is one this side never learns. Saying that here is the difference
                // between a limitation and a bug report that cannot be answered.
                None => decided.outbound = Some(outbound),
            }
        }

        // ★ After the send, not before: a send that fails leaves the intent dispatching, and what must be written down is
        // the state the caller is actually in — the far side may still have received the message.
        self.checkpoint_intent(intent);

        // ★ The decision's own line, with the trace it shares with the routing line. A user who copied the trace from
        // the received row can follow the action through both steps now; the plugin's execution itself is inside the call
        // above, so `ok` here is the outcome of running it.
        let answer = decided.to_json();
        tracing::info!(
            trace_id = %decided.trace,
            intent,
            ok = answer.get("ok").and_then(serde_json::Value::as_bool).unwrap_or(false),
            "action decided"
        );
        Ok(answer)
    }

    pub(super) fn command_intent_cancel(&self, intent: &str) -> Result<serde_json::Value, Refusal> {
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
            // A cancellation is not answered, so there is nothing to wait for.
            let _ = self.send_outbound(outbound, false)?;
        }

        self.checkpoint_intent(intent);

        Ok(change.to_json())
    }

    /// Puts an intent's envelope on a link to the device it names.
    ///
    /// # Errors
    ///
    /// [`Refusal`] naming what the user can act on: the device has never been seen on this network, or the link could not
    /// be established.
    fn send_outbound(
        &self,
        outbound: &synra_core::intent::remote::Outbound,
        wait_for_result: bool,
    ) -> Result<Option<synra_core::intent::remote::InvokeResult>, Refusal> {
        let Some(reply) = exchange(&self.host, outbound, wait_for_result)? else {
            return Ok(None);
        };
        match synra_core::dispatch::orchestrate::apply_result(&self.board, &reply) {
            Ok(Some(id)) => {
                // Written down now: the outcome is the state, and a crash before the next sweep would otherwise
                // persist a "dispatching" for work that has finished.
                self.checkpoint_intent(&id.to_string());
                let result = synra_core::intent::remote::result_from(&reply).ok();
                // ★ The remote step joins the trace: the routing and decision lines already name the action, and
                // without this the one step that happened on another device is the one a `synra logs --trace` cannot
                // show.
                if let Some(result) = &result {
                    tracing::info!(
                        trace_id = %reply.trace_id,
                        intent = %id,
                        ok = result.is_ok(),
                        "remote outcome applied"
                    );
                }
                Ok(result)
            }
            // A reply this device is not waiting on. Nothing to apply, and nothing to report: the intent may have
            // been cancelled while the answer was in flight.
            Ok(None) => Ok(None),
            Err(error) => {
                eprintln!("synra-daemon: the result could not be applied: {error}");
                Ok(None)
            }
        }
    }
}
