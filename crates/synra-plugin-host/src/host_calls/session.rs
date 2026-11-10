use synra_capability::Capability;
use synra_observe::audit::AuditOutcome;

use crate::host_surface;

use super::{
    AuditEntry, Budget, CallError, CallResult, CapabilitySet, Host, HostCalls, Health, PluginId,
    RateKind, event_scope, log_scope, network_scope, target_scope,
};
use super::helpers::clock_ms;

impl<'a> HostCalls<'a> {
/// A session of host calls for one plugin.
    ///
    /// The audit record is a `&mut Vec` the caller owns: a plugin's calls are recorded while it runs and handed to the
    /// kernel when it stops, so a call that outlives its plugin cannot leave a record attributed to a plugin that is
    /// gone.
    #[must_use]
    pub fn new(
        host: &'a dyn Host,
        plugin: PluginId,
        grants: &'a CapabilitySet,
        budget: &'a Budget,
        audit: &'a mut Vec<AuditEntry>,
    ) -> Self {
        Self {
            host,
            plugin,
            grants,
            budget,
            audit,
            side_effects: true,
            metrics: None,
        }
    }

    /// The same session, recording what it does.
    #[must_use]
    pub const fn with_metrics(mut self, metrics: &'a synra_observe::metrics::RingRecorder) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Which plugin.
    #[must_use]
    pub const fn plugin(&self) -> &PluginId {
        &self.plugin
    }

    /// What this plugin holds.
    #[must_use]
    pub const fn grants(&self) -> &CapabilitySet {
        self.grants
    }

    /// How the budget is doing, for a health screen.
    #[must_use]
    pub fn health(&self) -> Health {
        self.budget.health()
    }

    /// The rate limit a function's calls are counted against.
    ///
    /// # Why every gated function is rate limited and the ungated ones are not
    ///
    /// Because the five `env-*` queries and the two `*-capabilities`/`plugin-id` calls are reads of a constant: a
    /// plugin that called one a million times costs the host a million string copies and nothing else, and it needs
    /// them *before* it knows what to ask for. Everything else either takes a lock, touches a disk or leaves the
    /// process, which is what a rate limit is for.
    #[must_use]
    pub fn rate_kind(import_name: &str) -> RateKind {
        // Grouped by what the call *costs*, not by which domain it is in: a storage write and a storage read are the
        // same kind of thing to the host, and a network call is not.
        if import_name.starts_with("synra:plugin/host#network") {
            return RateKind::NetworkRequests;
        }
        if import_name.starts_with("synra:plugin/host#device") {
            return RateKind::DeviceSends;
        }
        if import_name.starts_with("synra:plugin/host#event-emit") {
            return RateKind::Events;
        }
        if import_name.starts_with("synra:plugin/host#transfer") {
            return RateKind::FsOps;
        }
        if import_name.starts_with("synra:plugin/host#platform") {
            return RateKind::HostCalls;
        }
        // Storage, secrets and the action table: everything left takes a lock and nothing else, which is what the
        // budget's general host-call kind counts.
        RateKind::HostCalls
    }

    /// Runs one host call.
    ///
    /// # The order, and why
    ///
    /// 1. **Is it a function at all.** A name the generated table does not list is refused before anything is counted,
    ///    because a call to something that does not exist is not a cost the plugin should be billed for.
    /// 2. **Does the plugin hold the capability.** Before the rate limit, so that a plugin calling something it was
    ///    never granted is refused for the reason that matters rather than for calling too often.
    /// 3. **Is it within the rate limit.**
    /// 4. **The call.**
    ///
    /// Calls associated with capabilities are audited, including refusals. Unknown imports and ungated queries
    /// have no capability to record, so no capability is fabricated for them.
    pub fn call(&mut self, import_name: &str, argument: &str) -> CallResult {
        let Some(gate) = host_surface::gate(import_name) else {
            let error = CallError::unknown(import_name);
            self.record(import_name, AuditOutcome::Denied, None);
            return Err(error);
        };

        if let Some(capability) = gate.capability() {
            // Scoped calls authorize the concrete operation, not the family's import label.
            let authorization = match import_name {
                "synra:plugin/host#network-fetch" => {
                    network_scope::authorize(self.grants, argument)
                }
                "synra:plugin/host#log" => log_scope::authorize(self.grants, argument),
                "synra:plugin/host#device-send" => target_scope::device(self.grants, argument),
                "synra:plugin/host#action-invoke" => target_scope::action(self.grants, argument),
                "synra:plugin/host#action-declare" => target_scope::declare(self.grants, argument),
                "synra:plugin/host#event-emit" => {
                    event_scope::authorize(self.grants, &self.plugin, argument)
                }
                _ if Capability::parse(capability)
                    .is_ok_and(|needed| self.grants.grants(&needed)) =>
                {
                    Ok(())
                }
                _ => Err(CallError::denied(capability, self.grants)),
            };
            if let Err(error) = authorization {
                let outcome = if error.code == CallError::CAPABILITY_DENIED {
                    AuditOutcome::Denied
                } else {
                    AuditOutcome::Failed
                };
                self.record(import_name, outcome, None);
                // ★ The numbers, written beside the audit rather than instead of it.
                //
                // The two answer different questions and neither replaces the other: the audit is *which plugin tried to do
                // what it could not*, one entry per call, bounded and read by a person. The metric is *how often*, aggregated
                // and read by a graph. The outcome label is `AuditOutcome`'s own name, so a count in the metrics and a line
                // in the audit cannot come to disagree about what happened.
                self.count("gate_checks_total", &[("result", outcome.as_str())], 1);
                if outcome == AuditOutcome::Denied {
                    self.count("gate_denied_total", &[("capability", capability)], 1);
                }
                return Err(error);
            }
            self.count(
                "gate_checks_total",
                &[("result", AuditOutcome::Allowed.as_str())],
                1,
            );
            if let Err(limited) = self
                .budget
                .consume(Self::rate_kind(import_name), 1, clock_ms())
            {
                let error = CallError::new(CallError::RATE_LIMITED, limited.to_string());
                self.record(import_name, AuditOutcome::RateLimited, None);
                self.count(
                    "gate_checks_total",
                    &[("result", AuditOutcome::RateLimited.as_str())],
                    1,
                );
                self.count(
                    "gate_rate_limited_total",
                    &[("plugin", self.plugin.as_str())],
                    1,
                );
                return Err(error);
            }
        }

        let started = clock_ms();
        let result = self.run(import_name, argument);
        let elapsed = clock_ms().saturating_sub(started);
        let outcome = match &result {
            Ok(_) => AuditOutcome::Allowed,
            Err(error) if error.code == CallError::CAPABILITY_DENIED => AuditOutcome::Denied,
            Err(_) => AuditOutcome::Failed,
        };
        let routine_input = import_name == "synra:plugin/host#input-session"
            && result.is_ok()
            && serde_json::from_str::<serde_json::Value>(argument)
                .ok()
                .is_some_and(|request| {
                    matches!(
                        request.get("op").and_then(serde_json::Value::as_str),
                        Some("frame" | "status")
                    )
                });
        if routine_input {
            // High-frequency input retains timing metrics and all permission gates,
            // without writing a persistent audit row for every touch sample.
            self.observe("host_call_ms", &[("import", import_name)], elapsed as f64);
        } else {
            self.record(import_name, outcome, Some(elapsed));
        }
        result
    }
}
