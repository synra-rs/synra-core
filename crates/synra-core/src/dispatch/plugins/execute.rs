use super::*;

impl PluginSet {
    /// Runs one entry point on one plugin.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::NotLoaded`] when the plugin is not here. A guest that *failed while running* is a
    /// [`CallOutcome`], not an error — a trap is something the caller decides about, and turning it into a failure here
    /// would mean the kernel could not tell "the plugin refused" from "the plugin is broken".
    pub fn call(
        &mut self,
        id: &PluginId,
        work: &synra_plugin_host::Work,
        budget: CallBudget,
        now_ms: u64,
    ) -> Result<CallOutcome, PluginSetError> {
        self.call_traced(id, work, budget, now_ms, None)
    }

    /// The same call, stamped with the trace of the user action it belongs to.
    ///
    /// # Why the trace is an argument rather than ambient
    ///
    /// Because most calls have no action behind them: `can-handle` runs for every plugin the router asks, before the user
    /// has chosen anything, and a lifecycle tick belongs to the plugin's life rather than to a share. Inventing a trace for
    /// those would make the audit say every matching pass was part of one user action. The calls that do have one — the
    /// confirmed action — are exactly the ones that pass a trace here, and the audit entries they produce carry it.
    ///
    /// # Errors
    ///
    /// As [`Self::call`].
    pub fn call_traced(
        &mut self,
        id: &PluginId,
        work: &synra_plugin_host::Work,
        budget: CallBudget,
        now_ms: u64,
        trace: Option<synra_protocol::ids::TraceId>,
    ) -> Result<CallOutcome, PluginSetError> {
        // ★ The action is made current for the whole call, including the guest's host functions. That is what lets a
        // plugin's own `log` line carry the trace without a trace argument in the plugin contract — the thread running the
        // call is the one that knows it.
        let _scope = synra_observe::trace_scope::enter(trace);
        let Some(loaded) = self.loaded.get_mut(id) else {
            return Err(PluginSetError::NotLoaded { id: id.clone() });
        };
        // ★ A faulted plugin is installed and has bytes, but the host has stopped asking. Running it again would make
        // the lifecycle decorative: the state exists to refuse calls, and this is the refusal.
        if let State::Faulted { reason, .. } = loaded.lifecycle.state() {
            return Err(PluginSetError::Faulted {
                id: id.clone(),
                reason: reason.clone(),
            });
        }
        let _execution = crate::plugin_events::context::enter(Arc::clone(&loaded.execution));
        let handle = match loaded.pool.acquire(None, now_ms) {
            Ok(handle) => handle,
            // A plugin at its instance limit is reported, not waited on. The caller turns this into something the user
            // can act on; a retry loop here would hide the limit by turning it into latency.
            Err(_) => {
                return Err(PluginSetError::AtInstanceLimit { id: id.clone() });
            }
        };
        let started = std::time::Instant::now();
        // ★ Whether this handle already had an instance when the call started. That is exactly what a "pool hit" means
        // — the pool handed out a warm slot — and it is knowable here because `live` is the set's own map, not the pool's.
        let had_instance = loaded.live.contains_key(&handle);
        let outcome = Self::run_on(&self.backend, &self.host, loaded, id, handle, work, budget);
        // ★ The plugin group's counter and latency, recorded here because this is the one funnel every call goes through —
        // the matcher's `can-handle`, an action invocation and a lifecycle tick all pass `call`.
        //
        // The interface comes from `Work::interface`, which is the protocol's own spelling (`share`, `actions`,
        // `lifecycle`); a second match here would be the third vocabulary for the same three names.
        if let Some(metrics) = &self.metrics {
            let labels = [
                ("interface".to_owned(), work.interface().to_owned()),
                ("plugin".to_owned(), id.as_str().to_owned()),
            ];
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                "plugin_calls_total",
                labels.clone(),
            ));
            metrics.histogram_observe(
                &synra_observe::metrics::SeriesKey::new("plugin_call_duration_us", labels),
                started.elapsed().as_secs_f64() * 1_000_000.0,
            );
        }
        // ★ A call the plugin misbehaved in counts against its health, which nothing did before.
        //
        // The ladder in `quota::Budget` was reached only by rate-limit refusals, so a plugin that trapped on every call was
        // never degraded: a trap is not a rate, it produced no refusals, nothing counted, and a plugin that could not run
        // kept being asked. `12` recorded that as a missing path, and this is the missing call.
        //
        // Here rather than inside `run_on` because this is where the clock is and where the plugin's own `Budget` is
        // reachable — `run_on` takes the *call* budget, which is a different type with a different job.
        if outcome.as_ref().is_ok_and(CallOutcome::is_misbehaviour) {
            let before = loaded.authority.budget.health();
            loaded.authority.budget.record_misbehaviour(now_ms);
            let after = loaded.authority.budget.health();
            // ★ The health rung is a fact the window can draw, and until this line nothing told it: `PluginHealthChanged`
            // existed in the contract with no publisher. The sink is called only when the rung actually moved, so a
            // plugin that traps ten times at `good` does not produce ten identical events.
            if after != before {
                let report = loaded.authority.budget.report();
                if let Some(sink) = &self.health_sink {
                    sink(id, &report.health, &report.explanation);
                }
                // ★ When the ladder reaches the bottom, the lifecycle follows it. A plugin that trapped, timed out or
                // exhausted its fuel often enough is `Faulted`, and every later call is refused above until a user
                // re-enables it (which reloads) — a health rung nobody enforces is a report, not a decision.
                if after == Health::Faulted {
                    let _ = loaded.lifecycle.apply(Transition::Fault {
                        reason: report.explanation,
                    });
                }
            }
            // ★ And the counter the plugin's card can show without reading its health ladder: a plugin that trapped five
            // times is a different story from one that has never run. The outcome is the protocol's own name (`trap`,
            // `timeout`, …), so "why did it fault" is a label rather than a second counter per kind.
            if let Some(metrics) = &self.metrics {
                let outcome = outcome.as_ref().map_or("unknown", CallOutcome::as_str);
                metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(
                    "plugin_faulted_total",
                    [
                        ("outcome".to_owned(), outcome.to_owned()),
                        ("plugin".to_owned(), id.as_str().to_owned()),
                    ],
                ));
            }
        }
        // ★ The instance's memory, read after the call and before the pool releases the handle: it is the only moment
        // the set can see how much the plugin is holding, and the number is what the design's `plugin_memory_bytes` gauge
        // names. A gauge rather than a delta, because memory can be given back.
        if let Some(metrics) = &self.metrics
            && let Some(instance) = loaded.live.get(&handle)
        {
            metrics.gauge_set(
                &synra_observe::metrics::SeriesKey::new(
                    "plugin_memory_bytes",
                    [("plugin".to_owned(), id.as_str().to_owned())],
                ),
                i64::try_from(instance.memory_bytes()).unwrap_or(i64::MAX),
            );
            // ★ And the fuel the call spent, when the engine counts it: a histogram because the question is "how close to
            // the budget does this plugin run", which is a distribution rather than a current value.
            if let Some(fuel) = instance.last_fuel_consumed() {
                #[allow(clippy::cast_precision_loss)]
                metrics.histogram_observe(
                    &synra_observe::metrics::SeriesKey::new(
                        "plugin_fuel_consumed",
                        [("plugin".to_owned(), id.as_str().to_owned())],
                    ),
                    fuel as f64,
                );
            }
        }
        // ★ One of the two, per call, from the flag taken before the call. A call that could not start (the pool refused
        // it) never reaches here, so the pair always sums to the calls the pool actually served.
        if let Some(metrics) = &self.metrics {
            let counter = if had_instance {
                "plugin_pool_hit_total"
            } else {
                "plugin_pool_miss_total"
            };
            metrics.counter_inc(&synra_observe::metrics::SeriesKey::new(counter, []));
        }
        let _ = loaded.pool.release(handle, now_ms);
        // ★ Drained **after** the call, not inside it: the entries are produced while the guest runs, and the ring lives
        // behind the set that the caller is borrowing. Collecting here is also what keeps the buffer one call deep.
        Self::drain_audit(loaded, &mut self.audit, self.audit_sink.as_ref(), trace);
        outcome
    }

    /// Runs the call against whichever instance the pool handed out.
    ///
    /// # Why the instance is made lazily and kept
    ///
    /// Instantiation is the expensive part, and the pool exists precisely so it is not paid per call. An instance is
    /// therefore created on the handle's first use and kept for as long as the pool holds the handle.
    ///
    /// # Why `loaded` and `backend` are passed rather than found
    ///
    /// Because **a handle is only meaningful to the pool that issued it**. Searching every loaded plugin for one that
    /// recognises a handle is how a call ends up running on another plugin's instance, and that failure is invisible:
    /// both plugins are loaded and both answers parse. Taking both arguments from the caller also keeps the borrow of
    /// one entry from reaching across the whole set.
    fn run_on(
        backend: &Backend,
        host: &Arc<dyn synra_plugin_host::host_calls::Host>,
        loaded: &mut Loaded,
        id: &PluginId,
        handle: u64,
        work: &synra_plugin_host::Work,
        budget: CallBudget,
    ) -> Result<CallOutcome, PluginSetError> {
        if !loaded.live.contains_key(&handle) {
            match backend.instantiate(loaded.compiled.as_ref()) {
                Ok(mut instance) => {
                    // ★ The session, which is what makes the capability gate run at all.
                    //
                    // `instantiate` leaves the instance with no session, and `linker::run` refuses **every** host call
                    // when there is no session — so before this, no plugin could reach a host function and nothing was
                    // audited. The gate is the mechanism the whole capability model rests on, and it was inert.
                    //
                    // Installed once per instance rather than per call: the session holds the audit buffer and the
                    // rate budget, and rebuilding it every call would reset both. `session_for` is where the loader's
                    // decision about this plugin's authority lives.
                    instance.set_session(loaded.authority.session_for(id, host));
                    loaded.live.insert(handle, instance);
                }
                Err(error) => return Err(PluginSetError::Compile(error)),
            }
        }

        // ★ The host's own panic must not cross this boundary.
        //
        // `Cargo.toml`'s release profile sets `panic = "unwind"` and gives one reason: "插件 panic 必须能被 catch_unwind
        // 捕获". Until this was written, `catch_unwind` appeared nowhere in the workspace — so the profile was built for
        // a mechanism that did not exist, and a panic raised inside a host function called by a guest (an index, an
        // unwrap, an arithmetic overflow in a debug build) unwound straight through `call`, through the pool, and out
        // of whatever kernel thread was dispatching. One plugin's bug took the process with it.
        //
        // The call is wrapped rather than the whole dispatcher, because the instance is what has to be thrown away: a
        // panic that unwound out of the middle of a guest call leaves the store in a state nothing can reason about, so
        // reusing it would trade a loud failure for a quiet wrong answer. The handle is dropped from `live` and a later
        // call instantiates a fresh instance — which is what the pool is for.
        //
        // `AssertUnwindSafe` is required and is sound to give here: the only shared state the closure touches is the
        // instance, and that instance is discarded on the unwind path rather than observed.
        let outcome = {
            let Some(instance) = loaded.live.get_mut(&handle) else {
                return Err(PluginSetError::NoInstance { id: id.clone() });
            };
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| instance.call(work, budget)))
        };

        match outcome {
            Ok(result) => {
                let outcome = result.map_err(PluginSetError::Compile)?;
                // ★ And the same rule applies when the **engine** stopped the guest, which is where it was missing.
                //
                // The panic path above discards the instance because a store that unwound out of a call cannot be reasoned
                // about. A guest that ran out of fuel, hit its memory ceiling or was interrupted by the clock is in exactly
                // that condition: it trapped **mid-execution**, and a trapped component instance cannot be entered again.
                // wasmtime answers the next call with `Trap { "cannot enter component instance" }`.
                //
                // Keeping it made one overrun permanent. Every later call to that plugin failed with a trap that says
                // nothing about the plugin and everything about the instance the kernel was holding, and the only remedy a
                // user had was to restart the app. Discarding it costs one instantiation on the next call, which is what the
                // pool exists for, and it is the difference between a plugin that misbehaved once and one that is broken.
                if outcome.is_misbehaviour() {
                    loaded.live.remove(&handle);
                }
                Ok(outcome)
            }
            Err(payload) => {
                // The instance is gone, so a later call builds a new one instead of inheriting the damage.
                loaded.live.remove(&handle);
                Ok(CallOutcome::Trap {
                    detail: panic_detail(payload.as_ref()),
                })
            }
        }
    }
}

/// A sentence describing a caught panic, for the plugin author and for the audit record.
///
/// The payload is `Box<dyn Any + Send>` because that is what `catch_unwind` hands back. The two shapes it takes in
/// practice are a `&str` (a `panic!("...")` with a literal) and a `String` (a formatted one); anything else is a
/// payload the caller chose, and saying so is better than guessing at a `Debug` rendering that may itself panic.
fn panic_detail(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return format!("the host panicked: {message}");
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return format!("the host panicked: {message}");
    }
    "the host panicked with a payload that is neither a string nor a string slice".to_owned()
}
