use super::*;

impl PluginSet {
    /// Compiles a plugin and makes it askable.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::Compile`] when the engine refuses the bytes, and [`PluginSetError::UndeclaredImport`] when the
    /// artifact imports a host function its capabilities do not cover. A plugin already loaded is replaced, because a
    /// reinstall is how an update arrives and refusing the second write would make updates depend on a clean shutdown.
    pub fn load(&mut self, spec: PluginSpec) -> Result<(), PluginSetError> {
        // A caller that has no digest or consent detail still gets a lifecycle that records what it did; the two steps
        // are installed → validated → granted, and the empty digest is a fact about the caller rather than a bypass.
        self.load_with_lifecycle(spec, String::new(), false)
    }

    /// Loads a plugin and records the manifest digest and consent outcome it was loaded under.
    ///
    /// # Errors
    ///
    /// The same refusals as [`Self::load`], plus [`PluginSetError::Lifecycle`] if the state machine will not make one of
    /// the two moves every load performs.
    pub fn load_with_lifecycle(
        &mut self,
        spec: PluginSpec,
        manifest_digest: String,
        partially_denied: bool,
    ) -> Result<(), PluginSetError> {
        // Scripted backends execute a table of answers, never untrusted component bytes.
        // Every executing backend must admit the complete world before native compilation.
        if self.backend.kind() != synra_plugin_host::BackendKind::Scripted {
            synra_plugin_host::component::inspect(&spec.wasm).map_err(|error| {
                BackendError::Compile {
                    detail: error.to_string(),
                }
            })?;
        }
        let compiled = self.backend.compile(&spec.wasm, spec.id.as_str())?;

        // Actual engine imports must also be covered by this load's effective grants.
        let undeclared =
            synra_plugin_host::host_surface::undeclared_imports(compiled.imports(), &spec.grants);
        if let Some(import) = undeclared.first() {
            return Err(PluginSetError::UndeclaredImport {
                id: spec.id,
                import: import.clone(),
            });
        }

        let mut lifecycle = Lifecycle::installed(spec.version.clone());
        lifecycle
            .apply(Transition::Validate {
                manifest_digest: manifest_digest.clone(),
            })
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;
        lifecycle
            .apply(Transition::Grant { partially_denied })
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;

        let pool = synra_plugin_host::InstancePool::new(spec.policy, spec.limit);
        pool.start();
        self.loaded.insert(
            spec.id.clone(),
            Loaded {
                execution: Arc::new(crate::plugin_events::context::Execution {
                    runtime: self.runtime_id,
                    generation: synra_protocol::RequestId::new(),
                    plugin: spec.id.clone(),
                    version: spec.version.clone(),
                    manifest_digest,
                }),
                version: spec.version,
                partially_denied,
                lifecycle,
                compiled,
                pool,
                live: HashMap::new(),
                // One budget per plugin rather than per instance: the rate is a property of what the plugin may
                // spend, and the pool hands out instances freely — a per-instance budget would multiply the allowance
                // by the instance limit.
                authority: {
                    let authority =
                        Authority::new(spec.grants, spec.quota, Arc::new(Mutex::new(Vec::new())));
                    match self.metrics.as_ref() {
                        Some(metrics) => authority.with_metrics(Arc::clone(metrics)),
                        None => authority,
                    }
                },
            },
        );
        Ok(())
    }

    /// The quota in force for a loaded plugin.
    ///
    /// # ★ Why this accessor exists
    ///
    /// Because `CallBudget::from_quota` was written, documented as the mapping — *"Every field is taken from the quota
    /// rather than chosen here, so the number a user sees in a settings screen is the number the sandbox enforces"* — and
    /// **production never called it**. Only the scripted backend's `enforcement` and a test did.
    ///
    /// The consequence was concrete: `share.execute` ran under a fixed five-second timeout with **no instruction limit at
    /// all**, and with no memory ceiling, whatever the plugin's quota said. The rates *were* enforced, which is what made
    /// the gap hard to see — a quota that does something looks like a quota that works.
    #[must_use]
    pub fn quota(&self, id: &PluginId) -> Option<synra_plugin_host::quota::Quota> {
        self.loaded.get(id).map(Loaded::quota)
    }

    /// The version a plugin is loaded at.
    #[must_use]
    pub fn version(&self, id: &PluginId) -> Option<&str> {
        self.loaded.get(id).map(|loaded| loaded.version.as_str())
    }

    /// Where a loaded plugin is in its lifecycle, or `None` when it is not loaded.
    ///
    /// The state is the machine's, not a rendering of the loader's flags: a plugin that is compiled but has not answered
    /// `activate` is `Granted`, and the caller that shows a state can say which step is missing.
    #[must_use]
    pub fn lifecycle(&self, id: &PluginId) -> Option<&Lifecycle> {
        self.loaded.get(id).map(|loaded| &loaded.lifecycle)
    }

    /// Records that a loaded plugin answered its `activate`.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::NotLoaded`] if it is not here, and [`PluginSetError::Lifecycle`] if the machine refuses the
    /// move — which would mean the loader activated something it had not finished validating.
    pub fn mark_active(&mut self, id: &PluginId) -> Result<(), PluginSetError> {
        let Some(loaded) = self.loaded.get_mut(id) else {
            return Err(PluginSetError::NotLoaded { id: id.clone() });
        };
        loaded
            .lifecycle
            .apply(Transition::Activate)
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;
        Ok(())
    }

    /// Clears a fault, resetting the health ladder so the plugin can be activated again.
    ///
    /// Returns `false` when the plugin is not faulted, which lets a caller fall back to a reload without asking twice.
    /// The ladder is reset **and** the lifecycle is moved back to `Granted`: clearing one without the other would leave a
    /// plugin that is allowed to run but still refused by `call`, or one that is still marked broken on the card.
    ///
    /// # Errors
    ///
    /// [`PluginSetError::NotLoaded`] when it is not here, and [`PluginSetError::Lifecycle`] if the machine refuses the
    /// move.
    pub fn clear_fault(&mut self, id: &PluginId, now_ms: u64) -> Result<bool, PluginSetError> {
        let Some(loaded) = self.loaded.get_mut(id) else {
            return Err(PluginSetError::NotLoaded { id: id.clone() });
        };
        if !matches!(loaded.lifecycle.state(), State::Faulted { .. }) {
            return Ok(false);
        }
        loaded
            .lifecycle
            .apply(Transition::ClearFault)
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;
        loaded
            .lifecycle
            .apply(Transition::Grant {
                partially_denied: loaded.partially_denied,
            })
            .map_err(|error| PluginSetError::Lifecycle(error.to_string()))?;
        loaded.authority.budget.reset(now_ms);
        Ok(true)
    }

    /// Forgets a plugin, dropping its compiled form and every instance of it.
    ///
    /// The reason this is more than a `HashMap::remove`: an instance still holding a `Box<dyn PluginInstance>` is a live
    /// Wasm store, and leaving one behind is a leak the kernel would report on every restart as a slowly rising number.
    pub fn unload(&mut self, id: &PluginId) -> bool {
        self.loaded.remove(id).is_some()
    }
}
