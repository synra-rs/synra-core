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

/// How long a dispatched action's outcome is waited for before the intent stays dispatching.
///
/// ★ **The number moved to the kernel.** It was the same arithmetic written in two hosts — this one and the desktop shell
/// — which drifts the first time the execution budget changes: one host would report an outcome while the other still
/// called the action in flight. [`synra_core::dispatch::REMOTE_RESULT_WAIT`] owns it now, derived from the budget there.
/// The reasoning and the limitation (a receiver slower than the wait answers into a closed link) live with it.
pub(super) use synra_core::dispatch::REMOTE_RESULT_WAIT;

impl Kernel for Runtime {
    fn plugin_publishers(&self) -> Result<serde_json::Value, Refusal> {
        super::publishers::list(self)
    }

    fn plugin_publisher_decide(
        &self,
        publisher_id: &str,
        fingerprint: &str,
        trust: &str,
    ) -> Result<serde_json::Value, Refusal> {
        super::publishers::decide(
            self,
            publisher_id,
            fingerprint,
            trust,
            synra_store::sqlite::now_ms(),
        )
    }

    fn plugin_registry(&self, urls: Option<&[String]>) -> Result<serde_json::Value, Refusal> {
        super::plugin_settings::registry(self, urls, synra_store::sqlite::now_ms())
    }

    fn plugin_update_policy(&self, policy: Option<&str>) -> Result<serde_json::Value, Refusal> {
        super::plugin_settings::policy(self, policy, synra_store::sqlite::now_ms())
    }

    fn plugin_check_updates(&self, plugin: Option<&str>) -> Result<serde_json::Value, Refusal> {
        super::updates::check_manually(self, plugin, synra_store::sqlite::now_ms())
    }

    fn plugin_update(
        &self,
        plugin: &str,
        version: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        super::updates::update_manually(self, plugin, version, synra_store::sqlite::now_ms())
    }

    fn version(&self) -> String {
        self.version.clone()
    }

    fn status(&self) -> Result<serde_json::Value, Refusal> {
        Ok(self.status_value(now_ms()))
    }

    fn devices(
        &self,
        include_unpaired: bool,
        scan_ms: Option<u64>,
    ) -> Result<serde_json::Value, Refusal> {
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
            Refusal::new(
                ErrorCode::Internal,
                format!("could not read the paired devices: {error}"),
            )
        })?;
        let mut paired_list: Vec<serde_json::Value> = Vec::new();
        for row in &paired {
            // The session is the proof the device is reachable *now*, as opposed to recorded once. A user asking for
            // devices is asking what they can act on, so the two are reported together.
            let device_id: synra_protocol::ids::DeviceId =
                row.device_id.parse().map_err(|error| {
                    Refusal::new(
                        ErrorCode::Internal,
                        format!(
                            "the stored device id {} is not a UUID: {error}",
                            row.device_id
                        ),
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
        } else {
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

        let parts = {
            let host = self.host.lock();
            host.dialling_parts()
        };
        let handshake_now = synra_core::reading_millis(now);
        let dialled = synra_core::retry::with_retries(
            synra_core::retry::ATTEMPTS,
            |_| {
                synra_core::dial_peer(&parts.0, parts.1, address, device_id, handshake_now)
                    .map_err(|error| refusal_of(&error))
            },
            |attempt| {
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * (u64::try_from(attempt).unwrap_or(0) + 1),
                ));
            },
        )?;
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
    fn plugin_set_enabled(
        &self,
        plugin_id: &str,
        enabled: bool,
    ) -> Result<serde_json::Value, Refusal> {
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
        // ★ Enabling loads and disabling stops — the same shape the shell has, and the design's lifecycle says enable is
        // *activating*, not "remember this for the next start". The revocation list is the one this daemon was started
        // with, so an enable cannot start a plugin the start-up pass would have refused.
        if let Ok(id) = synra_protocol::ids::PluginId::try_from(plugin_id.to_owned()) {
            if enabled {
                let should_run = {
                    let db = self.db.lock();
                    let rows = db
                        .plugins()
                        .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
                    // The database lock is released before the plugin set is taken: the two are never held in one
                    // order here, so there is no second order for another command to deadlock on.
                    drop(db);
                    rows.into_iter()
                        .find(|row| row.plugin_id == plugin_id)
                        .is_some_and(|row| row.should_run())
                };
                if should_run {
                    // Read the environment before the store lock: `KernelHost::locale` reads a setting, and the loader
                    // is about to hold that same lock.
                    let activation = {
                        let set = self.plugins.lock();
                        synra_core::plugin::activation_config(set.host().as_ref())
                    };
                    let outcome = {
                        let mut set = self.plugins.lock();
                        let db = self.db.lock();
                        synra_core::plugin::load_plugin_with_config(
                            &mut set,
                            &db,
                            &self.plugins_dir,
                            plugin_id,
                            &self.revocations,
                            &activation,
                        )
                    };
                    match outcome {
                        Ok(loaded) => self.plugin_loads.lock().record_loaded(loaded),
                        Err(reason) => {
                            self.plugin_loads
                                .lock()
                                .record_refused(plugin_id, reason.clone());
                            return Err(Refusal::new(ErrorCode::PluginTrapped, reason));
                        }
                    }
                }
            } else {
                synra_core::plugin::deactivate(&mut self.plugins.lock(), &id, now_ms());
                self.plugin_loads.lock().record_unloaded(&id);
            }
        }
        self.plugins_value()
    }

    /// Installs a plugin from a directory, through the eleven checks.
    ///
    /// ★ The write that had no caller. `verify::verify` was written, tested against a refusal for each stage, and
    /// called by nobody: a plugin became installed because a directory appeared, so a package whose signature covered
    /// other bytes installed exactly as one that was genuine. This is the production caller that closes that.
    fn plugin_install(&self, path: &str) -> Result<serde_json::Value, Refusal> {
        // Both locks are held across the install and released before anything is reported. The set's is held because
        // the backend inside it is what compiles the artifact, and compiling is what tells the pipeline what the
        // plugin imports; the database's because the row is written at the end of the same act. Neither is held while
        // the answer is built.
        let plugins = self.plugins.lock();
        let backend = plugins.backend();
        let mut db = self.db.lock();
        // ★ A path that is a file is a `.synra` package; one that is a directory is the unpacked form. Refusing the file
        // made the documented "install a plugin from a path" mean only one of the two shapes the product produces.
        let source = std::path::Path::new(path);
        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        let outcome = if source.is_file() {
            crate::runtime::install_from_package(&mut db, backend, &self.plugins_dir, source, now)
        } else {
            // The runtime's clock is `u64` and the database stamps `i64`; saturating rather than `as`, the same
            // direction as every other stamp in this host — a clock past 2262 should let the daemon run.
            crate::runtime::install_from_directory(&mut db, backend, &self.plugins_dir, source, now)
        };
        drop(db);
        drop(plugins);

        match outcome {
            Ok(installed) => Ok(serde_json::json!({
                "pluginId": installed.plugin_id,
                "version": installed.version,
                "path": installed.path.to_string_lossy(),
                "warnings": installed.warnings,
                // ★ `false`, and it is an answer rather than a detail: installing is not approving. The row this wrote
                // is `enabled = false, trusted = false` — the design's `AwaitingConsent` in durable form — and the
                // user's `plugin enable` is the act that changes it.
                "enabled": false,
            })),
            Err(refusal) => Err(Refusal::new(
                refusal.code(),
                format!("{} refused the package: {}", refusal.stage, refusal.reason),
            )),
        }
    }

    /// Installs a plugin the registry names.
    ///
    /// # Why the locks are held the same way as `plugin_install`
    ///
    /// Because the last step **is** that install: the registry path differs in where the directory came from, not in what
    /// it does with it. Holding the same two locks across both means a registry install cannot interleave with a local one
    /// on the same plugin identifier.
    fn plugin_install_package(
        &self,
        package: &str,
        version: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        let plugins = self.plugins.lock();
        let backend = plugins.backend();
        let mut db = self.db.lock();
        let staging = self
            .plugins_dir
            .parent()
            .unwrap_or(&self.plugins_dir)
            .join(".install-staging");
        std::fs::create_dir_all(&staging).map_err(|error| {
            Refusal::new(
                ErrorCode::Internal,
                format!("{}: {error}", staging.display()),
            )
        })?;
        let outcome = super::registry_install::install_from_registry(
            &mut db,
            backend,
            &self.plugins_dir,
            &staging,
            &super::registry_install::NetworkFetch::default(),
            package,
            version,
            i64::try_from(now_ms()).unwrap_or(i64::MAX),
        );
        drop(db);
        drop(plugins);

        let installed = outcome?;
        Ok(serde_json::json!({
            "pluginId": installed.plugin_id,
            "version": installed.version,
            "path": installed.path.to_string_lossy(),
            "warnings": installed.warnings,
            // Installing is not approving; the same answer the path install gives.
            "enabled": false,
        }))
    }

    /// Records the user's decision about a plugin's capabilities.
    ///
    /// ★ The writer `plugin_grants` had only in tests. The loader has read decisions since it stopped treating a
    /// manifest as its own authorisation, so a plugin could not run without consent — and nothing could record consent
    /// except a test helper. A plugin was therefore installable, visible, enable-able and permanently unloadable.
    ///
    /// ★ **What the decision means is not decided here.** `synra_core::consent` owns the rule — one row per declared
    /// capability, trusted when anything was allowed — because the shell asks the same question and the two hosts had
    /// answered it differently. This method moves that decision into the store and nothing else.
    fn plugin_consent(
        &self,
        plugin_id: &str,
        granted: &[String],
    ) -> Result<serde_json::Value, Refusal> {
        // The manifest on disk is the document the decision is about. Its digest is what makes a later edit — or an
        // update that adds a capability — visible to the loader, instead of silently inheriting the old consent.
        let text = std::fs::read_to_string(
            self.plugins_dir
                .join(synra_store::sanitise_component(plugin_id))
                .join("manifest.json"),
        )
        .map_err(|_| {
            Refusal::new(
                ErrorCode::PluginNotInstalled,
                format!("no plugin is installed as `{plugin_id}`"),
            )
        })?;
        let manifest = synra_plugin_api::Manifest::from_json(&text)
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        let decision = synra_core::consent::decide(&manifest, &text, granted)
            .map_err(|error| Refusal::new(ErrorCode::InvalidArgument, error.to_string()))?;

        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        {
            // Scoped so the guard is gone before `plugins_value` reads the same table: this mutex is not reentrant, and a
            // second lock on this thread would be a hang rather than an error.
            let db = self.db.lock();
            db.record_grants(plugin_id, &decision.pairs(), now, decision.digest())
                .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
            db.set_plugin_trusted(plugin_id, decision.trusted(), now)
                .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        }
        self.plugins_value()
    }

    fn plugin_remove(
        &self,
        plugin_id: &str,
        remove_data: bool,
    ) -> Result<serde_json::Value, Refusal> {
        // ★ The row first, then the files. The store's removal reports what actually went: measuring before and calling
        // that "freed" would count a locked directory that is still on disk.
        let files = synra_store::PluginFiles::new(self.paths.clone());
        let removed = self
            .db
            .lock()
            .remove_plugin(plugin_id)
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        if !removed {
            return Err(Refusal::new(
                ErrorCode::PluginNotInstalled,
                format!("no plugin is installed as `{plugin_id}`"),
            ));
        }
        // ★ Stop it before its files go. A loaded instance still holds the artifact open, and on Windows that is why a
        // removal reports leftovers; more importantly a removed plugin that stayed in the set could still answer a share
        // from bytes the user just deleted.
        if let Ok(id) = synra_protocol::ids::PluginId::try_from(plugin_id.to_owned()) {
            synra_core::plugin::deactivate(&mut self.plugins.lock(), &id, now_ms());
        }
        let removal = files
            .remove(plugin_id, remove_data)
            .map_err(|error| Refusal::new(ErrorCode::Internal, error.to_string()))?;
        // ★ Reported, not refused: the row is already gone, and a directory the operating system would not let go (a
        // loaded engine holds its wasm file open on Windows) is a fact the user has to see. The paths are the answer to
        // "so what is still on my disk?" — a count alone would make them go looking.
        let leftover_paths: Vec<String> = removal
            .leftovers
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        Ok(serde_json::json!({
            "pluginId": plugin_id,
            "bytesFreed": removal.bytes_freed,
            "dataKept": !remove_data,
            "leftovers": leftover_paths,
        }))
    }

    fn logs(
        &self,
        lines: usize,
        verbose: bool,
        trace: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
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
            // A cancellation is not answered, so there is nothing to wait for.
            let _ = self.send_outbound(outbound, false)?;
        }

        self.checkpoint_intent(intent);

        Ok(change.to_json())
    }

    fn credentials(
        &self,
        action: &synra_control::CredentialAction,
    ) -> Result<serde_json::Value, Refusal> {
        self.credential_action(action)
    }

    /// Starts or inspects the shared restricted pairing workflow without a business connection.
    fn pairing(&self, action: &synra_control::PairingAction) -> Result<serde_json::Value, Refusal> {
        self.pairing_action(action)
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
        let parts = {
            let host = self.host.lock();
            host.dialling_parts()
        };
        let handshake_now = synra_core::reading_millis(now);
        let dialled = synra_core::retry::with_retries(
            synra_core::retry::ATTEMPTS,
            |_| {
                synra_core::dial_peer(&parts.0, parts.1, address, device_id, handshake_now)
                    .map_err(|error| refusal_of(&error))
            },
            |attempt| {
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * (u64::try_from(attempt).unwrap_or(0) + 1),
                ));
            },
        )?;
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

/// Puts one envelope on a link, and reads the one answer the same connection carries.
///
/// # Why this is a free function
///
/// Because two things need it and only one of them has a `Runtime`: the command path, and the start-up pass that sends
/// again what a restart left in flight. The runtime owns the pieces; a resend thread owns only clones of them, and giving
/// it a whole runtime it cannot borrow would mean not resending at all.
///
/// # Returns
///
/// `Some(reply)` for an `INTENT_RESULT`, `None` when there is nothing to apply — a timeout, an unexpected event, or a
/// withdrawal that is not answered. A timeout is **not** a failed dispatch: the action may still be running over there, so
/// the intent stays dispatching and a late answer can still end it.
///
/// # Errors
///
/// [`Refusal`] for a device with no known address, a dial that never connected, or a write the link refused.
pub(super) fn exchange(
    host: &std::sync::Arc<parking_lot::Mutex<synra_core::Host>>,
    outbound: &synra_core::intent::remote::Outbound,
    wait_for_result: bool,
) -> Result<Option<synra_protocol::envelope::Envelope>, Refusal> {
    let now = synra_store::sqlite::now_ms();
    // Resolve and read the address under the lock; dial outside it, for the reason `send_text` gives — a `dial` blocks
    // for as long as a connection takes, and a host guard living across it would make a devices listing wait for a
    // network.
    let address = {
        let host = host.lock();
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

    // ★ The handshake runs **outside** the lock, so a `devices` listing does not wait for it. `Host::dial` needs
    // `&mut self` to record the session; `dial_peer` needs only a clone of this device's record, and `adopt` records what
    // the exchange proved.
    let parts = {
        let host = host.lock();
        host.dialling_parts()
    };
    let handshake_now = synra_core::reading_millis(now);
    let dialled = synra_core::retry::with_retries(
        synra_core::retry::ATTEMPTS,
        |_| {
            synra_core::dial_peer(&parts.0, parts.1, address, outbound.to, handshake_now)
                .map_err(|error| refusal_of(&error))
        },
        |attempt| {
            std::thread::sleep(std::time::Duration::from_millis(
                100 * (u64::try_from(attempt).unwrap_or(0) + 1),
            ));
        },
    )?;
    let mut guard = host.lock();
    let mut link = guard
        .adopt(dialled, handshake_now)
        .map_err(|error| refusal_of(&error))?;
    // ★ The read half of the send, under the lock that is already held; the write itself needs no host.
    guard.may_send(&link).map_err(|error| refusal_of(&error))?;
    drop(guard);
    // ★ And the write happens holding nothing, because the session layer already writes through a link without the host.
    // Only counting it needs the host again. The write and the answer are the kernel's halves so the window and the
    // daemon cannot disagree about what counts as an answer; the count sits between them because it is about a write
    // that actually happened.
    synra_core::intent::remote::send(&mut link, outbound)
        .map_err(|error| Refusal::new(error.code, error.message))?;
    host.lock().count_sent();

    // ★ An invocation is answered on **this** connection, so the answer is read before the link is closed. A sender that
    // said `bye` immediately after the write would make the request fire-and-forget: the far side runs the action and then
    // has no connection to reply on, and this side leaves the intent dispatching for ever.
    let wait = wait_for_result.then_some(REMOTE_RESULT_WAIT);
    synra_core::intent::remote::receive(&mut link, wait)
        .map_err(|error| Refusal::new(error.code, error.message))
}
