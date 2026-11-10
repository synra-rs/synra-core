use super::{CallError, CallResult, HostCalls, PlatformAction};
use super::arguments::{DeclareArguments, EventArguments, InvokeArguments, KeyValue, LogArguments, SendArguments};
use super::helpers::{json_array, json_devices};

impl HostCalls<'_> {
/// Performs the call, with the gate and the rate limit already passed.
    pub(super) fn run(&self, import_name: &str, argument: &str) -> CallResult {
        // The capability a call is audited against, which is the one the gate names — the audit record is *about* the
        // permission, so it says which one.
        let function = import_name
            .rsplit_once('#')
            .map_or(import_name, |(_, name)| name);
        let host = self.host;
        let plugin = &self.plugin;

        // ★ The purity rule, before anything else. A `can-handle` pass asks every plugin about every share before a
        // user has chosen; a plugin that acted here would have acted on shares the user then cancelled.
        if !self.side_effects && Self::ACTION_SHAPED.contains(&function) {
            return Err(CallError::new(
                CallError::SIDE_EFFECT_NOT_ALLOWED,
                format!(
                    "`{function}` cannot be called while matching: `share.can-handle` is a pure function"
                ),
            ));
        }

        match function {
            // ── Ungated: read-only facts ──────────────────────────────────────────────────────────────
            "env-sdk-version" => Ok(host.sdk_version()),
            "env-host-kind" => Ok(host.host_kind()),
            "env-locale" => Ok(host.locale()),
            "env-dark-mode" => Ok(host.dark_mode().to_string()),
            "env-can" => Ok(host.can(plugin, argument).to_string()),
            "platform-capabilities" => Ok(json_array(&host.platform_capabilities())),
            "plugin-id" => Ok(plugin.to_string()),

            // ── Logging ───────────────────────────────────────────────────────────────────────────────
            "log" => {
                let parsed: LogArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.log(
                    plugin,
                    &parsed.level,
                    &parsed.message,
                    parsed.context.as_deref(),
                )?;
                Ok(String::new())
            }

            // ── Events ────────────────────────────────────────────────────────────────────────────────
            "event-emit" => {
                let parsed: EventArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.event_emit(plugin, &parsed.event, &parsed.payload)?;
                Ok(String::new())
            }
            // ── Devices ───────────────────────────────────────────────────────────────────────────────
            "device-list" => Ok(json_devices(&host.devices())),
            "input-session" => host.input_session(plugin, argument),
            "device-send" => {
                let parsed: SendArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                Self::check_emittable(plugin, &parsed.event)?;
                host.device_send(plugin, &parsed.target, &parsed.event, &parsed.payload)?;
                Ok(String::new())
            }
            "device-broadcast" => {
                let parsed: EventArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                Self::check_emittable(plugin, &parsed.event)?;
                host.device_broadcast(plugin, &parsed.event, &parsed.payload)?;
                Ok(String::new())
            }

            // ── Storage ───────────────────────────────────────────────────────────────────────────────
            "storage-get" => match host.storage_get(plugin, argument)? {
                Some(value) => Ok(value),
                // ★ An absent key is an `err`, and the code says which kind: a plugin branching on `notFound` is doing
                // something ordinary, and one branching on `hostFailed` is not.
                None => Err(CallError::new(
                    "notFound",
                    format!("no value under `{argument}`"),
                )),
            },
            "storage-set" => {
                let parsed: KeyValue = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                // ★ The quota is checked **before** the write, and against what the total would become.
                //
                // Checking after would mean the value is already stored when the call is refused, so a plugin that kept
                // writing would keep growing past its ceiling while being told each time that it had — the one shape of
                // enforcement that does not enforce anything.
                //
                // The growth is the value's own length because a write **replaces**: a plugin rewriting a key with a
                // larger value grows by the difference, and one rewriting it with a smaller value does not grow at all.
                // That is why this is `used - replaced + new` rather than `used + new`.
                let used = host.storage_used(plugin)?;
                let replaced = host
                    .storage_get(plugin, &parsed.key)?
                    .map_or(0, |previous| previous.len() as u64);
                let after = used
                    .saturating_sub(replaced)
                    .saturating_add(parsed.value.len() as u64);
                if let Err(refusal) = self.budget.check_storage(after) {
                    return Err(CallError::new(
                        CallError::QUOTA_EXCEEDED,
                        refusal.to_string(),
                    ));
                }
                host.storage_set(plugin, &parsed.key, &parsed.value)?;
                Ok(String::new())
            }
            "storage-delete" => {
                host.storage_delete(plugin, argument)?;
                Ok(String::new())
            }
            "storage-keys" => {
                let prefix = if argument.is_empty() {
                    None
                } else {
                    Some(argument)
                };
                Ok(json_array(&host.storage_keys(plugin, prefix)?))
            }
            "storage-quota" => {
                // Usage from the host, the ceiling from the quota. The plugin gets the pair it was promised, and neither
                // half is a copy of the other's number.
                let used = host.storage_used(plugin)?;
                let allowed = self.budget.quota().max_storage_bytes;
                Ok(format!("[{used},{allowed}]"))
            }

            // ── Secrets ───────────────────────────────────────────────────────────────────────────────
            "secret-get" => match host.secret_get(plugin, argument)? {
                Some(value) => Ok(value),
                None => Err(CallError::new(
                    "notFound",
                    format!("no secret under `{argument}`"),
                )),
            },
            "secret-set" => {
                let parsed: KeyValue = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.secret_set(plugin, &parsed.key, &parsed.value)?;
                Ok(String::new())
            }
            "secret-delete" => {
                host.secret_delete(plugin, argument)?;
                Ok(String::new())
            }

            // ── Network ───────────────────────────────────────────────────────────────────────────────
            "network-fetch" => host.fetch(plugin, argument),
            "network-websocket" => {
                // ★ Refused rather than accepted and dropped. The contract declares it, so it cannot be an unknown
                // function — but this build has no socket, and a plugin handed a subscription that never delivers
                // would wait for ever rather than find out. `hostFailed` is the honest answer, and the guest can
                // offer the feature as unavailable.
                Err(CallError::new(
                    CallError::HOST_FAILED,
                    "this host does not open WebSockets; use `network-fetch`",
                ))
            }

            // ── Transfers ─────────────────────────────────────────────────────────────────────────────
            "transfer-send" => {
                let parsed: SendArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.transfer_send(plugin, &parsed.event, &parsed.target, &parsed.payload)
            }
            "transfer-status" => host.transfer_status(plugin, argument),

            // ── Platform ──────────────────────────────────────────────────────────────────────────────
            "platform-open-url" => self.platform(PlatformAction::OpenUrl, argument),
            "platform-open-path" => self.platform(PlatformAction::OpenPath, argument),
            "platform-reveal-path" => self.platform(PlatformAction::RevealPath, argument),
            "platform-simulate-keys" => self.platform(PlatformAction::SimulateKeys, argument),
            "platform-notify" => self.platform(PlatformAction::Notify, argument),
            "platform-read-clipboard" => self.platform(PlatformAction::ReadClipboard, argument),
            "platform-write-clipboard" => self.platform(PlatformAction::WriteClipboard, argument),

            // ── Actions ───────────────────────────────────────────────────────────────────────────────
            "action-declare" => {
                let parsed: DeclareArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.action_declare(plugin, &parsed.name, &parsed.schema)?;
                Ok(String::new())
            }
            "action-list" => host.action_list(plugin),
            "action-invoke" => {
                let parsed: InvokeArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.action_invoke(plugin, &parsed.plugin, &parsed.name, &parsed.args)
            }

            // ★ The table listed it and this does not know it. That is a generator/host disagreement, and the honest
            // answer is a refusal rather than a silent success: a call that appeared to work and did nothing would be
            // the hardest kind of bug for a plugin author to find.
            other => Err(CallError::new(
                CallError::UNKNOWN_FUNCTION,
                format!("`{other}` is declared but this host does not implement it"),
            )),
        }
        .map(|answer| {
            if answer.is_empty() {
                "null".to_owned()
            } else {
                answer
            }
        })
    }
}
