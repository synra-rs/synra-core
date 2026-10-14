//! What a plugin asks the host to do, and what the host answers.
//!
//! # Why this is not the Wasmtime bindings
//!
//! Because the bindings are a *translation* and this is the *decision*. Every function in the WIT contract becomes, on
//! the host side, a check and an effect: may this plugin make this call, is it within its rate limit, what did it
//! actually ask for, and what is the answer. Those four questions are answerable over values — a capability set, a
//! clock, a table of devices — and the generated glue that turns a Wasm stack into those values adds nothing to whether
//! the answers are right. Writing the decisions first is also what makes them testable without an engine, and the
//! engine is the part that cannot be tested without a guest.
//!
//! # The one rule
//!
//! [`call`] refuses anything the generated import table does not list. Not "refuses anything gated and unheld" —
//! *anything not listed*, including a function name nothing has ever heard of. The table is produced by `wit-codegen`
//! from the WIT file, so a function added to the contract without a gate is a build failure, and a function a plugin
//! asks for that is not in the contract is refused by the host rather than by a linker.
//!
//! # What the host is, for these calls
//!
//! [`Host`] is a **trait**, and the implementations are the point: the kernel implements it for real, and a test
//! implements it with a recording stub. A host that owned the kernel would make every rule below untestable without
//! one, and the rules — the gate, the rate limit, the audit record — are where the mistakes are.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use synra_capability::Capability;
use synra_capability::CapabilitySet;
use synra_observe::audit::{AuditEntry, AuditOutcome};
use synra_protocol::ids::PluginId;

use crate::host_surface;
use crate::quota::{Budget, Health, RateKind};

/// What a plugin is told when a call does not proceed.
///
/// # Why this is a value and not a trap
///
/// Because Wasm has no exceptions and a trap is for an unrecoverable bug. A plugin that asked for a capability it does
/// not hold has *failed*, which is something it can handle — hide a button, log a line, try another way. A host that
/// trapped here would turn a permission decision into a crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "camelCase")]
#[error("{code}: {message}")]
pub struct CallError {
    /// A stable code a plugin branches on, rather than a sentence it parses.
    pub code: &'static str,
    /// What happened, for a log line and for a developer.
    pub message: String,
    /// Anything else that helps, as JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl CallError {
    /// The plugin asked for a function this host does not have.
    pub const UNKNOWN_FUNCTION: &'static str = "unknownFunction";
    /// The plugin does not hold the capability the function needs.
    pub const CAPABILITY_DENIED: &'static str = "capabilityDenied";
    /// The plugin called faster than its rate limit allows.
    pub const RATE_LIMITED: &'static str = "rateLimited";
    /// The argument is not what the function takes.
    pub const BAD_ARGUMENT: &'static str = "badArgument";
    /// The host could not do it, for a reason that is not the plugin's fault.
    pub const HOST_FAILED: &'static str = "hostFailed";

    /// A refusal.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), details: None }
    }

    /// The same refusal with more to say.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// The refusal for a capability the plugin does not hold.
    #[must_use]
    pub fn denied(capability: &str) -> Self {
        Self::new(
            Self::CAPABILITY_DENIED,
            format!("this plugin does not hold `{capability}`"),
        )
        .with_details(format!("{{\"capability\":\"{capability}\"}}"))
    }

    /// The refusal for a function no host provides.
    #[must_use]
    pub fn unknown(import: &str) -> Self {
        Self::new(Self::UNKNOWN_FUNCTION, format!("`{import}` is not a host function"))
    }
}

/// What a call produced.
///
/// The WIT `outcome` variant, as a Rust value: `Ok` carries the JSON the function returns — a string for most, an
/// array for the three that return lists — and `Err` carries why not.
pub type CallResult = Result<String, CallError>;

/// What a host can do for a plugin.
///
/// # Why every function here is semantic rather than mechanical
///
/// `storage_get` rather than "read these bytes at this offset". The mechanical layer is the plugin's own storage
/// implementation, and it is behind this trait: what the gate, the rate limit and the audit record are about is *what
/// the plugin asked for*, so that is the unit the host sees.
///
/// # Why the answers are `Result` rather than values
///
/// Because the implementations are fallible for reasons that are not the plugin's fault — a keychain that is locked, a
/// device that went away between the list and the send — and a trait that could not express that would have to make
/// those look like a plugin error. [`CallError::HOST_FAILED`] is what they become.
#[allow(clippy::missing_errors_doc)]
pub trait Host: Send + Sync {
    /// The host SDK's version.
    fn sdk_version(&self) -> String;
    /// What kind of host this is: `desktop`, `mobile` or `headless`.
    fn host_kind(&self) -> String;
    /// The user's locale, as a BCP 47 tag.
    fn locale(&self) -> String;
    /// Whether the interface is in a dark theme.
    fn dark_mode(&self) -> bool;
    /// Whether a plugin holds a capability, without using it.
    fn can(&self, plugin: &PluginId, capability: &str) -> bool;
    /// Which platform actions this host can perform at all.
    fn platform_capabilities(&self) -> Vec<String>;

    /// Write a line to the kernel's log.
    fn log(&self, plugin: &PluginId, level: &str, message: &str, context: Option<&str>) -> Result<(), CallError>;
    /// Publish an event to whoever subscribed.
    fn event_emit(&self, plugin: &PluginId, event: &str, payload: &str) -> Result<(), CallError>;

    /// Every device this kernel can see, as `(id, name, kind)`.
    fn devices(&self) -> Vec<(String, String, String)>;
    /// Send an event to one device.
    fn device_send(&self, plugin: &PluginId, target: &str, event: &str, payload: &str) -> Result<(), CallError>;
    /// Send an event to every paired device.
    fn device_broadcast(&self, plugin: &PluginId, event: &str, payload: &str) -> Result<(), CallError>;

    /// Read a value, or `None` when the key is absent.
    fn storage_get(&self, plugin: &PluginId, key: &str) -> Result<Option<String>, CallError>;
    /// Write a value.
    fn storage_set(&self, plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError>;
    /// Remove a value.
    fn storage_delete(&self, plugin: &PluginId, key: &str) -> Result<(), CallError>;
    /// Every key under a prefix, or every key when there is none.
    fn storage_keys(&self, plugin: &PluginId, prefix: Option<&str>) -> Result<Vec<String>, CallError>;
    /// How much storage the plugin is using, and how much it may.
    fn storage_quota(&self, plugin: &PluginId) -> Result<(u64, u64), CallError>;

    /// Read a secret from the OS keychain.
    fn secret_get(&self, plugin: &PluginId, key: &str) -> Result<Option<String>, CallError>;
    /// Write a secret to the OS keychain.
    fn secret_set(&self, plugin: &PluginId, key: &str, value: &str) -> Result<(), CallError>;
    /// Remove a secret.
    fn secret_delete(&self, plugin: &PluginId, key: &str) -> Result<(), CallError>;

    /// Perform an HTTP request, as a JSON request object.
    fn fetch(&self, plugin: &PluginId, request_json: &str) -> Result<String, CallError>;

    /// Begin a transfer, returning its identifier.
    fn transfer_send(
        &self,
        plugin: &PluginId,
        kind: &str,
        target: &str,
        meta_json: &str,
    ) -> Result<String, CallError>;
    /// How a transfer is going.
    fn transfer_status(&self, plugin: &PluginId, transfer_id: &str) -> Result<String, CallError>;

    /// Perform a platform action.
    ///
    /// One function rather than eight, because the eight differ only in their argument shape and the host's answer is
    /// the same for all of them: the guard, the rate limiter, and the action. The name is a
    /// [`PlatformAction`](crate::host_calls::PlatformAction::as_str).
    fn platform(&self, plugin: &PluginId, action: &str, argument: &str) -> Result<Option<String>, CallError>;

    /// Declare an action other plugins may call.
    fn action_declare(&self, plugin: &PluginId, name: &str, schema_json: &str) -> Result<(), CallError>;
    /// Every action this kernel knows about, as a JSON array.
    fn action_list(&self, plugin: &PluginId) -> Result<String, CallError>;
    /// Call another plugin's action.
    fn action_invoke(
        &self,
        plugin: &PluginId,
        target_plugin: &str,
        name: &str,
        args_json: &str,
    ) -> Result<String, CallError>;
}

/// The eight actions `platform:*` covers, as the host names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlatformAction {
    /// Open a URL in the user's browser.
    OpenUrl,
    /// Open a file or directory with the system's handler.
    OpenPath,
    /// Show a file in the system's file manager.
    RevealPath,
    /// Synthesize a keystroke.
    SimulateKeys,
    /// Show a notification.
    Notify,
    /// Read the clipboard.
    ReadClipboard,
    /// Write the clipboard.
    WriteClipboard,
}

impl PlatformAction {
    /// Every action, in the order the contract lists them.
    pub const ALL: &'static [Self] = &[
        Self::OpenUrl,
        Self::OpenPath,
        Self::RevealPath,
        Self::SimulateKeys,
        Self::Notify,
        Self::ReadClipboard,
        Self::WriteClipboard,
    ];

    /// The name the contract uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenUrl => "openUrl",
            Self::OpenPath => "openPath",
            Self::RevealPath => "revealPath",
            Self::SimulateKeys => "simulateKeys",
            Self::Notify => "notify",
            Self::ReadClipboard => "readClipboard",
            Self::WriteClipboard => "writeClipboard",
        }
    }

    /// The capability it needs, which is one per action rather than one `platform:*`.
    ///
    /// # Why this is a method and not a table
    ///
    /// Because the contract's own claim is that a plugin which notifies has no business simulating keystrokes, and one
    /// capability for both would make the permission dialog ask for both. A table would let a new action be added with
    /// the wrong gate; here the mapping is the thing being written.
    #[must_use]
    pub const fn capability(self) -> &'static str {
        match self {
            Self::OpenUrl => "platform:open-url",
            Self::OpenPath => "platform:open-path",
            Self::RevealPath => "platform:reveal-path",
            Self::SimulateKeys => "platform:simulate-keys",
            Self::Notify => "platform:notify",
            Self::ReadClipboard => "platform:read-clipboard",
            Self::WriteClipboard => "platform:write-clipboard",
        }
    }

    /// The action with this name, when it is one.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|action| action.as_str() == name)
    }
}

/// What one host call is checked against.
///
/// # Why the grants are here and not asked of the host
///
/// Because a host implementation that had to answer "may this plugin call this" would be one where every
/// implementation had to get the gate table right — and the gate table is generated from the contract precisely so
/// that it is written once. The host implements *effects*; this decides *permission*.
pub struct HostCalls<'a> {
    host: &'a dyn Host,
    plugin: PluginId,
    grants: &'a CapabilitySet,
    budget: &'a Budget,
    audit: &'a mut Vec<AuditEntry>,
}

impl std::fmt::Debug for HostCalls<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostCalls")
            .field("plugin", &self.plugin)
            .field("grants", &self.grants.len())
            .field("audited", &self.audit.len())
            .finish_non_exhaustive()
    }
}

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
        Self { host, plugin, grants, budget, audit }
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
    /// Every outcome is recorded, refusals included: "which plugin tried to do what it could not" is the question an
    /// audit log is read to answer.
    pub fn call(&mut self, import_name: &str, argument: &str) -> CallResult {
        let Some(gate) = host_surface::gate(import_name) else {
            let error = CallError::unknown(import_name);
            self.record(import_name, AuditOutcome::Denied, None);
            return Err(error);
        };

        if let Some(capability) = gate.capability() {
            // `grants` rather than a string comparison, because the table's capability is a *pattern*: a plugin granted
            // `log:*` covers every function that needs it, and a comparison would make the two spellings different
            // capabilities.
            let held = Capability::parse(capability).is_ok_and(|needed| self.grants.grants(&needed));
            if !held {
                let error = CallError::denied(capability);
                self.record(import_name, AuditOutcome::Denied, None);
                return Err(error);
            }
            if let Err(limited) = self.budget.consume(Self::rate_kind(import_name), 1, clock_ms()) {
                let error = CallError::new(CallError::RATE_LIMITED, limited.to_string());
                self.record(import_name, AuditOutcome::RateLimited, None);
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
        self.record(import_name, outcome, Some(elapsed));
        result
    }

    /// Performs the call, with the gate and the rate limit already passed.
    fn run(&self, import_name: &str, argument: &str) -> CallResult {
        // The capability a call is audited against, which is the one the gate names — the audit record is *about* the
        // permission, so it says which one.
        let function = import_name.rsplit_once('#').map_or(import_name, |(_, name)| name);
        let host = self.host;
        let plugin = &self.plugin;

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
                host.log(plugin, &parsed.level, &parsed.message, parsed.context.as_deref())?;
                Ok(String::new())
            }

            // ── Events ────────────────────────────────────────────────────────────────────────────────
            "event-emit" => {
                let parsed: EventArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.event_emit(plugin, &parsed.event, &parsed.payload)?;
                Ok(String::new())
            }
            "event-subscribe" => {
                // The subscription is the host's callback table rather than a host-observable object: a Wasm sandbox
                // has no such thing, so what this answers is that the pattern was recorded.
                if argument.is_empty() {
                    return Err(CallError::new(CallError::BAD_ARGUMENT, "a subscription needs a pattern"));
                }
                Ok(String::new())
            }

            // ── Devices ───────────────────────────────────────────────────────────────────────────────
            "device-list" => Ok(json_devices(&host.devices())),
            "device-send" => {
                let parsed: SendArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.device_send(plugin, &parsed.target, &parsed.event, &parsed.payload)?;
                Ok(String::new())
            }
            "device-broadcast" => {
                let parsed: EventArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.device_broadcast(plugin, &parsed.event, &parsed.payload)?;
                Ok(String::new())
            }

            // ── Storage ───────────────────────────────────────────────────────────────────────────────
            "storage-get" => match host.storage_get(plugin, argument)? {
                Some(value) => Ok(value),
                // ★ An absent key is an `err`, and the code says which kind: a plugin branching on `notFound` is doing
                // something ordinary, and one branching on `hostFailed` is not.
                None => Err(CallError::new("notFound", format!("no value under `{argument}`"))),
            },
            "storage-set" => {
                let parsed: KeyValue = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                host.storage_set(plugin, &parsed.key, &parsed.value)?;
                Ok(String::new())
            }
            "storage-delete" => {
                host.storage_delete(plugin, argument)?;
                Ok(String::new())
            }
            "storage-keys" => {
                let prefix = if argument.is_empty() { None } else { Some(argument) };
                Ok(json_array(&host.storage_keys(plugin, prefix)?))
            }
            "storage-quota" => {
                let (used, allowed) = host.storage_quota(plugin)?;
                Ok(format!("[{used},{allowed}]"))
            }

            // ── Secrets ───────────────────────────────────────────────────────────────────────────────
            "secret-get" => match host.secret_get(plugin, argument)? {
                Some(value) => Ok(value),
                None => Err(CallError::new("notFound", format!("no secret under `{argument}`"))),
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
        .map(|answer| if answer.is_empty() { "null".to_owned() } else { answer })
    }

    /// Runs a platform action through the one host function they all share.
    fn platform(&self, action: PlatformAction, argument: &str) -> CallResult {
        // Only the write-clipboard action carries text; the rest carry a URL, a path or a chord, and notify carries a
        // title and a body as JSON.
        let text = match action {
            PlatformAction::Notify => {
                let parsed: NotifyArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                format!("{}\u{1}{}", parsed.title, parsed.body)
            }
            _ => argument.to_owned(),
        };
        match self.host.platform(&self.plugin, action.as_str(), &text)? {
            Some(answer) => Ok(answer),
            None => Ok(String::new()),
        }
    }

    /// Writes one audit record.
    fn record(&mut self, import_name: &str, outcome: AuditOutcome, elapsed_ms: Option<u64>) {
        // ★ A capability that cannot be parsed is recorded as `log:*`... no: it is *not* recorded under a capability
        // the plugin does not hold. The gate table is generated from the contract and every string in it is a
        // capability, so a parse failure here means the table and the capability crate disagree — which is a build
        // failure rather than a runtime one, and the record is skipped rather than invented.
        let Some(capability) = host_surface::gate(import_name).and_then(|gate| gate.capability()) else {
            return;
        };
        let Ok(parsed) = Capability::parse(capability) else {
            return;
        };
        self.audit.push(AuditEntry::new(
            clock_ms() as i64,
            self.plugin.clone(),
            parsed,
            outcome,
            elapsed_ms,
        ));
    }
}

/// The arguments `log` takes, as the JSON the glue layer passes.
#[derive(Debug, Deserialize)]
struct LogArguments {
    level: String,
    message: String,
    #[serde(default)]
    context: Option<String>,
}

/// The arguments `event-emit` and `device-broadcast` take.
#[derive(Debug, Deserialize)]
struct EventArguments {
    event: String,
    #[serde(default)]
    payload: String,
}

/// The arguments `device-send` and `transfer-send` take.
#[derive(Debug, Deserialize)]
struct SendArguments {
    target: String,
    event: String,
    #[serde(default)]
    payload: String,
}

/// The arguments `storage-set` and `secret-set` take.
#[derive(Debug, Deserialize)]
struct KeyValue {
    key: String,
    value: String,
}

/// The arguments `platform-notify` takes.
#[derive(Debug, Deserialize)]
struct NotifyArguments {
    title: String,
    #[serde(default)]
    body: String,
}

/// The arguments `action-declare` takes.
#[derive(Debug, Deserialize)]
struct DeclareArguments {
    name: String,
    #[serde(default)]
    schema: String,
}

/// The arguments `action-invoke` takes.
#[derive(Debug, Deserialize)]
struct InvokeArguments {
    plugin: String,
    name: String,
    #[serde(default)]
    args: String,
}

/// The one clock: milliseconds since the epoch, as the store reads it.
///
/// Read from `std` rather than from the budget, because the audit entry and a device's `last_seen_ms` have to be
/// comparable — two clocks would make a plugin's call appear to have happened before the device it addressed.
fn clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

/// A JSON array of strings.
///
/// Written by hand rather than through `serde_json`, because the values are already strings the host produced and the
/// only transformation is escaping — and a `serde_json::Value` round trip for a list of names would be a parse of
/// something that was never text.
fn json_array(values: &[String]) -> String {
    let body: Vec<String> = values.iter().map(|value| json_string(value)).collect();
    format!("[{}]", body.join(","))
}

/// A JSON string, escaped.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", other as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// The device list, as the JSON the contract's `list<device-target>` becomes.
fn json_devices(devices: &[(String, String, String)]) -> String {
    let body: Vec<String> = devices
        .iter()
        .map(|(id, name, kind)| {
            format!(
                "{{\"id\":{},\"name\":{},\"kind\":{}}}",
                json_string(id),
                json_string(name),
                json_string(kind)
            )
        })
        .collect();
    format!("[{}]", body.join(","))
}

/// How many distinct functions the host serves, keyed by their bare names.
///
/// # Why this exists
///
/// Because it is the one number that says whether the host and the contract are still the same surface. The generated
/// table has 33 entries and so does this; a test compares them, so a function added to the contract and not to
/// [`HostCalls::run`] fails rather than answering `unknownFunction` at run time — which a plugin author would see as
/// their own mistake.
#[must_use]
pub fn implemented() -> BTreeMap<&'static str, &'static str> {
    host_surface::provided()
        .into_iter()
        .map(|import| {
            let function = import.rsplit_once('#').map_or(import, |(_, name)| name);
            (function, import)
        })
        .collect()
}

#[cfg(test)]
#[path = "host_calls_tests.rs"]
mod tests;
