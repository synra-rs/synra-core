use serde::{Deserialize, Serialize};

/// What a client asks the kernel to do.
///
/// # Why this is not the IPC command registry
///
/// `synra-ipc`'s registry is the *interface's* contract: which commands the Tauri shell registers, what the plugin UI
/// may call, and how each result is shaped for a screen. This is a smaller and more stable surface — the handful of
/// questions a command-line tool asks — and it is deliberately separate because the two have different audiences and
/// therefore different reasons to change. A new command for the interface's settings screen is not a new thing a
/// script can call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum Request {
    /// A liveness and version check.
    ///
    /// The first thing a client sends, because everything else assumes it is talking to a kernel it understands.
    Hello {
        /// The protocol version the client speaks.
        version: u16,
    },

    /// The kernel's state and its links.
    Status,


    /// The devices the kernel has seen.
    Devices {
        /// Whether to include devices that are not paired.
        include_unpaired: bool,
        /// How long to scan the network before answering, in milliseconds.
        ///
        /// # Why the kernel scans rather than the client waiting
        ///
        /// Because only the kernel has the discovery socket. A client that slept for this long and then asked would get
        /// exactly the table it would have got without asking — the sleep would look like a scan and be a delay. Zero or
        /// absent means "answer from what you already know", which is what a cached listing is.
        ///
        /// # Why it is optional
        ///
        /// So a client that knows nothing about scanning sends a request this kernel still understands. The protocol's
        /// rule for evolution is that a peer may say a little more, and an absent field is an older client saying nothing
        /// rather than saying zero.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        scan_ms: Option<u64>,
    },

    /// Send text to a device.
    SendText {
        /// The device's id.
        to: String,
        /// What to send.
        text: String,
    },

    /// Send a file to a device.
    SendFile {
        /// The device's id.
        to: String,
        /// The file's path, as the client resolved it.
        path: String,
    },

    /// The installed plugins.
    Plugins,

    /// Lists previously verified publisher keys and this device's decisions.
    PluginPublishers,
    /// Records a decision for the exact key the user confirmed.
    PluginPublisherDecide {
        /// A publisher this device has met.
        publisher_id: String,
        /// The fingerprint displayed to the user.
        fingerprint: String,
        /// seen, trusted or revoked.
        trust: String,
    },

    /// Reads or changes the ordered registry source list.
    PluginRegistry {
        /// None reads; an empty list clears the setting; otherwise replaces it.
        urls: Option<Vec<String>>,
    },
    /// Reads or changes the background update policy.
    PluginUpdatePolicy {
        /// None reads; otherwise never, notify-only, auto-minor or auto-all.
        policy: Option<String>,
    },
    /// Explicitly checks current registry metadata without installing, even when automatic checks are disabled.
    PluginCheckUpdates {
        /// None checks all installed plugins.
        plugin_id: Option<String>,
    },
    /// Explicitly updates an installed plugin using verified registry bytes.
    PluginUpdate {
        /// The installed identifier.
        plugin_id: String,
        /// Exact version or range, or None for latest.
        version: Option<String>,
    },

    /// Search the plugin catalogue.
    ///
    /// ★ Why this is a request of its own rather than part of `Plugins`.
    ///
    /// Because the two answer questions about different machines. `Plugins` is what is **installed here**, which the store
    /// answers; this is what a **registry offers**, which is a network call that can take seconds and can fail. Merging them
    /// would make the installed list as slow as the network and make a screen that only wanted to show what is installed
    /// depend on a registry being reachable.
    CatalogSearch {
        /// The package name, as a registry spells it.
        package: String,
    },

    /// Turn a plugin on or off.
    ///
    /// ★ Why this had to exist.
    ///
    /// Because `synra plugin enable` and `synra plugin disable` are in the documented command list, they parse, and they
    /// did **nothing**: `plugin_request` answered `None` for every action but `list`, and a `None` from there means the
    /// CLI reports "this command needs a running kernel, and none is reachable" — a sentence that is false, and that
    /// sends a user to check a daemon which is running perfectly well.
    ///
    /// The database side already existed and was tested (`set_plugin_enabled`); what was missing was any way to reach it.
    PluginSetEnabled {
        /// Which plugin.
        plugin_id: String,
        /// Whether it should be usable.
        enabled: bool,
    },

    /// Install a plugin from a directory on this machine.
    ///
    /// # Why a path rather than a package identifier
    ///
    /// Because a registry install needs a fetcher, and there is none: the design's `InstallSource::Registry` has a
    /// packument parser and an integrity check and no HTTP client, so a request naming a package would fail at the
    /// first step for a reason the caller could not act on. A path is the source that exists, and the install pipeline
    /// behind it is the same one a registry install will run.
    ///
    /// # Why the kernel installs rather than the client
    ///
    /// Because installing means verifying, writing into the plugin directory and recording a row — three things only
    /// the process that owns the data directory may do. A client that copied files and asked the kernel to record them
    /// would be a second writer of the same state.
    PluginInstall {
        /// The directory the package is in, as the client resolved it.
        path: String,
    },

    /// Install a plugin from a registry, by the name the registry spells.
    ///
    /// # Why this is a request of its own rather than a `PluginInstall` with a URL
    ///
    /// Because the two need different things from the kernel: a path is already on disk and only has to be verified, while
    /// a package name means fetching a document, choosing a version, fetching bytes and comparing them with an integrity
    /// string. A request that carried a string the kernel had to classify would put that decision on the wrong side of
    /// the boundary — and would make "the path does not exist" and "the registry has no such version" the same failure.
    PluginInstallPackage {
        /// The package, as the registry spells it, such as `@acme/chat`.
        package: String,
        /// A version, or `None` for the registry's `latest` tag.
        version: Option<String>,
    },

    /// Records the user's decision about what a plugin may do.
    ///
    /// # Why this is a request and not a field on the install
    ///
    /// Because installing and approving are two acts. The design puts `AwaitingConsent` between them so that a package
    /// which arrived — from a registry, a file, or a peer — has not acquired any authority by arriving. An install that
    /// carried its own consent would make "I installed it" and "I let it read my clipboard" the same click.
    ///
    /// # Why the granted set rather than a yes/no
    ///
    /// Because consent is per capability, and a plugin is often useful with fewer than it asks for. A boolean would
    /// collapse "it may log but not open my browser" into "it may do everything it declared", which is the decision the
    /// capability model exists to avoid making on the user's behalf.
    PluginConsent {
        /// Which plugin.
        plugin_id: String,
        /// The capabilities the user allowed. Everything else the manifest declares is recorded as denied.
        granted: Vec<String>,
    },

    /// Removes a plugin, and its data when the caller asked for that.
    ///
    /// # Why the data decision is a parameter rather than a second request
    ///
    /// Because removing and deleting the data are one act with two outcomes, and the default is the reversible one. The
    /// CLI's `plugin remove` has a `--data` flag for the destructive half; a request that could not carry the decision
    /// would make the flag a promise with nothing behind it — which is the failure `--follow` was recorded for.
    PluginRemove {
        /// Which plugin.
        plugin_id: String,
        /// Whether to delete its data as well. Off by default at the command line.
        remove_data: bool,
    },

    /// Hands the kernel something to route.
    ///
    /// # ★ Why this request had to exist
    ///
    /// Because the matcher — the component that asks every plugin "can you handle this?" — had **no production caller at
    /// all**. `synra-core` implements it, tests it, and nothing could reach it: the control protocol had no intent
    /// request, the CLI had no command, and the daemon's transport writes an inbound share to an inbox and reports that
    /// nothing was delivered. A share arriving became a file, never an action, and the design document calls this
    /// routing "the kernel's most central orchestration".
    ///
    /// # Why this carries content rather than a `ShareItem`
    ///
    /// Because a `ShareItem` says which device shared it, and a caller on this machine's own socket is not a device: the
    /// only place that knows which device this is, is the kernel. So the caller sends what was shared and the kernel
    /// supplies the origin, rather than the caller inventing an identifier for itself that the kernel would then have to
    /// trust.
    IntentDispatch {
        /// The MIME type. `text/uri-list` for a link, `text/plain` for a sentence.
        mime: String,
        /// The content.
        text: String,
    },

    /// What has become of an intent.
    ///
    /// # Why a UI needs this
    ///
    /// Because routing is asynchronous from the user's point of view: a prompt appears after the plugins have answered,
    /// and the answer they give has to be applied to the same intent the prompt was about. Asking for the snapshot is how
    /// an interface finds out whether it is still choosing, now confirming, or already over.
    IntentSnapshot {
        /// Which intent.
        intent: String,
    },

    /// The user's answer to a prompt.
    IntentDecide {
        /// Which intent.
        intent: String,
        /// Which plugin the user picked, when they were choosing between several.
        ///
        /// `None` takes the candidate the board already settled on, which is the ordinary case: one plugin claimed the
        /// share and the user confirmed it.
        plugin_id: Option<String>,
        /// Where to run it, when the plugin that claimed the share did not say.
        ///
        /// # Why this is here now, and was not before
        ///
        /// Because `Board` could not answer the question. A candidate whose plugin suggested no device settles into
        /// `Choosing` — which *is* "where should this run?" — and no method advanced it: `choose` put a targetless
        /// candidate straight back into `Choosing`, and `confirm` refuses anything that is not `Confirming`. The field was
        /// left out rather than accepted and ignored.
        ///
        /// `Board::aim` is the method that answers it, so the parameter does what it says.
        target: Option<String>,
    },

    /// The user changed their mind.
    IntentCancel {
        /// Which intent.
        intent: String,
    },

    /// The tail of the kernel's log.
    Logs {
        /// How many lines.
        lines: usize,
        /// Whether to include debug-level lines.
        verbose: bool,
        /// Show only the lines for one trace, when the caller asked for one.
        ///
        /// # ★ Why this is a field and not a `--verbose` in disguise
        ///
        /// Because the CLI used to translate `--trace <id>` into `verbose: true` and **throw the id away**. The flag
        /// parsed, the command ran, the output looked plausible, and the filter the user asked for did not exist — the
        /// worst shape a broken flag can take, because nothing about the result says so.
        ///
        /// A trace is one user action's group of steps (`TraceContext`), and the id is what a person pastes out of a bug
        /// report to find the rest of it. Filtering is by substring on the rendered line, because the line format
        /// belongs to the logger and the daemon keeps no index of its own log — the same reason the level filter reads
        /// the level out of the text.
        ///
        /// `None` means "every trace", which is what a caller who did not ask for one gets.
        trace: Option<String>,
    },

}


