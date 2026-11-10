use serde::{Deserialize, Serialize};

/// Which interface a command belongs to.
///
/// Not a permission level: the two are not ordered. The host interface is the application's own screens talking
/// to its own kernel, and the plugin interface is a stranger's page talking to the same kernel through a token
/// the host issued it. A command being "more powerful" is not what decides which list it is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Interface {
    /// The host's own screens, through the Tauri command bridge.
    Host,
    /// A plugin's page, through `plugin_ui_rpc` and a session token.
    Plugin,
}

impl Interface {
    /// A name for a log line or a metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Plugin => "plugin",
        }
    }

    /// Whether a command belonging to `self` may be called by `caller`.
    ///
    /// Equality, and that is the whole rule. A "the plugin may call it if it holds a capability" check belongs
    /// inside a command, not in the routing: a command that is reachable at all from a plugin's page is one an
    /// attacker can reach with a stolen token, so the list is what has to be short.
    #[must_use]
    pub const fn allows(self, caller: Self) -> bool {
        matches!(
            (self, caller),
            (Self::Host, Self::Host) | (Self::Plugin, Self::Plugin)
        )
    }
}

/// The aggregate a command's group belongs to.
///
/// Named rather than a bare prefix string, so the registry can check that a command's name starts with its
/// domain's prefix. That check is what keeps the front end's module layout and the kernel's grouping the same
/// thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    /// This device's identity.
    Identity,
    /// The device view, derived from discovery, trust and transport.
    Devices,
    /// Intent routing.
    Intent,
    /// File transfers.
    Transfer,
    /// Plugins.
    Plugins,
    /// The configuration.
    Config,
    /// Diagnostics.
    Diag,
    /// The plugin interface's single entry point.
    ///
    /// Separate from the others because it is not an aggregate: it is the bridge a plugin's page calls through,
    /// and its verbs are the plugin's own (`rpc`, `ready`) rather than a domain's.
    PluginUi,
}

impl Domain {
    /// The prefix every command in this domain starts with.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Identity => "identity_",
            Self::Devices => "devices_",
            Self::Intent => "intent_",
            Self::Transfer => "transfer_",
            Self::Plugins => "plugins_",
            Self::Config => "config_",
            Self::Diag => "diag_",
            Self::PluginUi => "plugin_ui_",
        }
    }

    /// Every domain.
    pub const ALL: &'static [Self] = &[
        Self::Identity,
        Self::Devices,
        Self::Intent,
        Self::Transfer,
        Self::Plugins,
        Self::Config,
        Self::Diag,
        Self::PluginUi,
    ];
}

/// What a command hands back, at the level of "is it one value or many".
///
/// Not the Rust type — that is the shell's business. This is what the *interface generator* needs in order to
/// produce a typed call: whether the result is a value, a list, or nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnShape {
    /// Nothing.
    Unit,
    /// One value.
    One,
    /// A list, which may be empty.
    ///
    /// Separate from [`Self::One`] because the front end's typing differs: a list is something the interface
    /// renders as a collection, and a single value that happens to be a `Vec` in Rust is not.
    Many,
    /// An optional value, where absence is a normal answer rather than a failure.
    ///
    /// `plugins_check_update` is the case: "no update" is not an error, and a command that returned an error for
    /// it would make the interface handle a failure on the common path.
    Maybe,
}

/// One command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandDescriptor {
    /// Its name, as the front end spells it.
    pub name: &'static str,
    /// Which aggregate it belongs to.
    pub domain: Domain,
    /// Which interface may call it.
    pub interface: Interface,
    /// What it hands back.
    pub returns: ReturnShape,
    /// Whether it changes anything.
    ///
    /// The interface uses this to decide whether to refresh a snapshot afterwards, and a test uses it to assert
    /// that a command which mutates is not in the plugin interface by accident.
    pub mutates: bool,
}

impl CommandDescriptor {
    /// Whether its name starts with its domain's prefix.
    #[must_use]
    pub fn prefix_matches(&self) -> bool {
        self.name.starts_with(self.domain.prefix())
    }

    /// Whether it may be called by the given interface.
    #[must_use]
    pub const fn callable_by(&self, caller: Interface) -> bool {
        self.interface.allows(caller)
    }
}
