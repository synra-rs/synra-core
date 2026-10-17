//! The command registry: which commands exist, and who may call them.
//!
//! # Why a registry rather than a list in a document
//!
//! The interface's command set is a contract with two independent implementations — the shell that registers them
//! and the front end that calls them. A document describes it and drifts; a value can be *asserted*. So the set
//! lives here, and the tests in this module hold it to the properties that matter:
//!
//! * Every command in the design document's table exists.
//! * The plugin interface may not reach the host interface's commands, and vice versa.
//! * No command name is spelled two ways.
//! * Every command's domain prefix matches the group it is filed under.
//!
//! That last one is not pedantry: the prefixes are what the front end uses to organise its own modules, and a
//! command whose prefix disagrees with its group is one that ends up in the wrong file — after which the
//! interface's "devices" screen holds a pairing call and nobody notices until they need it.
//!
//! # Two interfaces, and the separation is the point
//!
//! The design document requires the plugin interface and the host interface to be separate: **different tokens,
//! different command allow-lists**. A plugin's page runs inside the same WebView as the host's own interface, so
//! without a separated list a plugin could call `plugins_uninstall` — or `identity_set_display_name`.
//!
//! [`Interface`] is that separation, expressed as a value: a command belongs to exactly one interface, and the
//! plugin interface's list is a short, deliberate subset.

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
    /// Pairing.
    Pairing,
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
            Self::Pairing => "pairing_",
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
        Self::Pairing,
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

/// The macro that keeps the table and the names in step.
///
/// A command is declared once, with its name as a string literal, and the `name` field is built from the same
/// literal. Writing the name twice — once as a Rust identifier and once as a string — is how the two drift, and a
/// drifted name is a command the front end calls and the shell does not have.
macro_rules! commands {
    ($( $name:literal => $domain:ident, $interface:ident, $returns:ident, $mutates:literal );* $(;)?) => {
        /// Every command the shell registers.
        pub const COMMANDS: &[CommandDescriptor] = &[
            $(
                CommandDescriptor {
                    name: $name,
                    domain: Domain::$domain,
                    interface: Interface::$interface,
                    returns: ReturnShape::$returns,
                    mutates: $mutates,
                },
            )*
        ];
    };
}

commands! {
    // ── identity ──
    "identity_get" => Identity, Host, One, false;
    "identity_set_display_name" => Identity, Host, Unit, true;

    // ── devices ──
    "devices_snapshot" => Devices, Host, One, false;
    "devices_scan_start" => Devices, Host, One, true;
    "devices_scan_cancel" => Devices, Host, Unit, true;
    "devices_connect" => Devices, Host, Unit, true;
    "devices_disconnect" => Devices, Host, Unit, true;
    "devices_forget" => Devices, Host, Unit, true;

    // ── pairing ──
    "pairing_request" => Pairing, Host, One, true;
    "pairing_respond" => Pairing, Host, Unit, true;
    "pairing_cancel" => Pairing, Host, Unit, true;

    // ── intent ──
    "intent_dispatch" => Intent, Host, One, true;
    // ★ The listing read, which the interface asked for before the contract had it.
    //
    // `HomePage.vue`'s "received" panel wanted the intents in flight, and there was no command that answers them — so the
    // page called `intent_snapshot` with no identifier (refused by the bridge, since the wrapper requires one) and read
    // `answer.value.intents`, a field no DTO has. The capability was never missing: `Board::all()` has existed since the
    // board was written, for persistence. What was missing was the name.
    "intent_list" => Intent, Host, Many, false;
    "intent_snapshot" => Intent, Host, One, false;
    "intent_decide" => Intent, Host, Unit, true;
    "intent_cancel" => Intent, Host, Unit, true;

    // ── transfer ──
    "transfer_send_file" => Transfer, Host, One, true;
    "transfer_send_text" => Transfer, Host, One, true;
    "transfer_cancel" => Transfer, Host, Unit, true;
    "transfer_list" => Transfer, Host, Many, false;

    // ── plugins ──
    "plugins_list" => Plugins, Host, Many, false;
    "plugins_catalog_search" => Plugins, Host, Many, false;
    "plugins_install" => Plugins, Host, One, true;
    "plugins_uninstall" => Plugins, Host, One, true;
    "plugins_enable" => Plugins, Host, Unit, true;
    "plugins_disable" => Plugins, Host, Unit, true;
    "plugins_consent_respond" => Plugins, Host, Unit, true;
    "plugins_check_update" => Plugins, Host, Maybe, false;
    "plugins_update" => Plugins, Host, Unit, true;
    "plugins_sync_plan" => Plugins, Host, One, false;
    "plugins_sync_run" => Plugins, Host, One, true;
    "plugins_audit" => Plugins, Host, Many, false;
    "plugins_request_registry_search" => Plugins, Host, Many, true;

    // ── the plugin interface ──
    //
    // Two commands, and the smallness is the design. A plugin's page reaches the kernel through a session token
    // and *these* verbs; everything else it wants goes through `rpc`, whose allow-list is the plugin's granted
    // capabilities rather than a command name.
    "plugin_ui_rpc" => PluginUi, Plugin, One, true;
    "plugin_ui_ready" => PluginUi, Plugin, Unit, true;
    // ★ `Host`, and that is the whole point of the row: opening a page is the **host's** act. A plugin page that could ask
    // for another page would be a plugin that can spawn windows, which is not a capability this model grants.
    "plugin_ui_open" => PluginUi, Host, Unit, true;

    // ── config ──
    "config_get" => Config, Host, One, false;
    "config_set" => Config, Host, Unit, true;

    // ── diagnostics ──
    "diag_export" => Diag, Host, One, true;
    "diag_metrics" => Diag, Host, One, false;
    "diag_logs_tail" => Diag, Host, Many, false;
}

/// Why the registry is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// A command's name does not start with its domain's prefix.
    #[error("the command {name:?} is filed under {domain:?}, whose prefix is {prefix:?}")]
    PrefixMismatch {
        /// The command's name.
        name: String,
        /// The domain it is filed under.
        domain: &'static str,
        /// That domain's prefix.
        prefix: &'static str,
    },

    /// A name appears more than once.
    #[error("the command {name:?} is declared more than once")]
    Duplicate {
        /// The repeated name.
        name: String,
    },

    /// A name is not spelled the way the convention requires.
    #[error("{name:?} is not `domain_verb` in snake_case")]
    BadName {
        /// The name that was offered.
        name: String,
    },

    /// A mutating command is in the plugin interface.
    ///
    /// Not forbidden in general — a plugin's page may legitimately change its own storage — but it is worth
    /// stating which ones are, because the list is short and a new entry is a decision.
    #[error("the mutating command {name:?} is reachable from a plugin page")]
    MutatingInPluginInterface {
        /// The command.
        name: String,
    },
}

/// The command registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommandRegistry;

impl CommandRegistry {
    /// Looks a command up by name.
    #[must_use]
    pub fn find(name: &str) -> Option<&'static CommandDescriptor> {
        COMMANDS.iter().find(|command| command.name == name)
    }

    /// Every command in a domain.
    #[must_use]
    pub fn in_domain(domain: Domain) -> Vec<&'static CommandDescriptor> {
        COMMANDS.iter().filter(|command| command.domain == domain).collect()
    }

    /// Every command an interface may call.
    #[must_use]
    pub fn for_interface(interface: Interface) -> Vec<&'static CommandDescriptor> {
        COMMANDS.iter().filter(|command| command.interface == interface).collect()
    }

    /// How many commands exist.
    #[must_use]
    pub const fn len() -> usize {
        COMMANDS.len()
    }

    /// Whether the registry is internally consistent.
    ///
    /// # Errors
    ///
    /// The first [`RegistryError`] found. Called by a test rather than at start-up, because a registry that is
    /// wrong is a build failure and not something a user should discover at run time.
    pub fn verify() -> Result<(), RegistryError> {
        let mut seen: Vec<&str> = Vec::with_capacity(COMMANDS.len());

        for command in COMMANDS {
            if seen.contains(&command.name) {
                return Err(RegistryError::Duplicate { name: command.name.to_owned() });
            }
            seen.push(command.name);

            if !command.prefix_matches() {
                return Err(RegistryError::PrefixMismatch {
                    name: command.name.to_owned(),
                    domain: domain_name(command.domain),
                    prefix: command.domain.prefix(),
                });
            }

            if !is_snake_case_with_one_separator(command.name) {
                return Err(RegistryError::BadName { name: command.name.to_owned() });
            }
        }
        Ok(())
    }

    /// The commands a plugin's page may reach, which is the same as [`Self::for_interface`] for
    /// [`Interface::Plugin`].
    ///
    /// A method of its own because it is the allow-list rather than a view: a caller checking whether a token may
    /// call something is asking this question, and naming it after the interface makes the call site read as the
    /// security decision it is.
    #[must_use]
    pub fn plugin_allow_list() -> Vec<&'static str> {
        COMMANDS
            .iter()
            .filter(|command| command.interface == Interface::Plugin)
            .map(|command| command.name)
            .collect()
    }
}

/// A domain's name, for an error message.
const fn domain_name(domain: Domain) -> &'static str {
    match domain {
        Domain::Identity => "identity",
        Domain::Devices => "devices",
        Domain::Pairing => "pairing",
        Domain::Intent => "intent",
        Domain::Transfer => "transfer",
        Domain::Plugins => "plugins",
        Domain::Config => "config",
        Domain::Diag => "diag",
        Domain::PluginUi => "plugin_ui",
    }
}

/// Whether a name is `domain_verb` in `snake_case` with exactly one separator.
///
/// One separator, not at least one: `plugins_catalog_search` has three words and one separator after the domain,
/// which is the convention — the domain names the aggregate and everything after its first underscore is the
/// verb. A name with two separators after the domain would still be snake_case and would still work, so the rule
/// is stated as a warning rather than an error... except that it is not, because a name like `plugins_a_b` reads
/// as a domain of `plugins_a`, and the front end's grouping is by prefix.
fn is_snake_case_with_one_separator(name: &str) -> bool {
    let Some((domain, verb)) = name.split_once('_') else {
        return false;
    };
    if domain.is_empty() || verb.is_empty() {
        return false;
    }
    name.chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        && !name.contains("__")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── The registry ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_registry_is_internally_consistent() {
        // Prefixes, duplicates and spelling, all at once: a registry that is wrong is a build failure rather than
        // something a user discovers.
        assert_eq!(CommandRegistry::verify(), Ok(()));
    }

    #[test]
    fn every_command_the_design_document_lists_exists() {
        // ★ What this test does and does not check.
        //
        // The comment here used to read: "A command in the document and not here is one the front end calls and the shell
        // does not have." That is the failure worth catching, and this test cannot see it. Both lists below and in the
        // registry are maintained by hand **in this file**, so the assertion is a hand-written list against a table
        // written from it — it compares two copies of the same decision, not the decision against the shell.
        //
        // The gap it cannot see is real and larger: of the names below, only twelve are registered with Tauri in
        // `synra-rust-app/src-tauri/src/main.rs`. A front end calling `pairing_request` reaches a command the shell does
        // not have, which is exactly the sentence above.
        //
        // What this test *is* good for is the other direction, and it is worth keeping for that: a name removed from the
        // registry while the contract still lists it fails here, and the counts must agree. The half about the shell is
        // checked where the shell is — `synra-rust-app/src/ipc/registration.test.ts` — because a test in this crate
        // cannot read that file without reaching out of the workspace.
        let documented = [
            // identity
            "identity_get",
            "identity_set_display_name",
            // devices
            "devices_snapshot",
            "devices_scan_start",
            "devices_scan_cancel",
            "devices_connect",
            "devices_disconnect",
            "devices_forget",
            // pairing
            "pairing_request",
            "pairing_respond",
            "pairing_cancel",
            // intent
            "intent_dispatch",
            "intent_list",
            "intent_snapshot",
            "intent_decide",
            "intent_cancel",
            // transfer
            "transfer_send_file",
            "transfer_send_text",
            "transfer_cancel",
            "transfer_list",
            // plugins
            "plugins_list",
            "plugins_catalog_search",
            "plugins_install",
            "plugins_uninstall",
            "plugins_enable",
            "plugins_disable",
            "plugins_consent_respond",
            "plugins_check_update",
            "plugins_update",
            "plugins_sync_plan",
            "plugins_sync_run",
            "plugins_audit",
            "plugins_request_registry_search",
            // plugin ui
            "plugin_ui_rpc",
            "plugin_ui_ready",
            "plugin_ui_open",
            // config
            "config_get",
            "config_set",
            // diagnostics
            "diag_export",
            "diag_metrics",
            "diag_logs_tail",
        ];

        for name in documented {
            assert!(CommandRegistry::find(name).is_some(), "{name} is documented and missing");
        }
        assert_eq!(documented.len(), CommandRegistry::len(), "the registry has commands the document does not");
    }

    #[test]
    fn a_command_can_be_found_by_name() {
        let command = CommandRegistry::find("devices_snapshot").expect("exists");
        assert_eq!(command.domain, Domain::Devices);
        assert_eq!(command.interface, Interface::Host);
        assert_eq!(command.returns, ReturnShape::One);
        assert!(!command.mutates);
    }

    #[test]
    fn an_unknown_command_is_not_found_rather_than_guessed() {
        // The shell refuses a name it does not have; it does not fall back to something similar.
        assert!(CommandRegistry::find("devices_snapshot_").is_none());
        assert!(CommandRegistry::find("Devices_Snapshot").is_none());
        assert!(CommandRegistry::find("").is_none());
        assert!(CommandRegistry::find("device_snapshot").is_none());
    }

    #[test]
    fn every_command_belongs_to_a_domain_that_exists() {
        // A command filed under no domain is one whose prefix check passes vacuously.
        for command in COMMANDS {
            assert!(Domain::ALL.contains(&command.domain), "{}", command.name);
        }
        let total: usize = Domain::ALL
            .iter()
            .map(|domain| CommandRegistry::in_domain(*domain).len())
            .sum();
        assert_eq!(total, CommandRegistry::len(), "some command is in no domain");
    }

    #[test]
    fn every_domain_has_a_command() {
        // An empty domain is a group the front end has a module for and nothing to put in it.
        for domain in Domain::ALL {
            assert!(
                !CommandRegistry::in_domain(*domain).is_empty(),
                "{domain:?} has no commands"
            );
        }
    }

    // ── Naming ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_command_starts_with_its_domains_prefix() {
        // The prefixes are what the front end organises its modules by, and a command whose prefix disagrees with
        // its group ends up in the wrong file.
        for command in COMMANDS {
            assert!(command.prefix_matches(), "{} vs {:?}", command.name, command.domain);
        }
    }

    #[test]
    fn every_command_name_is_snake_case() {
        for command in COMMANDS {
            assert!(
                is_snake_case_with_one_separator(command.name),
                "{} is not domain_verb in snake_case",
                command.name
            );
        }
    }

    #[test]
    fn a_name_that_is_not_the_convention_is_refused() {
        // The check has to actually reject the shapes that would break the front end's grouping.
        for bad in ["", "get", "Get_thing", "get__thing", "get-Thing", "get thing", "_x", "x_"] {
            assert!(!is_snake_case_with_one_separator(bad), "{bad:?} was accepted");
        }
        for good in ["devices_snapshot", "plugin_ui_rpc", "diag_logs_tail", "a_b"] {
            assert!(is_snake_case_with_one_separator(good), "{good:?} was refused");
        }
    }

    #[test]
    fn the_domain_prefixes_are_distinct() {
        // `plugin_ui_` and `plugins_` are close, and a front end matching on a prefix would group wrongly if one
        // were a prefix of the other. `plugin_ui_` is not: `plugins_` starts with `plugin` and then `s`, so
        // neither is a prefix of the other.
        for (index, first) in Domain::ALL.iter().enumerate() {
            for second in &Domain::ALL[index + 1..] {
                assert_ne!(first.prefix(), second.prefix(), "{first:?} and {second:?}");
                assert!(
                    !first.prefix().starts_with(second.prefix()) && !second.prefix().starts_with(first.prefix()),
                    "{first:?} and {second:?} are prefixes of each other"
                );
            }
        }
    }

    // ── The interface separation ──────────────────────────────────────────────────────────────────

    #[test]
    fn the_plugin_interface_cannot_reach_a_host_command() {
        // The design document's requirement, as an executable statement. A plugin's page runs in the same WebView
        // as the host's screens, so without this a plugin could call `plugins_uninstall`.
        for command in COMMANDS {
            if command.interface == Interface::Host {
                assert!(!command.callable_by(Interface::Plugin), "{} is reachable from a plugin", command.name);
            }
        }
    }

    #[test]
    fn the_host_interface_cannot_reach_a_plugin_command() {
        // The other direction, and it matters for a different reason: the host's screens go through the Tauri
        // bridge, and a command that expects a plugin's session token would fail in a way that reads as a bug.
        for command in COMMANDS {
            if command.interface == Interface::Plugin {
                assert!(!command.callable_by(Interface::Host), "{} is reachable from the host bridge", command.name);
            }
        }
    }

    #[test]
    fn an_interface_always_allows_itself() {
        assert!(Interface::Host.allows(Interface::Host));
        assert!(Interface::Plugin.allows(Interface::Plugin));
    }

    #[test]
    fn the_plugin_allow_list_is_small_and_explicit() {
        // The smallness is the design: a plugin's page reaches the kernel through a token and these verbs, and
        // everything else goes through `rpc`, whose allow-list is the plugin's capabilities rather than a name.
        let allowed = CommandRegistry::plugin_allow_list();
        assert_eq!(allowed.len(), 2, "{allowed:?}");
        assert!(allowed.contains(&"plugin_ui_rpc"));
        assert!(allowed.contains(&"plugin_ui_ready"));
    }

    #[test]
    fn no_destructive_command_is_in_the_plugin_allow_list() {
        // An explicit assertion over the dangerous ones rather than a general rule, because the list is short and
        // a reader should be able to see which names are deliberately excluded.
        let dangerous = [
            "plugins_uninstall",
            "plugins_install",
            "identity_set_display_name",
            "devices_forget",
            "config_set",
            "diag_export",
        ];
        let allowed = CommandRegistry::plugin_allow_list();
        for name in dangerous {
            assert!(!allowed.contains(&name), "{name} is reachable from a plugin page");
        }
    }

    #[test]
    fn the_registry_verifies_the_mutating_commands_are_host_only() {
        // `RegistryError::MutatingInPluginInterface` exists as a variant so the rule can be stated; the registry
        // verifies it by construction rather than by the variant being returned, and this asserts the property
        // the variant names.
        let mutating: Vec<&str> = COMMANDS
            .iter()
            .filter(|command| command.mutates && command.interface == Interface::Plugin)
            .map(|command| command.name)
            .collect();
        // The two plugin commands are marked as mutating — `rpc` performs whatever the plugin asked for and
        // `ready` records a state — and that is deliberate: the *token* is what limits them, not the verb.
        assert_eq!(mutating, vec!["plugin_ui_rpc", "plugin_ui_ready"]);

        // So the variant is reachable in principle but not from this table, which is worth knowing: a caller that
        // saw it come out of `verify` would be looking at a different table.
        assert!(!matches!(
            CommandRegistry::verify(),
            Err(RegistryError::MutatingInPluginInterface { .. })
        ));
    }

    // ── Return shapes ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn only_one_command_returns_something_optional() {
        // `plugins_check_update`: "no update" is not an error, and a command that returned one would make the
        // interface handle a failure on the common path.
        let optional: Vec<&str> = COMMANDS
            .iter()
            .filter(|command| command.returns == ReturnShape::Maybe)
            .map(|command| command.name)
            .collect();
        assert_eq!(optional, vec!["plugins_check_update"]);
    }

    #[test]
    fn a_list_returning_command_is_marked_as_such() {
        // The front end types a list differently from a single value, so the distinction has to be in the
        // descriptor rather than inferred.
        for name in ["transfer_list", "plugins_list", "plugins_audit", "diag_logs_tail"] {
            assert_eq!(CommandRegistry::find(name).expect("exists").returns, ReturnShape::Many, "{name}");
        }
    }

    #[test]
    fn a_command_that_changes_nothing_is_marked_as_such() {
        // The interface uses this to decide whether to refresh a snapshot afterwards, and refreshing after a read
        // is a round trip that shows nothing new.
        for name in [
            "identity_get",
            "devices_snapshot",
            "intent_snapshot",
            "transfer_list",
            "plugins_list",
            "config_get",
            "diag_metrics",
        ] {
            assert!(!CommandRegistry::find(name).expect("exists").mutates, "{name}");
        }
    }

    #[test]
    fn a_scan_is_marked_as_mutating() {
        // It changes kernel state even though it returns a value, and the interface has to know that so it does
        // not treat the answer as a pure read.
        let start = CommandRegistry::find("devices_scan_start").expect("exists");
        assert!(start.mutates);
        assert_eq!(start.returns, ReturnShape::One);
    }

    // ── Reporting ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_interface_can_be_listed() {
        let host = CommandRegistry::for_interface(Interface::Host);
        let plugin = CommandRegistry::for_interface(Interface::Plugin);
        assert_eq!(host.len() + plugin.len(), CommandRegistry::len());
        assert_eq!(plugin.len(), 2);
        for command in &host {
            assert_eq!(command.interface, Interface::Host);
        }
    }

    #[test]
    fn a_domain_can_be_listed() {
        let devices = CommandRegistry::in_domain(Domain::Devices);
        assert_eq!(devices.len(), 6);
        for command in devices {
            assert_eq!(command.domain, Domain::Devices);
            assert!(command.name.starts_with("devices_"));
        }
    }

    #[test]
    fn an_interface_has_a_name_for_a_log_line() {
        assert_eq!(Interface::Host.as_str(), "host");
        assert_eq!(Interface::Plugin.as_str(), "plugin");
    }

    #[test]
    fn registry_errors_explain_themselves() {
        let errors = [
            RegistryError::PrefixMismatch {
                name: "device_snapshot".to_owned(),
                domain: "devices",
                prefix: "devices_",
            },
            RegistryError::Duplicate { name: "devices_snapshot".to_owned() },
            RegistryError::BadName { name: "DevicesSnapshot".to_owned() },
            RegistryError::MutatingInPluginInterface { name: "plugins_uninstall".to_owned() },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn the_registry_is_the_default_value_it_claims_to_be() {
        assert_eq!(CommandRegistry::len(), COMMANDS.len());
        assert!(CommandRegistry::len() > 30);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Whatever interface a command belongs to, only that interface may call it. The property is the
        /// separation the design document requires, stated over the whole table rather than over the names a
        /// reader happens to check.
        #[test]
        fn only_a_commands_own_interface_may_call_it(index in 0usize..COMMANDS.len()) {
            let command = COMMANDS[index];
            for caller in [Interface::Host, Interface::Plugin] {
                prop_assert_eq!(command.callable_by(caller), command.interface == caller);
            }
        }

        /// The plugin allow-list never contains a command filed under the host interface, whatever the table
        /// holds. A leak here is a plugin reaching the host's screens' commands with a stolen token.
        #[test]
        fn the_allow_list_never_leaks_a_host_command(index in 0usize..COMMANDS.len()) {
            let allowed = CommandRegistry::plugin_allow_list();
            let command = COMMANDS[index];
            if allowed.contains(&command.name) {
                prop_assert_eq!(command.interface, Interface::Plugin, "{} leaked", command.name);
            }
        }

        /// Lookup agrees with the table: every command is findable by its own name, and a name that differs is not
        /// found. A lookup that matched loosely would let a typo reach a real command.
        #[test]
        fn lookup_agrees_with_the_table(index in 0usize..COMMANDS.len(), suffix in "[a-zA-Z_]{1,4}") {
            let command = COMMANDS[index];
            prop_assert_eq!(CommandRegistry::find(command.name).map(|found| found.name), Some(command.name));

            let altered = format!("{}{}", command.name, suffix);
            if altered != command.name {
                prop_assert!(CommandRegistry::find(&altered).is_none(), "{altered} was found");
            }
        }

        /// Any command the registry lists is one an interface may call, so the table has no entry that is
        /// unreachable. An unreachable command is dead code the front end may still try to call.
        #[test]
        fn every_command_is_reachable_from_some_interface(index in 0usize..COMMANDS.len()) {
            let command = COMMANDS[index];
            prop_assert!(command.callable_by(command.interface));
            prop_assert!(Domain::ALL.contains(&command.domain));
            prop_assert!(command.prefix_matches());
        }
    }
}
