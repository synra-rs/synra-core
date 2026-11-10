use super::{COMMANDS, CommandDescriptor, Domain, Interface};

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
        COMMANDS
            .iter()
            .filter(|command| command.domain == domain)
            .collect()
    }

    /// Every command an interface may call.
    #[must_use]
    pub fn for_interface(interface: Interface) -> Vec<&'static CommandDescriptor> {
        COMMANDS
            .iter()
            .filter(|command| command.interface == interface)
            .collect()
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
                return Err(RegistryError::Duplicate {
                    name: command.name.to_owned(),
                });
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
                return Err(RegistryError::BadName {
                    name: command.name.to_owned(),
                });
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
pub(super) fn is_snake_case_with_one_separator(name: &str) -> bool {
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
