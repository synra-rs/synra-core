//! Where a plugin is in its life.

use core::fmt;

use serde::{Deserialize, Serialize};
/// Where a plugin is in its life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state")]
#[non_exhaustive]
pub enum State {
    /// The artifact is on disk and has not been checked.
    ///
    /// The first state, and the only one reached without validation: the manifest has to be read before anything can
    /// be checked, and reading it is what this state means.
    Installed {
        /// The version that was unpacked.
        version: String,
    },
    /// The manifest, the artifacts and the signature have all been checked.
    Validated {
        /// The version.
        version: String,
        /// The digest of the manifest that was checked, which the grants are recorded against.
        manifest_digest: String,
    },
    /// The user has decided on every capability.
    Granted {
        /// The version.
        version: String,
        /// The digest the decision was made against.
        manifest_digest: String,
        /// Whether anything was denied.
        ///
        /// Recorded because a plugin running with some capabilities denied behaves differently from one running with
        /// all of them, and a bug report that does not say which is a bug report about a different plugin.
        partially_denied: bool,
    },
    /// Running.
    Active {
        /// The version.
        version: String,
        /// Whether it is running with fewer capabilities than it asked for.
        partially_denied: bool,
    },
    /// Stopped, but installed and still holding its grants.
    Deactivated {
        /// The version.
        version: String,
    },
    /// Unusable because of a fault.
    ///
    /// Reached from the quota ladder, and from a trap or a timeout the host could not recover from. Distinct from
    /// [`Self::Deactivated`] because the reason matters to the user: a deactivated plugin was stopped, a faulted one
    /// broke.
    Faulted {
        /// The version.
        version: String,
        /// Why, in a sentence the interface can show.
        reason: String,
    },
    /// Nothing loaded, so the plugin may be updated or removed.
    ///
    /// The state the host returns to for an upgrade or an uninstall. Also where a plugin sits after a crash severe
    /// enough that the host will not try again in this session.
    Parked {
        /// The version that was loaded, if any.
        version: Option<String>,
    },
}

impl State {
    /// Which version is loaded, if any.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Installed { version }
            | Self::Validated { version, .. }
            | Self::Granted { version, .. }
            | Self::Active { version, .. }
            | Self::Deactivated { version }
            | Self::Faulted { version, .. } => Some(version),
            Self::Parked { version } => version.as_deref(),
        }
    }

    /// Whether the plugin's code may be executing.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    /// Whether the plugin holds resources a package change would invalidate.
    ///
    /// True for anything that has loaded the module or holds an instance. An upgrade and an uninstall both go
    /// through [`Self::Parked`] first, so this is what says "you cannot do that yet".
    #[must_use]
    pub const fn holds_loaded_code(&self) -> bool {
        matches!(
            self,
            Self::Validated { .. }
                | Self::Granted { .. }
                | Self::Active { .. }
                | Self::Deactivated { .. }
                | Self::Faulted { .. }
        )
    }

    /// Whether the plugin may be activated from here.
    #[must_use]
    pub const fn can_activate(&self) -> bool {
        // Only from `Granted`. A plugin that runs first and asks later is one whose first action was unauthorised,
        // and a faulted plugin staying faulted is what makes the ladder's last rung mean something.
        matches!(self, Self::Granted { .. } | Self::Deactivated { .. })
    }

    /// Whether the plugin may be uninstalled from here.
    ///
    /// Only where nothing has loaded. A `Validated` plugin has had its artifacts resolved and its module read, so
    /// removing the package under it would leave the host holding a description of something that is gone — and the
    /// caller's next step is [`Transition::Park`], which is why this agrees exactly with
    /// `!holds_loaded_code()`.
    #[must_use]
    pub const fn can_uninstall(&self) -> bool {
        !self.holds_loaded_code()
    }

    /// A name for a log line, a metric label or a state column.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Installed { .. } => "installed",
            Self::Validated { .. } => "validated",
            Self::Granted { .. } => "granted",
            Self::Active { .. } => "active",
            Self::Deactivated { .. } => "deactivated",
            Self::Faulted { .. } => "faulted",
            Self::Parked { .. } => "parked",
        }
    }

    /// A sentence for the interface.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Installed { version } => format!("version {version} is installed and not yet checked"),
            Self::Validated { version, .. } => format!("version {version} has been checked"),
            Self::Granted { version, partially_denied, .. } => {
                if *partially_denied {
                    format!("version {version} may run with fewer permissions than it asked for")
                }
                else {
                    format!("version {version} may run")
                }
            }
            Self::Active { version, partially_denied } => {
                if *partially_denied {
                    format!("version {version} is running with fewer permissions than it asked for")
                }
                else {
                    format!("version {version} is running")
                }
            }
            Self::Deactivated { version } => format!("version {version} is stopped"),
            Self::Faulted { version, reason } => format!("version {version} was stopped: {reason}"),
            Self::Parked { version } => match version {
                Some(version) => format!("version {version} is parked and may be replaced"),
                None => "nothing is loaded".to_owned(),
            },
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
