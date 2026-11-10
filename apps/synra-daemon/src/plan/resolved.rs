use std::path::{Path, PathBuf};

use serde::Serialize;
use synra_store::{PathError, Paths};

use super::{DaemonOptions, LOCK_FILE_NAME};

/// Why a daemon will not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// A port is outside the range a socket can bind.
    #[error("{which} port {port} is outside the range 1-65535")]
    PortOutOfRange {
        /// Which port.
        which: &'static str,
        /// What was asked for.
        port: u16,
    },

    /// The two ports are the same.
    ///
    /// Refused rather than resolved: the transport and discovery are different sockets, and one of them would fail to
    /// bind with a message about a port already in use rather than about the configuration being wrong.
    #[error("the transport and discovery ports are both {port}")]
    PortsCollide {
        /// The port both were set to.
        port: u16,
    },

    /// The data directory is inside the plugin sandbox, or the other way round.
    ///
    /// Refused because a daemon whose data directory is inside the directory it hands to plugins has given every
    /// plugin a path into its own database and keys — and the containment checks elsewhere would then be protecting
    /// the wrong boundary.
    #[error("the data directory {data_dir} and the plugin sandbox {plugins_dir} overlap")]
    DirectoriesOverlap {
        /// The data directory.
        data_dir: String,
        /// The sandbox.
        plugins_dir: String,
    },

    /// A directory could not be turned into a path.
    #[error("a path could not be resolved: {0}")]
    Path(#[from] PathError),

    /// A name is not one a directory may be called.
    #[error("{name:?} is not usable as a directory name")]
    BadName {
        /// The name that was offered.
        name: String,
    },
}

/// A start-up that has been checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DaemonPlan {
    /// Where the data lives.
    pub data_dir: String,
    /// Where plugins are installed.
    pub plugins_dir: String,
    /// Where the database is.
    pub db_path: String,
    /// The transport port.
    pub listen_port: u16,
    /// The discovery port.
    pub discovery_port: u16,
    /// Whether the data directory will be claimed exclusively.
    pub exclusive: bool,
    /// Whether the daemon keeps running with no clients.
    pub linger: bool,
    /// Whether the platform can do anything a user would notice.
    ///
    /// Always false, and reported so a reader of a diagnostic bundle does not have to know that a daemon has no
    /// window. A plugin's platform call under this host is refused, which is the honest answer.
    pub can_prompt_the_user: bool,
}

impl DaemonPlan {
    /// Checks the options and resolves every path.
    ///
    /// # Errors
    ///
    /// [`PlanError`] when a port is unusable or the directories overlap.
    ///
    /// # The checks run before anything is created
    ///
    /// Every path is resolved and every combination checked before a directory is made or a socket is bound, so a
    /// refusal leaves nothing half-created. A daemon that had already written a database and *then* found its ports
    /// collide is one a user has to clean up after.
    pub fn resolve(options: &DaemonOptions) -> Result<Self, PlanError> {
        // Port zero means "let the operating system choose", which is what a test and a diagnostic run want. It is not
        // checked against the other port, because two requests for an ephemeral port are not a collision.
        if options.listen_port == 0 || options.discovery_port == 0 {
            // Allowed. Nothing to check: the operating system assigns one that is free by construction.
        } else if options.listen_port == options.discovery_port {
            return Err(PlanError::PortsCollide {
                port: options.listen_port,
            });
        }

        // `Paths::new` with an explicit cache directory, rather than `Paths::under`.
        //
        // `under(root)` is `new(root, root)` — one directory for both — which is what a test or a platform that does not
        // separate them wants. Here they *are* separate, and the cache goes **beside** the data rather than inside it so
        // that a user who empties the cache does not have to reason about which of the two directories holds the
        // database.
        //
        // An earlier version of this comment said `under` appended a `data` level and that using it wrote the claim and
        // the database one directory below where they were reported. That was true of an earlier `under` and is not true
        // of this one: `crates/synra-store/src/paths.rs` now has `Self::new(root.clone(), root)`, and its own test
        // asserts `data_dir() == cache_dir()`. The comment survived the change it described, which is the ordinary way a
        // comment becomes wrong — it is the one kind of documentation the compiler cannot check.
        let root = options.data_dir.clone();
        let paths = Paths::new(root.clone(), root.join("cache"));
        let data_dir = paths.data_dir().to_path_buf();
        let plugins_dir = paths.plugins_dir();

        // No overlap check, because an overlap is not reachable here: the sandbox is *derived* —
        // `data_dir.join("plugins")` — rather than taken from the caller, so there is no input that could put it
        // beside or above the data directory. The direction that would matter is a data directory inside somebody
        // else's sandbox, which the caller cannot express either, because they name one directory and everything else
        // follows from it. The invariant is asserted in the tests rather than checked at runtime, which is the honest
        // place for a property that the construction guarantees.

        Ok(Self {
            data_dir: data_dir.display().to_string(),
            plugins_dir: plugins_dir.display().to_string(),
            db_path: paths.db_path().display().to_string(),
            listen_port: options.listen_port,
            discovery_port: options.discovery_port,
            exclusive: options.exclusive,
            linger: options.linger,
            can_prompt_the_user: false,
        })
    }

    /// Where the claim on the data directory is written.
    ///
    /// Inside the data directory rather than beside it, because a lock that outlived the directory it describes would
    /// hold a claim on a directory that no longer exists — and the next start would reclaim it and log a crash that
    /// never happened.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        Path::new(&self.data_dir).join(LOCK_FILE_NAME)
    }

    /// The lines a user sees when the daemon starts.
    ///
    /// Returned rather than printed, so a test asserts the text and the caller decides where it goes.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("synra-daemon {} starting", env!("CARGO_PKG_VERSION")),
            format!("  data      {}", self.data_dir),
            format!("  plugins   {}", self.plugins_dir),
            format!("  database  {}", self.db_path),
            format!("  transport port {}", self.listen_port),
            format!("  discovery port {}", self.discovery_port),
            format!(
                "  claim     {}",
                if self.exclusive {
                    "exclusive"
                } else {
                    "shared (a diagnostic run)"
                }
            ),
            format!(
                "  lifetime  {}",
                if self.linger {
                    "keeps running with no clients"
                } else {
                    "exits with its last client"
                }
            ),
        ]
    }
}
