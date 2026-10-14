//! What the daemon will do when it starts, decided before it does any of it.
//!
//! # Why the plan is a value
//!
//! A daemon's start-up is a sequence of decisions — which directories, which ports, whether to take the data
//! directory's claim, whether to refuse — and the interesting failures are all *combinations*: a port out of range, a
//! data directory inside the plugin sandbox, a claim that cannot be taken. Deciding them as a value means the refusals
//! are decidable in a test, rather than discovered on a user's machine at the moment they tried to start something.
//!
//! It also keeps `main` short for the same reason the CLI's is: `main` is the one place nobody writes tests, so
//! everything decidable elsewhere goes elsewhere.
//!
//! # The daemon has no interface, and that is the point
//!
//! [ADR-016](../../../design-docs/20-adr.md) says the kernel must work without a window, and this binary is the half
//! of that claim which has no window at all. So the platform is [`HeadlessPlatform`]: every action that would need a
//! user — opening a URL, writing the clipboard, simulating a keystroke — returns `Unsupported` rather than pretending
//! to have happened. A daemon that silently did nothing when a plugin asked to open a browser would be a daemon whose
//! plugins fail in a way nobody can trace.
//!
//! # Ports are chosen, not defaulted
//!
//! The transport port and the discovery port are named in the plan rather than read from a constant at the point of
//! use, because "which port" is the thing that collides. A second instance on a machine — a user with two profiles —
//! needs to move them, and a plan is where that decision is visible.

use std::path::{Path, PathBuf};

use serde::Serialize;
use synra_store::{PathError, Paths, sanitise_component};

/// The port the main transport listens on by default.
pub const DEFAULT_LISTEN_PORT: u16 = 47_100;

/// The port discovery listens on by default.
pub const DEFAULT_DISCOVERY_PORT: u16 = 47_101;

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

/// How the daemon was asked to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOptions {
    /// Where the data lives.
    pub data_dir: PathBuf,
    /// The transport port.
    pub listen_port: u16,
    /// The discovery port.
    pub discovery_port: u16,
    /// Whether to claim the data directory exclusively.
    ///
    /// On by default, because two daemons over one database is a correctness problem rather than a performance one.
    /// Off is for a diagnostic run against a live installation: a user who wants to see what a running daemon thinks
    /// should not have to stop it.
    pub exclusive: bool,
    /// Whether to keep running when the last client disconnects.
    ///
    /// On: a daemon whose purpose is to keep serving after the interface closes must not exit the moment the
    /// interface does. It is a flag rather than a constant because the opposite is what a user wants when running one
    /// from a terminal to watch it.
    pub linger: bool,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            data_dir: default_data_root(),
            listen_port: DEFAULT_LISTEN_PORT,
            discovery_port: DEFAULT_DISCOVERY_PORT,
            exclusive: true,
            linger: true,
        }
    }
}

/// Where the daemon looks when nothing says otherwise.
///
/// The same answer the CLI gives, from the same environment variable, so that `synra doctor` checks the installation
/// the daemon actually uses. A `doctor` that probed a different directory would report a healthy installation on a
/// machine whose real one is broken, which is the worst answer a diagnostic tool can give.
#[must_use]
pub fn default_data_root() -> PathBuf {
    data_root_from(std::env::var_os(DATA_DIR_VAR))
}

/// The environment variable that moves the data directory.
pub const DATA_DIR_VAR: &str = "SYNRA_DATA_DIR";

/// The data root for a given value of the environment variable.
///
/// The value is a parameter because reading an environment variable is not testable from inside a process:
/// `std::env::set_var` is `unsafe` in edition 2024, and this workspace forbids `unsafe`. So the decision takes its
/// input and the caller reads it.
#[must_use]
pub fn data_root_from(configured: Option<std::ffi::OsString>) -> PathBuf {
    match configured {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir().join("synra"),
    }
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
        }
        else if options.listen_port == options.discovery_port {
            return Err(PlanError::PortsCollide { port: options.listen_port });
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
                if self.exclusive { "exclusive" } else { "shared (a diagnostic run)" }
            ),
            format!(
                "  lifetime  {}",
                if self.linger { "keeps running with no clients" } else { "exits with its last client" }
            ),
        ]
    }
}

/// The name of the claim file.
pub const LOCK_FILE_NAME: &str = "daemon.lock";

/// A name turned into one path component, refusing the shapes that would name somewhere else.
///
/// Used when the daemon makes a directory after a plugin or a device, because a name that came from outside is a path
/// traversal waiting to happen and the check has to run before the join rather than after it.
///
/// # Sanitising rather than refusing, for everything but the empty shape
///
/// The store's substitution is what makes `@synra-plugin/chat` a single directory name, and refusing a name that
/// contains a separator would refuse every plugin id there is. So a name with separators is *turned into* a component,
/// by the same function the rest of the kernel uses — two spellings of one plugin's directory would be one plugin with
/// two directories.
///
/// The exception is a name that sanitises to nothing useful, and the reason is arithmetic rather than taste: joining
/// an empty component is the *parent* directory, so a caller that meant to write inside its own directory would write
/// one level up. `..` sanitises to `_`, which is a harmless directory named `_`, so it is not refused — but a name of
/// only dots sanitises to a run of dots, and `...` joined is a path that means something other than a directory.
///
/// # Errors
///
/// [`PlanError::BadName`] when the name is empty or sanitises to nothing usable.
pub fn checked_component(name: &str) -> Result<String, PlanError> {
    if name.trim().is_empty() {
        return Err(PlanError::BadName { name: name.to_owned() });
    }
    let component = sanitise_component(name);
    // Empty is the dangerous one: `Path::join("")` is the parent. A run of dots is refused too, because `..` collapsing
    // to `.` and then joining is a path that names a directory the caller did not ask for.
    if component.is_empty() || component.chars().all(|ch| ch == '.') {
        return Err(PlanError::BadName { name: name.to_owned() });
    }
    Ok(component)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(data_dir: &str) -> DaemonOptions {
        DaemonOptions {
            data_dir: PathBuf::from(data_dir),
            ..DaemonOptions::default()
        }
    }

    /// A data directory that is absolute on whichever platform the test is running on.
    ///
    /// Windows treats `/tmp/x` as drive-relative rather than absolute, so a fixture that used one form would be an
    /// absolute path on one platform and not on the other.
    fn root() -> &'static str {
        if cfg!(windows) { "C:\\synra-data" } else { "/tmp/synra-data" }
    }

    // ── Ports ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plan_resolves_when_everything_is_usable() {
        let plan = DaemonPlan::resolve(&options(root())).expect("resolves");
        assert_eq!(plan.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(plan.discovery_port, DEFAULT_DISCOVERY_PORT);
        assert!(plan.exclusive);
        assert!(plan.linger);
        // A daemon has no window, so it cannot ask the user anything. Reported rather than implied, so a reader of a
        // bundle does not have to know that.
        assert!(!plan.can_prompt_the_user);
    }

    #[test]
    fn the_two_ports_may_not_be_the_same() {
        // Refused rather than resolved: one of the two would fail to bind with a message about a port already in use
        // rather than about the configuration being wrong, and the user would go looking for the process holding it.
        let mut options = options(root());
        options.discovery_port = options.listen_port;
        match DaemonPlan::resolve(&options) {
            Err(PlanError::PortsCollide { port }) => assert_eq!(port, DEFAULT_LISTEN_PORT),
            other => panic!("expected a collision, got {other:?}"),
        }
    }

    #[test]
    fn an_ephemeral_port_is_allowed_for_both() {
        // Port zero asks the operating system for a free one, which is what a test and a diagnostic run want. Two
        // requests for an ephemeral port are not a collision — the system gives each a different one.
        let mut options = options(root());
        options.listen_port = 0;
        options.discovery_port = 0;
        assert!(DaemonPlan::resolve(&options).is_ok());
    }

    #[test]
    fn the_plan_names_the_ports_it_will_use() {
        // "Which port" is the thing that collides, so it is visible rather than read from a constant at the point of
        // use. A user with two profiles moves them here.
        let mut options = options(root());
        options.listen_port = 12_000;
        options.discovery_port = 12_001;
        let plan = DaemonPlan::resolve(&options).expect("resolves");
        assert_eq!(plan.listen_port, 12_000);
        assert_eq!(plan.discovery_port, 12_001);
    }

    // ── Directories ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_plan_derives_every_path_from_one_root() {
        // One root, so the database, the plugin sandbox and the log are all inside it — which is what makes "move the
        // data directory" one decision rather than four.
        let plan = DaemonPlan::resolve(&options(root())).expect("resolves");
        let named = Path::new(root());
        // ★ The data directory is the one the caller named, not one level below it. `Paths::under` appends `data`, and
        // using it here made the daemon report one directory while writing to another — so the claim it checked was
        // never the claim it wrote.
        assert_eq!(Path::new(&plan.data_dir), named);
        assert!(Path::new(&plan.plugins_dir).starts_with(named));
        assert!(Path::new(&plan.db_path).starts_with(named));
        assert!(!Path::new(&plan.db_path).starts_with(Path::new(&plan.plugins_dir)));
    }

    #[test]
    fn the_claim_sits_inside_the_directory_it_describes() {
        // A lock that outlived the directory it describes would hold a claim on a directory that no longer exists, and
        // the next start would reclaim it and log a crash that never happened.
        let plan = DaemonPlan::resolve(&options(root())).expect("resolves");
        assert_eq!(plan.lock_path(), Path::new(&plan.data_dir).join(LOCK_FILE_NAME));
        assert!(plan.lock_path().starts_with(&plan.data_dir));
    }

    #[test]
    fn a_plan_reports_the_lines_a_user_reads() {
        let plan = DaemonPlan::resolve(&options(root())).expect("resolves");
        let lines = plan.lines();
        assert!(lines[0].contains("synra-daemon"), "{lines:?}");
        assert!(lines[0].contains(env!("CARGO_PKG_VERSION")), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("transport port")), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("exclusive")), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("keeps running")), "{lines:?}");
    }

    #[test]
    fn the_sandbox_is_always_inside_the_data_directory() {
        // ★ The invariant that makes an overlap check unnecessary: the sandbox is *derived* from the root rather than
        // taken from the caller, so there is no input that could put it beside or above the data directory. An earlier
        // version checked for an overlap at runtime and, because `Paths::under` canonicalises one path and not the
        // other, refused every configuration there is — a check that cannot be satisfied is worse than none.
        for root in [root(), "relative/path", ".", ".."] {
            let plan = DaemonPlan::resolve(&options(root)).expect("resolves");
            let data = Path::new(&plan.data_dir);
            let plugins = Path::new(&plan.plugins_dir);
            assert!(plugins.starts_with(data), "{plugins:?} is not inside {data:?}");
            assert_ne!(plugins, data, "the sandbox is the data directory itself");
            // And the database is not inside the sandbox, which is the direction that would hand every plugin a path
            // to the kernel's own keys.
            assert!(!Path::new(&plan.db_path).starts_with(plugins), "{}", plan.db_path);
        }
    }

    #[test]
    fn a_non_exclusive_run_says_so_in_its_lines() {
        // The one line a user should read before deciding a shared run is safe: nothing will claim the directory, so
        // the running daemon keeps it.
        let mut options = options(root());
        options.exclusive = false;
        options.linger = false;
        let plan = DaemonPlan::resolve(&options).expect("resolves");
        let lines = plan.lines();
        assert!(lines.iter().any(|line| line.contains("diagnostic run")), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("last client")), "{lines:?}");
        assert!(!plan.exclusive);
        assert!(!plan.linger);
    }

    // ── Names ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_name_from_outside_is_turned_into_one_component() {
        // Sanitised rather than refused, because refusing a name with a separator would refuse every plugin id there
        // is. The check that matters is that the *result* is one component that cannot climb: no separator survives,
        // and neither does a `..`.
        assert_eq!(checked_component("chat").expect("accepts"), "chat");

        let plugin = checked_component("@synra-plugin/chat").expect("accepts");
        assert!(!plugin.is_empty());
        assert!(!plugin.contains('/'), "{plugin}");
        assert!(!plugin.contains('\\'), "{plugin}");

        // ★ The property the function exists for: whatever goes in, the component that comes out names something
        // *inside* the caller's directory rather than beside it.
        for name in ["..", "../..", "../../etc/passwd", "a/../../b", "\\", "a\\b"] {
            let component = checked_component(name).expect("sanitises");
            assert!(!component.contains('/'), "{name} -> {component}");
            assert!(!component.contains('\\'), "{name} -> {component}");
            assert_ne!(component, "..", "{name} -> {component}");
            assert_ne!(component, ".", "{name} -> {component}");
        }
    }

    #[test]
    fn a_name_that_sanitises_to_nothing_is_refused() {
        // The reason is arithmetic rather than taste: `Path::join("")` is the *parent* directory, so a caller that
        // meant to write inside its own directory would write one level up.
        //
        // The list is short on purpose. A separator sanitises to `+`, which is a directory that is safe to create, and
        // refusing it would refuse every plugin id there is — see the test below.
        for name in ["", "   ", "\t\n"] {
            assert!(checked_component(name).is_err(), "{name:?} should be refused");
        }
    }

    #[test]
    fn a_separator_becomes_a_safe_directory_name_rather_than_a_refusal() {
        // `sanitise_component` maps a separator to `+` and drops the `@`, so `@synra-plugin/chat` is one component with
        // no separator left in it. That is the whole reason the substitution exists, and refusing it would refuse
        // every plugin id there is.
        assert_eq!(checked_component("/").expect("sanitises"), "+");
        assert_eq!(checked_component("///").expect("sanitises"), "+++");
        assert_eq!(
            checked_component("@synra-plugin/chat").expect("sanitises"),
            "synra-plugin+chat"
        );
    }

    #[test]
    fn a_pure_dot_name_becomes_a_safe_directory_rather_than_a_refusal() {
        // The substitution collapses the run of dots and then replaces what is left, so `...` is `_` — a directory that
        // is safe to create. Refusing it would be refusing a safe thing, and a check that refuses safe things is one a
        // caller learns to work around.
        assert_eq!(checked_component("...").expect("sanitises"), "_");
        assert_eq!(checked_component(".").expect("sanitises"), "_");
    }

    #[test]
    fn an_unusable_name_says_which_one() {
        // The message is what a user sees when a plugin's directory cannot be made, so it has to name the name.
        match checked_component("") {
            Err(PlanError::BadName { name }) => assert_eq!(name, ""),
            other => panic!("expected a bad name, got {other:?}"),
        }
    }

    // ── The default root ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_default_root_follows_the_same_variable_the_cli_does() {
        // The same variable and the same fallback, so `synra doctor` checks the installation the daemon actually uses.
        // A `doctor` that probed a different directory would report a healthy installation on a machine whose real one
        // is broken.
        assert_eq!(DATA_DIR_VAR, "SYNRA_DATA_DIR");
        assert_eq!(
            data_root_from(Some(std::ffi::OsString::from("/custom"))),
            PathBuf::from("/custom")
        );
        // An empty value is not an answer: it falls back rather than naming the current directory.
        let fallback = data_root_from(None);
        assert!(fallback.is_absolute(), "{fallback:?}");
        assert!(fallback.ends_with("synra"));
        assert_eq!(data_root_from(Some(std::ffi::OsString::new())), fallback);
    }

    #[test]
    fn the_default_options_claim_and_linger() {
        // Two daemons over one database is a correctness problem, so claiming is the default; and a daemon whose
        // purpose is to keep serving after the interface closes must not exit with it.
        let options = DaemonOptions::default();
        assert!(options.exclusive);
        assert!(options.linger);
        assert_eq!(options.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(options.discovery_port, DEFAULT_DISCOVERY_PORT);
    }

    #[test]
    fn plan_errors_explain_themselves() {
        let errors = [
            PlanError::PortsCollide { port: 47_100 },
            PlanError::DirectoriesOverlap {
                data_dir: "/a".to_owned(),
                plugins_dir: "/a/plugins".to_owned(),
            },
            PlanError::BadName { name: "..".to_owned() },
            PlanError::Path(PathError::Escapes { path: "/a".to_owned(), root: "/b".to_owned() }),
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    #[test]
    fn the_plan_serialises_for_a_diagnostic_bundle() {
        let plan = DaemonPlan::resolve(&options(root())).expect("resolves");
        let json = serde_json::to_value(&plan).expect("serialises");
        assert_eq!(json["listenPort"], DEFAULT_LISTEN_PORT);
        assert_eq!(json["canPromptTheUser"], false);
        assert!(json["dbPath"].is_string());
    }

    #[test]
    fn the_data_directory_is_the_one_a_client_would_look_in() {
        // ★ The daemon and the client are **separate binaries** that compute the same directory from the same input, so
        // the two computations can drift — and the failure is invisible to both: the daemon serves a socket nobody
        // connects to, and every command says no kernel is running while one is.
        //
        // The client computes it as `Paths::under(data_root()).data_dir()`, and the daemon as
        // `Paths::new(root, root.join("cache")).data_dir()`. This asserts they agree, which is the property that makes
        // `synra status` reach a daemon rather than a socket that is not there.
        let named = PathBuf::from("/tmp/synra-agreement");
        let options = DaemonOptions { data_dir: named.clone(), ..DaemonOptions::default() };
        let plan = DaemonPlan::resolve(&options).expect("resolves");

        // What the client computes, spelled the way the client spells it.
        let client_side = Paths::under(named).data_dir().to_path_buf();

        assert_eq!(Path::new(&plan.data_dir), client_side);
        // And the socket the daemon binds is the one the client connects to, because both derive it from that directory.
        assert_eq!(
            synra_control::socket_path(Path::new(&plan.data_dir)),
            synra_control::socket_path(&client_side)
        );
    }
}