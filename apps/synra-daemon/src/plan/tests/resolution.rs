use std::path::Path;
use super::super::{DaemonPlan, PlanError, DEFAULT_DISCOVERY_PORT, DEFAULT_LISTEN_PORT, LOCK_FILE_NAME};
use super::{options, root};

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
    assert_eq!(
        plan.lock_path(),
        Path::new(&plan.data_dir).join(LOCK_FILE_NAME)
    );
    assert!(plan.lock_path().starts_with(&plan.data_dir));
}

#[test]
fn a_plan_reports_the_lines_a_user_reads() {
    let plan = DaemonPlan::resolve(&options(root())).expect("resolves");
    let lines = plan.lines();
    assert!(lines[0].contains("synra-daemon"), "{lines:?}");
    assert!(lines[0].contains(env!("CARGO_PKG_VERSION")), "{lines:?}");
    assert!(
        lines.iter().any(|line| line.contains("transport port")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("exclusive")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("keeps running")),
        "{lines:?}"
    );
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
        assert!(
            plugins.starts_with(data),
            "{plugins:?} is not inside {data:?}"
        );
        assert_ne!(plugins, data, "the sandbox is the data directory itself");
        // And the database is not inside the sandbox, which is the direction that would hand every plugin a path
        // to the kernel's own keys.
        assert!(
            !Path::new(&plan.db_path).starts_with(plugins),
            "{}",
            plan.db_path
        );
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
    assert!(
        lines.iter().any(|line| line.contains("diagnostic run")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("last client")),
        "{lines:?}"
    );
    assert!(!plan.exclusive);
    assert!(!plan.linger);
}

#[test]
fn the_plan_serialises_for_a_diagnostic_bundle() {
    let plan = DaemonPlan::resolve(&options(root())).expect("resolves");
    let json = serde_json::to_value(&plan).expect("serialises");
    assert_eq!(json["listenPort"], DEFAULT_LISTEN_PORT);
    assert_eq!(json["canPromptTheUser"], false);
    assert!(json["dbPath"].is_string());
}
