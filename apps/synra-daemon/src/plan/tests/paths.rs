use std::path::{Path, PathBuf};
use synra_store::Paths;
use super::super::{DaemonPlan, DaemonOptions, PlanError, checked_component};

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
        assert!(
            checked_component(name).is_err(),
            "{name:?} should be refused"
        );
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
    let options = DaemonOptions {
        data_dir: named.clone(),
        ..DaemonOptions::default()
    };
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
