use synra_control::{Request, Response};

use crate::args::OutputFormat;

use super::reinstall_with;

fn plugin_entry(id: &str, source: Option<&str>) -> synra_store::PluginEntry {
    synra_store::PluginEntry {
        plugin_id: id.to_owned(),
        version: Some("1.0.0".to_owned()),
        enabled: true,
        source: source.map(ToOwned::to_owned),
        grants: Vec::new(),
    }
}

#[test]
fn a_reinstall_clears_the_restored_row_then_installs_every_recorded_source() {
    // ★ The import restored the database, so the row says installed while the artifact directory is gone. The installer
    // refuses an identifier it believes is already here, which is why the row is removed first — and why this test
    // checks the **order**, not only that both requests happen.
    let entries = vec![
        plugin_entry("@acme/a", Some("/tmp/packages/a.synra")),
        plugin_entry("@acme/b", None),
    ];
    let asked = std::cell::RefCell::new(Vec::new());
    let outcome = reinstall_with(entries, Some(OutputFormat::Text), |request| match request {
        Request::Plugins => {
            asked.borrow_mut().push("list".to_owned());
            Ok(Response::ok(
                serde_json::json!({"plugins": [{"pluginId": "@acme/a"}]}),
            ))
        }
        Request::PluginRemove {
            plugin_id,
            remove_data,
        } => {
            asked
                .borrow_mut()
                .push(format!("remove {plugin_id} data={remove_data}"));
            Ok(Response::ok(serde_json::json!({})))
        }
        Request::PluginInstall { path } => {
            asked.borrow_mut().push(format!("install {path}"));
            Ok(Response::ok(serde_json::json!({"pluginId": "@acme/a"})))
        }
        other => panic!("unexpected request {other:?}"),
    });

    assert_eq!(
        asked.into_inner(),
        vec![
            "list".to_owned(),
            "remove @acme/a data=false".to_owned(),
            "install /tmp/packages/a.synra".to_owned()
        ]
    );
    match outcome {
        crate::session::CommandOutcome::Lines(lines) => {
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("reinstalled @acme/a")),
                "{lines:?}"
            );
            assert!(
                lines.iter().any(|line| line.contains("skipped @acme/b")),
                "the plugin with no origin must be named: {lines:?}"
            );
        }
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn a_reinstall_does_not_remove_a_row_that_is_not_there() {
    // The ordinary first-install case: nothing to clear, and a removal request would be a needless refusal to explain.
    let entries = vec![plugin_entry("@acme/a", Some("/tmp/packages/a.synra"))];
    let asked = std::cell::RefCell::new(Vec::new());
    let outcome = reinstall_with(entries, Some(OutputFormat::Text), |request| match request {
        Request::Plugins => {
            asked.borrow_mut().push("list".to_owned());
            Ok(Response::ok(serde_json::json!({"plugins": []})))
        }
        Request::PluginInstall { path } => {
            asked.borrow_mut().push(format!("install {path}"));
            Ok(Response::ok(serde_json::json!({})))
        }
        other => panic!("unexpected request {other:?}"),
    });

    assert_eq!(
        asked.into_inner(),
        vec![
            "list".to_owned(),
            "install /tmp/packages/a.synra".to_owned()
        ],
        "a plugin that is not installed must not be removed"
    );
    assert!(
        matches!(outcome, crate::session::CommandOutcome::Lines(_)),
        "{outcome:?}"
    );
}

#[test]
fn a_reinstall_restores_the_consent_and_the_switch() {
    // ★ Without the consent list the plugin is installed and unloadable: `load_one` refuses a plugin with no decisions
    // on record. Restoring it — after the install, before the switch — is what makes the restore complete.
    let mut entry = plugin_entry("@acme/a", Some("/tmp/packages/a.synra"));
    entry.grants = vec!["log:*".to_owned()];
    let asked = std::cell::RefCell::new(Vec::new());
    let outcome = reinstall_with(
        vec![entry],
        Some(OutputFormat::Text),
        |request| match request {
            Request::Plugins => Ok(Response::ok(serde_json::json!({"plugins": []}))),
            Request::PluginInstall { path } => {
                asked.borrow_mut().push(format!("install {path}"));
                Ok(Response::ok(serde_json::json!({})))
            }
            Request::PluginConsent { plugin_id, granted } => {
                asked
                    .borrow_mut()
                    .push(format!("consent {plugin_id} [{}]", granted.join(",")));
                Ok(Response::ok(serde_json::json!({})))
            }
            Request::PluginSetEnabled { plugin_id, enabled } => {
                asked
                    .borrow_mut()
                    .push(format!("enable {plugin_id} {enabled}"));
                Ok(Response::ok(serde_json::json!({})))
            }
            other => panic!("unexpected request {other:?}"),
        },
    );

    assert_eq!(
        asked.into_inner(),
        vec![
            "install /tmp/packages/a.synra".to_owned(),
            "consent @acme/a [log:*]".to_owned(),
            "enable @acme/a true".to_owned()
        ]
    );
    assert!(
        matches!(outcome, crate::session::CommandOutcome::Lines(_)),
        "{outcome:?}"
    );
}

#[test]
fn a_reinstall_without_a_consent_list_leaves_the_switch_off() {
    // ★ An old container has no grants. Enabling the plugin would be opening a plugin nobody approved; the honest
    // outcome is installed, consent required, switch off.
    let mut entry = plugin_entry("@acme/a", Some("/tmp/packages/a.synra"));
    entry.grants = Vec::new();
    entry.enabled = true;
    let asked = std::cell::RefCell::new(Vec::new());
    let outcome = reinstall_with(
        vec![entry],
        Some(OutputFormat::Text),
        |request| match request {
            Request::Plugins => Ok(Response::ok(serde_json::json!({"plugins": []}))),
            Request::PluginInstall { path } => {
                asked.borrow_mut().push(format!("install {path}"));
                Ok(Response::ok(serde_json::json!({})))
            }
            Request::PluginConsent { .. } | Request::PluginSetEnabled { .. } => {
                panic!("a plugin with no recorded consent must not be approved or enabled");
            }
            other => panic!("unexpected request {other:?}"),
        },
    );
    assert_eq!(
        asked.into_inner(),
        vec!["install /tmp/packages/a.synra".to_owned()]
    );
    assert!(
        matches!(outcome, crate::session::CommandOutcome::Lines(_)),
        "{outcome:?}"
    );
}

#[test]
fn a_failed_consent_removes_the_partial_install() {
    // ★ Installed but unapproved is the worst of the two halves: the plugin is on disk and listed, and the loader will
    // refuse it. The failure takes it back out, and the sentence says that it did.
    let mut entry = plugin_entry("@acme/a", Some("/tmp/packages/a.synra"));
    entry.grants = vec!["log:*".to_owned()];
    let asked = std::cell::RefCell::new(Vec::new());
    let outcome = reinstall_with(
        vec![entry],
        Some(OutputFormat::Text),
        |request| match request {
            Request::Plugins => Ok(Response::ok(serde_json::json!({"plugins": []}))),
            Request::PluginInstall { path } => {
                asked.borrow_mut().push(format!("install {path}"));
                Ok(Response::ok(serde_json::json!({})))
            }
            Request::PluginConsent { .. } => {
                asked.borrow_mut().push("consent".to_owned());
                Ok(Response::failed(
                    "consent",
                    "the consent could not be recorded",
                    false,
                ))
            }
            Request::PluginRemove { plugin_id, .. } => {
                asked.borrow_mut().push(format!("remove {plugin_id}"));
                Ok(Response::ok(serde_json::json!({})))
            }
            other => panic!("unexpected request {other:?}"),
        },
    );

    assert_eq!(
        asked.into_inner(),
        vec![
            "install /tmp/packages/a.synra".to_owned(),
            "consent".to_owned(),
            "remove @acme/a".to_owned()
        ]
    );
    match outcome {
        crate::session::CommandOutcome::Failed(message) => {
            assert!(
                message.contains("consent could not be restored"),
                "{message}"
            );
            assert!(message.contains("partial install was removed"), "{message}");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}

#[test]
fn a_refused_reinstall_stops_and_names_the_plugin() {
    // ★ The kernel's refusal is about one package; reporting it as "@acme/a could not be reinstalled: …" is what lets
    // the user fix the package rather than the whole sequence.
    let entries = vec![plugin_entry("@acme/a", Some("/tmp/packages/a.synra"))];
    let outcome = reinstall_with(entries, Some(OutputFormat::Text), |request| match request {
        Request::Plugins => Ok(Response::ok(serde_json::json!({"plugins": []}))),
        _ => Ok(Response::failed(
            "consent",
            "the plugin needs consent",
            false,
        )),
    });
    match outcome {
        crate::session::CommandOutcome::Failed(message) => {
            assert!(message.contains("@acme/a"), "{message}");
            assert!(message.contains("needs consent"), "{message}");
        }
        other => panic!("expected a failure, got {other:?}"),
    }
}
