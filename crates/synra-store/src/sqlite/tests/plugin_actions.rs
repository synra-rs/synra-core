use super::migrated;

#[test]
fn removing_a_plugin_takes_its_decisions_with_it() {
    // ★ Two deletes, one transaction. A grant recorded against a plugin that no longer exists is not history worth
    // keeping — plugin_grants is the current state — and the row left behind would let a reinstall inherit consent
    // nobody gave about the new package. The assertion is that both tables agree afterwards, not just the one.

    let mut db = migrated();
    let plugin = "@acme/removable";
    db.insert_plugin(plugin, true, true, "installed", 1, 1).expect("a row");
    db.record_grants(plugin, &[("log:*".to_owned(), true)], 2, "digest").expect("a decision");
    assert_eq!(db.plugin_grants(plugin).expect("decisions").len(), 1);

    assert!(db.remove_plugin(plugin).expect("removed"), "a row was there");

    assert!(!db.plugin_is_installed(plugin).expect("the table"), "no row");
    assert!(db.plugin_grants(plugin).expect("decisions").is_empty(), "and no decisions either");
    // A second removal answers honestly rather than claiming a success.
    assert!(!db.remove_plugin(plugin).expect("removed"), "nothing was there");
}

#[test]
fn an_action_is_replaced_rather_than_repeated() {
    // ★ A plugin declares its actions each time it activates. The second declaration of one name is the same action
    // with a possibly newer schema — an upsert. An insert would make the declaration path work once and fail on every
    // restart, which is the shape of a bug that only appears after a restart.
    let db = migrated();
    let plugin = "@acme/actionful";
    db.insert_plugin(plugin, true, true, "installed", 1, 1).expect("a row");

    db.record_plugin_action(plugin, "send", Some(r#"{"type":"object"}"#), Some("Send a message"))
        .expect("declared");
    db.record_plugin_action(plugin, "send", Some(r#"{"type":"object","required":["to"]}"#), None)
        .expect("declared again");

    let actions = db.plugin_actions(plugin).expect("actions");
    assert_eq!(actions.len(), 1, "a redeclaration added a row: {actions:?}");
    assert_eq!(actions[0].name, "send");
    assert_eq!(actions[0].args_schema.as_deref(), Some(r#"{"type":"object","required":["to"]}"#));
    // The new declaration said nothing about a description, so there is none: keeping the old sentence would attribute
    // it to a schema it never described.
    assert_eq!(actions[0].description, None);
}

#[test]
fn actions_are_ordered_and_scoped_to_their_plugin() {
    let db = migrated();
    for plugin in ["@acme/one", "@acme/two"] {
        db.insert_plugin(plugin, true, true, "installed", 1, 1).expect("a row");
    }
    db.record_plugin_action("@acme/one", "zeta", None, None).expect("zeta");
    db.record_plugin_action("@acme/one", "alpha", None, None).expect("alpha");
    db.record_plugin_action("@acme/two", "other", None, None).expect("other");

    let one: Vec<String> = db
        .plugin_actions("@acme/one")
        .expect("actions")
        .into_iter()
        .map(|action| action.name)
        .collect();
    assert_eq!(one, vec!["alpha".to_owned(), "zeta".to_owned()], "not sorted: {one:?}");
    assert_eq!(db.plugin_actions("@acme/two").expect("actions").len(), 1, "scoped by plugin");
}

#[test]
fn an_action_cannot_outlive_its_plugin() {
    // The foreign key is the enforcement, and it is the right one: a page's `self.invoke` checks the action belongs to
    // the plugin, so an action row for a plugin that is not installed would be a name that resolves to nothing.
    let db = migrated();

    let refused = db.record_plugin_action("@acme/absent", "send", None, None);

    assert!(refused.is_err(), "an action was recorded for a plugin nobody installed");
}
