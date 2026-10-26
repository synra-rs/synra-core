//! The manifest's tests.
//!
//! # Why the case-by-case tests are separate from the property tests
//!
//! Because they assert different things. These name a case and its expected refusal; `proptests` assert a property over
//! generated input. A reader asking "what does a version comparison guarantee" should not have to pass a hundred
//! case-by-case tests to find it.

use rstest::rstest;

use synra_capability::Capability;
use synra_protocol::PluginId;

use super::error::ManifestError;
use super::types::*;
use super::version::*;

/// A minimal manifest that passes every check, so a test can change one thing.
    const MINIMAL: &str = r#"{
        "id": "@synra-plugin/chat",
        "version": "1.0.0",
        "title": "Chat",
        "publisher": { "id": "synra-official" },
        "sdk": { "min": "1.0.0" },
        "wit": "synra:plugin@1.0.0",
        "runtime": { "headless": { "artifact": "dist/plugin.wasm", "stateful": false } },
        "capabilities": [{ "cap": "log:*" }]
    }"#;

    fn parse(text: &str) -> Manifest {
        Manifest::from_json(text).expect("the fixture parses")
    }

    fn minimal() -> Manifest {
        parse(MINIMAL)
    }

    // ── Parsing ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_minimal_manifest_parses_and_validates() {
        let manifest = minimal();
        assert_eq!(manifest.id.as_str(), "@synra-plugin/chat");
        assert_eq!(manifest.title, "Chat");
        assert_eq!(manifest.validate(ValidationLevel::Schema, &ManifestContext::default()), Ok(()));
        assert!(manifest.is_headless());
        assert!(!manifest.has_ui());
        assert!(!manifest.is_hybrid());
    }

    #[test]
    fn a_legacy_capability_spelling_is_corrected_when_the_manifest_is_read() {
        // ★ The contract has always checked `platform:read-clipboard`, and this workspace's documentation used
        // `platform:clipboard:read`. A manifest written from the documentation therefore asked for a permission that
        // could never authorise anything. Correcting at the boundary means everything after this point — the consent
        // prompt, the grant row, the gate — sees one name.
        let manifest = parse(&MINIMAL.replace(r#""log:*""#, r#""platform:clipboard:read""#));

        assert_eq!(manifest.capabilities[0].cap, "platform:read-clipboard");

        // And an ordinary capability is untouched: this is a correction table, not a rewriting of the vocabulary.
        let untouched = parse(&MINIMAL.replace(r#""log:*""#, r#""network:fetch:api.example.com""#));
        assert_eq!(untouched.capabilities[0].cap, "network:fetch:api.example.com");
    }

    #[test]
    fn the_schema_field_is_normalised_and_an_unknown_one_is_refused() {
        let manifest = minimal();
        assert_eq!(manifest.schema.as_deref(), Some(MANIFEST_SCHEMA));

        // A manifest naming a schema this build does not know may have fields whose meaning changed, and the
        // unknown-field rule would not catch a field that kept its name.
        let wrong = MINIMAL.replace("\"id\":", "\"$schema\": \"https://example.com/v9.json\", \"id\":");
        assert!(matches!(Manifest::from_json(&wrong), Err(ManifestError::Malformed(_))));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // A field the host silently ignores is a field whose author believes it does something.
        let text = MINIMAL.replace("\"title\": \"Chat\",", "\"title\": \"Chat\", \"mystery\": true,");
        assert!(matches!(Manifest::from_json(&text), Err(ManifestError::Malformed(_))));
    }

    #[test]
    fn a_missing_required_field_is_refused() {
        for field in ["\"id\": \"@synra-plugin/chat\",", "\"version\": \"1.0.0\",", "\"capabilities\": [{ \"cap\": \"log:*\" }]"] {
            let text = MINIMAL.replace(field, "");
            assert!(Manifest::from_json(&text).is_err(), "removing {field} should fail");
        }
    }

    #[test]
    fn capabilities_may_be_an_empty_list_but_the_field_must_be_present() {
        // A missing field and an empty list are different statements — "the author forgot" and "this plugin
        // needs nothing" — and the loader has to be able to tell them apart.
        let empty = MINIMAL.replace("\"capabilities\": [{ \"cap\": \"log:*\" }]", "\"capabilities\": []");
        let manifest = parse(&empty);
        assert!(manifest.capabilities.is_empty());
        assert!(manifest.capability_set().expect("compiles").is_empty());

        let missing = MINIMAL.replace(",\n        \"capabilities\": [{ \"cap\": \"log:*\" }]", "");
        assert!(Manifest::from_json(&missing).is_err());
    }

    #[test]
    fn optional_arrays_are_absent_rather_than_empty() {
        let manifest = minimal();
        assert!(manifest.actions.is_empty());
        assert!(manifest.events.is_empty());
        assert!(manifest.handles.is_empty());
        assert!(manifest.pages.is_empty());
        assert!(manifest.network.is_none());

        // And a round trip does not turn them into empty arrays, so two manifests of the same plugin compare
        // equal.
        let json = serde_json::to_string(&manifest).expect("serialises");
        assert!(!json.contains("\"actions\""), "{json}");
    }

    // ── Ids and slugs ─────────────────────────────────────────────────────────────────────────────

    #[rstest]
    #[case("@synra-plugin/chat", "chat")]
    #[case("@imba97/synra-plugin-notes", "notes")]
    #[case("@my-scope/thing", "thing")]
    #[case("@a1/b2", "b2")]
    fn a_slug_is_the_name_without_the_official_prefix(#[case] id: &str, #[case] expected: &str) {
        let id = PluginId::parse(id).expect("valid id");
        assert_eq!(to_project_slug(&id).expect("has a slug"), expected);
    }

    #[test]
    fn an_id_with_no_usable_slug_is_refused() {
        // A plugin whose events would live under `_plugin..` is one nobody can declare a handler for.
        let id = PluginId::parse("@scope/synra-plugin-").expect("parses as a string");
        assert!(matches!(to_project_slug(&id), Err(ManifestError::UnsluggedId { .. })));
    }

    #[rstest]
    #[case("@synra-plugin/chat", true)]
    #[case("@imba97/synra-plugin-notes", true)]
    #[case("@a1/b2", true)]
    #[case("chat", false)]
    #[case("@synra/chat", false)]
    #[case("@core/chat", false)]
    #[case("@system/chat", false)]
    #[case("@a/chat", false)]
    #[case("@Synra-Plugin/chat", false)]
    #[case("@synra-plugin/Chat", false)]
    #[case("@synra-plugin/", false)]
    #[case("@synra-plugin/a b", false)]
    fn plugin_ids_are_checked_against_the_grammar(#[case] id: &str, #[case] ok: bool) {
        assert_eq!(check_plugin_id(id).is_ok(), ok, "{id}");
    }

    #[test]
    fn a_reserved_scope_says_so() {
        match check_plugin_id("@core/chat") {
            Err(ManifestError::BadId { reason, .. }) => assert!(reason.contains("reserved"), "{reason}"),
            other => panic!("expected a reserved-scope refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_id_too_long_for_its_grammar_is_refused() {
        let long_scope = format!("@{}/chat", "a".repeat(40));
        assert!(check_plugin_id(&long_scope).is_err());
        let long_name = format!("@synra-plugin/{}", "a".repeat(65));
        assert!(check_plugin_id(&long_name).is_err());
        // Exactly at each limit is fine.
        assert!(check_plugin_id(&format!("@{}/chat", "a".repeat(39))).is_ok());
        assert!(check_plugin_id(&format!("@synra-plugin/{}", "a".repeat(64))).is_ok());
    }

    // ── Versions ──────────────────────────────────────────────────────────────────────────────────

    #[rstest]
    #[case("1.0.0")]
    #[case("0.0.0")]
    #[case("10.20.30")]
    #[case("1.0.0-rc.1")]
    #[case("1.0.0-alpha")]
    #[case("1.0.0+build.1")]
    #[case("1.0.0-rc.1+build.2")]
    fn legal_versions_are_accepted(#[case] version: &str) {
        assert_eq!(check_version(version), Ok(()), "{version}");
    }

    #[rstest]
    #[case("1.0")]
    #[case("1")]
    #[case("1.0.0.0")]
    #[case("v1.0.0")]
    #[case("01.0.0")]
    #[case("1.0.0-")]
    #[case("1.0.0+")]
    #[case("1.0.0-rc..1")]
    #[case("")]
    #[case("one.two.three")]
    fn illegal_versions_are_refused(#[case] version: &str) {
        assert!(check_version(version).is_err(), "{version} should not parse");
    }

    #[test]
    fn versions_compare_by_their_parts() {
        use core::cmp::Ordering;
        assert_eq!(compare_versions("1.0.0", "1.0.0").expect("ok"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.1", "1.0.0").expect("ok"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.1.0").expect("ok"), Ordering::Less);
        assert_eq!(compare_versions("2.0.0", "1.99.99").expect("ok"), Ordering::Greater);
    }

    #[test]
    fn a_prerelease_sorts_below_its_release() {
        // Getting this backwards would let a release candidate satisfy a minimum that the release was written
        // for, so a plugin would be installed and then fail on a function that is not in the RC.
        use core::cmp::Ordering;
        assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0").expect("ok"), Ordering::Less);
        assert_eq!(compare_versions("1.0.0", "1.0.0-rc.1").expect("ok"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0-rc.1", "1.0.0-rc.2").expect("ok"), Ordering::Less);
        // Numeric identifiers compare numerically, not as strings: `rc.10` is above `rc.9`.
        assert_eq!(compare_versions("1.0.0-rc.10", "1.0.0-rc.9").expect("ok"), Ordering::Greater);
        // Fewer identifiers is lower.
        assert_eq!(compare_versions("1.0.0-rc", "1.0.0-rc.1").expect("ok"), Ordering::Less);
        // A numeric identifier is below an alphanumeric one.
        assert_eq!(compare_versions("1.0.0-1", "1.0.0-alpha").expect("ok"), Ordering::Less);
    }

    #[test]
    fn comparing_an_illegal_version_is_an_error_not_an_ordering() {
        assert!(compare_versions("1.0", "1.0.0").is_err());
        assert!(compare_versions("1.0.0", "nonsense").is_err());
    }

    // ── Runtime ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plugin_must_declare_a_runtime() {
        let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": {}",
        );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::NoRuntime)
        ));
    }

    #[test]
    fn a_ui_only_plugin_is_recognised() {
        let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
        );
        // And its `log:*` capability is fine, because a UI plugin runs in the interface and can still log.
        let manifest = parse(&text);
        assert!(manifest.has_ui());
        assert!(!manifest.is_headless());
        assert_eq!(manifest.validate(ValidationLevel::Schema, &ManifestContext::default()), Ok(()));
    }

    #[test]
    fn a_hybrid_plugin_is_recognised() {
        let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \
                \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false }, \
                \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
        );
        let manifest = parse(&text);
        assert!(manifest.is_hybrid());
    }

    #[test]
    fn a_missing_artifact_is_reported_when_the_package_is_known() {
        let context = ManifestContext {
            present_artifacts: Some(vec!["dist/other.wasm".to_owned()]),
            ..ManifestContext::default()
        };
        match minimal().validate(ValidationLevel::Schema, &context) {
            Err(ManifestError::MissingArtifact { kind, path }) => {
                assert_eq!(kind, "headless");
                assert_eq!(path, "dist/plugin.wasm");
            }
            other => panic!("expected a missing artifact, got {other:?}"),
        }
    }

    #[test]
    fn a_present_artifact_passes_that_check() {
        let context = ManifestContext {
            present_artifacts: Some(vec!["dist/plugin.wasm".to_owned()]),
            ..ManifestContext::default()
        };
        assert_eq!(minimal().validate(ValidationLevel::Schema, &context), Ok(()));
    }

    #[test]
    fn an_empty_ui_entry_is_refused() {
        let text = MINIMAL.replace(
            "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
            "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"  \" } }",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    // ── Capabilities ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_malformed_capability_is_refused_and_names_itself() {
        let text = MINIMAL.replace("\"log:*\"", "\"not a capability\"");
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::BadCapability { cap, .. }) => assert_eq!(cap, "not a capability"),
            other => panic!("expected a capability error, got {other:?}"),
        }
    }

    #[test]
    fn a_headless_plugin_may_not_declare_ui_capabilities() {
        // A `ui:*` grant on a headless plugin is one the user approves at install time and that nothing can
        // ever exercise: the consent screen said something untrue.
        let text = MINIMAL.replace(
            "[{ \"cap\": \"log:*\" }]",
            "[{ \"cap\": \"log:*\" }, { \"cap\": \"ui:page\" }]",
        );
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::UnusableCapability { cap, kind }) => {
                assert_eq!(cap, "ui:page");
                assert_eq!(kind, "headless");
            }
            other => panic!("expected an unusable capability, got {other:?}"),
        }
    }

    #[test]
    fn a_ui_plugin_may_declare_ui_capabilities() {
        let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
            )
            .replace(
                "[{ \"cap\": \"log:*\" }]",
                "[{ \"cap\": \"log:*\" }, { \"cap\": \"ui:page\" }]",
            );
        assert_eq!(
            parse(&text).validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_declared_pages_list_on_a_headless_plugin_is_refused() {
        // There is no interface to put a page in.
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"pages\": [{ \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }]",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn a_duplicate_page_key_is_refused() {
        let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\" } }",
            )
            .replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                "\"capabilities\": [{ \"cap\": \"log:*\" }], \"pages\": [\
                 { \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }, \
                 { \"key\": \"home\", \"title\": \"Again\", \"path\": \"/again\" }]",
            );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::DuplicatePageKey { key }) if key == "home"
        ));
    }

    #[test]
    fn a_default_page_that_is_not_declared_is_refused() {
        let text = MINIMAL
            .replace(
                "\"runtime\": { \"headless\": { \"artifact\": \"dist/plugin.wasm\", \"stateful\": false } }",
                "\"runtime\": { \"ui\": { \"artifact\": \"dist/ui.zip\", \"entry\": \"index.html\", \
                 \"defaultPage\": \"missing\" } }",
            )
            .replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                "\"capabilities\": [{ \"cap\": \"log:*\" }], \
                 \"pages\": [{ \"key\": \"home\", \"title\": \"Home\", \"path\": \"/home\" }]",
            );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    // ── Events ────────────────────────────────────────────────────────────────────────────────────

    /// The minimal manifest with one event declared.
    fn with_event(name: &str) -> Manifest {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"{name}\", \
                 \"payload\": {{ \"type\": \"object\", \"properties\": {{}}, \
                 \"additionalProperties\": false }} }}]"
            ),
        );
        parse(&text)
    }

#[test]
fn publishers_and_conventional_prefixes_do_not_alias_manifest_event_owners() {
    let mut manifest = with_event("_plugin.@synra-plugin/chat.text");
    assert!(
        manifest
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_ok()
    );
    for id in ["@other/chat", "@synra-plugin/synra-plugin-chat"] {
        manifest.id = PluginId::parse(id).unwrap();
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::ForeignEventNamespace { .. })
        ));
    }
}

#[test]
fn malformed_owned_events_are_not_valid_declarations() {
    for name in [
        "_plugin.@synra-plugin/chat.a b",
        "_plugin.@synra-plugin/chat.a..b",
        "_plugin.@synra-plugin/chat.*",
    ] {
        assert!(
            matches!(
                with_event(name).validate(ValidationLevel::Schema, &ManifestContext::default()),
                Err(ManifestError::BadEventName { .. })
            ),
            "{name}"
        );
    }
    let long = format!("_plugin.@synra-plugin/chat.{}", "x".repeat(240));
    assert!(matches!(
        with_event(&long).validate(ValidationLevel::Schema, &ManifestContext::default()),
        Err(ManifestError::BadEventName { .. })
    ));
}

#[test]
fn event_identity_does_not_require_a_short_project_directory_name() {
    let mut manifest = parse(MINIMAL);
    manifest.id = PluginId::parse("@acme/synra-plugin-").unwrap();
    assert!(manifest.project_slug().is_err());
    assert_eq!(manifest.event_namespace(), "_plugin.@acme/synra-plugin-.");
    assert!(
        manifest
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_ok()
    );
}

#[test]
fn an_event_in_the_plugins_own_namespace_is_accepted() {
    let manifest = with_event("_plugin.@synra-plugin/chat.text");
    assert_eq!(manifest.event_namespace(), "_plugin.@synra-plugin/chat.");
    assert_eq!(
        manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
        Ok(())
    );
}

#[test]
fn an_event_in_another_plugins_namespace_is_refused() {
    // The check that stops one plugin emitting under another's name, which a receiving side would route as
    // a legitimate message with nothing in any log to say otherwise.
    let manifest = with_event("_plugin.@synra-plugin/notes.text");
    match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
        Err(ManifestError::ForeignEventNamespace { name, namespace }) => {
            assert_eq!(name, "_plugin.@synra-plugin/notes.text");
            assert_eq!(namespace, "_plugin.@synra-plugin/chat.");
        }
        other => panic!("expected a namespace refusal, got {other:?}"),
    }
}

    #[test]
    fn an_event_outside_any_plugin_namespace_is_refused() {
        for name in ["_synra.device.changed", "device.ping", "chat.text"] {
            let manifest = with_event(name);
            assert!(
                manifest
                    .validate(ValidationLevel::Schema, &ManifestContext::default())
                    .is_err(),
                "{name} should be refused"
            );
        }
    }

    #[test]
    fn the_namespace_prefix_alone_is_not_an_event() {
        // `_plugin.@synra-plugin/chat.` names nothing, and accepting it would make an event whose logical name is empty.
        let manifest = with_event("_plugin.@synra-plugin/chat.");
        assert!(manifest
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn a_duplicate_event_name_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [\
             { \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": { \"type\": \"object\" } }, \
             { \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": { \"type\": \"object\" } }]",
        );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::DuplicateName { kind: "event", .. })
        ));
    }

    #[test]
    fn an_event_may_declare_no_payload() {
        // An event that is only a notification has nothing to carry, and requiring a schema would make authors
        // write `{"type":"object","properties":{}}` to say nothing.
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"events\": [{ \"name\": \"_plugin.@synra-plugin/chat.ping\" }]",
        );
        assert_eq!(
            parse(&text).validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    // ── Payload schemas ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_payload_schema_must_be_a_top_level_object() {
        for payload in [
            r#"{ "type": "array" }"#,
            r#"{ "type": "string", "maxLength": 10 }"#,
            r#"{ "properties": {} }"#,
            r#"[1, 2]"#,
        ] {
            let text = MINIMAL.replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                &format!(
                    "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                     \"events\": [{{ \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": {payload} }}]"
                ),
            );
            let manifest = parse(&text);
            assert!(
                matches!(
                    manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
                    Err(ManifestError::BadPayloadSchema { .. })
                ),
                "{payload} should be refused for its shape"
            );
        }
    }

    #[rstest]
    #[case(r##"{ "type": "object", "properties": { "a": { "$ref": "#/x" } } }"##, "$ref")]
    #[case(r#"{ "type": "object", "properties": { "a": { "type": "string", "format": "email", "maxLength": 5 } } }"#, "format")]
    #[case(r#"{ "type": "object", "properties": { "a": { "type": "string", "pattern": "^x$", "maxLength": 5 } } }"#, "pattern")]
    #[case(r#"{ "type": "object", "patternProperties": {} }"#, "patternProperties")]
    fn a_schema_using_something_the_host_cannot_enforce_is_refused(#[case] payload: &str, #[case] needle: &str) {
        // Each is a validator the host does not have, so honouring the rest while ignoring it would be a
        // partial check reported as a complete one.
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": {payload} }}]"
            ),
        );
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::BadPayloadSchema { detail, .. }) => {
                assert!(detail.contains(needle), "{detail} does not mention {needle}");
            }
            other => panic!("expected a schema refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_string_property_must_be_bounded() {
        // A string with no `maxLength` is one whose length the host cannot bound, so the payload validator
        // cannot promise anything about it — and the promise is what the receiving side trusted.
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [{ \"name\": \"_plugin.@synra-plugin/chat.text\", \
             \"payload\": { \"type\": \"object\", \"properties\": { \"body\": { \"type\": \"string\" } } } }]",
        );
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::BadPayloadSchema { detail, .. }) => {
                assert!(detail.contains("maxLength"), "{detail}");
            }
            other => panic!("expected a bounds refusal, got {other:?}"),
        }

        // With the bound, it passes.
        let bounded = text.replace("\"type\": \"string\"", "\"type\": \"string\", \"maxLength\": 65536");
        assert_eq!(
            parse(&bounded).validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_non_numeric_bound_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"events\": [{ \"name\": \"_plugin.@synra-plugin/chat.text\", \
             \"payload\": { \"type\": \"object\", \"properties\": { \"body\": \
             { \"type\": \"string\", \"maxLength\": \"lots\" } } } }]",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn a_deeply_nested_payload_schema_is_refused() {
        // Either a mistake or an attempt to make the loader's walk expensive.
        let mut nested = String::from(r#"{ "type": "object", "properties": { "a": "#);
        for _ in 0..20 {
            nested = format!("{nested} {{ \"type\": \"object\", \"properties\": {{ \"a\": ");
        }
        nested.push_str("{}");
        for _ in 0..21 {
            nested.push_str(" } }");
        }
        nested.push_str(" }");

        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                 \"events\": [{{ \"name\": \"_plugin.@synra-plugin/chat.text\", \"payload\": {nested} }}]"
            ),
        );
        // Parsing may fail first if the fixture is malformed; either way it is refused rather than walked.
        if let Ok(manifest) = Manifest::from_json(&text) {
            assert!(
                manifest
                    .validate(ValidationLevel::Schema, &ManifestContext::default())
                    .is_err(),
                "a deeply nested schema should be refused"
            );
        }
    }

    // ── Handles ───────────────────────────────────────────────────────────────────────────────────

    /// The minimal manifest with the given `handles` entries.
    fn with_handles(entries: &str) -> Manifest {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!("\"capabilities\": [{{ \"cap\": \"log:*\" }}], \"handles\": [{entries}]"),
        );
        parse(&text)
    }

    #[test]
    fn a_known_host_event_may_be_handled() {
        for event in [
            "_synra.transfer.completed",
            "_synra.device.changed",
            "_synra.share.received",
        ] {
            let manifest = with_handles(&format!("{{ \"event\": \"{event}\" }}"));
            assert_eq!(
                manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
                Ok(()),
                "{event}"
            );
        }
    }

    #[test]
    fn a_plugin_may_handle_its_own_declared_event() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"events\": [{ \"name\": \"_plugin.@synra-plugin/chat.text\" }], \
             \"handles\": [{ \"event\": \"_plugin.@synra-plugin/chat.text\" }]",
        );
        assert_eq!(
            parse(&text).validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_wildcard_handle_is_accepted_by_its_grammar() {
        for pattern in ["_plugin.@synra-plugin/chat.*", "_synra.*", "_synra.device.*"] {
            let manifest = with_handles(&format!("{{ \"event\": \"{pattern}\" }}"));
            assert_eq!(
                manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
                Ok(()),
                "{pattern}"
            );
        }
    }

    #[test]
    fn a_handle_that_can_never_fire_is_refused() {
        // A plugin that silently never receives anything is the hardest kind of bug to find.
        for entry in ["", "nonsense", "not-an-event", "_unknown.thing"] {
            let manifest = with_handles(&format!("{{ \"event\": \"{entry}\" }}"));
            assert!(
                matches!(
                    manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
                    Err(ManifestError::BadHandle { .. })
                ),
                "{entry:?} should be refused"
            );
        }
    }

    #[test]
    fn a_handle_may_carry_a_condition() {
        let manifest = with_handles(
            "{ \"event\": \"_synra.transfer.completed\", \"match\": { \"kind\": \"attachment\" } }",
        );
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    // ── Network ───────────────────────────────────────────────────────────────────────────────────

    /// The minimal manifest with network declarations.
    fn with_network(hosts: &str, capabilities: &str) -> Manifest {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            &format!(
                "\"capabilities\": [{capabilities}], \
                 \"network\": {{ \"outbound\": [{hosts}] }}"
            ),
        );
        parse(&text)
    }

    #[test]
    fn a_declared_host_without_a_capability_is_refused() {
        // Two lists that disagree produce a consent screen showing one thing and a plugin holding another.
        let manifest = with_network(
            "{ \"host\": \"api.github.com\" }",
            "{ \"cap\": \"network:fetch:api.github.com\" }",
        );
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );

        let mismatched = with_network(
            "{ \"host\": \"api.github.com\" }",
            "{ \"cap\": \"network:fetch:api.x.com\" }",
        );
        assert!(matches!(
            mismatched.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn a_capability_without_a_declared_host_is_refused() {
        let manifest = with_network(
            "{ \"host\": \"api.x.com\" }",
            "{ \"cap\": \"network:fetch:api.x.com\" }, { \"cap\": \"network:fetch:api.y.com\" }",
        );
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::NetworkMismatch { detail }) => {
                assert!(detail.contains("api.y.com"), "{detail}");
            }
            other => panic!("expected a network mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_wildcard_capability_needs_no_declared_host() {
        // A wildcard has no finite description, which is exactly why the interface spells it out as "any
        // website" rather than pretending a list covers it.
        let manifest = with_network("{ \"host\": \"api.x.com\" }", "{ \"cap\": \"network:fetch:*\" }");
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_wildcard_declared_host_needs_its_capability() {
        let manifest = with_network(
            "{ \"host\": \"*.example.com\", \"methods\": [\"GET\"] }",
            "{ \"cap\": \"network:fetch:*.example.com:GET\" }",
        );
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

#[test]
fn finite_network_method_declarations_match_their_authority_in_both_directions() {
    let cases = [
        (
            r#""methods":["GET"]"#,
            r#"{"cap":"network:fetch:api.x.com:GET"}"#,
            true,
        ),
        (
            r#""methods":["GET","POST"]"#,
            r#"{"cap":"network:fetch:api.x.com:GET"},{"cap":"network:fetch:api.x.com:POST"}"#,
            true,
        ),
        (
            r#""methods":["GET"]"#,
            r#"{"cap":"network:fetch:api.x.com:POST"}"#,
            false,
        ),
        (
            r#""methods":[]"#,
            r#"{"cap":"network:fetch:api.x.com:GET"}"#,
            false,
        ),
        (
            r#""methods":["GET"]"#,
            r#"{"cap":"network:fetch:api.x.com"}"#,
            false,
        ),
        (
            r#""methods":["GET","POST"]"#,
            r#"{"cap":"network:fetch:api.x.com:GET"}"#,
            false,
        ),
        (
            r#""methods":["GET"]"#,
            r#"{"cap":"network:fetch:api.x.com:*"}"#,
            false,
        ),
    ];
    for (methods, caps, allowed) in cases {
        let declaration = format!(r#"{{"host":"api.x.com",{methods}}}"#);
        let result = with_network(&declaration, caps)
            .validate(ValidationLevel::Schema, &ManifestContext::default());
        assert_eq!(result.is_ok(), allowed, "{methods} / {caps}: {result:?}");
    }
}

    #[test]
    fn a_non_fetch_network_capability_needs_no_declared_host() {
        // `network:websocket` is not a host-scoped grant, so the two lists say nothing about each other.
        let manifest = with_network("{ \"host\": \"api.x.com\" }", "{ \"cap\": \"network:websocket\" }, { \"cap\": \"network:fetch:api.x.com\" }");
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    #[test]
    fn a_network_capability_with_no_qualifier_needs_no_declared_host() {
        let manifest = with_network("{ \"host\": \"api.x.com\" }", "{ \"cap\": \"network:fetch:api.x.com\" }, { \"cap\": \"network:fetch\" }");
        assert_eq!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Ok(())
        );
    }

    // ── Implementation ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn handles_without_on_event_is_refused() {
        // A plugin that is installed, appears to work, and silently drops every message it asked for.
        let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
        let context = ManifestContext {
            implementation: Some(Implementation::default()),
            ..ManifestContext::default()
        };
        match manifest.validate(ValidationLevel::Verify, &context) {
            Err(ManifestError::MissingImplementation { declared }) => assert_eq!(declared, "`handles`"),
            other => panic!("expected a missing implementation, got {other:?}"),
        }
    }

    #[test]
    fn on_event_without_handles_is_refused() {
        // Dead code, and a sign that the manifest and the implementation have drifted apart — at which point no
        // other declaration can be trusted either.
        let manifest = minimal();
        let context = ManifestContext {
            implementation: Some(Implementation { on_event: true, ..Implementation::default() }),
            ..ManifestContext::default()
        };
        match manifest.validate(ValidationLevel::Verify, &context) {
            Err(ManifestError::UndeclaredImplementation { implemented }) => {
                assert_eq!(implemented, "on_event");
            }
            other => panic!("expected an undeclared implementation, got {other:?}"),
        }
    }

    #[test]
    fn a_declaration_and_its_implementation_agreeing_passes() {
        let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
        let context = ManifestContext {
            implementation: Some(Implementation { on_event: true, ..Implementation::default() }),
            ..ManifestContext::default()
        };
        assert_eq!(manifest.validate(ValidationLevel::Verify, &context), Ok(()));
    }

    #[test]
    fn actions_without_execute_is_refused_for_a_headless_plugin() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"actions\": [{ \"name\": \"send-message\" }]",
        );
        let manifest = parse(&text);
        let context = ManifestContext {
            implementation: Some(Implementation::default()),
            ..ManifestContext::default()
        };
        assert!(matches!(
            manifest.validate(ValidationLevel::Verify, &context),
            Err(ManifestError::MissingImplementation { declared }) if declared == "`actions`"
        ));

        let with_execute = ManifestContext {
            implementation: Some(Implementation { execute: true, ..Implementation::default() }),
            ..ManifestContext::default()
        };
        assert_eq!(manifest.validate(ValidationLevel::Verify, &with_execute), Ok(()));
    }

    #[test]
    fn execute_without_actions_is_refused() {
        let manifest = minimal();
        let context = ManifestContext {
            implementation: Some(Implementation { execute: true, ..Implementation::default() }),
            ..ManifestContext::default()
        };
        assert!(manifest.validate(ValidationLevel::Verify, &context).is_err());
    }

    #[test]
    fn the_schema_level_skips_the_implementation_checks() {
        // The CLI has the source tree but not a parsed module, so a check that needs one cannot be in this
        // level — and a level that reported a failure it could not see would be worse than not checking.
        let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
        let context = ManifestContext {
            implementation: Some(Implementation::default()),
            ..ManifestContext::default()
        };
        assert_eq!(manifest.validate(ValidationLevel::Schema, &context), Ok(()));
        assert!(manifest.validate(ValidationLevel::Verify, &context).is_err());
    }

    #[test]
    fn a_missing_implementation_context_skips_the_check_rather_than_failing() {
        let manifest = with_handles("{ \"event\": \"_synra.device.changed\" }");
        assert_eq!(
            manifest.validate(ValidationLevel::Verify, &ManifestContext::default()),
            Ok(())
        );
    }

    // ── Versions and WIT ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plugin_needing_a_newer_sdk_than_the_host_is_refused_with_both_versions() {
        let manifest = parse(&MINIMAL.replace("\"min\": \"1.0.0\"", "\"min\": \"9.0.0\""));
        let context = ManifestContext {
            host_sdk: Some("1.2.0".to_owned()),
            ..ManifestContext::default()
        };
        match manifest.validate(ValidationLevel::Schema, &context) {
            Err(ManifestError::SdkTooOld { min, host }) => {
                assert_eq!(min, "9.0.0");
                assert_eq!(host, "1.2.0");
            }
            other => panic!("expected an SDK refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_plugin_the_host_satisfies_is_accepted() {
        let manifest = minimal();
        let context = ManifestContext { host_sdk: Some("1.0.0".to_owned()), ..ManifestContext::default() };
        assert_eq!(manifest.validate(ValidationLevel::Schema, &context), Ok(()));

        // A host above the minimum is fine, including one where the plugin's minimum is a pre-release of it.
        let below = parse(&MINIMAL.replace("\"min\": \"1.0.0\"", "\"min\": \"1.0.0-rc.1\""));
        assert_eq!(below.validate(ValidationLevel::Schema, &context), Ok(()));
    }

    #[test]
    fn a_wit_mismatch_names_both_worlds() {
        let manifest = minimal();
        let context = ManifestContext {
            host_wit: Some("synra:plugin@2.0.0".to_owned()),
            ..ManifestContext::default()
        };
        match manifest.validate(ValidationLevel::Schema, &context) {
            Err(ManifestError::WitMismatch { plugin, host }) => {
                assert_eq!(plugin, "synra:plugin@1.0.0");
                assert_eq!(host, "synra:plugin@2.0.0");
            }
            other => panic!("expected a WIT refusal, got {other:?}"),
        }
    }

    // ── Composition and names ─────────────────────────────────────────────────────────────────────

    #[test]
    fn a_plugin_that_composes_with_itself_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"compose\": [{ \"id\": \"@synra-plugin/chat\", \"version\": \"^1.0.0\" }]",
        );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::CompositionCycle { .. })
        ));
    }

    #[test]
    fn a_dependency_with_a_bad_version_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \
             \"compose\": [{ \"id\": \"@synra-plugin/format\", \"version\": \"latest\" }]",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn a_dependency_range_is_accepted_with_its_operator() {
        for range in ["^1.0.0", "~1.2.0", "=1.0.0", ">=1.0.0"] {
            let text = MINIMAL.replace(
                "\"capabilities\": [{ \"cap\": \"log:*\" }]",
                &format!(
                    "\"capabilities\": [{{ \"cap\": \"log:*\" }}], \
                     \"compose\": [{{ \"id\": \"@synra-plugin/format\", \"version\": \"{range}\" }}]"
                ),
            );
            assert_eq!(
                parse(&text).validate(ValidationLevel::Schema, &ManifestContext::default()),
                Ok(()),
                "{range}"
            );
        }
    }

#[test]
fn action_names_are_validated_when_a_manifest_is_admitted() {
    for (name, allowed) in [
        ("format-date", true),
        ("*", false),
        ("a:b", false),
        ("a/b", false),
        ("中文", false),
    ] {
        let mut document: serde_json::Value = serde_json::from_str(MINIMAL).expect("fixture");
        document["actions"] = serde_json::json!([{ "name": name }]);
        let result = parse(&document.to_string())
            .validate(ValidationLevel::Schema, &ManifestContext::default());
        assert_eq!(result.is_ok(), allowed, "{name}: {result:?}");
    }
}

    #[test]
    fn a_duplicate_action_name_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"actions\": [\
             { \"name\": \"send\" }, { \"name\": \"send\" }]",
        );
        let manifest = parse(&text);
        assert!(matches!(
            manifest.validate(ValidationLevel::Schema, &ManifestContext::default()),
            Err(ManifestError::DuplicateName { kind: "action", .. })
        ));
    }

    #[test]
    fn an_action_with_an_empty_name_is_refused() {
        let text = MINIMAL.replace(
            "\"capabilities\": [{ \"cap\": \"log:*\" }]",
            "\"capabilities\": [{ \"cap\": \"log:*\" }], \"actions\": [{ \"name\": \"\" }]",
        );
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_err());
    }

    #[test]
    fn length_limits_are_enforced_on_what_the_interface_draws() {
        // A title of a thousand characters pushes everything else off the screen.
        let long = "x".repeat(MAX_TITLE_LEN + 1);
        let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{long}\""));
        let manifest = parse(&text);
        match manifest.validate(ValidationLevel::Schema, &ManifestContext::default()) {
            Err(ManifestError::TooLong { field, len, max }) => {
                assert_eq!(field, "title");
                assert_eq!(len, MAX_TITLE_LEN + 1);
                assert_eq!(max, MAX_TITLE_LEN);
            }
            other => panic!("expected a length refusal, got {other:?}"),
        }

        // Exactly at the limit is fine.
        let exact = "x".repeat(MAX_TITLE_LEN);
        let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{exact}\""));
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_ok());
    }

    #[test]
    fn a_long_title_is_measured_in_characters_not_bytes() {
        // A CJK title of the same character count is not "too long" in a unit the user cannot see.
        let cjk = "电".repeat(MAX_TITLE_LEN);
        let text = MINIMAL.replace("\"title\": \"Chat\"", &format!("\"title\": \"{cjk}\""));
        assert!(parse(&text)
            .validate(ValidationLevel::Schema, &ManifestContext::default())
            .is_ok());
    }

    // ── Localisation ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_localised_title_is_chosen_by_tag_with_a_fallback_chain() {
        let text = MINIMAL.replace(
            "\"title\": \"Chat\"",
            "\"title\": \"Chat\", \"description\": \"Cross-device chat\", \"locales\": { \
             \"zh-CN\": { \"title\": \"聊天\", \"description\": \"跨设备聊天\" }, \
             \"zh\": { \"title\": \"中文\" }, \
             \"en\": { \"title\": \"Chat!\" } }",
        );
        let manifest = parse(&text);

        assert_eq!(manifest.localised_title("zh-CN"), "聊天", "an exact match wins");
        assert_eq!(manifest.localised_title("en"), "Chat!");
        // The chain shortens the *reader's* tag: `zh-Hans-CN` looks for itself, then for `zh`. It does not
        // extend the manifest's, so a manifest declaring only `zh-CN` would not answer here.
        assert_eq!(manifest.localised_title("zh-Hans-CN"), "中文");
        // A language with no entry falls back to the default.
        assert_eq!(manifest.localised_title("fr"), "Chat");
        assert_eq!(manifest.localised_description("fr"), Some("Cross-device chat"));
        assert_eq!(manifest.localised_description("zh-CN"), Some("跨设备聊天"));
        // The `zh` entry has no description, so the reader gets the default rather than an empty string.
        assert_eq!(manifest.localised_description("zh-Hans-CN"), Some("Cross-device chat"));
    }

    #[test]
    fn a_manifest_with_no_locales_uses_its_defaults() {
        let manifest = minimal();
        assert_eq!(manifest.localised_title("zh-CN"), "Chat");
        assert_eq!(manifest.localised_title(""), "Chat");
        assert_eq!(manifest.localised_description("zh-CN"), None);
    }

    #[test]
    fn a_locale_missing_the_requested_string_falls_through() {
        // A `zh-CN` entry with only a `title` must not make the description disappear.
        let text = MINIMAL.replace(
            "\"title\": \"Chat\"",
            "\"title\": \"Chat\", \"description\": \"Cross-device chat\", \
             \"locales\": { \"zh-CN\": { \"title\": \"聊天\" } }",
        );
        let manifest = parse(&text);
        assert_eq!(manifest.localised_title("zh-CN"), "聊天");
        assert_eq!(manifest.localised_description("zh-CN"), Some("Cross-device chat"));
    }

    // ── Round trip ────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_full_manifest_parses_and_survives_a_round_trip() {
        // The example from the design document, so a change to the shape is caught here rather than by an
        // author whose manifest stopped loading.
        let text = r#"{
            "$schema": "https://synra-app.dev/schema/manifest/v1.json",
            "id": "@synra-plugin/chat",
            "version": "1.2.0",
            "title": "Chat",
            "description": "cross-device chat",
            "icon": "assets/icon.svg",
            "publisher": { "id": "synra-official", "name": "Synra Official", "url": "https://synra-app.dev" },
            "license": "MIT",
            "repository": "https://github.com/synra/plugin-chat",
            "sdk": { "min": "1.0.0", "preferred": "1.2.0" },
            "wit": "synra:plugin@1.0.0",
            "runtime": {
                "headless": { "artifact": "dist/plugin.wasm", "stateful": false, "hints": ["cpu-heavy"] },
                "ui": { "artifact": "dist/ui.zip", "entry": "index.html", "defaultPage": "home" }
            },
            "capabilities": [
                { "cap": "log:*" },
                { "cap": "device:list" },
                { "cap": "device:send:*" },
                { "cap": "storage:local:read" },
                { "cap": "event:emit:_plugin.@synra-plugin/chat.*" },
                { "cap": "ui:page" },
                { "cap": "network:fetch:api.github.com" }
            ],
            "actions": [
                { "name": "send-message",
                  "args": { "type": "object", "required": ["target", "body"],
                            "properties": { "target": { "type": "string", "maxLength": 64 },
                                            "body": { "type": "string", "maxLength": 65536 } } },
                  "returns": { "type": "object", "properties": { "messageId": { "type": "string", "maxLength": 64 } } },
                  "description": "send a message" }
            ],
            "shareHandlers": [{ "kinds": ["text", "url"], "description": "recognise message text" }],
            "events": [
                { "name": "_plugin.@synra-plugin/chat.text",
                  "payload": { "type": "object", "required": ["body"],
                               "properties": { "body": { "type": "string", "maxLength": 65536 },
                                               "sentAtMs": { "type": "integer" } },
                               "additionalProperties": false } },
                { "name": "_plugin.@synra-plugin/chat.typing",
                  "payload": { "type": "object", "properties": {}, "additionalProperties": false } }
            ],
            "handles": [
                { "event": "_plugin.@synra-plugin/chat.*" },
                { "event": "_synra.transfer.completed" },
                { "event": "_synra.device.changed" }
            ],
            "compose": [{ "id": "@synra-plugin/format", "version": "^1.0.0", "optional": false }],
            "network": { "outbound": [{ "host": "api.github.com" }] },
            "pages": [
                { "key": "home", "title": "Chat", "path": "/home", "icon": "chat" },
                { "key": "settings", "title": "Settings", "path": "/settings" }
            ],
            "resources": { "preferredMemoryMb": 32, "preferredTimeoutMs": 2000 },
            "locales": { "zh-CN": { "title": "聊天", "description": "跨设备聊天" } }
        }"#;

        let manifest = parse(text);
        assert_eq!(manifest.validate(ValidationLevel::Schema, &ManifestContext::default()), Ok(()));
        assert!(manifest.is_hybrid());
        assert_eq!(manifest.capabilities.len(), 7);
        assert_eq!(manifest.events.len(), 2);
        assert_eq!(manifest.pages.len(), 2);
        assert_eq!(manifest.localised_title("zh-CN"), "聊天");

        let json = serde_json::to_string(&manifest).expect("serialises");
        let back = Manifest::from_json(&json).expect("re-parses");
        assert_eq!(back, manifest);
        // And the capability set compiles, which is what the loader actually uses.
        assert!(manifest.capability_set().expect("compiles").contains(
            &Capability::parse("device:list").expect("valid")
        ));
    }

    #[test]
    fn a_full_manifest_with_its_implementation_verifies() {
        let text = r#"{
            "id": "@synra-plugin/chat",
            "version": "1.0.0",
            "title": "Chat",
            "publisher": { "id": "synra-official" },
            "sdk": { "min": "1.0.0" },
            "wit": "synra:plugin@1.0.0",
            "runtime": {
                "headless": { "artifact": "dist/plugin.wasm", "stateful": false },
                "ui": { "artifact": "dist/ui.zip", "entry": "index.html" }
            },
            "capabilities": [{ "cap": "log:*" }],
            "actions": [{ "name": "send" }],
            "handles": [{ "event": "_synra.device.changed" }]
        }"#;
        let manifest = parse(text);
        let context = ManifestContext {
            host_sdk: Some("1.0.0".to_owned()),
            host_wit: Some("synra:plugin@1.0.0".to_owned()),
            present_artifacts: Some(vec![
                "dist/plugin.wasm".to_owned(),
                "dist/ui.zip".to_owned(),
            ]),
            implementation: Some(Implementation { on_event: true, execute: true, activate: true }),
        };
        assert_eq!(manifest.validate(ValidationLevel::Verify, &context), Ok(()));
    }

    #[test]
    fn every_error_variant_explains_itself() {
        // The loader shows these to a user, so a variant without a sentence is one the interface cannot render.
        let errors = vec![
            ManifestError::Malformed("x".to_owned()),
            ManifestError::BadId { id: "x".to_owned(), reason: "y".to_owned() },
            ManifestError::UnsluggedId { id: "x".to_owned() },
            ManifestError::BadVersion { version: "x".to_owned(), reason: "y".to_owned() },
            ManifestError::NoRuntime,
            ManifestError::MissingArtifact { kind: "headless", path: "x".to_owned() },
            ManifestError::BadCapability {
                cap: "x".to_owned(),
                source: Capability::parse("nope").expect_err("invalid"),
            },
            ManifestError::UnusableCapability { cap: "ui:page".to_owned(), kind: "headless" },
            ManifestError::NetworkMismatch { detail: "x".to_owned() },
            ManifestError::DuplicateName { kind: "action", name: "x".to_owned() },
            ManifestError::ForeignEventNamespace { name: "x".to_owned(), namespace: "y".to_owned() },
            ManifestError::BadPayloadSchema { name: "x".to_owned(), detail: "y".to_owned() },
            ManifestError::BadHandle { event: "x".to_owned() },
            ManifestError::MissingImplementation { declared: "`handles`" },
            ManifestError::UndeclaredImplementation { implemented: "on_event" },
            ManifestError::DuplicatePageKey { key: "x".to_owned() },
            ManifestError::SdkTooOld { min: "9".to_owned(), host: "1".to_owned() },
            ManifestError::WitMismatch { plugin: "a".to_owned(), host: "b".to_owned() },
            ManifestError::CompositionCycle { through: vec!["a".to_owned()] },
            ManifestError::TooLong { field: "title", len: 100, max: 64 },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 10, "{error:?} -> {text:?}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }

    // ── The digest a consent decision is recorded against ────────────────────────────────────────

    #[test]
    fn the_manifest_digest_is_sha256_of_the_bytes_it_was_given() {
        // ★ The expected value is the **published NIST vector** for SHA-256("abc"), not a value this build computed and
        // wrote down. That distinction is the whole test: a constant recorded from our own output would pass against a
        // wrong implementation just as happily, because it would have been produced by that implementation.
        //
        // The property being pinned is that two callers agree to the byte — the shell records a decision against this
        // value and the daemon refuses a plugin whose manifest no longer hashes to it. A construction that drifted (a
        // different algorithm, a prefix, a trailing newline) would mismatch on every plugin.
        assert_eq!(
            manifest_digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn two_manifests_that_differ_in_their_bytes_have_different_digests() {
        // The direction that makes the column useful: a plugin that ships an update declaring one more capability is a
        // different document, and the rows decided about the old one must be visibly older. Whitespace counts, because
        // the bytes are what the user's file actually says — and a digest over the *parsed* value would call these two
        // the same.
        let a = r#"{"capabilities":[{"cap":"log:*"}]}"#;
        let b = r#"{"capabilities":[{"cap":"log:*"},{"cap":"device:list"}]}"#;
        let c = r#"{"capabilities": [{"cap":"log:*"}]}"#;

        assert_ne!(manifest_digest(a), manifest_digest(b), "a capability was added");
        assert_ne!(manifest_digest(a), manifest_digest(c), "the bytes differ, so the document differs");
        assert_eq!(manifest_digest(a), manifest_digest(a), "and the same bytes always agree");
    }
