use rstest::rstest;
use synra_protocol::PluginId;
use super::super::error::ManifestError;
use super::super::version::{check_plugin_id, to_project_slug};

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
    assert!(matches!(
        to_project_slug(&id),
        Err(ManifestError::UnsluggedId { .. })
    ));
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
        Err(ManifestError::BadId { reason, .. }) => {
            assert!(reason.contains("reserved"), "{reason}")
        }
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
