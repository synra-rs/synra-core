//! The list, the entries it refuses, and the scan that acts on it.

use crate::publisher::Fingerprint;
use crate::revocation::{Installed, RevocationError, RevocationList};

/// The design's own example, which is what the format has to accept.
const DOCUMENT: &str = r#"{
  "revoked": [
    { "plugin": "@bad/plugin", "versions": ["1.0.0", "1.0.1"], "reason": "malicious code", "at": "2026-01-01" },
    { "publisher": "evil-actor", "pubkeyFingerprint": "AAAA BBBB CCCC DDDD", "reason": "impersonation" }
  ]
}"#;

#[test]
fn the_designs_own_example_parses() {
    // ★ The format is the document's, so the document's example is the first test. A parser that only accepted a
    // convenient shape would be a second format nobody wrote down.
    let list = RevocationList::parse(DOCUMENT).expect("the design's example");

    assert_eq!(list.len(), 2);
    assert_eq!(list.revokes("@bad/plugin", "1.0.0"), Some("malicious code"));
    assert_eq!(list.revokes("@bad/plugin", "1.0.1"), Some("malicious code"));
    assert_eq!(list.revokes_key(&fingerprint("AAAA BBBB CCCC DDDD")), Some("impersonation"));
}

#[test]
fn a_revoked_publisher_is_reported_by_name_as_well_as_by_key() {
    // ★ The name the document spells. The first version of the parser read it and threw it away — while the variant's own
    // doc comment claimed it was "kept for the message a user reads", which is exactly the kind of comment that makes a gap
    // invisible. It is asserted here so the two cannot drift apart again.
    let list = RevocationList::parse(DOCUMENT).expect("a list");
    let key = fingerprint("AAAA BBBB CCCC DDDD");

    assert_eq!(list.revokes_key(&key), Some("impersonation"));
    assert_eq!(list.revoked_publisher(&key), Some("evil-actor"));
    // And a key nobody named answers neither question.
    assert_eq!(list.revoked_publisher(&fingerprint("1111 2222 3333 4444")), None);
}

#[test]
fn a_version_the_list_does_not_name_is_not_revoked() {
    // The list names exact versions, so the version next to a revoked one is untouched. An implementation that compared
    // prefixes would revoke `1.0.10` for naming `1.0.1`, which is a plugin somebody never asked to disable.
    let list = RevocationList::parse(DOCUMENT).expect("a list");

    assert_eq!(list.revokes("@bad/plugin", "1.0.2"), None);
    assert_eq!(list.revokes("@bad/plugin", "1.0.10"), None);
    assert_eq!(list.revokes("@bad/plugin", "2.0.0"), None);
    // And a different plugin at a revoked version number is a different plugin.
    assert_eq!(list.revokes("@good/plugin", "1.0.0"), None);
}

#[test]
fn a_version_spelled_differently_misses_and_the_scan_is_where_that_shows() {
    // ★ The cost of exact matching, pinned so a reader knows it rather than discovers it.
    //
    // `must_disable` is a scan rather than a check at the point of use precisely because of this: a miss is invisible in a
    // check that answers "not revoked", and it is visible in a scan, where the installed set and the list sit side by side
    // and a caller can log what was compared.
    let list = RevocationList::parse(DOCUMENT).expect("a list");

    assert_eq!(list.revokes("@bad/plugin", "v1.0.0"), None, "a leading v is a different string");

    let installed = [
        Installed { plugin: "@bad/plugin", version: "1.0.0" },
        Installed { plugin: "@bad/plugin", version: "v1.0.0" },
    ];
    let disabled = list.must_disable(&installed);
    assert_eq!(disabled.len(), 1, "only the one the list spells exactly");
    assert_eq!(disabled[0].version, "1.0.0");
}

#[test]
fn the_scan_names_every_installed_version_that_is_revoked() {
    let list = RevocationList::parse(DOCUMENT).expect("a list");
    let installed = [
        Installed { plugin: "@bad/plugin", version: "1.0.0" },
        Installed { plugin: "@fine/plugin", version: "1.0.0" },
        Installed { plugin: "@bad/plugin", version: "1.0.1" },
    ];

    let disabled = list.must_disable(&installed);
    assert_eq!(disabled.len(), 2);
    // In the order given, so the report reads in the order the caller listed them.
    assert_eq!(disabled[0].plugin, "@bad/plugin");
    assert_eq!(disabled[0].version, "1.0.0");
    assert_eq!(disabled[0].reason, "malicious code");
    assert_eq!(disabled[1].version, "1.0.1");
}

#[test]
fn an_empty_list_disables_nothing_and_says_it_is_empty() {
    // ★ "Nothing is revoked" and "there is no list" are different facts — the first is a decision and the second is a
    // machine that has never been told. This type is the first; the caller is what has to tell them apart.
    let list = RevocationList::empty();

    assert!(list.is_empty());
    assert_eq!(list.len(), 0);
    assert!(list.must_disable(&[Installed { plugin: "@any/plugin", version: "1.0.0" }]).is_empty());

    let parsed = RevocationList::parse(r#"{"revoked":[]}"#).expect("an empty document");
    assert_eq!(parsed, list, "an empty document and an empty list are the same thing");
}

#[test]
fn an_entry_that_names_a_plugin_and_no_versions_is_refused() {
    // ★ A malformed entry must not be skipped. This is the one document where a silently dropped entry is a security
    // decision: a typo in a field name would remove a revocation and leave everything looking healthy.
    let error = RevocationList::parse(r#"{"revoked":[{"plugin":"@bad/plugin","reason":"malicious"}]}"#)
        .expect_err("a plugin with no versions revokes nothing");

    match error {
        RevocationError::NoVersions { plugin, index } => {
            assert_eq!(plugin, "@bad/plugin");
            assert_eq!(index, 0);
        }
        other => panic!("expected the missing versions, got {other:?}"),
    }
}

#[test]
fn an_entry_that_names_nothing_is_refused_with_its_position() {
    let error = RevocationList::parse(
        r#"{"revoked":[{"plugin":"@bad/plugin","versions":["1.0.0"],"reason":"x"},{"reason":"orphan"}]}"#,
    )
    .expect_err("an orphan entry revokes nothing");

    assert_eq!(error, RevocationError::EmptyEntry { index: 1 });
}

#[test]
fn a_publisher_with_no_key_is_refused() {
    // ★ Revoking a publisher **name** would be revoking a claim: a name is free, and the next person can make the same
    // claim. The design's other rule says the same where it explains why a changed key means "do not install", so an entry
    // that names a publisher and no key is refused rather than honoured.
    let error = RevocationList::parse(r#"{"revoked":[{"publisher":"evil-actor","reason":"x"}]}"#)
        .expect_err("a name with no key");

    assert_eq!(error, RevocationError::EmptyEntry { index: 0 });
}

#[test]
fn a_fingerprint_that_is_not_one_is_refused() {
    let error = RevocationList::parse(
        r#"{"revoked":[{"publisher":"evil","pubkeyFingerprint":"nonsense","reason":"x"}]}"#,
    )
    .expect_err("a fingerprint has a shape");

    match error {
        RevocationError::BadFingerprint { index, .. } => assert_eq!(index, 0),
        other => panic!("expected a fingerprint error, got {other:?}"),
    }
}

#[test]
fn a_revocation_with_no_reason_is_still_a_revocation() {
    // ★ Refusing this would leave a plugin running because of a missing field, which inverts the point of the document. The
    // reason is for a person; the revocation is for the plugin.
    let list = RevocationList::parse(r#"{"revoked":[{"plugin":"@bad/plugin","versions":["1.0.0"]}]}"#)
        .expect("a reason is not required");

    assert_eq!(list.revokes("@bad/plugin", "1.0.0"), Some("revoked with no reason given"));
}

#[test]
fn a_document_that_is_not_json_says_so() {
    let error = RevocationList::parse("not json").expect_err("not a document");

    assert!(matches!(error, RevocationError::Malformed { .. }), "{error:?}");
    // And the parser's own words are kept, because the list ships with the application and whoever has to fix it is its
    // author rather than its reader.
    assert!(error.to_string().contains("not readable"), "{error}");
}

#[test]
fn the_list_names_the_plugins_it_revokes_whether_or_not_they_are_installed() {
    // The other half of the design's behaviour: an *attempt to install* a revoked version is refused with the same reason,
    // and a caller needs to be able to ask that without having anything installed.
    let list = RevocationList::parse(DOCUMENT).expect("a list");
    let names: Vec<&str> = list.plugin_names().collect();

    assert_eq!(names, vec!["@bad/plugin"]);
}

/// A fingerprint from the text the document spells.
fn fingerprint(text: &str) -> Fingerprint {
    Fingerprint::parse(text).expect("a fingerprint")
}
