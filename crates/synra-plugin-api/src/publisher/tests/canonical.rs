use super::super::{Digests, SigningSubject};
use super::subject;

#[test]
fn the_canonical_bytes_have_no_whitespace_and_a_fixed_key_order() {
    // ★ The property the whole signing scheme rests on. `serde_json::to_string` on a struct is a promise about field
    // order that a later refactor can break silently, and a signature that stopped verifying after an unrelated
    // change is indistinguishable from a tampered package.
    let canonical = String::from_utf8(subject().canonical_bytes()).expect("utf-8");
    assert_eq!(canonical, r#"{"manifest":"sha256-bbb","artifacts":{"plugin.wasm":"sha256-aaa"}}"#);
    assert!(!canonical.contains(' '), "whitespace would make the payload depend on a formatting option");
    assert!(!canonical.contains('\n'));
}

#[test]
fn the_artifact_order_is_the_maps_and_not_the_insertion_order() {
    // A list would make two packages with the same files in a different order have different signed bytes, so a
    // repackaging that changed nothing would invalidate a signature.
    let mut first = Digests::new();
    first.insert("z.wasm".to_owned(), "sha256-z".to_owned());
    first.insert("a.wasm", "sha256-a");

    let mut second = Digests::new();
    second.insert("a.wasm".to_owned(), "sha256-a".to_owned());
    second.insert("z.wasm".to_owned(), "sha256-z".to_owned());

    let one = SigningSubject { manifest: "m".to_owned(), artifacts: first };
    let two = SigningSubject { manifest: "m".to_owned(), artifacts: second };
    assert_eq!(one.canonical_bytes(), two.canonical_bytes());
}

#[test]
fn a_name_with_a_quote_in_it_is_escaped_by_the_json_rules() {
    // Otherwise two implementations read the same bytes as different payloads, and one of them verifies a signature
    // over something other than what it checked.
    let mut artifacts = Digests::new();
    artifacts.insert("a\"b\\c\n.wasm", "sha256-1");
    let canonical = String::from_utf8(SigningSubject { manifest: "m".to_owned(), artifacts }.canonical_bytes())
        .expect("utf-8");
    assert!(canonical.contains(r#"a\"b\\c\n.wasm"#), "{canonical}");
    // And it round-trips as JSON, which is what makes it the same bytes a conforming implementation produces.
    let parsed: serde_json::Value = serde_json::from_str(&canonical).expect("valid JSON");
    assert!(parsed.get("artifacts").is_some());
}

#[test]
fn an_empty_artifact_map_is_still_valid_json() {
    let canonical = String::from_utf8(
        SigningSubject { manifest: "m".to_owned(), artifacts: Digests::new() }.canonical_bytes(),
    )
    .expect("utf-8");
    assert_eq!(canonical, r#"{"manifest":"m","artifacts":{}}"#);
    let _: serde_json::Value = serde_json::from_str(&canonical).expect("valid JSON");
}
