//! The generated bindings, and the check that keeps them from drifting.
//!
//! # The problem this module solves
//!
//! The interface needs the kernel's types in TypeScript. There are three ways to give them to it, and two are wrong:
//!
//! * **Write them by hand.** This is what the JavaScript package did, and the failure is silent: a field renamed in
//!   Rust arrives as `undefined`, and the symptom is a blank panel rather than a compile error. Nothing catches it
//!   except a person reading both files.
//! * **Derive them everywhere.** The right answer, and not reachable here: the types the interface needs most — the
//!   error codes, the capability names, the six identifiers — live in `synra-protocol`, and Rust's orphan rule forbids
//!   implementing a foreign trait for a foreign type. Putting the code-generation dependency into the protocol crate
//!   would make the kernel's own core carry it.
//! * **Declare the unreachable ones here, and check them against the protocol.**
//!
//! This module is the third. The declarations are generated *from the same data the protocol serialises* — a test
//! round-trips every variant through `serde_json` and asserts the generated union has a matching member — so the list
//! is written once and compared, rather than written twice and hoped about.
//!
//! # Why a test rather than a build script
//!
//! A build script would have to parse Rust source to learn what the variants are, which is a parser that goes stale in
//! its own way. A test can ask the *serialiser*, which cannot be wrong about what it produces.

/// The `ErrorCode` union, generated from the protocol's own variant list.
///
/// # Why the serialisation is the source
///
/// `ErrorCode` is a `snake_case` enum, so the union's members are the strings `serde` produces and not the Rust variant
/// names. Deriving them from `Serialize` rather than from the variant list is what makes `CapabilityDenied` become
/// `capability_denied` here as well as on the wire — a difference that a hand-written file gets wrong once and then
/// forever.
#[must_use]
pub fn error_code_declaration() -> String {
    let members: Vec<String> = synra_protocol::ErrorCode::all()
        .iter()
        .filter_map(|code| serde_json::to_value(code).ok())
        .filter_map(|value| value.as_str().map(str::to_owned))
        .map(|code| format!("  | '{code}'"))
        .collect();

    let mut declaration = String::from(
        "/**\n * Every way a kernel call can fail, as the interface sees it.\n *\n * The strings are the wire \
         values: `serde` renames the Rust variants to `snake_case`, so a member here is\n * what arrives in \
         `SynraError.code` and not what the variant is called in Rust.\n */\nexport type ErrorCode =\n",
    );
    declaration.push_str(&members.join("\n"));
    declaration.push_str(";\n");
    declaration
}

/// The `SuggestedAction` union, generated from the protocol's own variant list.
///
/// # Why each member is a whole object
///
/// `SuggestedAction` is *internally tagged* by `kind`, so a member is not a string: it is `{ kind: 'openSettings',
/// section: string }`. The union of those objects is what lets the interface narrow on `kind` and get the payload
/// typed — which is the whole reason the protocol tags it that way.
#[must_use]
pub fn suggested_action_declaration() -> String {
    let mut members = Vec::new();
    for action in synra_protocol::error::SuggestedAction::all() {
        let Ok(value) = serde_json::to_value(&action) else {
            continue;
        };
        let Some(object) = value.as_object() else {
            continue;
        };

        let mut fields = Vec::new();
        for (key, field) in object {
            // `kind` is the tag, and it is a literal rather than a type: the discriminator is what the union narrows
            // on, so it has to be the exact string.
            if key == "kind" {
                if let Some(tag) = field.as_str() {
                    fields.push(format!("kind: '{tag}'"));
                }
                continue;
            }
            fields.push(format!("{key}: {}", ts_type_of(field)));
        }
        members.push(format!("  | {{ {} }}", fields.join("; ")));
    }

    let mut declaration = String::from(
        "/**\n * Something the interface can offer to do about a failure.\n *\n * Internally tagged by `kind`, so \
         the interface narrows on that field and gets the rest of the object typed.\n */\nexport type \
         SuggestedAction =\n",
    );
    declaration.push_str(&members.join("\n"));
    declaration.push_str(";\n");
    declaration
}

/// The TypeScript type for a JSON value, for the payload fields of a suggestion.
///
/// A closed set rather than a guess: the payloads are short strings and numbers today, and a shape that is neither is
/// reported as `unknown` rather than as `any` — because a field the interface has to narrow is one it should be told
/// about.
const fn ts_type_of(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::String(_) => "string",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Array(_) => "readonly unknown[]",
        serde_json::Value::Object(_) => "Readonly<Record<string, unknown>>",
        serde_json::Value::Null => "null",
    }
}

/// Every declaration this module generates, keyed by the file it belongs in.
///
/// Returned as data rather than written here, so a test decides where the files go and a caller can compare two runs
/// without touching a filesystem.
#[must_use]
pub fn declarations() -> Vec<(&'static str, String)> {
    vec![
        ("ErrorCode.ts", error_code_declaration()),
        ("SuggestedAction.ts", suggested_action_declaration()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_protocol::ErrorCode;

    // ── The error codes ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_error_code_has_a_member() {
        // ★ The property a hand-written file cannot have. `ErrorCode::all()` is the protocol's own list, and the
        // declaration is built from it — so a variant added to the kernel appears here without anyone editing this
        // file, and one that serialises differently appears with the serialised spelling.
        let declaration = error_code_declaration();
        let mut checked = 0;
        for code in ErrorCode::all() {
            let wire = serde_json::to_value(code)
                .expect("a code serialises")
                .as_str()
                .expect("a code is a string on the wire")
                .to_owned();
            assert!(
                declaration.contains(&format!("'{wire}'")),
                "{code:?} serialises as {wire:?}, which is not a member of:\n{declaration}"
            );
            checked += 1;
        }
        assert!(checked >= 20, "only {checked} codes were checked");
    }

    #[test]
    fn a_member_is_the_wire_value_not_the_variant_name() {
        // `CapabilityDenied` becomes `capability_denied`. A declaration built from variant names would have the right
        // *count* and the wrong *strings*, and the interface would never match one — the failure that looks like the
        // kernel refusing every call.
        let declaration = error_code_declaration();
        assert!(declaration.contains("'capability_denied'"), "{declaration}");
        assert!(
            !declaration.contains("CapabilityDenied"),
            "a Rust variant name reached the declaration:\n{declaration}"
        );
        // And the fallback, which every interface branches on.
        assert!(declaration.contains("'internal'"), "{declaration}");
    }

    #[test]
    fn the_error_code_union_is_never_empty() {
        // An empty union would type every code as `never`, so `switch` on it would compile and match nothing. The
        // generated file would still be valid TypeScript, which is what makes this worth asserting.
        let declaration = error_code_declaration();
        assert!(declaration.contains("export type ErrorCode ="), "{declaration}");
        assert!(declaration.matches("  | '").count() >= 20, "{declaration}");
        assert!(declaration.ends_with(";\n"), "{declaration}");
    }

    #[test]
    fn the_error_code_list_is_the_protocols_exactly() {
        // Both directions: a member with no variant would be a code the interface handles and the kernel never sends,
        // which is a `switch` arm that is dead and a reader who wonders why.
        //
        // The *first* member shares its line with `=`, so a parser that looked only at lines beginning with `|` would
        // count one short — a fixture bug that would have made this test pass against a generator that dropped a code.
        let declaration = error_code_declaration();
        let members: Vec<&str> = declaration
            .lines()
            .flat_map(|line| line.split("| '").skip(1))
            .filter_map(|line| line.split('\'').next())
            .collect();
        assert_eq!(members.len(), ErrorCode::all().len(), "{declaration}");
        assert_eq!(members.len(), 22, "the union has {} members", members.len());
        assert!(members.contains(&"capability_denied"), "{members:?}");
        assert!(members.contains(&"internal"), "{members:?}");
    }

    // ── The suggestions ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_suggestion_is_a_member_with_its_tag() {
        // Internally tagged by `kind`, so each member is an object and the tag is a literal. A union of bare strings
        // would type the payload as absent, and the interface's narrowing would find nothing.
        let declaration = suggested_action_declaration();
        for action in synra_protocol::error::SuggestedAction::all() {
            let value = serde_json::to_value(&action).expect("a suggestion serialises");
            let kind = value
                .get("kind")
                .and_then(|kind| kind.as_str())
                .expect("a suggestion is tagged by `kind`");
            assert!(
                declaration.contains(&format!("kind: '{kind}'")),
                "{action:?} is tagged {kind:?}, which is not a member of:\n{declaration}"
            );
        }
    }

    #[test]
    fn a_suggestion_payload_is_typed_rather_than_any() {
        // `any` would silence the type checker on exactly the field the tag exists to type.
        let declaration = suggested_action_declaration();
        assert!(!declaration.contains(": any"), "{declaration}");
        assert!(declaration.contains("kind: '"), "{declaration}");
        assert!(declaration.contains("section: string"), "{declaration}");
    }

    #[test]
    fn the_tag_is_a_literal_and_not_a_type() {
        // `kind: string` would compile and would make the union un-narrowable: every member would match every tag.
        let declaration = suggested_action_declaration();
        assert!(!declaration.contains("kind: string"), "{declaration}");
    }

    // ── The shape of the output ───────────────────────────────────────────────────────────────────

    #[test]
    fn every_declaration_is_valid_typescript_by_shape() {
        // Not a parse — the type check is what the JavaScript package's `check` script does — but the assertions that
        // catch a generator that produced nothing or produced a fragment.
        for (name, declaration) in declarations() {
            assert!(declaration.starts_with("/**"), "{name}: no doc comment");
            assert!(declaration.contains("export type "), "{name}: no export");
            assert!(declaration.ends_with(";\n"), "{name}: unterminated");
            assert!(!declaration.contains("{{"), "{name}: braces were not formatted");
        }
    }

    #[test]
    fn the_declarations_are_deterministic() {
        // A generator whose output depended on a hash map's iteration order would produce a diff on every run, and the
        // person reviewing it would stop reading.
        assert_eq!(declarations(), declarations());
        assert_eq!(error_code_declaration(), error_code_declaration());
        assert_eq!(suggested_action_declaration(), suggested_action_declaration());
    }

    #[test]
    fn a_json_payload_is_typed_by_its_shape() {
        assert_eq!(ts_type_of(&serde_json::json!("a")), "string");
        assert_eq!(ts_type_of(&serde_json::json!(1)), "number");
        assert_eq!(ts_type_of(&serde_json::json!(true)), "boolean");
        assert_eq!(ts_type_of(&serde_json::json!([1])), "readonly unknown[]");
        assert_eq!(ts_type_of(&serde_json::json!({"a": 1})), "Readonly<Record<string, unknown>>");
        assert_eq!(ts_type_of(&serde_json::json!(null)), "null");
    }
}
