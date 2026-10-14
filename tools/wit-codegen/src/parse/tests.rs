use crate::parse::{Contract, Gate, ParseError};

/// A miniature contract, for the parser's own tests.
const SMALL: &str = r#"
package synra:plugin@1.0.0;

interface types {
    enum log-level { trace, info }
}

interface host {
    use types.{log-level};

    /// A fact about the environment.
    @ungated
    env-sdk-version: func() -> string;

    /// Write a line.
    @capability("log:*")
    log: func(level: log-level, message: string, ctx: option<string>);
}

interface lifecycle {
    activate: func(config-json: string) -> string;
}

world plugin {
    import host;
    export lifecycle;
}
"#;

fn contract() -> Contract {
    Contract::parse(SMALL).expect("parses")
}

// ── The package ───────────────────────────────────────────────────────────────────────────────

#[test]
fn the_package_and_its_version_are_read() {
    let contract = contract();
    assert_eq!(contract.package, "synra:plugin");
    assert_eq!(contract.version, "1.0.0");
    assert_eq!(contract.world, "plugin");
}

#[test]
fn a_package_with_no_version_is_read_rather_than_refused() {
    // Legal WIT, and refusing it would make this parser stricter than the language for no gain: nothing here
    // compares versions.
    let contract = Contract::parse("package synra:plugin;\nworld plugin { import host; }\ninterface host {\n@ungated\nx: func();\n}")
        .expect("parses");
    assert_eq!(contract.package, "synra:plugin");
    assert_eq!(contract.version, "");
}

#[test]
fn a_file_with_no_package_is_refused() {
    assert_eq!(Contract::parse("interface host {\n}\n"), Err(ParseError::NoPackage));
}

// ── Gates ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn every_function_gets_its_gate() {
    let contract = contract();
    let table = contract.capability_table();
    assert_eq!(table.get("synra:plugin/host#env-sdk-version"), Some(&Gate::Ungated));
    assert_eq!(
        table.get("synra:plugin/host#log"),
        Some(&Gate::Capability("log:*".to_owned()))
    );
}

#[test]
fn a_function_with_no_annotation_is_refused_rather_than_defaulted() {
    // ★ The refusal this module exists for. Defaulting to ungated is a hole; defaulting to gated invents a
    // capability nobody chose. Both are worse than an error naming the line.
    let text = "package synra:plugin@1.0.0;\n\ninterface host {\n    sneaky: func() -> string;\n}\n\nworld plugin { import host; }\n";
    match Contract::parse(text) {
        Err(ParseError::UngatedFunction { line, function }) => {
            assert_eq!(line, 4);
            assert_eq!(function, "sneaky");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_capability_with_no_argument_is_not_a_gate() {
    // `@capability` with nothing after it would otherwise be a capability whose string is empty, which the host
    // could never match — a function reachable by nobody, or worse, by whoever owns the empty capability.
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @capability\n    x: func();\n}\nworld plugin { import host; }\n";
    assert!(matches!(Contract::parse(text), Err(ParseError::UngatedFunction { .. })));
}

#[test]
fn a_comment_between_an_annotation_and_its_function_does_not_drop_the_gate() {
    // The annotation and the function it belongs to are usually adjacent and not always — a multi-paragraph doc
    // comment is the normal case.
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @capability(\"log:*\")\n    ///\n    /// Writes a line, and says why.\n    log: func(message: string);\n}\nworld plugin { import host; }\n";
    let contract = Contract::parse(text).expect("parses");
    assert_eq!(
        contract.capability_table().get("synra:plugin/host#log").cloned(),
        Some(Gate::Capability("log:*".to_owned()))
    );
}

#[test]
fn an_unknown_annotation_is_skipped_rather_than_refused() {
    // A note for a reader — `@since`, say — must not make the build fail, or adding one would be a breaking change.
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @since(\"1.1.0\")\n    /// @capability(\"log:*\")\n    log: func(message: string);\n}\nworld plugin { import host; }\n";
    let contract = Contract::parse(text).expect("parses");
    assert_eq!(
        contract.capability_table().get("synra:plugin/host#log").cloned(),
        Some(Gate::Capability("log:*".to_owned()))
    );
}

#[test]
fn the_last_annotation_wins() {
    // A function carrying two gates is a mistake, and the one nearest it is what a reader assumes. The alternative
    // is a parse whose result depends on the order of a set.
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @capability(\"a\")\n    /// @capability(\"b\")\n    x: func();\n}\nworld plugin { import host; }\n";
    let contract = Contract::parse(text).expect("parses");
    assert_eq!(
        contract.capability_table().get("synra:plugin/host#x"),
        Some(&Gate::Capability("b".to_owned()))
    );
}

// ── The world ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_world_decides_each_interfaces_direction() {
    let contract = contract();
    assert_eq!(contract.host().map(|interface| interface.name.as_str()), Some("host"));
    let exports: Vec<&str> = contract
        .exports()
        .iter()
        .map(|interface| interface.name.as_str())
        .collect();
    assert_eq!(exports, vec!["lifecycle"]);
}

#[test]
fn a_world_naming_an_interface_that_does_not_exist_is_refused() {
    // A component built from it would fail to load, and the message a toolchain gives names the interface rather
    // than the file.
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @ungated\n    x: func();\n}\nworld plugin { import host; export telepathy; }\n";
    assert_eq!(
        Contract::parse(text),
        Err(ParseError::UndefinedInterface { name: "telepathy".to_owned() })
    );
}

#[test]
fn the_world_does_not_have_to_come_last() {
    // The file is written by hand, and a world between two interfaces is legal WIT. A parser that required an order
    // would be a parser an author has to know about.
    let text = "package synra:plugin@1.0.0;\nworld plugin { import host; export lifecycle; }\ninterface host {\n    /// @ungated\n    x: func();\n}\ninterface lifecycle {\n    activate: func();\n}\n";
    let contract = Contract::parse(text).expect("parses");
    assert_eq!(contract.host().map(|interface| interface.name.as_str()), Some("host"));
    assert_eq!(contract.exports().len(), 1);
}

// ── Refusals ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_same_function_twice_is_refused() {
    // The second would silently replace the first, so a capability could be removed by adding a line.
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @capability(\"a\")\n    x: func();\n    /// @ungated\n    x: func();\n}\nworld plugin { import host; }\n";
    match Contract::parse(text) {
        Err(ParseError::DuplicateFunction { line, function, interface }) => {
            assert_eq!(line, 6);
            assert_eq!(function, "x");
            assert_eq!(interface, "host");
        }
        other => panic!("expected a duplicate refusal, got {other:?}"),
    }
}

#[test]
fn a_function_outside_an_interface_is_refused() {
    let text = "package synra:plugin@1.0.0;\n/// @ungated\nx: func();\nworld plugin { }\n";
    assert!(matches!(Contract::parse(text), Err(ParseError::Syntax { .. })));
}

#[test]
fn an_import_outside_a_world_is_refused() {
    // `import host;` inside an interface is not WIT, and reading it as one would put the interface in the wrong
    // direction — which is the difference between "the host provides this" and "the plugin must implement it".
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    import other;\n}\nworld plugin { import host; }\n";
    assert!(matches!(Contract::parse(text), Err(ParseError::Syntax { .. })));
}

// ── What it derives ───────────────────────────────────────────────────────────────────────────

#[test]
fn the_capability_list_is_sorted_and_deduplicated() {
    // Two functions may share a capability — `storage-get` and `storage-keys` are both reads — and the list a
    // permission dialog shows must name it once.
    let contract = contract();
    let capabilities = contract.capabilities();
    assert_eq!(capabilities, vec!["log:*".to_owned()]);
    let mut sorted = capabilities.clone();
    sorted.sort();
    assert_eq!(capabilities, sorted);
}

#[test]
fn the_ungated_functions_are_listed() {
    // The exception the design document names, and the list a reviewer checks: an entry here is a host call any
    // plugin may make.
    let contract = contract();
    let ungated: Vec<&str> = contract
        .ungated()
        .iter()
        .map(|function| function.name.as_str())
        .collect();
    assert_eq!(ungated, vec!["env-sdk-version"]);
}

#[test]
fn the_provided_names_include_both_gated_and_ungated_functions() {
    // The list the plugin CLI checks an artifact's imports against: a component naming a function this file does
    // not declare is one the host cannot answer, whether or not the call would have needed a capability.
    let contract = contract();
    let names = contract.provided_names();
    assert!(names.contains(&"log".to_owned()));
    assert!(names.contains(&"env-sdk-version".to_owned()));
    // And the exported entry points are not on it: those are what the *plugin* provides.
    assert!(!names.contains(&"activate".to_owned()));
}

#[test]
fn the_import_name_is_the_one_a_component_carries() {
    // `synra:plugin/host#log` — what appears in a compiled component's import section. A check against the bare name
    // would match a function in another interface.
    let contract = contract();
    let function = &contract.host().expect("a host").functions[1];
    assert_eq!(function.import_name("synra:plugin", "host"), "synra:plugin/host#log");
}

#[test]
fn the_summary_names_the_world_and_counts_what_it_found() {
    let lines = contract().summary_lines();
    assert!(lines[0].contains("synra:plugin@1.0.0"), "{lines:?}");
    assert!(lines.iter().any(|line| line.contains("world plugin")), "{lines:?}");
    assert!(lines.iter().any(|line| line.starts_with("import host")), "{lines:?}");
    assert!(lines.iter().any(|line| line.contains("gated function")), "{lines:?}");
}

#[test]
fn an_empty_file_parses_to_nothing_rather_than_failing_oddly() {
    // No package, so it is refused — but with the error that says so, not a panic from an index.
    assert_eq!(Contract::parse(""), Err(ParseError::NoPackage));
    assert_eq!(Contract::parse("\n\n// just a comment\n"), Err(ParseError::NoPackage));
}

#[test]
fn parse_errors_explain_themselves() {
    let errors = [
        ParseError::Syntax {
            line: 3,
            reason: "nothing here and nothing expected".to_owned(),
        },
        ParseError::UngatedFunction { line: 4, function: "x".to_owned() },
        ParseError::DuplicateFunction {
            line: 5,
            function: "x".to_owned(),
            interface: "host".to_owned(),
        },
        ParseError::NoPackage,
        ParseError::UndefinedInterface { name: "y".to_owned() },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
