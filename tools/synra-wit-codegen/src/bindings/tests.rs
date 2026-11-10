use crate::parse::Contract;

use super::{BindingError, binding_paths, emit_host_trait, emit_sdk_bindings, rust_const, rust_ident, rust_param};

const REAL: &str = include_str!("../../wit/synra-plugin.wit");

fn contract() -> Contract {
    Contract::parse(REAL).expect("the repository's contract parses")
}

// ── The host trait ────────────────────────────────────────────────────────────────────────────

#[test]
fn the_host_trait_has_one_method_per_host_function() {
    // The property that makes the trait worth generating: a function the contract declares is a method the host
    // must implement, so the host cannot silently not provide one.
    let contract = contract();
    let trait_text = emit_host_trait(&contract).expect("renders");
    let host = contract.host().expect("a host");

    assert!(trait_text.contains("pub trait Host {"), "{trait_text}");
    for function in &host.functions {
        let method = format!("fn {}(", rust_ident(&function.name));
        assert!(
            trait_text.contains(&method),
            "{} is missing from the trait",
            function.name
        );
    }
    // And no method beyond them: a trait with a stale method is a host that implements something the contract does
    // not declare.
    let methods = trait_text.matches("    fn ").count();
    assert_eq!(methods, host.functions.len(), "{trait_text}");
}

#[test]
fn a_method_takes_the_parameters_the_contract_declares() {
    let trait_text = emit_host_trait(&contract()).expect("renders");
    assert!(
        trait_text.contains("fn log(level: LogLevel, message: String, ctx: Option<String>)"),
        "{trait_text}"
    );
    assert!(
        trait_text.contains(
            "fn device_send(target: String, event: String, payload: String) -> Outcome"
        ),
        "{trait_text}"
    );
}

#[test]
fn a_function_that_returns_nothing_returns_nothing() {
    // The component model distinguishes "returns nothing" from "returns unit", and the one function in the contract
    // with no return is `plugin-id`'s opposite number — the one a host implements against the model.
    let contract = contract();
    let trait_text = emit_host_trait(&contract).expect("renders");
    let without: Vec<&str> = contract
        .host()
        .expect("a host")
        .functions
        .iter()
        .filter(|function| function.returns.is_none())
        .map(|function| function.name.as_str())
        .collect();

    for name in without {
        let method = format!("fn {}(", rust_ident(name));
        let at = trait_text.find(&method).expect("the method");
        let end = trait_text[at..]
            .find(';')
            .expect("the end of the declaration");
        let declaration = &trait_text[at..at + end];
        assert!(!declaration.contains("->"), "{declaration}");
    }
}

#[test]
fn every_type_the_contract_uses_is_spelled() {
    // ★ The refusal that matters. A type mapped to whatever the generator guessed would compile and would be wrong
    // — the component model would pass a list where the host expected a string, and the failure is at the boundary
    // with no type to blame.
    let contract = contract();
    assert!(emit_host_trait(&contract).is_ok());
    assert!(emit_sdk_bindings(&contract).is_ok());
}

#[test]
fn an_unknown_type_is_refused_rather_than_guessed() {
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @ungated\n    x: func(a: list<float>) -> string;\n}\nworld plugin { import host; }\n";
    let contract = Contract::parse(text).expect("parses");
    match emit_host_trait(&contract) {
        Err(BindingError::UnknownType { function, wit_type }) => {
            assert_eq!(function, "x");
            assert_eq!(wit_type, "list<float>");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_option_of_an_unknown_type_is_refused_too() {
    // The nesting is followed, so `option<list<float>>` is refused for the same reason `list<float>` is.
    let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @ungated\n    x: func(a: option<list<float>>) -> string;\n}\nworld plugin { import host; }\n";
    let contract = Contract::parse(text).expect("parses");
    assert!(matches!(
        emit_host_trait(&contract),
        Err(BindingError::UnknownType { .. })
    ));
}

#[test]
fn a_contract_with_no_host_is_refused() {
    let text = "package synra:plugin@1.0.0;\ninterface lifecycle {\n    activate: func();\n}\nworld plugin { export lifecycle; }\n";
    let contract = Contract::parse(text).expect("parses");
    assert_eq!(emit_host_trait(&contract), Err(BindingError::NoHost));
    assert_eq!(emit_sdk_bindings(&contract), Err(BindingError::NoHost));
}

// ── The SDK bindings ──────────────────────────────────────────────────────────────────────────

#[test]
fn the_sdk_bindings_name_the_import_the_component_model_resolves() {
    // ★ The name is written down rather than derived from the Rust function's, because the two spell the same thing
    // differently. A plugin that called the wrong one would trap at the boundary, and the message would name a
    // function nothing in the repository declares.
    let contract = contract();
    let sdk = emit_sdk_bindings(&contract).expect("renders");

    for function in &contract.host().expect("a host").functions {
        let import = function.import_name(&contract.package, "host");
        assert!(
            sdk.contains(&import),
            "{} does not carry {import}",
            function.name
        );
    }
    assert!(sdk.contains("\"synra:plugin/host#device-list\""), "{sdk}");
}

#[test]
fn the_output_is_sorted_by_the_contracts_order_and_deterministic() {
    // A generator whose output depended on a hash map's order would produce a diff on every run, and the person
    // reviewing it would stop reading.
    assert_eq!(emit_host_trait(&contract()), emit_host_trait(&contract()));
    assert_eq!(
        emit_sdk_bindings(&contract()),
        emit_sdk_bindings(&contract())
    );
}

#[test]
fn neither_output_declares_the_reference_types() {
    // ★ A generated `Outcome` would be a second definition of the thing the plugin and the host exchange, and the
    // two would drift at the first field added. Where they arrive from differs — the trait imports them, the SDK
    // module reaches them through its crate root — and what must not happen either way is a declaration.
    for output in [
        emit_host_trait(&contract()).expect("renders"),
        emit_sdk_bindings(&contract()).expect("renders"),
    ] {
        assert!(!output.contains("pub struct Outcome"), "{output}");
        assert!(!output.contains("pub enum Outcome"), "{output}");
        assert!(!output.contains("pub enum LogLevel"), "{output}");
        assert!(!output.contains("pub struct DeviceTarget"), "{output}");
    }

    // The trait imports them, because nothing above it does.
    let r#trait = emit_host_trait(&contract()).expect("renders");
    assert!(
        r#trait.contains("use synra_plugin_api::{DeviceTarget, LogLevel, Outcome};"),
        "{trait}"
    );
}

#[test]
fn the_host_trait_imports_the_reference_types_explicitly() {
    // ★ An explicit import rather than a glob over the parent. The first version relied on `use super::*` reaching
    // the crate root's re-exports, and inside a module brought in by `include!` a glob does not carry a parent's
    // `pub use` into scope — so the module could see neither, and the fix is to say where the types come from.
    //
    // Only the trait is checked now: the SDK's module is generated by `wit-bindgen`, which emits its own imports,
    // and the file this tool writes for the SDK is a list of constants that names no type at all.
    let r#trait = emit_host_trait(&contract()).expect("renders");
    assert!(
        r#trait.contains("use synra_plugin_api::{DeviceTarget, LogLevel, Outcome};"),
        "{trait}"
    );
    assert!(!r#trait.contains("use super::*"), "{trait}");

    // And the file that remains is constants only: a type in it would be a type nothing declares.
    let imports = emit_sdk_bindings(&contract()).expect("renders");
    assert!(imports.contains("pub const"), "{imports}");
    assert!(
        !imports.contains("pub fn "),
        "the SDK's functions come from `wit-bindgen`: {imports}"
    );
}

#[test]
fn the_doc_comment_says_which_capability_the_call_needs() {
    // The one fact a caller needs at the declaration, and the contract has the rest.
    let trait_text = emit_host_trait(&contract()).expect("renders");
    assert!(trait_text.contains("Requires `log:*`"), "{trait_text}");
    assert!(
        trait_text.contains("Ungated: it reads a fact about the environment"),
        "{trait_text}"
    );
}

#[test]
fn the_binding_paths_are_where_the_generated_files_live() {
    let [host, report, imports] = binding_paths();
    assert!(host.ends_with("host_trait.rs"), "{host}");
    assert!(host.starts_with("../crates/synra-plugin-host/"), "{host}");
    assert_eq!(report, "GENERATED.md");
    assert!(
        imports.starts_with("../crates/synra-plugin-sdk/"),
        "{imports}"
    );
    assert!(imports.ends_with("imports.rs"), "{imports}");
    // ★ And the SDK's *module* is not in the list, because it is no longer a generated file: `wit-bindgen`
    // generates it at compile time from the same contract, so there is nothing to write and nothing to keep in
    // step. A path here would be a file this tool overwrote with `todo!()` stubs.
    assert!(
        !binding_paths().iter().any(|path| path.ends_with("host.rs")),
        "the SDK's module is generated by `wit-bindgen`, not by this tool"
    );
}

#[test]
fn names_are_translated_by_hyphen_alone() {
    // The two languages spell a hyphenated name the same way otherwise, and a transformation beyond that would make
    // the generated signature unrecognisable to someone reading the contract.
    assert_eq!(rust_ident("device-list"), "device_list");
    assert_eq!(rust_const("device-list"), "DEVICE_LIST");
    assert_eq!(rust_param("request-json"), "request_json");
    assert_eq!(rust_ident("log"), "log");
}

#[test]
fn binding_errors_explain_themselves() {
    let errors = [
        BindingError::NoHost,
        BindingError::UnknownType {
            function: "x".to_owned(),
            wit_type: "list<float>".to_owned(),
        },
    ];
    for error in errors {
        let text = error.to_string();
        assert!(text.len() > 30, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
