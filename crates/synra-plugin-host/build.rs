//! Regenerates the capability table from the WIT contract, before the crate is compiled.
//!
//! # Why a build script rather than a `just` recipe
//!
//! The design document's CI gate is `cargo test --features ts-export export_bindings && git diff --exit-code`, which
//! catches a generated file that is out of date **after** someone forgets to regenerate it. A build script makes the
//! same statement earlier and without a second command: the file is regenerated as part of building the crate, so a
//! contract change that is not reflected in it cannot produce a binary at all.
//!
//! # Why the file is still committed
//!
//! A generated file that is not in the repository cannot be reviewed, and the table is exactly the thing a reviewer
//! should read: it is the list of what a plugin may call. Committing it and regenerating it keeps the review possible
//! and the drift impossible.
//!
//! # Why a missing contract is not a failure
//!
//! `wit/synra-plugin.wit` is not in the crate's own directory — it belongs to the repository, because the plugin CLI
//! reads it too. A crate published without the repository around it would have no contract to read, and failing there
//! would make the crate unbuildable from a package. So a missing contract leaves the committed table in place, which is
//! the one that shipped.

// ★ A build script's only way to fail is a panic. The workspace forbids `panic` in production code — because the
// kernel must not abort on a condition it could report — and this file is not the kernel: it runs on the machine of
// whoever builds the crate, its output is a compile error, and there is no caller to hand an error to. `Result` from
// `main` is not enough either: cargo reads an unsuccessful *exit* and a build script that returned `Err` from a
// `Result`-returning main would still have to have printed the reason, which is the same thing with more steps.
#![allow(clippy::panic)]

use std::path::{Path, PathBuf};

fn main() {
    // The contract, from the crate's own directory: `crates/synra-plugin-host/../../wit/…`.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let contract = Path::new(&manifest_dir).join("../../wit/synra-plugin.wit");
    let generated = Path::new(&manifest_dir).join("src/generated/capability_table.rs");

    // Rebuild when the contract changes, so editing it is enough.
    println!("cargo::rerun-if-changed={}", contract.display());
    println!("cargo::rerun-if-changed={}", generated.display());

    let Ok(text) = std::fs::read_to_string(&contract) else {
        // See the module docs: a crate without the repository has no contract, and the committed table is what ships.
        return;
    };

    // The generator is called as a library rather than as a program, because a build dependency on a binary's output
    // path is a path that depends on the profile. This crate is published, so it depends on `wit-codegen` by version.
    let contract = match wit_codegen::Contract::parse(&text) {
        Ok(contract) => contract,
        Err(error) => {
            // ★ A contract change that leaves a host function ungated fails the build, which is the point: the
            // alternative is a host call any plugin can make, and nothing in the kernel would be wrong.
            panic!("wit/synra-plugin.wit: {error}");
        }
    };

    let rendered = match wit_codegen::emit_rust(&contract) {
        Ok(rendered) => rendered,
        Err(error) => panic!("the capability table could not be rendered: {error}"),
    };

    // Written only when it differs, so a build does not touch the file's timestamp on every run — which would make
    // every `cargo build` a rebuild of this crate and everything above it.
    if std::fs::read_to_string(&generated).is_ok_and(|current| current == rendered) {
        return;
    }

    if let Some(parent) = generated.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        panic!("{}: {error}", parent.display());
    }
    if let Err(error) = std::fs::write(&generated, rendered) {
        panic!("{}: {error}", generated.display());
    }

    // And the readable report, so a reviewer reads prose rather than a Rust constant.
    let report: PathBuf = Path::new(&manifest_dir).join("../../wit/GENERATED.md");
    let _ = std::fs::write(report, wit_codegen::emit_text(&contract));

    // The trait the host implements, from the same contract and for the same reason as the table: a function the
    // contract gained is a method this crate does not implement, which is a compile error rather than a call that traps
    // at the component boundary.
    let trait_path = Path::new(&manifest_dir).join("src/generated/host_trait.rs");
    match wit_codegen::emit_host_trait(&contract) {
        Ok(rendered) => write_if_changed(&trait_path, &rendered),
        // A type the generator does not know: refused rather than mapped to something that compiles and is wrong at
        // the boundary.
        Err(error) => panic!("the host trait could not be rendered: {error}"),
    }
}

/// Writes a generated file, but only when its contents changed.
///
/// A build script that rewrote every file on every run would touch their timestamps, which makes every `cargo build` a
/// rebuild of this crate and everything above it.
fn write_if_changed(path: &Path, contents: &str) {
    if std::fs::read_to_string(path).is_ok_and(|current| current == contents) {
        return;
    }
    if let Some(parent) = path.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        panic!("{}: {error}", parent.display());
    }
    if let Err(error) = std::fs::write(path, contents) {
        panic!("{}: {error}", path.display());
    }
}