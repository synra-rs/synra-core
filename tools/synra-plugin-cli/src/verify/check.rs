//! Reports manifest, binary contract and artifact findings.

use synra_plugin_api::manifest::{Manifest, ManifestContext};
use synra_plugin_host::host_surface;

use super::{
    ComponentInfo, Finding, MAX_UI_BYTES, MAX_UI_FILES, MAX_WASM_BYTES, Target, VerifyReport,
};

/// Checks actual artifact metadata against the manifest and the production host surface.
#[must_use]
pub fn verify(target: &Target) -> VerifyReport {
    let mut findings = Vec::new();
    let manifest = manifest(target, &mut findings);
    if manifest
        .as_ref()
        .is_none_or(|manifest| manifest.runtime.headless.is_some())
    {
        match &target.wasm {
            Err(error) => findings.push(Finding::fail(
                "wasm",
                error,
                "run synra-plugin build and check the manifest artifact path",
            )),
            Ok(component) => component_findings(component, manifest.as_ref(), &mut findings),
        }
    }
    if manifest
        .as_ref()
        .is_none_or(|manifest| manifest.runtime.ui.is_some())
    {
        match &target.ui_bundle {
            Err(error) => findings.push(Finding::fail(
                "ui",
                error,
                "build the declared UI bundle and entry file",
            )),
            Ok((0, _)) => findings.push(Finding::fail(
                "ui",
                "the UI directory is empty",
                "build the declared entry file",
            )),
            Ok((files, bytes)) if *files > MAX_UI_FILES || *bytes > MAX_UI_BYTES => {
                findings.push(Finding::fail(
                    "ui",
                    format!(
                        "the UI bundle has {files} files and {bytes} bytes and exceeds its limits"
                    ),
                    "remove unnecessary files from the bundle",
                ))
            }
            Ok((files, bytes)) => {
                findings.push(Finding::pass("ui", format!("{files} files, {bytes} bytes")))
            }
        }
    }
    VerifyReport {
        plugin_id: manifest.as_ref().map(|manifest| manifest.id.to_string()),
        version: manifest.as_ref().map(|manifest| manifest.version.clone()),
        findings,
    }
}

fn manifest(target: &Target, findings: &mut Vec<Finding>) -> Option<Manifest> {
    let text = match &target.manifest_json {
        Ok(text) => text,
        Err(error) => {
            findings.push(Finding::fail(
                "manifest",
                error,
                "check manifest.json in the plugin directory",
            ));
            return None;
        }
    };
    let parsed = Manifest::from_json(text).and_then(|manifest| {
        let context = ManifestContext {
            host_sdk: Some(manifest.sdk.min.clone()),
            host_wit: Some(synra_plugin_host::host_world()),
            ..ManifestContext::default()
        };
        manifest.validate(&context)?;
        Ok(manifest)
    });
    match parsed {
        Ok(manifest) => {
            findings.push(Finding::pass("manifest", "parses and validates"));
            Some(manifest)
        }
        Err(error) => {
            findings.push(Finding::fail(
                "manifest",
                format!("the manifest does not parse or validate: {error}"),
                "check the named field against the schema and host WIT contract",
            ));
            None
        }
    }
}

fn component_findings(
    component: &ComponentInfo,
    manifest: Option<&Manifest>,
    findings: &mut Vec<Finding>,
) {
    if component.bytes == 0 || component.bytes > MAX_WASM_BYTES {
        findings.push(Finding::fail(
            "wasm",
            if component.bytes == 0 {
                "the component is empty".to_owned()
            } else {
                format!(
                    "the component is {} bytes and must be between 1 and {MAX_WASM_BYTES} bytes",
                    component.bytes
                )
            },
            "rebuild a valid component within the size limit",
        ));
        return;
    }
    findings.push(Finding::pass(
        "wasm",
        format!(
            "{} bytes and a validated plugin WIT component",
            component.bytes
        ),
    ));
    if component.bytes > MAX_WASM_BYTES / 2 {
        findings.push(Finding::warn(
            "wasm-size",
            format!("{} bytes is over half the limit", component.bytes),
            "enable size optimisation or move work into the host",
        ));
    }
    let Some(manifest) = manifest else {
        return;
    };
    let declared = match manifest.capability_set() {
        Ok(declared) => declared,
        Err(error) => {
            findings.push(Finding::fail(
                "imports",
                error.to_string(),
                "fix the manifest capabilities",
            ));
            return;
        }
    };
    let denied = host_surface::undeclared_imports(&component.imports, &declared);
    if denied.is_empty() {
        findings.push(Finding::pass(
            "imports",
            format!(
                "{} actual import(s) covered by the manifest",
                component.imports.len()
            ),
        ));
    }
    for import in denied {
        let detail = if host_surface::provides(&import) {
            format!("{import} is not covered by manifest capabilities")
        } else {
            format!("{import} is not provided by this SDK host contract")
        };
        findings.push(Finding::fail(
            "imports",
            detail,
            "remove the import or declare the required SDK capability",
        ));
    }
}
