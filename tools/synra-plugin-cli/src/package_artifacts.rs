use synra_plugin_api::Manifest;

/// The declared component and UI bundle, in the order used for packing and signing.
pub(crate) fn artifact_names(manifest: &Manifest) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(runtime) = &manifest.runtime.headless {
        names.push(runtime.artifact.clone());
    }
    if let Some(runtime) = &manifest.runtime.ui {
        names.push(runtime.artifact.clone());
    }
    names
}
