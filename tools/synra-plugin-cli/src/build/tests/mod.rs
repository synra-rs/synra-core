use std::path::{Path, PathBuf};

mod planning;
mod reports;

/// A temporary plugin directory.
struct Cleanup(PathBuf);

impl Cleanup {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("synra-build-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("creates");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// Writes a file, making its parents.
    fn write(&self, path: &str, contents: &str) {
        let full = self.0.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("creates");
        }
        std::fs::write(full, contents).expect("writes");
    }

    /// Writes a manifest with the given runtime block and artifact.
    fn manifest(&self, runtime: &str, artifact: &str) {
        self.write(
            "manifest.json",
            &format!(
                r#"{{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": {{ "id": "synra-official" }},
  "sdk": {{ "min": "0.1.0" }},
  "wit": "synra:plugin@1.0.0",
  "runtime": {runtime},
  "capabilities": []
}}"#
            ),
        );
        let _ = artifact;
    }

    fn headless(&self, artifact: &str) {
        self.manifest(
            &format!(r#"{{ "headless": {{ "artifact": "{artifact}", "stateful": false }} }}"#),
            artifact,
        );
    }

    fn ui(&self, artifact: &str) {
        self.manifest(
            &format!(r#"{{ "ui": {{ "artifact": "{artifact}", "entry": "index.html" }} }}"#),
            artifact,
        );
    }

    fn hybrid(&self, wasm: &str, ui: &str) {
        self.manifest(
            &format!(
                r#"{{ "headless": {{ "artifact": "{wasm}", "stateful": false }}, "ui": {{ "artifact": "{ui}", "entry": "index.html" }} }}"#
            ),
            wasm,
        );
    }

    /// A `package.json` with a build script.
    fn package_with_build(&self) {
        self.write("Cargo.toml", "[package.metadata.synra.ui]\nsource = 'ui/dist'\ncommand = ['npm', 'run', 'build']\n");
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
