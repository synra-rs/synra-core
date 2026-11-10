use std::path::Path;

use clap::Parser as _;

use crate::args::Cli;

mod arguments;
mod build;
mod scaffold;
mod signing;

struct Cleanup(std::path::PathBuf);

impl Cleanup {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("synra-exec-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("creates");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, path: &str, contents: &[u8]) {
        let full = self.0.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).expect("creates");
        }
        std::fs::write(full, contents).expect("writes");
    }

    fn plugin(&self) {
        self.write(
            "manifest.json",
            br#"{
  "id": "@synra-plugin/example",
  "version": "1.0.0",
  "title": "Example",
  "publisher": { "id": "synra-official" },
  "sdk": { "min": "0.1.0" },
  "wit": "synra:plugin@1.0.0",
  "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } },
  "capabilities": []
}"#,
        );
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cli(args: &[&str]) -> Cli {
    Cli::try_parse_from(args).expect("parses")
}
