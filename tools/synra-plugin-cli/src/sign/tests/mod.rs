use std::path::PathBuf;

use super::{SigningKeyFile, hex_encode};

mod keys;
mod signed_content;
mod verification;

/// A package directory that removes itself.
struct Package {
    path: PathBuf,
}

impl Package {
    /// Writes a manifest and one artifact.
    fn new(name: &str, artifact: &str) -> Self {
        let unique = format!(
            "synra-sign-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        );
        let path = std::env::temp_dir().join(unique.replace(['\\', ':', '.', ' '], "-"));
        std::fs::create_dir_all(&path).expect("a directory");
        let manifest = format!(
            r#"{{
                "id": "@acme/{name}",
                "version": "1.2.3",
                "title": "Hello",
                "publisher": {{ "id": "acme" }},
                "sdk": {{ "min": "1.0.0" }},
                "wit": "1.0.0",
                "capabilities": [],
                "runtime": {{ "headless": {{ "artifact": "{artifact}", "stateful": false }} }}
            }}"#
        );
        std::fs::write(path.join("manifest.json"), manifest).expect("a manifest");
        // A directory artifact is a UI bundle: the path is a directory the fixture leaves empty, so a test can put
        // files in it. A file artifact is a file with a header.
        if artifact == "ui" {
            std::fs::create_dir_all(path.join(artifact)).expect("a bundle directory");
        }
        else {
            std::fs::write(path.join(artifact), b"\0asm\x01\0\0\0").expect("an artifact");
        }
        Self { path }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.path.join(name), bytes).expect("a file");
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.path.join(name)).expect("a file")
    }
}

impl Drop for Package {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn key(seed: u8) -> SigningKeyFile {
    SigningKeyFile::parse(&hex_encode(&[seed; 32])).expect("a key")
}
