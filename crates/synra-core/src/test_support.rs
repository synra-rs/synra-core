//! Fixtures shared by the session and transfer tests.

use std::path::PathBuf;

use tempfile::{Builder, TempDir};

pub(crate) fn temp_dir(tag: &str) -> TempDir {
    Builder::new().prefix(tag).tempdir().expect("a unique directory per test")
}

pub(crate) fn file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("writes the test file");
    path
}
