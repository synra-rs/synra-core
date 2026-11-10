//! Plugin sandbox directories, paths and cache management.

use std::path::PathBuf;

use super::PluginDataRoot;

fn unique_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// A sandbox in a fresh temporary directory.
struct Fixture {
    parent: PathBuf,
    sandbox: PluginDataRoot,
}

impl Fixture {
    fn new() -> Self {
        let parent = std::env::temp_dir().join(format!("synra-sandbox-{}", unique_suffix()));
        let _ = std::fs::remove_dir_all(&parent);
        let sandbox =
            PluginDataRoot::ensure(&parent, "@synra-plugin/chat").expect("creates the sandbox");
        Self { parent, sandbox }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.parent);
    }
}

mod layout;
mod resolution;
mod maintenance;
mod proptests;
