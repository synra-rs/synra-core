use std::path::Path;

use clap::Parser as _;
use crate::args::DaemonArgs;
use crate::lock::LockFile;
use crate::plan::{DaemonOptions, DaemonPlan};

mod claim_lifecycle;
mod decision;
mod diagnostics;

/// A directory that exists for the duration of one test.
struct Cleanup(std::path::PathBuf);

impl Cleanup {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("synra-startup-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("creates");
        Self(dir)
    }

    /// The data directory itself.
    ///
    /// No extra level: `--data-dir` names the data directory rather than a parent of it, and a fixture that added
    /// one would be testing a layout the daemon does not use — which is exactly the bug this fixture found once
    /// already.
    fn data(&self) -> std::path::PathBuf {
        self.0.clone()
    }

    /// Writes a claim for a heartbeat at a reading.
    ///
    /// The path comes from the *plan* rather than from the raw root, because `Paths::under` canonicalises the data
    /// directory — on Windows that adds a `\\?\` prefix — so a claim written beside the root is a claim the daemon
    /// never looks at. A fixture that wrote to the wrong path would make every case look like a free directory.
    fn write_claim(&self, heartbeat_ms: u64, pid: u32) {
        let plan = DaemonPlan::resolve(&DaemonOptions {
            data_dir: self.data(),
            listen_port: 0,
            ..DaemonOptions::default()
        })
        .expect("resolves");
        let lock = LockFile::claim(pid, "0.1.0", heartbeat_ms);
        std::fs::write(plan.lock_path(), serde_json::to_string(&lock).expect("serialises"))
            .expect("writes");
    }

    /// The path a claim for this directory would be read from.
    fn lock_path(&self) -> std::path::PathBuf {
        DaemonPlan::resolve(&DaemonOptions {
            data_dir: self.data(),
            listen_port: 0,
            ..DaemonOptions::default()
        })
        .expect("resolves")
        .lock_path()
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn args(dir: &Path, extra: &[&str]) -> DaemonArgs {
    let root = dir.display().to_string();
    let mut argv = vec!["synra-daemon", "--data-dir", root.as_str(), "--listen-port", "0"];
    argv.extend_from_slice(extra);
    DaemonArgs::try_parse_from(argv).expect("parses")
}
