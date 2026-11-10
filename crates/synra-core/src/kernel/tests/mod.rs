//! The kernel's bootstrap order and its two read paths, driven the way a caller drives them.
//!
//! What is asserted here is mostly *ordering* and *agreement*: that a kernel can be built twice over the same store
//! without making a second identity, that a snapshot and the events describe the same state, and that a subscriber
//! which fell behind is told rather than left with a gap.

use synra_observe::crash::StartupVerdict;

use super::*;
use crate::supervisor::TaskSpec;

fn kernel() -> Kernel {
    Kernel::in_memory(&KernelConfig::headless()).expect("a kernel")
}


/// A path of this process's own, which the caller removes.
fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("synra-kernel-{name}-{}", std::process::id()))
}

mod bootstrap;
mod lifecycle;
mod snapshots;
mod state;
