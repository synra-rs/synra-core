//! Installing a plugin from a directory on this machine, through the checks the design document orders.
//!
//! # Why this is in the kernel and not in a host
//!
//! Because there are two hosts and one pipeline. The daemon and the Tauri shell each bring their own engine and their
//! own data directory, and a second implementation of "verify, then write, then record" would be a second place for the
//! order to drift — and the order *is* the security argument. The one thing a host supplies is what it can do
//! ([`HostFacts`]), which is what the platform-applicability check reads.
//!
//! # Why a directory and not a package format
//!
//! Because a directory is what `synra-plugin build` produces and what an author is testing, and the archive format
//! (`.synra`) does not exist yet. The pipeline is the same one a registry install will run — the source of the bytes
//! is the only difference — so this is the small end of a seam rather than a second install path.
//!
//! # The order is the security argument
//!
//! Every step below is only meaningful if the one before it held, so the sequence is not a preference: digest, then
//! signature, then the manifest, then capabilities, then what the artifact imports. That order lives in
//! [`synra_plugin_host::verify`] and this module does not restate it — it supplies the bytes and writes the result.
//!
//! # What this refuses to do
//!
//! It does not build anything. The design document is explicit that a user's machine never runs `pnpm install`: the
//! package ships built, and an author who has not built it gets a refusal that says so rather than an npm supply-chain
//! surface. It also does not follow a symlink or accept an artifact name that leaves the package directory — an install
//! that read `../../etc/passwd` because a manifest said so would be a manifest that decides what a host reads.
//!

mod archive;
mod automatic;
mod directory;
mod package;
mod replacement;
mod security;
mod writing;

pub use archive::{artifact_names, package_directory};
pub use automatic::{PreparedUpdate, prepare_automatic_update};
pub use directory::{from_directory, update_from_directory};
pub use package::{from_package, package_manifest, unpack_published_tarball, update_from_package, UnpackedTarball};
pub use replacement::{PreparedReplacement, prepare_replacement};

pub(crate) use archive::{discard, discard_unpacked, is_artifact_path};
pub(crate) use directory::{prepare, Prepared};
pub(crate) use security::{signed_publisher, trust_store};

use std::path::PathBuf;
/// The largest single artifact a directory install will read.
///
/// The design document's ceiling for a Wasm artifact. It is checked on the file's metadata **and** on the bytes that
/// were read, because the two are not the same number when something is writing to the file while it is read.
pub(crate) const MAX_ARTIFACT_BYTES: u64 = synra_plugin_ui::artifact::MAX_ARCHIVE_BYTES;

/// The largest package, added up.
///
/// Three artifacts of the maximum size would fit; a package that needs more is one whose author should ship fewer
/// files, and a host that had no total would let a hundred small files exhaust the same memory one large one would.
pub(crate) const MAX_PACKAGE_BYTES: u64 = 96 * 1024 * 1024;

/// What an install produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The plugin's identifier, as its manifest spells it.
    pub plugin_id: String,
    /// The version that was installed.
    pub version: String,
    /// Where it now lives.
    pub path: PathBuf,
    /// The checks that passed with a warning, in sentences.
    ///
    /// A warning is a fact to tell the user — "this plugin's notification action will not work on this host" — and a
    /// report that dropped it would present a plugin that half-works as one that works.
    pub warnings: Vec<String>,
    /// Who signed the package, when it carried a genuine signature.
    ///
    /// ★ Carried out of the install because it is the **question** an interface has to ask next: the fingerprint is what a
    /// person compares, and a caller that had to re-read the signature file from the plugin directory would be reading a
    /// copy the install had already checked. It is also the only place the install knows the publisher was *new* — the
    /// prompt is worth showing for `seen`, and noise for a key the user already decided.
    pub signed_by: Option<SignedPublisher>,
}

/// The publisher of a package, as the install saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPublisher {
    /// The publisher's own identifier.
    pub publisher_id: String,
    /// The key's fingerprint, as a person reads it.
    pub fingerprint: String,
    /// The key, base64. Not shown to the interface; stored because a fingerprint cannot be turned back into a key.
    pub pubkey: String,
}

/// Why an install did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRefusal {
    /// Which step refused: a [`verify::Stage`] name, or `source`/`manifest`/`read`/`write`/`record`.
    pub stage: &'static str,
    /// What was wrong, in a sentence an author can act on.
    pub reason: String,
}

impl InstallRefusal {
    fn new(stage: &'static str, reason: impl Into<String>) -> Self {
        Self { stage, reason: reason.into() }
    }

    /// The wire code this refusal carries.
    ///
    /// # Why one answer is enough for every check
    ///
    /// Because the distinction that matters to a caller is **whose problem it is**. A package a check refused — a path
    /// that is not there, a manifest that does not parse, a signature over other bytes, a dependency cycle — is the
    /// caller's: the detail names the stage and the author can act on it. The two stages that are not the caller's are
    /// the two after every check passed: writing the directory and recording the row, which are this host failing.
    ///
    /// This lives here rather than in each host because both the daemon and the shell answer the same refusal to a
    /// caller, and two mappings would be two chances to disagree about what an install failure means.
    #[must_use]
    pub fn code(&self) -> synra_protocol::error::ErrorCode {
        match self.stage {
            "write" | "record" => synra_protocol::error::ErrorCode::Internal,
            // A published tarball whose bytes are not the ones its own document names. The code exists and callers
            // already branch on it, so folding it into `InvalidArgument` would make a tampered package look like a
            // malformed request.
            "integrity" => synra_protocol::error::ErrorCode::IntegrityMismatch,
            _ => synra_protocol::error::ErrorCode::InvalidArgument,
        }
    }
}


#[cfg(test)]
use std::path::Path;
#[cfg(test)]
use synra_plugin_host::{Backend, verify::HostFacts};
#[cfg(test)]
#[path = "contract_tests.rs"]
mod contract_tests;

#[cfg(test)]
mod tests;
