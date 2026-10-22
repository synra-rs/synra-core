//! Verified bytes for an explicit update, retained across the host's lifecycle switch.

use std::path::{Path, PathBuf};

use synra_plugin_host::{Backend, verify::HostFacts};
use synra_store::SynraDb;

use super::{InstallRefusal, Installed, Prepared, prepare, signed_publisher, writing};

/// A fully verified manual replacement, bound to the version it replaces.
#[derive(Debug)]
pub struct PreparedReplacement {
    prepared: Prepared,
    plugins_dir: PathBuf,
    previous_version: String,
}

impl PreparedReplacement {
    /// The identifier in the verified bytes.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        self.prepared.manifest.id.as_str()
    }

    /// The version in the verified bytes.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.prepared.manifest.version
    }

    /// Commits retained bytes after the host stops the old instance.
    ///
    /// # Errors
    ///
    /// Refuses a changed installed version or a newly revoked signing key, plus the installer's write failures.
    pub fn install(self, db: &mut SynraDb, now_ms: i64) -> Result<Installed, InstallRefusal> {
        if current(db, &self.prepared)? != self.previous_version {
            return Err(InstallRefusal::new(
                "update",
                "the installed version changed during preparation",
            ));
        }
        writing::write(db, &self.plugins_dir, now_ms, self.prepared, true)
    }
}

/// Verifies a newer package without changing files, grants or the running instance.
///
/// Explicit updates may introduce permissions or prereleases. Publisher verification still rejects unapproved key
/// changes. The writer retains consent only when the signer and capability set permit it.
///
/// # Errors
///
/// The normal install checks, or `update` when the target is absent or does not advance its installed version.
pub fn prepare_replacement(
    db: &SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    source: &Path,
    now_ms: i64,
    host: HostFacts,
) -> Result<PreparedReplacement, InstallRefusal> {
    let prepared = prepare(db, backend, source, now_ms, host, true)?;
    let previous_version = current(db, &prepared)?;
    if synra_plugin_api::manifest::compare_versions(&prepared.manifest.version, &previous_version)
        .map_err(|error| InstallRefusal::new("update", error.to_string()))?
        != std::cmp::Ordering::Greater
    {
        return Err(InstallRefusal::new(
            "update",
            "an update must advance the installed version",
        ));
    }
    Ok(PreparedReplacement {
        prepared,
        plugins_dir: plugins_dir.to_owned(),
        previous_version,
    })
}

fn current(db: &SynraDb, prepared: &Prepared) -> Result<String, InstallRefusal> {
    let version = db
        .active_plugin(prepared.manifest.id.as_str())
        .map_err(|error| InstallRefusal::new("update", error.to_string()))?
        .ok_or_else(|| InstallRefusal::new("update", "the plugin is no longer installed"))?
        .version;
    if let Some(signer) = prepared.signature.as_deref().and_then(signed_publisher) {
        let publishers = db
            .publishers()
            .map_err(|error| InstallRefusal::new("update", error.to_string()))?;
        if publishers.iter().any(|row| {
            row.fingerprint == signer.fingerprint && row.trust == synra_store::TRUST_REVOKED
        }) {
            return Err(InstallRefusal::new("update", "the signing key was revoked"));
        }
    }
    Ok(version)
}
