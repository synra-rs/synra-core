//! Installing a package the registry names, from the registry's own bytes.
//!
//! # What this pipeline is, in order
//!
//! Fetch a packument from a mirror, pick a version, fetch the tarball it points at, verify the tarball against the
//! integrity string in that document, unpack it, and hand the directory to the installer that already exists. The last
//! step is deliberately not a second installer: consent, version rows and the atomic rename are one implementation, and a
//! registry install is a different **source**, not a different install.
//!
//! # What is trusted, and what is not
//!
//! Every field of a packument is a claim. The tarball address is followed only after the host is checked by the network
//! guard, the integrity string is compared with the bytes, and the manifest inside the tarball is checked by the same
//! verifier a local package goes through — including the signature, if there is one. A registry that lies about a version
//! can therefore make the fetch fail, not make the checks pass.
//!
//! # Why this is separate from the catalogue
//!
//! The catalogue answers "what exists", and is allowed to answer from a cache. This answers "install it", and a cached
//! document is not a reason to install bytes: the packument is fetched again here, and the tarball has never been cached.

use std::path::Path;

use synra_core::install::Installed;
use synra_plugin_host::registry::RegistryConfig;
use synra_protocol::error::ErrorCode;
use synra_registry::Packument;
use synra_store::SynraDb;

use synra_control::Refusal;

/// What the install needs from the network.
///
/// # Why a trait
///
/// Because a test for "an integrity mismatch is refused" must not need a registry, and a pipeline that can only be tested
/// by publishing a package is a pipeline tested by nobody. The real implementation is [`NetworkFetch`]; the interesting
/// cases drive a fake.
pub(crate) trait Fetch {
    /// Reads a URL into memory, with the network guard already applied by the implementation.
    fn get(&self, url: &str) -> Result<Vec<u8>, String>;
}

mod network;
pub(crate) use network::NetworkFetch;

/// Installs `package` at `version` (or the `latest` tag) from a registry.
///
/// # Errors
///
/// [`Refusal`] with `DeviceOffline` when no mirror answered, `Unsupported` when the version or its integrity is absent,
/// `IntegrityMismatch` when the bytes do not match the declared digest, and the installer's own code when the package it
/// unpacked is refused.
#[allow(clippy::too_many_arguments, reason = "the pipeline's inputs: the store, the host, two paths, the network, the package, the version and the clock")]
pub(crate) fn install_from_registry(
    db: &mut SynraDb,
    backend: &synra_plugin_host::Backend,
    plugins_dir: &Path,
    staging_root: &Path,
    fetch: &impl Fetch,
    package: &str,
    version: Option<&str>,
    now_ms: i64,
) -> Result<Installed, Refusal> {
    let config = RegistryConfig::new();
    let mirrors = config.resolve(package);
    if mirrors.is_empty() {
        return Err(Refusal::new(
            ErrorCode::Unsupported,
            format!("no registry is configured for `{package}`"),
        ));
    }

    let mut attempts: Vec<(String, String)> = Vec::new();
    for mirror in mirrors {
        let url = synra_plugin_host::catalog::packument_url(&mirror, package);
        let bytes = match fetch.get(&url) {
            Ok(bytes) => bytes,
            Err(detail) => {
                attempts.push((mirror, detail));
                continue;
            }
        };
        let packument = match std::str::from_utf8(&bytes)
            .map_err(|error| error.to_string())
            .and_then(|text| Packument::parse(text).map_err(|error| error.to_string()))
        {
            Ok(packument) => packument,
            Err(error) => {
                attempts.push((mirror, error));
                continue;
            }
        };
        // ★ Exact, range or `latest` — the same decision the shell makes, in the same place. The old code compared the
        // request with the version map's keys, so `^1.9` was "no such version" even when it matched several.
        let entry = match packument.select(version) {
            Ok(entry) => entry,
            Err(error) => {
                return Err(Refusal::new(ErrorCode::Unsupported, error.to_string()));
            }
        };
        let Some(declared) = entry.dist.integrity.as_deref() else {
            // ★ No integrity is not "skip the check": there is nothing to check the bytes against, and installing them
            // would be trusting the transport. A private mirror that cannot publish integrity has to be fixed.
            return Err(Refusal::new(
                ErrorCode::Unsupported,
                format!(
                    "{} {} carries no integrity string, and bytes nothing vouches for are not installed",
                    package, entry.version
                ),
            ));
        };
        let tarball = fetch
            .get(&entry.dist.tarball)
            .map_err(|detail| Refusal::new(ErrorCode::DeviceOffline, detail))?;
        // ★ Verify and unpack are the kernel's, not this host's: the digest is checked before a single entry is written,
        // and the shell runs the same function. The unpacked copy is outside `plugins/`, so a half-unpacked package is
        // never discovered as an installed plugin.
        let unpacked = synra_core::install::unpack_published_tarball(
            &tarball,
            Some(declared),
            &entry.dist.tarball,
            staging_root,
            now_ms,
        )
        .map_err(|refusal| Refusal::new(refusal.code(), format!("{}: {}", refusal.stage, refusal.reason)))?;
        let outcome = super::install_from_directory(db, backend, plugins_dir, unpacked.path(), now_ms);
        // ★ Removed whether the install worked or not: after a success it is a second copy nothing reads, and after a
        // failure it is a directory the next attempt would refuse.
        unpacked.cleanup();
        return outcome.map_err(|refusal| {
            Refusal::new(
                refusal.code(),
                format!("{} refused the package: {}", refusal.stage, refusal.reason),
            )
        });
    }

    Err(Refusal::new(
        ErrorCode::DeviceOffline,
        format!(
            "no registry answered for `{package}`: {}",
            attempts
                .iter()
                .map(|(mirror, why)| format!("{mirror}: {why}"))
                .collect::<Vec<String>>()
                .join("; ")
        ),
    ))
}

#[cfg(test)]
mod tests;
