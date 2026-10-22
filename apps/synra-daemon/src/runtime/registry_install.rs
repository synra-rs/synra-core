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
mod tests {
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::Arc;

    use synra_plugin_host::Backend;

    use super::*;

    /// A registry that answers with bytes this test wrote.
    struct Fake {
        packument: Vec<u8>,
        tarball: Vec<u8>,
    }

    impl Fetch for Fake {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            // The scoped name is percent-encoded in the URL the client builds, so the fake matches the path's tail rather
            // than the spelling of the package.
            if url.contains("acme/hello") && !url.ends_with(".tgz") {
                Ok(self.packument.clone())
            }
            else if url.ends_with(".tgz") {
                Ok(self.tarball.clone())
            }
            else {
                Err(format!("the fake registry has nothing at {url}"))
            }
        }
    }

    /// A scratch root, removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!("synra-registry-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("a scratch directory");
            Self(path)
        }

        fn staging(&self) -> PathBuf {
            self.0.join("staging")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn database() -> SynraDb {
        let mut db = SynraDb::open_in_memory().expect("a database");
        db.migrate().expect("migrates");
        db
    }

    fn backend() -> Backend {
        Backend::new(Arc::new(synra_plugin_host::ScriptedBackend::new()))
    }

    /// A tarball with `package/manifest.json` and `package/plugin.wasm`, as a registry publishes one.
    fn tarball() -> Vec<u8> {
        let manifest = format!(
            r#"{{"id": "@acme/hello", "version": "1.0.0", "title": "Hello",
                "publisher": {{"id": "@acme"}}, "sdk": {{"min": "0.1.0"}},
                "wit": "{}", "capabilities": [{{"cap": "log:*"}}],
                "runtime": {{"headless": {{"artifact": "plugin.wasm", "stateful": false}}}}}}"#,
            synra_plugin_host::host_world()
        );
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in [
            ("package/manifest.json", manifest.into_bytes()),
            ("package/plugin.wasm", b"\0asm\x01\0\0\0".to_vec()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, bytes.as_slice()).expect("a tar entry");
        }
        let tar = builder.into_inner().expect("the tar ends");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar).expect("the gzip body");
        encoder.finish().expect("the gzip ends")
    }

    fn packument(integrity: Option<&str>) -> Vec<u8> {
        let dist = match integrity {
            Some(integrity) => format!(
                r#"{{"tarball":"https://registry.test/@acme/hello/-/hello-1.0.0.tgz","integrity":"{integrity}"}}"#
            ),
            None => r#"{"tarball":"https://registry.test/@acme/hello/-/hello-1.0.0.tgz"}"#.to_owned(),
        };
        serde_json::json!({
            "name": "@acme/hello",
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "name": "@acme/hello", "version": "1.0.0", "dist": serde_json::from_str::<serde_json::Value>(&dist).expect("JSON") } }
        })
        .to_string()
        .into_bytes()
    }

    fn integrity_of(bytes: &[u8]) -> String {
        synra_core::ObjectDigest::of(bytes).as_sri().to_string()
    }

    #[test]
    fn a_registry_package_installs_from_the_bytes_it_declares() {
        let scratch = Scratch::new("install");
        let bytes = tarball();
        let declared = integrity_of(&bytes);
        let fake = Fake { packument: packument(Some(&declared)), tarball: bytes };
        let plugins = scratch.0.join("plugins");

        let installed = install_from_registry(
            &mut database(),
            &backend(),
            &plugins,
            &scratch.staging(),
            &fake,
            "@acme/hello",
            None,
            1_000,
        )
        .expect("installs");

        assert_eq!(installed.plugin_id, "@acme/hello");
        assert_eq!(installed.version, "1.0.0");
        assert!(installed.path.join("plugin.wasm").is_file());
        // The unpacked copy is not left behind: a second copy nothing reads is what makes a data directory grow.
        assert!(
            !scratch.staging().exists() || std::fs::read_dir(scratch.staging()).expect("staging").next().is_none(),
            "the unpacked package was left in the staging directory"
        );
    }

    #[test]
    fn bytes_that_do_not_match_the_declared_integrity_are_refused() {
        let scratch = Scratch::new("mismatch");
        let wrong = integrity_of(b"something else");
        let bytes = tarball();
        let fake = Fake { packument: packument(Some(&wrong)), tarball: bytes };

        let refusal = install_from_registry(
            &mut database(),
            &backend(),
            &scratch.0.join("plugins"),
            &scratch.staging(),
            &fake,
            "@acme/hello",
            None,
            1_000,
        )
        .expect_err("a mismatch is refused");
        assert_eq!(refusal.code, ErrorCode::IntegrityMismatch, "{refusal:?}");
    }

    #[test]
    fn a_document_without_integrity_installs_nothing() {
        let scratch = Scratch::new("no-integrity");
        let bytes = tarball();
        let fake = Fake { packument: packument(None), tarball: bytes };

        let refusal = install_from_registry(
            &mut database(),
            &backend(),
            &scratch.0.join("plugins"),
            &scratch.staging(),
            &fake,
            "@acme/hello",
            None,
            1_000,
        )
        .expect_err("nothing to verify against");
        assert_eq!(refusal.code, ErrorCode::Unsupported, "{refusal:?}");
        assert!(refusal.message.contains("no integrity"), "{refusal:?}");
    }

    #[test]
    fn an_unknown_version_is_named_rather_than_guessed() {
        let scratch = Scratch::new("version");
        let bytes = tarball();
        let fake = Fake { packument: packument(Some("sha256-aaaa")), tarball: bytes };

        let refusal = install_from_registry(
            &mut database(),
            &backend(),
            &scratch.0.join("plugins"),
            &scratch.staging(),
            &fake,
            "@acme/hello",
            Some("2.0.0"),
            1_000,
        )
        .expect_err("a version that is not there is refused");
        assert_eq!(refusal.code, ErrorCode::Unsupported, "{refusal:?}");
        assert!(refusal.message.contains("2.0.0"), "{refusal:?}");
    }

    #[test]
    fn a_registry_that_answers_nothing_is_reported_as_offline() {
        struct Silent;
        impl Fetch for Silent {
            fn get(&self, _: &str) -> Result<Vec<u8>, String> {
                Err("connection refused".to_owned())
            }
        }

        let scratch = Scratch::new("offline");
        let refusal = install_from_registry(
            &mut database(),
            &backend(),
            &scratch.0.join("plugins"),
            &scratch.staging(),
            &Silent,
            "@acme/hello",
            None,
            1_000,
        )
        .expect_err("no mirror answered");
        assert_eq!(refusal.code, ErrorCode::DeviceOffline, "{refusal:?}");
    }
}
