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
use crate::transfer::ObjectDigest;

#[cfg(test)]
#[path = "contract_tests.rs"]
mod contract_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::sync::Arc;

    /// A scratch directory for one test, removed by the test.
    fn scratch(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("synra-package-{label}-{}-{}", std::process::id(), crate::reading_millis(synra_store::sqlite::now_ms())))
    }

    /// A manifest naming one headless artifact, in the shape the verifier accepts.
    fn manifest() -> String {
        manifest_version("1.0.0")
    }

    /// The same manifest at another version, for the update tests.
    fn manifest_version(version: &str) -> String {
        format!(
            r#"{{"id": "@acme/hello", "version": "{version}", "title": "Hello",
                "publisher": {{"id": "@acme"}}, "sdk": {{"min": "0.1.0"}},
                "wit": "{}",
                "capabilities": [{{"cap": "log:*"}}],
                "runtime": {{"headless": {{"artifact": "plugin.wasm", "stateful": false}}}}}}"#,
            synra_plugin_host::host_world()
        )
    }

    /// A directory an installer would take: a manifest and one artifact.
    fn write_source(directory: &Path) {
        std::fs::create_dir_all(directory).expect("the source directory");
        std::fs::write(directory.join("manifest.json"), manifest()).expect("a manifest");
        std::fs::write(
            directory.join("plugin.wasm"),
            synra_testkit::component::inert_component().expect("a valid component"),
        )
        .expect("an artifact");
    }

    fn backend() -> Backend {
        Backend::new(Arc::new(synra_plugin_host::ScriptedBackend::new()))
    }

    fn database() -> synra_store::SynraDb {
        let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
        db.migrate().expect("migrates");
        db
    }

    #[test]
    fn a_package_installs_what_the_directory_inside_it_would() {
        let root = scratch("valid");
        let source = root.join("source");
        write_source(&source);
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let archive = root.join("hello.synra");
        package_directory(&source, &archive).expect("the package is written");

        let mut db = database();
        let installed =
            from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
                .expect("the package installs");

        assert_eq!(installed.plugin_id, "@acme/hello");
        assert_eq!(installed.version, "1.0.0");
        // ★ The sanitised name, which is what `Paths::plugin_dir`, the removal and the sweep all use. A scoped id used raw
        // put the artifact two levels down and made an uninstall delete a directory that never existed.
        assert_eq!(installed.path, plugins.join("acme+hello"));
        assert!(installed.path.join("manifest.json").is_file(), "the manifest was not written");
        assert!(installed.path.join("plugin.wasm").is_file(), "the artifact was not written");
        // ★ The origin travels with the copy: a backup can list the plugin, and only this note can say where to get it
        // back from on this host.
        let source_note: serde_json::Value = serde_json::from_slice(
            &std::fs::read(installed.path.join("source.json")).expect("the source note"),
        )
        .expect("source.json is JSON");
        let noted = PathBuf::from(
            source_note["path"].as_str().expect("a path in the source note"),
        );
        assert_eq!(
            std::fs::canonicalize(noted).expect("a canonical noted source"),
            std::fs::canonicalize(&archive).expect("a canonical archive"),
            "the source note names the unpacked temporary directory rather than the package"
        );
        assert!(
            !root.join(".install-staging").read_dir().expect("the staging directory").any(|_| true),
            "the unpacked archive was left behind"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_manifest_can_be_read_without_installing_it() {
        // ★ The update path needs the version before it replaces anything, and a package's manifest is inside the
        // archive. Reading it must not leave a plugin, a staging directory or an installed row behind.
        let root = scratch("package-inspect");
        let source = root.join("source");
        write_source(&source);
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let archive = root.join("hello.synra");
        package_directory(&source, &archive).expect("the package");

        let manifest = package_manifest(&archive).expect("a readable manifest");

        assert_eq!(manifest.id.as_str(), "@acme/hello");
        assert_eq!(manifest.version, "1.0.0");
        assert!(plugins.read_dir().expect("the plugins directory").next().is_none(), "nothing was installed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_can_replace_an_installed_plugin() {
        // ★ The update path for the interface's "install a package" flow: the same `.synra`, replacing the directory rather
        // than being refused because the identifier is already installed.
        let root = scratch("package-update");
        let first = root.join("first");
        write_source(&first);
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let first_archive = root.join("hello-1.synra");
        package_directory(&first, &first_archive).expect("the first package");
        let mut db = database();
        from_package(&mut db, &backend(), &plugins, &first_archive, 1_000, HostFacts::headless())
            .expect("installs");

        let second = root.join("second");
        std::fs::create_dir_all(&second).expect("the second source");
        std::fs::write(second.join("manifest.json"), manifest_version("2.0.0"))
            .expect("a manifest");
        std::fs::write(
            second.join("plugin.wasm"),
            synra_testkit::component::inert_component().expect("a valid component"),
        )
        .expect("an artifact");
        let second_archive = root.join("hello-2.synra");
        package_directory(&second, &second_archive).expect("the second package");

        let updated = update_from_package(
            &mut db,
            &backend(),
            &plugins,
            &second_archive,
            2_000,
            HostFacts::headless(),
        )
        .expect("updates");
        assert_eq!(updated.version, "2.0.0");
        assert_eq!(
            db.active_plugin_version("@acme/hello").expect("a version").map(|(version, _)| version),
            Some("2.0.0".to_owned()),
            "the version row did not move"
        );
        let note: serde_json::Value = serde_json::from_slice(
            &std::fs::read(updated.path.join("source.json")).expect("the source note"),
        )
        .expect("source.json is JSON");
        assert_eq!(
            std::fs::canonicalize(PathBuf::from(note["path"].as_str().expect("a path"))).expect("canonical"),
            std::fs::canonicalize(&second_archive).expect("a canonical archive"),
            "the note should name the package that replaced the first one"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_directory_install_records_where_it_came_from() {
        // ★ The directory is the package the user still has; unlike the archive path, nothing removes it after the
        // install, so the note is a reinstall instruction rather than a name of something that is already gone.
        let root = scratch("directory-origin");
        let source = root.join("source");
        write_source(&source);
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");

        let installed = from_directory(&mut database(), &backend(), &plugins, &source, 1_000, HostFacts::headless())
            .expect("installs");
        let note: serde_json::Value = serde_json::from_slice(
            &std::fs::read(installed.path.join("source.json")).expect("the source note"),
        )
        .expect("source.json is JSON");
        let noted = PathBuf::from(note["path"].as_str().expect("a path"));
        assert_eq!(
            std::fs::canonicalize(noted).expect("a canonical noted source"),
            std::fs::canonicalize(&source).expect("a canonical source"),
            "the note does not name the directory it was installed from"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_that_escapes_its_directory_is_refused_before_anything_is_installed() {
        // ★ The archive's own rules, not the installer's: an entry named `../escape.txt` is a package asking to write
        // outside the directory it is unpacked into. `unpack` refuses it and removes what it wrote, and the installer is
        // never reached.
        let root = scratch("escape");
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let archive = root.join("evil.synra");
        {
            let file = std::fs::File::create(&archive).expect("a file");
            let mut writer = zip::ZipWriter::new(file);
            for (name, bytes) in [
                ("manifest.json", manifest().into_bytes()),
                ("../escape.txt", b"outside".to_vec()),
            ] {
                writer
                    .start_file(name, zip::write::SimpleFileOptions::default())
                    .expect("an entry");
                writer.write_all(&bytes).expect("the bytes");
            }
            writer.finish().expect("a finished archive");
        }

        let mut db = database();
        let refused = from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
            .expect_err("the entry escapes");

        assert_eq!(refused.stage, "archive", "{}", refused.reason);
        assert!(!root.join("escape.txt").exists(), "the entry was written outside the package");
        assert!(
            !plugins.join("@acme/hello").exists(),
            "a refused package left an installed plugin behind"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_package_with_no_manifest_is_refused_by_the_installer() {
        let root = scratch("no-manifest");
        let plugins = root.join("plugins");
        std::fs::create_dir_all(&plugins).expect("the plugins directory");
        let archive = root.join("empty.synra");
        {
            let file = std::fs::File::create(&archive).expect("a file");
            let mut writer = zip::ZipWriter::new(file);
            writer
                .start_file("plugin.wasm", zip::write::SimpleFileOptions::default())
                .expect("an entry");
            writer.write_all(b"\0asm\x01\0\0\0").expect("the bytes");
            writer.finish().expect("a finished archive");
        }

        let mut db = database();
        let refused = from_package(&mut db, &backend(), &plugins, &archive, 1_000, HostFacts::headless())
            .expect_err("there is no manifest");

        assert_eq!(refused.stage, "read", "{}", refused.reason);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn packaging_an_installed_plugin_leaves_the_unpacked_ui_out() {
        // ★ `ui.zip` is the artifact; `ui/` is this device's rendering of it. Shipping both would send the same files
        // twice and give the installer two sources for one directory.
        let root = scratch("ui");
        let source = root.join("source");
        write_source(&source);
        std::fs::create_dir_all(source.join("ui")).expect("a ui directory");
        std::fs::write(source.join("ui").join("index.html"), b"<html></html>").expect("a ui file");
        std::fs::write(source.join("ui.zip"), b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").expect("a ui zip");
        let archive = root.join("hello.synra");
        package_directory(&source, &archive).expect("the package is written");

        let mut zip = zip::ZipArchive::new(std::fs::File::open(&archive).expect("the archive")).expect("a zip");
        let mut names: Vec<String> = (0..zip.len())
            .map(|index| zip.by_index(index).expect("an entry").name().to_owned())
            .collect();
        names.sort();

        assert!(names.contains(&"ui.zip".to_owned()), "{names:?}");
        assert!(!names.iter().any(|name| name.starts_with("ui/")), "the unpacked UI was packaged: {names:?}");
        assert!(names.contains(&"manifest.json".to_owned()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_published_tarball_without_a_digest_is_refused_before_anything_is_written() {
        // ★ "No integrity string" is not "skip the check": there is nothing to compare the bytes against. It is refused
        // with the same `IntegrityMismatch` code a wrong digest gets, because both mean the bytes are not vouched for.
        let root = scratch("tarball-no-integrity");
        let refusal = unpack_published_tarball(b"not even a tarball", None, "hello.tgz", &root, 1)
            .expect_err("bytes nothing vouches for are not opened");
        assert_eq!(refusal.stage, "integrity");
        assert_eq!(refusal.code(), synra_protocol::error::ErrorCode::IntegrityMismatch);
        assert!(!root.exists(), "nothing should have been created: {}", root.display());
    }

    #[test]
    fn a_published_tarball_whose_bytes_do_not_match_its_digest_is_refused() {
        let root = scratch("tarball-mismatch");
        let declared = ObjectDigest::of(b"the bytes the publisher signed").as_sri().to_string();
        let refusal = unpack_published_tarball(b"other bytes", Some(&declared), "hello.tgz", &root, 1)
            .expect_err("a mismatch is not unpacked");
        assert_eq!(refusal.stage, "integrity");
        assert!(refusal.reason.contains("digest") || refusal.reason.contains("integrity"), "{}", refusal.reason);
        assert!(!root.exists(), "nothing should have been created: {}", root.display());
    }
}
