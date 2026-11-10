use std::path::{Path, PathBuf};

use synra_plugin_api::Manifest;
use synra_plugin_host::Backend;
use synra_plugin_host::verify::HostFacts;

use super::*;

/// A `.tgz` a registry published, opened into a directory this process owns.
///
/// The caller installs from [`Self::path`] and **must** call [`Self::cleanup`]: the directory is outside `plugins/` so a
/// half-unpacked package is never discovered as an installed plugin, and leaving it behind is a copy nothing reads.
#[derive(Debug)]
pub struct UnpackedTarball {
    directory: PathBuf,
    files: Vec<PathBuf>,
}

impl UnpackedTarball {
    /// The package root the installer takes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.directory
    }

    /// Removes the unpacked copy.
    pub fn cleanup(self) {
        discard_unpacked(&self.directory, &self.files);
    }
}

/// Verifies a published tarball against its own document and opens it for the installer.
///
/// # ★ Why both hosts call this
///
/// Because the ordering is the security argument: **the digest is checked before a single entry is written**. The daemon
/// and the shell each had their own copy of "check, then extract, then install", with their own error mappings and their
/// own staging directories. The copies agreed today; the next change to either would have made "tampered bytes are never
/// unpacked" true in one host and false in the other.
///
/// # The document's digest is not optional
///
/// A package whose entry carries no integrity string is refused rather than trusted. There is nothing to compare the
/// bytes against, which is not the same claim as "the bytes are correct" — a private mirror that cannot publish an
/// integrity string has to be fixed, not accommodated.
///
/// # Errors
///
/// [`InstallRefusal`] with stage `integrity` for missing or mismatching bytes, and `archive` for a tarball the extractor
/// refuses. Nothing is left on disk in either case.
pub fn unpack_published_tarball(
    tarball: &[u8],
    declared_integrity: Option<&str>,
    label: &str,
    staging_root: &Path,
    now_ms: i64,
) -> Result<UnpackedTarball, InstallRefusal> {
    let Some(declared) = declared_integrity else {
        return Err(InstallRefusal::new(
            "integrity",
            format!(
                "{label} carries no integrity string, and bytes nothing vouches for are not installed"
            ),
        ));
    };
    synra_plugin_host::registry::check_integrity(label, declared, tarball)
        .map_err(|failure| InstallRefusal::new("integrity", failure.to_string()))?;

    std::fs::create_dir_all(staging_root).map_err(|error| {
        InstallRefusal::new("archive", format!("{}: {error}", staging_root.display()))
    })?;
    // ★ A counter as well as the clock and the pid: two installs from the same process in the same millisecond are
    // exactly what a test does, and one of them would find the other's directory and refuse.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let directory = staging_root.join(format!("tarball.{now_ms}.{}.{unique}", std::process::id()));
    std::fs::create_dir(&directory).map_err(|error| {
        InstallRefusal::new("archive", format!("{}: {error}", directory.display()))
    })?;

    match synra_registry::extract_tgz(
        tarball,
        &directory,
        Some("package"),
        synra_registry::Limits::default(),
    ) {
        Ok(files) => Ok(UnpackedTarball { directory, files }),
        Err(error) => {
            // The extractor removed the entries it wrote; the directory it wrote them into is this function's.
            let _ = std::fs::remove_dir(&directory);
            Err(InstallRefusal::new("archive", error.to_string()))
        }
    }
}

/// Installs a plugin from a `.synra` archive.
///
/// # What the archive is
///
/// A zip of the directory [`from_directory`] takes: `manifest.json`, the artifacts the manifest names, and
/// `signature.json` when the publisher signed it. The container is zip because the UI half is already one and the same
/// reader covers both — and because the unpacking rules that matter (no `..`, no absolute path, no link, entry and size
/// limits) are about archives rather than about UI bundles, so there is one implementation of them.
///
/// # Why the unpack goes through the UI crate
///
/// Because `synra_plugin_ui::artifact::unpack` is the tested implementation of those rules, with a plan-then-write split
/// and a cleanup of what a refusal already wrote. A second unpacker here would be a second place for a zip-slip check to
/// be forgotten.
///
/// # Errors
///
/// [`InstallRefusal`] with stage `archive` for an archive the rules refuse, and any stage [`from_directory`] reports.
pub fn from_package(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    archive: &Path,
    now_ms: i64,
    host: HostFacts,
) -> Result<Installed, InstallRefusal> {
    from_package_inner(db, backend, plugins_dir, archive, now_ms, host, false)
}

/// Replaces the installed version of a plugin with the package at `archive`.
///
/// # Why this exists
///
/// Because an update can arrive as a `.synra` file just as easily as a directory — the interface's "install a package"
/// flow selects a file — and the only difference from [`from_package`] is the last step: the old directory is moved aside
/// rather than the package being refused for an identifier that is already installed.
///
/// # Errors
///
/// As [`from_package`], plus `update` when nothing is installed at the identifier.
pub fn update_from_package(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    archive: &Path,
    now_ms: i64,
    host: HostFacts,
) -> Result<Installed, InstallRefusal> {
    from_package_inner(db, backend, plugins_dir, archive, now_ms, host, true)
}

/// Reads a package's manifest without installing it.
///
/// # Why this exists
///
/// The update path has to know the version **before** it replaces the old directory, because the migration runs against
/// the old instance first. A directory's manifest can be read in place; a package's is inside the archive, and
/// `from_package` only reveals it after it has already unpacked and verified everything. This is the same unpack, with
/// the files thrown away and the manifest kept — a package whose bytes cannot be unpacked is refused here exactly as it
/// would be by the installer.
///
/// # Errors
///
/// [`InstallRefusal`] with stage `archive` for an archive that cannot be unpacked or whose manifest does not parse.
pub fn package_manifest(archive: &Path) -> Result<Manifest, InstallRefusal> {
    let staging_root = archive
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".package-inspect");
    std::fs::create_dir_all(&staging_root).map_err(|error| {
        InstallRefusal::new("archive", format!("{}: {error}", staging_root.display()))
    })?;
    let unpacked = staging_root.join(format!(
        "inspect.{}.{}",
        std::process::id(),
        synra_store::sqlite::now_ms()
    ));
    std::fs::create_dir(&unpacked).map_err(|error| {
        InstallRefusal::new("archive", format!("{}: {error}", unpacked.display()))
    })?;

    let outcome = (|| {
        synra_plugin_ui::artifact::unpack(
            archive,
            &unpacked,
            synra_plugin_ui::artifact::ArchiveLimits::package(),
        )
        .map_err(|error| InstallRefusal::new("archive", error.to_string()))?;
        let text = std::fs::read_to_string(unpacked.join("manifest.json")).map_err(|error| {
            InstallRefusal::new(
                "archive",
                format!("the manifest could not be read: {error}"),
            )
        })?;
        Manifest::from_json(&text).map_err(|error| {
            InstallRefusal::new("archive", format!("the manifest is not readable: {error}"))
        })
    })();
    // ★ Through the one owner of a recursive delete rather than `std::fs::remove_dir_all` here.
    //
    // 11 §D2's guard allows exactly two production files to remove a directory tree, and this is not one of them. The
    // first version of `package_manifest` called `remove_dir_all` directly and made the guard red on the commit that
    // added it — the rule working as intended, on the round that introduced a temp tree nobody had removed before.
    let _ = synra_store::remove_tree(&staging_root, &unpacked);
    outcome
}

#[allow(
    clippy::too_many_arguments,
    reason = "the package's inputs, plus whether it replaces an installed copy"
)]
fn from_package_inner(
    db: &mut synra_store::SynraDb,
    backend: &Backend,
    plugins_dir: &Path,
    archive: &Path,
    now_ms: i64,
    host: HostFacts,
    replace: bool,
) -> Result<Installed, InstallRefusal> {
    let staging_root = plugins_dir
        .parent()
        .unwrap_or(plugins_dir)
        .join(".install-staging");
    std::fs::create_dir_all(&staging_root).map_err(|error| {
        InstallRefusal::new("archive", format!("{}: {error}", staging_root.display()))
    })?;
    // Outside `plugins/` for the same reason the installer's own staging is: a directory with a manifest under the
    // plugins tree is discovered as an installed plugin, so a half-unpacked archive must not be there.
    let unpacked = staging_root.join(format!("package.{now_ms}.{}", std::process::id()));
    if unpacked.exists() {
        return Err(InstallRefusal::new(
            "archive",
            format!(
                "{} is left over from an earlier install",
                unpacked.display()
            ),
        ));
    }
    std::fs::create_dir(&unpacked).map_err(|error| {
        InstallRefusal::new("archive", format!("{}: {error}", unpacked.display()))
    })?;

    let written = match synra_plugin_ui::artifact::unpack(
        archive,
        &unpacked,
        synra_plugin_ui::artifact::ArchiveLimits::package(),
    ) {
        Ok(written) => written,
        Err(error) => {
            // The unpacker removed the files it wrote; what is left is the directory this function made.
            let _ = std::fs::remove_dir(&unpacked);
            return Err(InstallRefusal::new("archive", error.to_string()));
        }
    };
    let outcome = if replace {
        update_from_directory(db, backend, plugins_dir, &unpacked, now_ms, host)
    } else {
        from_directory(db, backend, plugins_dir, &unpacked, now_ms, host)
    };
    discard_unpacked(&unpacked, &written);
    // ★ The unpacked directory is about to disappear, so the note the inner install wrote names a path that will not
    // exist. Rewrite it with the archive the user actually has: a reinstall list that pointed at a deleted temporary
    // directory would be exactly as useless as no list at all.
    if let Ok(installed) = &outcome {
        let note = serde_json::json!({
            "path": archive.display().to_string(),
            "installedAtMs": now_ms,
        });
        if let Ok(bytes) = serde_json::to_vec_pretty(&note) {
            let _ = std::fs::write(installed.path.join("source.json"), bytes);
        }
    }
    outcome
}
