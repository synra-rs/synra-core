//! Build metadata for support conversations and diagnostics.
//!
//! The values are captured once by the crate build script. Release artifacts therefore carry the exact source
//! revision that produced them, while source archives and non-git builds still compile with empty git fields.

/// The version and source revision of this core build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildInfo {
    /// The crate version from `Cargo.toml`.
    pub version: &'static str,
    /// The crate package name.
    pub name: &'static str,
    /// The complete commit hash, or an empty string outside a git checkout.
    pub hash: &'static str,
    /// The first seven characters of [`Self::hash`].
    pub short_hash: &'static str,
    /// The branch name, `HEAD` for a detached checkout, or an empty string outside git.
    pub branch: &'static str,
    /// The latest commit time in ISO 8601 form, or an empty string when unavailable.
    pub commit_time: &'static str,
    /// The build time in ISO 8601 form.
    pub build_time: &'static str,
    /// Whether tracked files were modified when the build started.
    pub dirty: bool,
}

/// Returns the metadata captured for this build of `synra-core`.
#[must_use]
pub fn current() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        name: env!("CARGO_PKG_NAME"),
        hash: env!("SYNRA_CORE_GIT_HASH"),
        short_hash: env!("SYNRA_CORE_GIT_SHORT_HASH"),
        branch: env!("SYNRA_CORE_GIT_BRANCH"),
        commit_time: env!("SYNRA_CORE_COMMIT_TIME"),
        build_time: env!("SYNRA_CORE_BUILD_TIME"),
        dirty: env!("SYNRA_CORE_GIT_DIRTY") == "true",
    }
}

#[cfg(test)]
mod tests {
    use super::current;

    #[test]
    fn metadata_has_a_package_version_and_consistent_short_hash() {
        let info = current();
        assert!(!info.version.is_empty());
        assert!(info.hash.is_empty() || info.hash.starts_with(info.short_hash));
        assert!(info.short_hash.len() <= 7);
    }
}
