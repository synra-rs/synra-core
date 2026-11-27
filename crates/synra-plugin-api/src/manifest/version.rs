//! Plugin identifiers, Semantic Versions and version requirements.

use core::cmp::Ordering;
use synra_protocol::PluginId;

use super::error::ManifestError;
use super::types::RESERVED_SCOPES;

/// A short directory name for a local development project.
///
/// Conventional package prefixes may be omitted here. Event ownership always uses the full id.
///
/// # Errors
///
/// [`ManifestError::UnsluggedId`] when the name has no usable ending — an empty name, or one that is all
/// prefixes.
pub fn to_project_slug(id: &PluginId) -> Result<String, ManifestError> {
    let text = id.as_str();
    // The name is everything after the last `/`, or the whole string when there is no scope.
    let name = text.rsplit('/').next().unwrap_or(text);
    let stripped = name.strip_prefix("synra-plugin-").unwrap_or(name);

    if stripped.is_empty() || !is_slug_segment(stripped) {
        return Err(ManifestError::UnsluggedId {
            id: text.to_owned(),
        });
    }
    Ok(stripped.to_owned())
}

/// Whether a string is usable as a slug segment.
fn is_slug_segment(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    // A project directory label starts with a letter and does not end in a hyphen.
    // These readability rules do not define event identity.
    if !first.is_ascii_lowercase() {
        return false;
    }
    if text.ends_with('-') {
        return false;
    }
    chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// Checks a plugin id against the grammar.
///
/// # Errors
///
/// [`ManifestError::BadId`] with the reason.
pub fn check_plugin_id(id: &str) -> Result<(), ManifestError> {
    let Some((scope, name)) = id.strip_prefix('@').and_then(|rest| rest.split_once('/')) else {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a plugin id must be scoped, as `@scope/name`".to_owned(),
        });
    };

    if RESERVED_SCOPES.contains(&scope) {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: format!("the scope `{scope}` is reserved for the host"),
        });
    }

    // `scope ::= [a-z0-9][a-z0-9-]{1,38}` — at least two characters, and the first may be a digit.
    if scope.len() < 2 || scope.len() > 39 {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a scope must be between 2 and 39 characters".to_owned(),
        });
    }
    if !scope
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a scope may contain only lowercase letters, digits and hyphens".to_owned(),
        });
    }

    // `name ::= [a-z0-9][a-z0-9-]{0,63}`
    if name.is_empty() || name.len() > 64 {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a name must be between 1 and 64 characters".to_owned(),
        });
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
    {
        return Err(ManifestError::BadId {
            id: id.to_owned(),
            reason: "a name may contain only lowercase letters, digits and hyphens".to_owned(),
        });
    }

    Ok(())
}

/// A parsed plugin version. Equality includes build identity, while precedence excludes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginVersion(semver::Version);

impl PluginVersion {
    /// Parse a complete `major.minor.patch` version with optional prerelease and build identifiers.
    ///
    /// # Errors
    /// Returns [`ManifestError::BadVersion`] for malformed or unrepresentable input.
    pub fn parse(version: &str) -> Result<Self, ManifestError> {
        semver::Version::parse(version)
            .map(Self)
            .map_err(|error| ManifestError::BadVersion {
                version: version.to_owned(),
                reason: error.to_string(),
            })
    }

    /// Compare SemVer precedence, excluding build metadata.
    #[must_use]
    pub fn cmp_precedence(&self, other: &Self) -> Ordering {
        self.0.cmp_precedence(&other.0)
    }

    /// The major version component.
    #[must_use]
    pub const fn major(&self) -> u64 {
        self.0.major
    }

    /// The minor version component.
    #[must_use]
    pub const fn minor(&self) -> u64 {
        self.0.minor
    }

    /// Whether this version precedes its associated stable release.
    #[must_use]
    pub fn is_prerelease(&self) -> bool {
        !self.0.pre.is_empty()
    }
}

/// A SemVer requirement used by plugin manifests and registry selection.
#[derive(Debug, Clone)]
pub struct PluginVersionReq(semver::VersionReq);

impl PluginVersionReq {
    /// Parse a SemVer range such as `^1.2` or `>=1.2.0, <2.0.0`.
    ///
    /// # Errors
    /// Returns [`ManifestError::BadVersion`] if the requirement is malformed.
    pub fn parse(requirement: &str) -> Result<Self, ManifestError> {
        semver::VersionReq::parse(requirement)
            .map(Self)
            .map_err(|error| ManifestError::BadVersion {
                version: requirement.to_owned(),
                reason: format!("invalid version requirement: {error}"),
            })
    }

    /// Test a parsed version against this requirement.
    #[must_use]
    pub fn matches(&self, version: &PluginVersion) -> bool {
        self.0.matches(&version.0)
    }
}

/// Check a manifest version against the plugin version grammar.
///
/// # Errors
/// Returns [`ManifestError::BadVersion`] when parsing fails.
pub fn check_version(version: &str) -> Result<(), ManifestError> {
    PluginVersion::parse(version).map(|_| ())
}

/// Compare complete version strings by SemVer precedence.
///
/// # Errors
/// Returns [`ManifestError::BadVersion`] if either input is malformed.
pub fn compare_versions(left: &str, right: &str) -> Result<Ordering, ManifestError> {
    Ok(PluginVersion::parse(left)?.cmp_precedence(&PluginVersion::parse(right)?))
}
