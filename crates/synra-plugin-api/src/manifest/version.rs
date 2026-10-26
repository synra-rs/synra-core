//! Plugin identifiers and version ordering.
//!
//! # Why version arithmetic is hand-written
//!
//! Because a manifest is read by the host, and the host must agree with a publisher's toolchain about what `1.2.0-rc.1`
//! precedes. Delegating to a dependency would make the host's answer whatever that dependency says, so the comparison is
//! here, explicit, and testable.


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
        return Err(ManifestError::UnsluggedId { id: text.to_owned() });
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

/// Checks a version string is a legal semver.
///
/// Hand-written rather than pulled from the `semver` crate: the manifest needs `major.minor.patch` with
/// optional pre-release and build metadata, and a dependency for that is one more thing to keep current in a
/// crate whose whole job is to be a stable contract.
///
/// # Errors
///
/// [`ManifestError::BadVersion`] with the reason.
pub fn check_version(version: &str) -> Result<(), ManifestError> {
    let bad = |reason: &str| ManifestError::BadVersion {
        version: version.to_owned(),
        reason: reason.to_owned(),
    };

    // Build metadata first, since it may contain `+` and dots.
    let (without_build, _build) = match version.split_once('+') {
        Some((head, build)) => {
            if build.is_empty() || !build.split('.').all(is_identifier) {
                return Err(bad("build metadata is empty or malformed"));
            }
            (head, Some(build))
        }
        None => (version, None),
    };

    let (core, _pre) = match without_build.split_once('-') {
        Some((head, pre)) => {
            if pre.is_empty() || !pre.split('.').all(is_identifier) {
                return Err(bad("a pre-release is empty or malformed"));
            }
            (head, Some(pre))
        }
        None => (without_build, None),
    };

    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return Err(bad("a version is `major.minor.patch`"));
    }
    for part in parts {
        if part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()) {
            return Err(bad("each of major, minor and patch must be digits"));
        }
        // A leading zero is legal only for the number zero itself.
        if part.len() > 1 && part.starts_with('0') {
            return Err(bad("a numeric part must not have a leading zero"));
        }
    }
    Ok(())
}

/// Whether a pre-release or build identifier is well formed.
fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

/// Compares two versions, returning their ordering.
///
/// Pre-release versions sort *below* the release they lead to, which is the rule that makes `1.0.0-rc.1` less
/// than `1.0.0`. Getting that backwards would let a release candidate satisfy a minimum that the release was
/// written for.
///
/// # Errors
///
/// [`ManifestError::BadVersion`] if either string is not a legal semver.
pub fn compare_versions(left: &str, right: &str) -> Result<core::cmp::Ordering, ManifestError> {
    check_version(left)?;
    check_version(right)?;

    let parse = |version: &str| {
        let (without_build, _) = version.split_once('+').unwrap_or((version, ""));
        let (core, pre) = without_build.split_once('-').unwrap_or((without_build, ""));
        let numbers: Vec<u64> = core
            .split('.')
            .filter_map(|part| part.parse::<u64>().ok())
            .collect();
        (numbers, pre.to_owned())
    };

    let (left_numbers, left_pre) = parse(left);
    let (right_numbers, right_pre) = parse(right);

    match left_numbers.cmp(&right_numbers) {
        core::cmp::Ordering::Equal => {}
        other => return Ok(other),
    }

    Ok(match (left_pre.is_empty(), right_pre.is_empty()) {
        // A release is above any of its pre-releases.
        (true, true) => core::cmp::Ordering::Equal,
        (true, false) => core::cmp::Ordering::Greater,
        (false, true) => core::cmp::Ordering::Less,
        // Both are pre-releases: compared identifier by identifier.
        (false, false) => compare_prerelease(&left_pre, &right_pre),
    })
}

/// Compares two pre-release strings.
fn compare_prerelease(left: &str, right: &str) -> core::cmp::Ordering {
    let left_parts: Vec<&str> = left.split('.').collect();
    let right_parts: Vec<&str> = right.split('.').collect();

    for (a, b) in left_parts.iter().zip(&right_parts) {
        let ordering = match (a.parse::<u64>(), b.parse::<u64>()) {
            // Numeric identifiers compare numerically, so `rc.10` is above `rc.9` rather than below it.
            (Ok(a), Ok(b)) => a.cmp(&b),
            // A numeric identifier is below an alphanumeric one.
            (Ok(_), Err(_)) => core::cmp::Ordering::Less,
            (Err(_), Ok(_)) => core::cmp::Ordering::Greater,
            (Err(_), Err(_)) => a.cmp(b),
        };
        if ordering != core::cmp::Ordering::Equal {
            return ordering;
        }
    }
    // Fewer identifiers is lower, so `rc` is below `rc.1`.
    left_parts.len().cmp(&right_parts.len())
}
