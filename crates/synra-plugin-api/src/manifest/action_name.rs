//! Literal action identifiers shared by manifests and runtime calls.

use super::{MAX_NAME_LEN, ManifestError};

/// Validate one action name, without interpreting it as a capability pattern.
///
/// # Errors
/// Empty names, names longer than the manifest limit, and characters outside ASCII
/// letters, digits, dot, underscore and hyphen are refused.
pub fn validate_action_name(name: &str) -> Result<(), ManifestError> {
    if name.is_empty() {
        return Err(ManifestError::Malformed(
            "an action has an empty name".to_owned(),
        ));
    }
    let len = name.chars().count();
    if len > MAX_NAME_LEN {
        return Err(ManifestError::TooLong {
            field: "action name",
            len,
            max: MAX_NAME_LEN,
        });
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ManifestError::Malformed(
            "an action name must be a literal ASCII identifier using letters digits dot underscore or hyphen".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_bounded_literals_instead_of_patterns_or_capability_paths() {
        for name in ["format-date", "A1.b_c", &"a".repeat(MAX_NAME_LEN)] {
            assert!(validate_action_name(name).is_ok());
        }
        for name in [
            "",
            "*",
            "**",
            "a*b",
            "a:b",
            "a/b",
            "a@b",
            "two words",
            "中文",
            "a\n",
        ] {
            assert!(validate_action_name(name).is_err(), "{name:?}");
        }
        assert!(matches!(
            validate_action_name(&"a".repeat(MAX_NAME_LEN + 1)),
            Err(ManifestError::TooLong { .. })
        ));
    }
}
