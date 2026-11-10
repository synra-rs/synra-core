//! Reading the WIT package declaration.

use crate::parse::ParseError;

/// The package declaration, as `(name, version)`.
pub(super) fn parse_package(text: &str) -> Result<(String, String), ParseError> {
    for (index, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        let Some(rest) = trimmed.strip_prefix("package ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';').trim();

        // `synra:plugin@1.0.0`, and a package with no version is legal WIT. The version is kept as text rather than
        // parsed: this tool does not compare versions, it reports them.
        return match rest.split_once('@') {
            Some((name, version)) => Ok((name.to_owned(), version.to_owned())),
            None if rest.is_empty() => Err(ParseError::Syntax {
                line: index + 1,
                reason: "a package declaration with no name".to_owned(),
            }),
            None => Ok((rest.to_owned(), String::new())),
        };
    }
    Err(ParseError::NoPackage)
}

