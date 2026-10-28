//! Whether a requested path may be served, and what it is served as.

use super::limits::{ArtifactError, MAX_ARTIFACT_PATH_LEN, PathRefusal};
/// Checks a path is one an artifact may name.
///
/// # Errors
///
/// [`ArtifactError::BadPath`] naming the reason.
pub fn check_path(path: &str) -> Result<(), ArtifactError> {
    let refuse = |reason: PathRefusal| ArtifactError::BadPath { path: path.to_owned(), reason };

    if path.is_empty() {
        return Err(refuse(PathRefusal::Empty));
    }
    if path.len() > MAX_ARTIFACT_PATH_LEN {
        return Err(refuse(PathRefusal::TooLong));
    }
    if path.contains('\0') {
        return Err(refuse(PathRefusal::NullByte));
    }
    // Refused rather than accepted on the platforms where it is a filename character: the same artifact is served on
    // all of them, so a path that means one thing on Windows and another elsewhere is a difference nobody would find.
    if path.contains('\\') {
        return Err(refuse(PathRefusal::Backslash));
    }
    if path.starts_with('/') {
        return Err(refuse(PathRefusal::Absolute));
    }
    // A drive letter, as Windows spells one. Checked by shape rather than by platform, for the same reason.
    if path.len() >= 2 && path.as_bytes().get(1) == Some(&b':') {
        return Err(refuse(PathRefusal::DriveLetter));
    }

    for component in path.split('/') {
        if component.is_empty() {
            // A doubled separator or a trailing one. Refused rather than collapsed, because two spellings of one path
            // is two index keys for one file.
            return Err(refuse(PathRefusal::BadCharacter));
        }
        if component == ".." {
            return Err(refuse(PathRefusal::Traversal));
        }
        // A single `.` is a directory reference, not a file, and a file named `.` is not one an artifact can hold.
        if component == "." {
            return Err(refuse(PathRefusal::BadCharacter));
        }
        if component
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
            || component.ends_with(['.', ' '])
            || reserved_component(component)
        {
            return Err(refuse(PathRefusal::BadCharacter));
        }
    }

    Ok(())
}

fn reserved_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or_default();
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|name| stem.eq_ignore_ascii_case(name))
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.get(..3)
                .is_some_and(|name| name.eq_ignore_ascii_case(prefix))
                && stem.get(3..).is_some_and(|suffix| {
                    matches!(
                        suffix,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
        })
}

/// Check a runtime artifact path without allowing it to shadow package metadata or extracted UI files.
///
/// # Errors
/// Reports malformed paths or a case-insensitive collision with a reserved package root name.
pub fn check_package_artifact_path(path: &str) -> Result<(), ArtifactError> {
    check_path(path)?;
    let root = path.split('/').next().unwrap_or_default();
    if [
        "manifest.json",
        "signature.json",
        "source.json",
        ".synra-build.json",
        "ui",
    ]
    .iter()
    .any(|name| root.eq_ignore_ascii_case(name))
    {
        return Err(ArtifactError::ReservedPackagePath {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// The content type for a path, from its extension.
///
/// A closed list, and `None` for anything else — which is what an interface is told to serve as an opaque download.
/// A guessed type is worse than none: a browser that is told a file is `text/html` will render it, and a plugin that
/// ships a file named `.html` that is not a document would then be able to run script.
#[must_use]
pub fn content_type_for(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.').map(|(_, extension)| extension)?;
    // Lowercased for the comparison without allocating: an extension is short and ASCII in every case here.
    let matches = |candidate: &str| extension.eq_ignore_ascii_case(candidate);

    if matches("html") || matches("htm") {
        return Some("text/html; charset=utf-8");
    }
    if matches("js") || matches("mjs") {
        return Some("text/javascript; charset=utf-8");
    }
    if matches("css") {
        return Some("text/css; charset=utf-8");
    }
    if matches("json") {
        return Some("application/json");
    }
    if matches("svg") {
        return Some("image/svg+xml");
    }
    if matches("png") {
        return Some("image/png");
    }
    if matches("jpg") || matches("jpeg") {
        return Some("image/jpeg");
    }
    if matches("webp") {
        return Some("image/webp");
    }
    if matches("gif") {
        return Some("image/gif");
    }
    if matches("woff2") {
        return Some("font/woff2");
    }
    if matches("woff") {
        return Some("font/woff");
    }
    if matches("ttf") {
        return Some("font/ttf");
    }
    if matches("wasm") {
        return Some("application/wasm");
    }
    if matches("map") {
        return Some("application/json");
    }
    None
}
