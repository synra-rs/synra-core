//! Platform policy and guard fixtures.

use std::path::Path;

mod actions;
mod arguments;
mod headless;
mod paths;
mod policies;
mod rate_limit;
mod urls;

/// A directory that is absolute on the platform running the test.
///
/// Not a literal `/tmp`: on Windows that is *drive-relative* — it names the root of whichever drive is current —
/// so `Path::is_absolute` is false for it and every path test would exercise the wrong branch.
fn absolute_base() -> &'static str {
    if cfg!(windows) { "C:\\tmp" } else { "/tmp" }
}

/// An absolute path under the base directory.
fn absolute(name: &str) -> std::path::PathBuf {
    Path::new(absolute_base()).join(name)
}

/// A path literal that is absolute on this platform, for the cases that take a `&str`.
fn absolute_text(name: &str) -> String {
    absolute(name).display().to_string()
}

/// A plugin's sandbox root, absolute on this platform.
fn sandbox_root() -> std::path::PathBuf {
    absolute("sandbox")
}

/// A directory that shares a string prefix with [`sandbox_root`] but is not inside it.
///
/// The case a string-prefix containment check gets wrong, kept as a named helper so every test that needs it
/// uses the same shape.
fn sibling_root() -> std::path::PathBuf {
    absolute("sandbox-other")
}
