//! Public error boundaries for the unpublished workspace.
//!
//! Interfaces and data formats may be refactored directly. This tool checks diagnostic boundaries,
//! not SemVer compatibility, container choices or non_exhaustive annotations.
//! Dependency direction, capability gates, resource bounds and actual callers retain their own gates.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod foreign;

/// A failed boundary check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Violation {
    /// A domain interface exposes a dependency's unclassified error.
    #[error("{file}:{line}: `{item}` exposes {foreign} without a Synra error boundary")]
    ForeignError {
        /// Source file.
        file: String,
        /// Source line.
        line: usize,
        /// Public item.
        item: String,
        /// Dependency error type.
        foreign: String,
    },
    /// A source could not be read or parsed.
    #[error("{path} could not be read: {reason}")]
    Unreadable {
        /// Source path.
        path: String,
        /// Failure reason.
        reason: String,
    },
}

/// The role of a workspace library, independent of publication or compatibility promises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    /// Shared domain interfaces return the application's own classified failures.
    Domain,
    /// Host adapters, implementation helpers and test support are checked through their callers.
    Adapter,
}

impl Boundary {
    /// Whether public dependency errors must be mapped at this boundary.
    #[must_use]
    pub const fn checks_errors(self) -> bool {
        matches!(self, Self::Domain)
    }
}

/// Every workspace library and its diagnostic boundary, mirrored by STABILITY.md.
pub const CRATES: &[(&str, Boundary)] = &[
    ("synra-protocol", Boundary::Domain),
    ("synra-capability", Boundary::Domain),
    ("synra-plugin-api", Boundary::Domain),
    ("synra-net", Boundary::Domain),
    ("synra-store", Boundary::Domain),
    ("synra-core", Boundary::Domain),
    ("synra-plugin-host", Boundary::Domain),
    ("synra-observe", Boundary::Adapter),
    ("synra-platform", Boundary::Adapter),
    ("synra-plugin-ui", Boundary::Adapter),
    ("synra-ipc", Boundary::Adapter),
    ("synra-testkit", Boundary::Adapter),
    ("synra-testkit-alloc", Boundary::Adapter),
    ("synra-fetch", Boundary::Adapter),
    ("synra-registry", Boundary::Adapter),
    ("synra-control", Boundary::Adapter),
    ("synra-plugin-sdk", Boundary::Adapter),
];

/// Dependency error types that need classification at a shared domain boundary.
pub const FOREIGN_ERRORS: &[&str] = &[
    "io::Error",
    "serde_json::Error",
    "fmt::Error",
    "num::ParseIntError",
    "str::Utf8Error",
    "FromUtf8Error",
];

/// One Rust source file.
#[derive(Debug, Clone)]
pub struct Source {
    /// Source path.
    pub path: String,
    /// UTF-8 source text.
    pub text: String,
}

impl Source {
    /// Read a source file without silently skipping an IO failure.
    ///
    /// # Errors
    /// A structured unreadable-source violation.
    pub fn read(path: &std::path::Path) -> Result<Self, Violation> {
        let text = std::fs::read_to_string(path).map_err(|error| Violation::Unreadable {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        Ok(Self {
            path: path.display().to_string(),
            text,
        })
    }
}

/// Check public domain error types and signatures. DTO layout and exhaustive enums may change.
#[must_use]
pub fn check(source: &Source, boundary: Boundary) -> Vec<Violation> {
    let mut violations = foreign::check(source);
    if !boundary.checks_errors() {
        violations.retain(|violation| matches!(violation, Violation::Unreadable { .. }));
    }
    violations
}

#[cfg(test)]
mod tests;
