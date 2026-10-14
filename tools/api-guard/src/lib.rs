//! The rules `STABILITY.md` promises, as checks rather than as intentions.
//!
//! # Why not `cargo public-api`
//!
//! The design document names `cargo public-api` snapshots, and they are the right tool: they catch a concrete type in
//! a public signature, a `pub` that should have been `pub(crate)`, and a surface that grew by accident. What they need
//! is `rustdoc --output-format json`, which is nightly-only — and this repository builds on stable, so a snapshot tool
//! that only worked on one machine's toolchain would be a check that is skipped exactly where it matters.
//!
//! The design document also classifies the snapshot diff as **PR review** rather than as a gate. So this module does
//! the part that can be decided without a compiler: it reads the source of the crates that make a promise and checks
//! the rules that promise is made of.
//!
//! # What it checks
//!
//! * **A concrete container in a public signature.** A public `HashMap` is a promise about the implementation:
//!   replacing it with a `BTreeMap` would be a breaking change, and that replacement is exactly what a performance
//!   problem calls for. This is the most common way a stable crate accidentally breaks its consumers.
//! * **A public enum in a stable crate without `#[non_exhaustive]`.** A consumer matching on it has their build broken
//!   by a new variant, and the message they get is a wildcard arm they will add — which then hides every future
//!   variant from them.
//! * **A public enum in an internal crate *with* `#[non_exhaustive]`.** The opposite mistake: it forces a wildcard arm
//!   inside the workspace, which suppresses the compiler's own exhaustiveness check.
//! * **A third-party error type in a public error.** A public variant holding `std::io::Error` is a promise about
//!   `std`'s version, and the same for `serde_json`.
//!
//! # What it deliberately does not check
//!
//! Anything needing types: whether a `pub` item is reachable, whether a signature compiles, what a macro expands to.
//! This reads text, and it says so in every message it produces.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning. An assertion that indexes a
// vector of findings and panics on an unexpected one is the shape every test in this file has.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

/// Why a rule was broken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Violation {
    /// A public signature names a concrete container type.
    #[error("{file}:{line}: `{item}` exposes {container} in its public signature")]
    ConcreteContainer {
        /// Where.
        file: String,
        /// Which line.
        line: usize,
        /// The item.
        item: String,
        /// The container.
        container: String,
    },

    /// A public enum a consumer must match on is missing `#[non_exhaustive]`.
    #[error("{file}:{line}: `{item}` is a public enum in a stable crate without `#[non_exhaustive]`")]
    NotNonExhaustive {
        /// Where.
        file: String,
        /// Which line.
        line: usize,
        /// The enum.
        item: String,
    },


    /// A public error variant holds a third-party error type.
    #[error("{file}:{line}: `{item}` holds {foreign}, which is a promise about that crate's version")]
    ForeignError {
        /// Where.
        file: String,
        /// Which line.
        line: usize,
        /// The item.
        item: String,
        /// The foreign type.
        foreign: String,
    },

    /// A file could not be read.
    #[error("{path} could not be read: {reason}")]
    Unreadable {
        /// Which file.
        path: String,
        /// What went wrong.
        reason: String,
    },
}

/// What a crate promises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// SemVer, with every rule.
    Stable,
    /// SemVer, and a trait may gain a defaulted method in a minor version.
    SemiStable,
    /// No promise. The rules that apply are the ones about not making a promise by accident.
    Internal,
}

impl Tier {
    /// Whether the extra rules for a crate a consumer depends on apply.
    #[must_use]
    pub const fn makes_a_promise(self) -> bool {
        matches!(self, Self::Stable | Self::SemiStable)
    }

    /// The word, for a message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::SemiStable => "semi-stable",
            Self::Internal => "internal",
        }
    }
}

/// The tiers, as `STABILITY.md` declares them.
///
/// A table in code rather than in a file, because it is the thing this tool checks *against*: a crate whose tier moved
/// and whose rules did not would be a crate with no rules. `STABILITY.md` and this list have to agree, and a test
/// asserts they do by reading the file.
pub const CRATES: &[(&str, Tier)] = &[
    ("synra-protocol", Tier::Stable),
    ("synra-capability", Tier::Stable),
    ("synra-plugin-api", Tier::Stable),
    ("synra-net", Tier::SemiStable),
    ("synra-store", Tier::SemiStable),
    ("synra-core", Tier::SemiStable),
    ("synra-plugin-host", Tier::SemiStable),
    ("synra-observe", Tier::Internal),
    ("synra-platform", Tier::Internal),
    ("synra-plugin-ui", Tier::Internal),
    ("synra-ipc", Tier::Internal),
    ("synra-testkit", Tier::Internal),
    ("synra-testkit-alloc", Tier::Internal),
];

/// The container types a public signature may not name.
///
/// `Vec` is deliberately absent: a list is often the contract, and `&[T]` on the way in and a `Vec<T>` out is the
/// signature a caller expects. What the rule is about is the *mapping* types, whose choice is an implementation
/// decision — replacing a `HashMap` with a `BTreeMap` is exactly what a performance or a determinism problem calls for,
/// and with a public `HashMap` it is a breaking change.
pub const FORBIDDEN_CONTAINERS: &[&str] = &[
    "HashMap",
    "HashSet",
    "BTreeMap",
    "BTreeSet",
    "VecDeque",
    "BinaryHeap",
    "LinkedList",
];

/// The third-party error types a public error may not hold.
///
/// The *type* names, without their paths: `std::io::Error` and `io::Error` are one type that a signature may spell
/// either way, and two entries for one type would report a line twice. The match is on the last two path segments, so
/// `core::fmt::Error` and `std::fmt::Error` are the same finding.
pub const FOREIGN_ERRORS: &[&str] = &[
    "io::Error",
    "serde_json::Error",
    "fmt::Error",
    "num::ParseIntError",
    "str::Utf8Error",
    "FromUtf8Error",
];

/// One source file to check.
#[derive(Debug, Clone)]
pub struct Source {
    /// Its path, for a message.
    pub path: String,
    /// Its text.
    pub text: String,
}

impl Source {
    /// Reads a file.
    ///
    /// # Errors
    ///
    /// [`Violation::Unreadable`] when it cannot be read, because a check that silently skipped a file would be a check
    /// whose coverage nobody knows.
    pub fn read(path: &std::path::Path) -> Result<Self, Violation> {
        let text = std::fs::read_to_string(path).map_err(|error| Violation::Unreadable {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
        Ok(Self { path: path.display().to_string(), text })
    }
}

/// Checks one file against the rules for its crate's tier.
///
/// # Why text and not a syntax tree
///
/// A tree would need a parser, and a parser would need to be kept in step with the language. What these rules are
/// about — is a `HashMap` in this signature, is this enum annotated — is visible in the text, and a text check that
/// occasionally has to be told about a false positive is one a reviewer can reason about. Every message quotes the
/// line it is about.
#[must_use]
pub fn check(source: &Source, tier: Tier) -> Vec<Violation> {
    let mut violations = Vec::new();
    let lines: Vec<&str> = source.text.lines().collect();

    for (index, raw) in lines.iter().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();

        // A comment or a doc comment is not a signature. `missing_docs` means the documents are full of the words this
        // check looks for, and a rule that matched them would fire on every explanation of the rule.
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }

        if let Some(item) = public_enum(trimmed) {
            // ★ `#[non_exhaustive]` need not be the line directly above, and the first version of this check assumed it
            // was. An attribute block can be in any order, and `#[non_exhaustive]` conventionally comes *first* — before
            // the derives — so looking one line up reported three enums that already had it. The consequence was the
            // shape this tool exists to prevent: a violation nobody could see, because the fix was already made and the
            // check kept asking for it.
            //
            // The scan walks up over the item's whole attribute block and stops at the first line that is not an
            // attribute — a comment or a blank line ends it, which is what keeps an `#[non_exhaustive]` from a
            // *previous* item counting.
            let mut annotated = false;
            let mut previous = index;
            while let Some(before) = previous.checked_sub(1) {
                let Some(line) = lines.get(before) else { break };
                let trimmed = line.trim();
                if trimmed.starts_with("#[") {
                    if trimmed.contains("non_exhaustive") {
                        annotated = true;
                        break;
                    }
                    previous = before;
                    continue;
                }
                break;
            }

            // ★ Only a crate that makes a promise is checked, and only in the direction that protects a consumer.
            //
            // The design document's other rule — an internal enum must *not* be `#[non_exhaustive]`, because a wildcard
            // arm suppresses the exhaustiveness check — is about the **kernel's own** enums, and this tool cannot tell
            // "the kernel's own" from "a crate the kernel happens to keep in the internal tier". `synra-observe` and
            // `synra-platform` are internal by tier and their enums are matched by a human reading a log or a CLI
            // report; forcing them to be exhaustive would be a rule applied to the wrong thing. So this checks the
            // direction that has a victim and leaves the other to review.
            if tier.makes_a_promise() && !annotated {
                violations.push(Violation::NotNonExhaustive {
                    file: source.path.clone(),
                    line,
                    item,
                });
            }
        }

        if !tier.makes_a_promise() {
            continue;
        }

        if let Some(item) = public_fn_or_field(trimmed) {
            // ★ A *tuple* struct is the one place a container in a public item is not a violation, and it is the fix
            // rather than the problem: `pub struct Digests(BTreeMap<String, String>);` is how a crate stops naming a
            // standard container in the API it promises. Reporting it would mean the rule's own remedy failed the rule.
            //
            // The field is private by construction — a tuple struct's fields have the struct's visibility, and there is
            // no `pub` on the field — so what a consumer sees is `Digests`, which is the point. A *braced* struct with a
            // container field is a different thing and is still reported: `pub struct Wrapper { pub inner: BTreeMap<..> }`
            // hands the container out by name.
            let tuple_struct = trimmed.starts_with("pub struct ") && trimmed.contains('(');
            if !tuple_struct {
                for container in FORBIDDEN_CONTAINERS {
                    // The bare name, not `std::collections::HashMap`: the signature may import it, and `use` is where
                    // the short name comes from either way.
                    if names_container(trimmed, container) {
                        violations.push(Violation::ConcreteContainer {
                            file: source.path.clone(),
                            line,
                            item: item.clone(),
                            container: (*container).to_owned(),
                        });
                    }
                }
            }
        }

        for foreign in FOREIGN_ERRORS {
            // ★ Not `starts_with("pub ")`: an enum variant is indented and carries no visibility keyword of its own —
            // `Io(std::io::Error),` is a public variant of a public enum, and a rule that required `pub` on the line
            // would check nothing. What makes it a violation is the *type*, and the type is on the line.
            //
            // The false-positive surface is a private helper taking an `io::Error`, which is legitimate and would be
            // reported. That is the safe direction for this rule: a public error type is a promise, and the message
            // quotes the line so a reviewer can see which it is.
            if names_type(trimmed, foreign) {
                violations.push(Violation::ForeignError {
                    file: source.path.clone(),
                    line,
                    item: trimmed.trim_end_matches(',').trim().to_owned(),
                    foreign: (*foreign).to_owned(),
                });
            }
        }
    }

    violations
}

/// The name of a public enum declared on a line, if one is.
fn public_enum(line: &str) -> Option<String> {
    let rest = line.strip_prefix("pub enum ")?;
    Some(rest.split([' ', '{', '<']).next().unwrap_or_default().to_owned())
}

/// The name of a public function or struct field declared on a line, if one is.
///
/// # What "public" means here, and the two ways to get it wrong
///
/// This reports items a **consumer of the crate** can name. `std::io::Error` in a `pub(crate) fn` is not a promise to
/// anybody outside the crate, and neither is one in a `pub(super) fn` — so a rule about foreign types in a public
/// signature has nothing to say about either. The first version of this matched a bare `pub ` prefix, which reported
/// two crate-private functions in `synra-core`; the fix is to require the `pub` to be followed by the item kind rather
/// than by a parenthesis.
///
/// The second way is the opposite one and is not this function's job: a `pub fn` inside a private module is not
/// reachable either, and telling that from a line of text needs the module tree rather than the line. What keeps that
/// from mattering is the direction of the rule — a false positive here is a request to look, and a false negative would
/// be a promise nobody checked.
fn public_fn_or_field(line: &str) -> Option<String> {
    for prefix in ["pub fn ", "pub const fn ", "pub async fn ", "pub unsafe fn "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            // Up to the generic list or the argument list, which is where the name ends.
            return Some(rest.split(['(', '<']).next().unwrap_or_default().trim().to_owned());
        }
    }
    if let Some(rest) = line.strip_prefix("pub struct ") {
        return Some(rest.split([' ', '{', '(', '<']).next().unwrap_or_default().to_owned());
    }
    // A public field in a struct whose fields are public, which this rule also applies to. The `pub` must be followed
    // by the field's name, so `pub(crate)` — which the parenthesis rules out — is not one.
    if line.starts_with("pub ") && line.contains(':') {
        return Some(line.split(':').next().unwrap_or_default().trim().to_owned());
    }
    None
}

/// Whether a signature names a container as a **type**.
///
/// # Why a bare identifier is not enough
///
/// The first version of this check matched any whole identifier, and it reported a field called
/// `refusals_by_kind: [u64; 5]` because the line also contained a *variable* named `BTreeMap` — a false positive that
/// would have taught a reviewer to ignore the tool. A container is named as a type when it is followed by the
/// punctuation a type is followed by: `<` for its arguments, `,` or `>` or `)` inside a generic list, `;` at the end of
/// a field, or the end of the line.
///
/// A function *returning* one is the case the rule exists for, and it is caught by the `>` and end-of-line forms.
fn names_container(line: &str, container: &str) -> bool {
    let bytes = line.as_bytes();
    let needle = container.as_bytes();
    let mut start = 0;
    while let Some(offset) = line[start..].find(container) {
        let at = start + offset;
        let before = at.checked_sub(1).and_then(|index| bytes.get(index)).copied();
        let after = bytes.get(at + needle.len()).copied();

        let left_ok = before.is_none_or(|byte| !is_identifier_byte(byte));
        let right_ok = after.is_none_or(|byte| !is_identifier_byte(byte));
        let used_as_type = after.is_none_or(|byte| {
            byte.is_ascii_whitespace()
                || matches!(byte, b'<' | b'>' | b',' | b';' | b')' | b'\'' | b':')
        });

        if left_ok && right_ok && used_as_type {
            return true;
        }
        start = at + 1;
        if start >= line.len() {
            break;
        }
    }
    false
}

/// Whether a type name appears as a whole identifier in a line.
fn names_type(line: &str, type_name: &str) -> bool {
    names_identifier(line, type_name)
}

/// Whether `needle` appears in `haystack` as a whole identifier.
///
/// A byte-wise scan rather than a regex, because the workspace has no regex dependency and the rule is eight lines.
fn names_identifier(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() || bytes.len() < needle_bytes.len() {
        return false;
    }

    let mut start = 0;
    while let Some(offset) = haystack[start..].find(needle) {
        let at = start + offset;
        let before = at.checked_sub(1).and_then(|index| bytes.get(index)).copied();
        let after = bytes.get(at + needle_bytes.len()).copied();

        // A boundary is anything that cannot be part of an identifier: the start of the line, a character that is not
        // alphanumeric and not `_`, and the same on the right. A `.` on the left is allowed, so `io::Error` and
        // `std::io::Error` both match.
        let left_ok = before.is_none_or(|byte| !is_identifier_byte(byte));
        let right_ok = after.is_none_or(|byte| !is_identifier_byte(byte));
        if left_ok && right_ok {
            return true;
        }
        start = at + 1;
        if start >= haystack.len() {
            break;
        }
    }
    false
}

/// Whether a byte may appear inside an identifier or a path segment.
const fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(text: &str) -> Source {
        Source { path: "src/lib.rs".to_owned(), text: text.to_owned() }
    }

    fn check_stable(text: &str) -> Vec<Violation> {
        check(&source(text), Tier::Stable)
    }

    // ── Concrete containers ───────────────────────────────────────────────────────────────────────

    #[test]
    fn a_public_hashmap_in_a_return_type_is_a_violation() {
        // ★ The most common way a stable crate breaks its consumers: replacing the map is a breaking change, and the
        // replacement is exactly what a performance problem calls for.
        let violations = check_stable("pub fn devices(&self) -> HashMap<String, Device> {");
        assert_eq!(violations.len(), 1, "{violations:?}");
        match &violations[0] {
            Violation::ConcreteContainer { container, item, line, .. } => {
                assert_eq!(container, "HashMap");
                assert_eq!(item, "devices");
                assert_eq!(*line, 1);
            }
            other => panic!("expected a container violation, got {other:?}"),
        }
    }

    #[test]
    fn every_forbidden_container_is_caught() {
        for container in FORBIDDEN_CONTAINERS {
            let line = format!("pub fn f() -> {container}<String> {{");
            let violations = check_stable(&line);
            assert_eq!(violations.len(), 1, "{container}: {violations:?}");
        }
    }

    #[test]
    fn vec_is_allowed_because_a_list_is_often_the_contract() {
        // A `Vec` out and a `&[T]` in is the signature a caller expects, and the order is part of what the function
        // promises. The rule is about the *mapping* types, whose choice is an implementation decision.
        assert!(check_stable("pub fn names(&self) -> Vec<String> {").is_empty());
        assert!(check_stable("pub fn set(&self, names: &[String]) {").is_empty());
    }

    #[test]
    fn a_private_signature_is_not_checked() {
        // The rule is about the promise, and a private function is not one.
        assert!(check_stable("fn devices(&self) -> HashMap<String, Device> {").is_empty());
        assert!(check_stable("pub(crate) fn devices() -> HashMap<String, Device> {").is_empty());
    }

    #[test]
    fn an_internal_crate_is_not_checked_for_containers() {
        // `synra-observe` may return whatever it likes: nothing downstream depends on its shapes.
        let violations = check(&source("pub fn f() -> HashMap<String, u32> {"), Tier::Internal);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn a_doc_comment_that_names_a_container_is_not_a_violation() {
        // `missing_docs` means the documentation is full of the words this check looks for, and a rule that matched them
        // would fire on every explanation of the rule — including this file's own.
        assert!(check_stable("/// Returns a `HashMap` of devices.\npub fn devices(&self) -> Devices {").is_empty());
        assert!(check_stable("// A HashMap would be wrong here.\npub fn devices(&self) -> Devices {").is_empty());
    }

    #[test]
    fn an_identifier_that_contains_a_container_name_is_not_a_container() {
        // A field called `hash_map_iterations` is not a `HashMap`, and a check that fired on it is one a reviewer
        // learns to ignore.
        assert!(check_stable("pub fn f() -> u32 {").is_empty());
        assert!(check_stable("pub extra_hash_maps: usize,").is_empty());
        assert!(check_stable("pub fn hash_mapper(&self) -> u32 {").is_empty());
    }

    #[test]
    fn a_qualified_container_name_is_caught_too() {
        // The short name may come from a `use`, and the qualified one may not. Both are the same promise.
        let violations = check_stable("pub fn f() -> std::collections::HashMap<String, u32> {");
        assert_eq!(violations.len(), 1, "{violations:?}");
    }

    // ── `#[non_exhaustive]` ───────────────────────────────────────────────────────────────────────

    #[test]
    fn a_public_enum_in_a_stable_crate_must_be_non_exhaustive() {
        // A consumer matching on it has their build broken by a new variant, and the arm they add then hides every
        // future variant from them.
        let violations = check_stable("pub enum Kind {\n    A,\n}");
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(matches!(violations[0], Violation::NotNonExhaustive { .. }));

        // With the attribute it is fine.
        assert!(check_stable("#[non_exhaustive]\npub enum Kind {\n    A,\n}").is_empty());
    }

    #[test]
    fn an_internal_crates_enums_are_left_alone_either_way() {
        // ★ This check deliberately does *not* forbid `#[non_exhaustive]` on an internal crate's enum, which was the
        // first version of the rule and was wrong.
        //
        // The design document's rule — an internal enum must not be `#[non_exhaustive]`, because a wildcard arm
        // suppresses the exhaustiveness check — is about the **kernel's own** enums. A text check cannot tell "the
        // kernel's own" from "a crate the kernel keeps in the internal tier", and `synra-observe` and `synra-platform`
        // are internal by tier while their enums are matched by a person reading a log or a CLI report. A rule applied
        // to the wrong thing is worse than no rule: it teaches a reviewer to ignore the tool.
        assert!(check(&source("#[non_exhaustive]\npub enum Kind {"), Tier::Internal).is_empty());
        assert!(check(&source("pub enum Kind {"), Tier::Internal).is_empty());
    }

    #[test]
    fn a_semi_stable_crate_follows_the_stable_rule_for_enums() {
        // It makes a promise, so the rule that protects a consumer applies.
        let violations = check(&source("pub enum Kind {"), Tier::SemiStable);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(matches!(violations[0], Violation::NotNonExhaustive { .. }));
    }

    #[test]
    fn a_private_enum_is_not_checked() {
        assert!(check_stable("enum Kind {").is_empty());
    }

    // ── Third-party error types ───────────────────────────────────────────────────────────────────

    #[test]
    fn a_public_error_holding_a_foreign_error_is_a_violation() {
        // A promise about that crate's version: a minor release of `serde_json` would change this crate's error type.
        let violations = check_stable("    Io(std::io::Error),");
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(matches!(violations[0], Violation::ForeignError { .. }));
    }

    #[test]
    fn a_foreign_error_in_a_details_string_is_the_point() {
        // The rule's own advice: keep the third-party error in a `String`, where it is useful and not a promise.
        assert!(check_stable("    pub details: Option<String>,").is_empty());
    }

    #[test]
    fn the_kernels_own_error_code_is_not_a_foreign_error() {
        // The rule is about *third-party* types. The kernel's own error type is what a stable crate is supposed to
        // expose.
        assert!(check_stable("    pub code: ErrorCode,").is_empty());
        assert!(check_stable("    Network(NetworkError),").is_empty());
    }

    // ── The tiers ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn only_the_crates_that_promise_get_the_promise_rules() {
        for (name, tier) in CRATES {
            let source = source("pub fn f() -> HashMap<String, u32> {\n    todo!()\n}");
            let violations = check(&source, *tier);
            if tier.makes_a_promise() {
                assert_eq!(violations.len(), 1, "{name} is {} and did not check", tier.as_str());
            }
            else {
                assert!(violations.is_empty(), "{name} is internal and checked");
            }
        }
    }

    #[test]
    fn the_tier_names_are_the_ones_the_document_uses() {
        assert_eq!(Tier::Stable.as_str(), "stable");
        assert_eq!(Tier::SemiStable.as_str(), "semi-stable");
        assert_eq!(Tier::Internal.as_str(), "internal");
    }

    #[test]
    fn every_crate_in_the_workspace_has_a_tier() {
        // A crate with no tier is one with no rules, and a test in `synra-core` asserts this list against the workspace's
        // own members so an addition cannot be forgotten.
        assert!(CRATES.len() >= 13, "only {} crates", CRATES.len());
        let mut names: Vec<&str> = CRATES.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), CRATES.len(), "a crate is listed twice");
    }

    #[test]
    fn violation_messages_name_the_file_the_line_and_the_item() {
        let violations = check_stable("pub fn devices(&self) -> HashMap<String, Device> {");
        let text = violations[0].to_string();
        assert!(text.contains("src/lib.rs"), "{text}");
        assert!(text.contains(":1:"), "{text}");
        assert!(text.contains("devices"), "{text}");
        assert!(text.contains("HashMap"), "{text}");
        assert!(!text.contains('{'), "{text}");
    }

    #[test]
    fn an_unreadable_file_is_a_violation_rather_than_a_skip() {
        // A check that silently skipped a file would be a check whose coverage nobody knows.
        let result = Source::read(std::path::Path::new("/nonexistent/synra/api-guard.rs"));
        assert!(matches!(result, Err(Violation::Unreadable { .. })));
    }
}
