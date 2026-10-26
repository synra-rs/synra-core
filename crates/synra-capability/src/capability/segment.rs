//! The vocabulary: one segment of a capability, and which wildcard it is.

use core::fmt;

use compact_str::CompactString;

/// A single segment of a capability.
///
/// A newtype rather than a bare string so that the invariant "this is a valid segment" is carried by
/// the type. A `Pattern` is built out of these, and matching never has to re-check what parsing
/// already established.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Segment(CompactString);

impl Segment {
    /// A segment that matches exactly itself.
    #[must_use]
    pub fn literal(text: &str) -> Self {
        Self(CompactString::from(text))
    }

    /// The single-segment wildcard.
    #[must_use]
    pub fn star() -> Self {
        Self(CompactString::from("*"))
    }

    /// The multi-segment wildcard.
    #[must_use]
    pub fn double_star() -> Self {
        Self(CompactString::from("**"))
    }

    /// The segment text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether this is the single-segment wildcard.
    #[must_use]
    pub fn is_star(&self) -> bool {
        self.0 == "*"
    }

    /// Whether this is the multi-segment wildcard.
    #[must_use]
    pub fn is_double_star(&self) -> bool {
        self.0 == "**"
    }

    /// Whether this is either wildcard.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.is_star() || self.is_double_star()
    }

    /// Whether this segment contains a wildcard anywhere.
    ///
    /// True for `*` and `**`, and also for a qualifier that embeds one, such as `/data/**` or
    /// `_plugin.@acme/chat.*`. Those match by their own rules, but they are still patterns rather than
    /// literal values — which matters when deciding whether a set of capabilities can be enumerated
    /// exactly.
    #[must_use]
    pub fn contains_wildcard(&self) -> bool {
        self.0.contains('*')
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
