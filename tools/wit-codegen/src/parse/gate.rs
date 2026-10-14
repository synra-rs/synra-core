/// What a host function is gated on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// No capability, because the call only reads a fact about the environment.
    Ungated,
    /// The capability string the host checks before the call.
    Capability(String),
}

impl Gate {
    /// The capability, when there is one.
    #[must_use]
    pub fn capability(&self) -> Option<&str> {
        match self {
            Self::Ungated => None,
            Self::Capability(capability) => Some(capability),
        }
    }

    /// Whether anything is checked.
    #[must_use]
    pub const fn is_ungated(&self) -> bool {
        matches!(self, Self::Ungated)
    }
}

/// Reads the gate from the annotations above a function.
///
/// `None` when there is no annotation at all, which the caller turns into [`ParseError::UngatedFunction`].
pub(super) fn read_gate(annotations: &[String]) -> Option<Gate> {
    // The last annotation wins, so a function carrying two is one whose gate is the one nearest it — which is what a
    // reader assumes, and the alternative is a parse that depends on the order of a set.
    for annotation in annotations.iter().rev() {
        let annotation = annotation.trim();
        if annotation.starts_with("@ungated") {
            return Some(Gate::Ungated);
        }
        if let Some(rest) = annotation.strip_prefix("@capability") {
            let rest = rest.trim();
            // `("log:*")`, with the parentheses and the quotes. Both required: a bare `@capability` with no argument is
            // a gate nobody chose, and accepting it would invent a capability whose string is empty.
            let inner = rest
                .strip_prefix('(')?
                .strip_suffix(')')?
                .trim()
                .trim_matches('"');
            if inner.is_empty() {
                return None;
            }
            return Some(Gate::Capability(inner.to_owned()));
        }
        // An annotation this parser does not know, such as `@since("1.1.0")`, is skipped rather than refused: it is a
        // note for a reader, and refusing would mean adding one broke the build.
    }
    None
}
