//! Small grammar predicates used by capability parsing.

/// Whether a string is a prefix name: `[a-z][a-z0-9-]{0,63}`.
pub(super) fn is_prefix_name(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// Whether a string is usable as a qualifier segment.
pub(super) fn is_qualifier_segment(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '/' | '*' | '-')
        })
}
