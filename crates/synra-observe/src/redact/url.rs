/// Removes a URL's query and fragment, returning the remainder and how many characters went.
///
/// A value counts as a URL only when it *begins* with a scheme: `https://host/p?x=1` yes, and
/// `the form is scheme://host?query` no. Searching the whole string for `://` instead would treat
/// prose that happens to mention a scheme as a URL and silently cut the sentence in half — and the
/// sentence is a log line somebody wrote to be read.
pub(super) fn strip_url_query(value: &str) -> (String, usize) {
    let Some(scheme_end) = value.find("://") else {
        return (value.to_owned(), 0);
    };
    let scheme = &value[..scheme_end];
    // The `://` has to be at the very start: `scheme_end == 0` means the value begins `://`, which no
    // URL does, so the scheme must be non-empty *and* the marker must come right after it.
    //
    // Stating "at the start" as a length check rather than relying on the scheme's own character class
    // is deliberate: a rule that depends on a second validator agreeing is a rule that breaks when
    // either of them changes.
    if scheme_end == 0 || scheme.is_empty() || scheme.len() > 32 {
        return (value.to_owned(), 0);
    }
    let plausible_scheme = scheme.starts_with(|ch: char| ch.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '-' || ch == '.');
    if !plausible_scheme {
        return (value.to_owned(), 0);
    }

    let cut = value
        .get(scheme_end..)
        .and_then(|rest| rest.find(['?', '#']))
        .map(|offset| scheme_end + offset);

    match cut {
        Some(cut) => {
            let kept = value[..cut].to_owned();
            let removed = value.chars().count() - kept.chars().count();
            (kept, removed)
        }
        None => (value.to_owned(), 0),
    }
}
