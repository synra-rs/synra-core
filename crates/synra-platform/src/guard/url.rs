//! URL shape, size and scheme checks.

use crate::actions::{MAX_URL_LEN, Policies};
use crate::error::{PlatformError, UrlRefusal};

/// Checks a URL against the policies, without opening it.
///
/// # Errors
///
/// [`PlatformError::BadUrl`] or [`PlatformError::TooLong`].
pub fn check_url(url: &str, policies: &Policies) -> Result<(), PlatformError> {
    if url.len() > MAX_URL_LEN {
        return Err(bad_url(url, UrlRefusal::TooLong));
    }
    if url.is_empty() {
        return Err(bad_url(url, UrlRefusal::Empty));
    }
    // A control character could forge the consent prompt's text, or split a log line, so it is refused before
    // anything else looks at the string.
    if url.chars().any(char::is_control) {
        return Err(bad_url(url, UrlRefusal::ControlCharacter));
    }

    let Some((scheme, rest)) = url.split_once(':') else {
        return Err(bad_url(url, UrlRefusal::NoScheme));
    };
    let scheme = scheme.to_ascii_lowercase();

    match scheme.as_str() {
        "https" => {}
        "http" if policies.allow_insecure_urls => {}
        "http" => return Err(bad_url(url, UrlRefusal::Insecure)),
        // Everything that is not a web scheme names something local or is handled by another program, and the
        // list is closed rather than "anything not http": `javascript:`, `data:` and `vbscript:` are all things a
        // plugin could put in an "open this link" prompt.
        _ => {
            if !policies.allow_local_schemes {
                return Err(bad_url(url, UrlRefusal::LocalScheme));
            }
        }
    }

    // A web address must name a host: `https:///x` and `https://?q` both have an empty authority, and the consent
    // prompt's whole value is that it says where the user is going.
    //
    // A non-web scheme is not checked this way, because having no host is ordinary for it — `file:///etc/passwd`
    // has an empty authority and names a path. Such a scheme reached this point only because the policy allows
    // local schemes, so the user has already agreed to the class of thing; demanding a host would refuse the
    // common spelling of exactly what they allowed.
    if matches!(scheme.as_str(), "http" | "https") {
        let authority = rest.trim_start_matches("//");
        let host_end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
        let host = authority.get(..host_end).unwrap_or_default();
        if host.is_empty() {
            return Err(bad_url(url, UrlRefusal::NoHost));
        }
    }

    Ok(())
}

/// Builds a URL refusal.
fn bad_url(url: &str, reason: UrlRefusal) -> PlatformError {
    PlatformError::BadUrl { url: url.to_owned(), reason }
}

/// Checks a URL's length for a caller building one, so the failure happens before the open.
///
/// # Errors
///
/// [`PlatformError::TooLong`].
pub const fn check_url_length(url: &str) -> Result<(), PlatformError> {
    if url.len() > MAX_URL_LEN {
        return Err(PlatformError::TooLong { field: "address", len: url.len(), max: MAX_URL_LEN });
    }
    Ok(())
}
