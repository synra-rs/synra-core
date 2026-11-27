//! Fetch family availability and authorization of the actual HTTP destination.

use http::Method;
use serde::Deserialize;
use std::borrow::Cow;
use synra_capability::{Capability, CapabilitySet, Domain};
use url::Url;

use super::CallError;

const MAX_URL_BYTES: usize = 2048;

pub(crate) fn available(grants: &CapabilitySet) -> bool {
    // Import loading checks the fetch family. Each request needs a concrete grant.
    grants.iter().any(|grant| {
        grant
            .as_str()
            .strip_prefix("network:fetch:")
            .is_some_and(|scope| !scope.is_empty())
            || Capability::parse("network:fetch:*").is_ok_and(|family| grant.matches(&family))
    })
}

#[derive(Deserialize)]
struct Request<'a> {
    #[serde(borrow)]
    url: Cow<'a, str>,
    #[serde(borrow, default = "get")]
    method: Cow<'a, str>,
}

const fn get() -> Cow<'static, str> {
    Cow::Borrowed("GET")
}

pub(super) fn authorize(grants: &CapabilitySet, argument: &str) -> Result<(), CallError> {
    let request: Request<'_> = serde_json::from_str(argument).map_err(bad_argument)?;
    authorize_request(grants, &request.url, &request.method).map(|_| ())
}

/// Returns the parsed destination after checking it against the supplied current grants.
///
/// Use the returned URL for transport and perform this check on every redirect before DNS or IO.
///
/// # Errors
/// Returns a capability denial or a malformed URL/method diagnosis.
pub fn authorize_request(grants: &CapabilitySet, input: &str, method: &str) -> Result<Url, CallError> {
    let url = parse_url(input)?;
    let host = url
        .host_str()
        .ok_or_else(|| bad_argument("the fetch URL has no host"))?;
    let host = host.strip_suffix('.').unwrap_or(host);
    let method: Method = method.parse().map_err(bad_argument)?;
    let destination = concrete(&format!("network:fetch:{host}"))?;
    let operation = concrete(&format!("network:fetch:{host}:{method}"))?;

    if grants.iter().any(|grant| {
        names_host(grant, host) && (grant.matches(&destination) || grant.matches(&operation))
    }) {
        Ok(url)
    } else {
        Err(CallError::denied(operation.as_str(), grants))
    }
}

fn parse_url(input: &str) -> Result<Url, CallError> {
    if input.len() > MAX_URL_BYTES || input.contains([' ', '\\']) || input.chars().any(char::is_control) {
        return Err(bad_argument(
            "the fetch URL is too long or contains forbidden characters",
        ));
    }
    let absolute = input.split_once("://").is_some_and(|(scheme, authority)| {
        (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
            && !authority.is_empty()
            && !authority.starts_with(['/', '?', '#'])
    });
    if !absolute {
        return Err(bad_argument("fetch requires an absolute http or https URL"));
    }
    let url = Url::parse(input).map_err(bad_argument)?;
    if url.as_str().len() > MAX_URL_BYTES {
        return Err(bad_argument("the normalized fetch URL is too long"));
    }
    Ok(url)
}

fn names_host(grant: &Capability, host: &str) -> bool {
    grant.domain() == Domain::Network
        && grant
            .prefixes()
            .first()
            .is_some_and(|prefix| prefix.as_str() == "fetch")
        && grant
            .qualifier()
            .first()
            .is_some_and(|target| target.as_str() == host)
}

fn concrete(text: &str) -> Result<Capability, CallError> {
    let capability = Capability::parse(text).map_err(bad_argument)?;
    if !capability.is_exact() {
        return Err(bad_argument(
            "a fetch request must name a concrete host and method",
        ));
    }
    Ok(capability)
}

fn bad_argument(error: impl std::fmt::Display) -> CallError {
    CallError::new(CallError::BAD_ARGUMENT, error.to_string())
}
