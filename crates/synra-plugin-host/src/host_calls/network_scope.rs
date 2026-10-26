//! Fetch family availability and authorization of the actual HTTP destination.

use http::{Method, Uri};
use serde::Deserialize;
use std::borrow::Cow;
use synra_capability::{Capability, CapabilitySet};

use super::CallError;

pub(crate) fn available(grants: &CapabilitySet) -> bool {
    // Loading asks whether any destination can be used; it never grants a concrete request.
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
    authorize_request(grants, &request.url, &request.method)
}

/// Checks a concrete destination and method against the supplied current grants.
///
/// Call this again for every redirect before DNS resolution or network IO.
///
/// # Errors
/// Returns a capability denial or a malformed URL/method diagnosis.
pub fn authorize_request(grants: &CapabilitySet, url: &str, method: &str) -> Result<(), CallError> {
    // Use the same URI and method types as the HTTP transport, including authority/userinfo semantics.
    if url.len() > 2048 || url.contains('\\') || url.chars().any(char::is_control) {
        return Err(bad_argument(
            "the fetch URL is too long or contains forbidden characters",
        ));
    }
    let uri: Uri = url.parse().map_err(bad_argument)?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) {
        return Err(bad_argument("fetch requires an absolute http or https URL"));
    }
    let host = uri
        .host()
        .ok_or_else(|| bad_argument("the fetch URL has no host"))?
        .to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    let method: Method = method.parse().map_err(bad_argument)?;
    let destination = concrete(&format!("network:fetch:{host}"))?;
    let operation = concrete(&format!("network:fetch:{host}:{method}"))?;
    if grants.grants(&destination) || grants.grants(&operation) {
        Ok(())
    } else {
        Err(CallError::denied(operation.as_str(), grants))
    }
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
