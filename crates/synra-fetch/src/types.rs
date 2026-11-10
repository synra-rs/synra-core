use std::time::Duration;

use serde::{Deserialize, Serialize};


/// The one sentence a plugin sees when a capability is granted but this host cannot honour it.
///
/// A refusal rather than a silent default, because a plugin that assumed a limit it did not get would be one whose
/// author cannot reason about it.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// What one plugin's requests are held to.
///
/// # Why these are the host's numbers and not the plugin's
///
/// Because a limit a plugin chooses is not a limit. The design lists them under the network capability's rules
/// (`10 §4.4` steps 5–7), and a plugin's own manifest may ask for less — a host that took the ceiling from third-party
/// code would be taking its resource budget from the thing it is budgeting for.
#[derive(Debug, Clone)]
pub struct Limits {
    /// How many bytes a request body may carry.
    pub max_request_bytes: usize,
    /// How many bytes of a response will be read.
    pub max_response_bytes: u64,
    /// How long one request — connect, send, read — may take.
    pub timeout: Duration,
    /// How many redirects may be followed.
    pub max_redirects: u8,
    /// How many requests this plugin may have in flight at once.
    pub max_concurrent: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // A request body is something a plugin wrote, and 1 MiB is far past any API's JSON payload.
            max_request_bytes: 1024 * 1024,
            // The same ceiling `Envelope` uses for a frame body, so a plugin cannot pull in one call what the transport
            // would refuse to carry in ten.
            max_response_bytes: 4 * 1024 * 1024,
            timeout: DEFAULT_TIMEOUT,
            max_redirects: synra_core::network::MAX_REDIRECTS,
            max_concurrent: 4,
        }
    }
}

/// What a plugin asked for.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    /// The address.
    pub url: String,
    /// The method. `GET` when absent, because a request that names none is a read.
    #[serde(default = "default_method")]
    pub method: String,
    /// The headers, by name.
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// The body, when there is one.
    #[serde(default)]
    pub body: Option<String>,
}

/// `GET`, for a request that named no method.
fn default_method() -> String {
    "GET".to_owned()
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    /// The status code, as it arrived — including a 3xx that was refused, so a plugin can see what happened.
    pub status: u16,
    /// The reason phrase, when the status has one.
    ///
    /// ★ Carried because the interface contract declares `statusText`, and an empty string is a different answer from
    /// "not applicable": `200` has a phrase and a custom status may not.
    pub status_text: String,
    /// The response headers, lowercased.
    pub headers: std::collections::BTreeMap<String, String>,
    /// The address the response actually came from, after any redirects.
    ///
    /// ★ Why this is not the request's URL: a redirect chain that ends somewhere else is exactly what a plugin reading
    /// `response.url` wants to know, and reporting the address it asked for would hide the hop.
    pub url: String,
    /// Whether at least one redirect was followed to get here.
    pub redirected: bool,
    /// The body, as text.
    ///
    /// # Why this is not parsed
    ///
    /// Because a response is not always JSON. A plugin fetching a CSV or a page is doing something ordinary, and a host
    /// that parsed every body would refuse most of the web — and would then have to decide what to do with a body that is
    /// not UTF-8, which is a question the plugin's own code is better placed to answer.
    pub body: String,
}

/// What came back, as bytes.
///
/// The text [`Response`] refuses a body that is not UTF-8 — deliberately, because it is for a plugin reading a page. A
/// registry tarball is the other case: it is bytes by definition, and decoding it as text would corrupt it before the
/// signature could check it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryResponse {
    /// The status code, as it arrived.
    pub status: u16,
    /// The reason phrase, when the status has one.
    pub status_text: String,
    /// The response headers, lowercased.
    pub headers: std::collections::BTreeMap<String, String>,
    /// The address the response actually came from, after any redirects.
    pub url: String,
    /// Whether at least one redirect was followed to get here.
    pub redirected: bool,
    /// The body, unmodified.
    pub body: Vec<u8>,
}
