use std::sync::Arc;

use parking_lot::Mutex;
use synra_core::network::{NetworkGuard, Refusal};
use synra_protocol::error::ErrorCode;

use crate::{BinaryResponse, Limits, Request, Response};

mod redirect;
mod transport;

/// One plugin's fetcher.
///
/// # Why one of these per plugin
///
/// Because [`Limits::max_concurrent`] is a per-plugin number. A counter shared between plugins would let one plugin's
/// slow requests refuse another's, which is the shape of coupling the capability model exists to prevent.
#[derive(Debug)]
pub struct Client {
    guard: NetworkGuard,
    limits: Limits,
    /// How many requests are in flight. A counter rather than a semaphore because the check is "am I at the limit" and
    /// the wait is a refusal, not a queue.
    in_flight: Arc<Mutex<usize>>,
}

/// How a body is read. The two answers are the two response types, and a caller chooses one rather than a client
/// guessing from the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyMode {
    /// A string, for a plugin reading a page or an API.
    Text,
    /// Bytes, for a package or any other artefact.
    Bytes,
}

/// What one request produced, before it is shaped into a [`Response`] or a [`BinaryResponse`].
#[derive(Debug)]
struct Fetched {
    status: u16,
    status_text: String,
    headers: std::collections::BTreeMap<String, String>,
    url: String,
    redirected: bool,
    text: Option<String>,
    bytes: Option<Vec<u8>>,
}

impl Client {
    /// A fetcher for one plugin.
    #[must_use]
    pub fn new(guard: NetworkGuard, limits: Limits) -> Self {
        Self { guard, limits, in_flight: Arc::new(Mutex::new(0)) }
    }

    /// Fetches one URL, refusing before the request is made when the guard says no.
    ///
    /// # Errors
    ///
    /// [`Refusal`] with a code from the contract: `schemeNotAllowed`, `hostNotAllowed`, `ipNotAllowed`, `redirectBlocked`,
    /// `responseTooLarge`, `timeout`, `rateLimited`, or `hostFailed` for a transport failure. The code is what a plugin
    /// branches on and the sentence is what a person reads, as everywhere else.
    pub fn fetch(&self, request: &Request) -> Result<Response, Refusal> {
        self.fetch_scoped(request, None)
    }

    /// Fetches for a plugin using its current grants on every redirect before network IO.
    ///
    /// # Errors
    /// As [`Self::fetch`], including capability denial for the actual host or HTTP method.
    pub fn fetch_authorized(
        &self,
        request: &Request,
        grants: &[String],
    ) -> Result<Response, Refusal> {
        let mut parsed = synra_capability::CapabilitySet::new();
        for grant in grants {
            parsed.insert_str(grant).map_err(|error| {
                Refusal::new(
                    ErrorCode::Internal,
                    format!("invalid stored fetch authority: {error}"),
                )
            })?;
        }
        self.fetch_scoped(request, Some(&parsed))
    }

    /// Runs the plugin JSON request flow with its current stored grants.
    ///
    /// # Errors
    /// Preserves capability denial across the protocol/plugin error-code boundary.
    pub fn fetch_plugin(
        &self,
        request_json: &str,
        grants: &[String],
    ) -> Result<String, synra_plugin_host::CallError> {
        use synra_plugin_host::CallError;
        let request: Request = serde_json::from_str(request_json).map_err(|error| {
            CallError::new(
                CallError::BAD_ARGUMENT,
                format!("the request is not readable: {error}"),
            )
        })?;
        let response = self.fetch_authorized(&request, grants).map_err(|refusal| {
            CallError::new(
                if refusal.code == ErrorCode::CapabilityDenied {
                    CallError::CAPABILITY_DENIED
                } else {
                    refusal.code.as_str()
                },
                refusal.message,
            )
        })?;
        serde_json::to_string(&response).map_err(|error| {
            CallError::new(
                CallError::HOST_FAILED,
                format!("the answer could not be written: {error}"),
            )
        })
    }

    fn fetch_scoped(
        &self,
        request: &Request,
        grants: Option<&synra_capability::CapabilitySet>,
    ) -> Result<Response, Refusal> {
        let fetched = self.request(request, BodyMode::Text, grants)?;
        Ok(Response {
            status: fetched.status,
            status_text: fetched.status_text,
            headers: fetched.headers,
            url: fetched.url,
            redirected: fetched.redirected,
            body: fetched.text.unwrap_or_default(),
        })
    }

    /// Fetches one URL, answering the body as bytes.
    ///
    /// Same guards, same limits, same redirect loop as [`Client::fetch`]; the only difference is that the body is not
    /// decoded. A registry tarball is the reason this exists (16 §4.1).
    ///
    /// # Errors
    ///
    /// As [`Client::fetch`].
    pub fn fetch_bytes(&self, request: &Request) -> Result<BinaryResponse, Refusal> {
        let fetched = self.request(request, BodyMode::Bytes, None)?;
        Ok(BinaryResponse {
            status: fetched.status,
            status_text: fetched.status_text,
            headers: fetched.headers,
            url: fetched.url,
            redirected: fetched.redirected,
            body: fetched.bytes.unwrap_or_default(),
        })
    }

    /// The checks both fetches share, then the request itself.
    fn request(
        &self,
        request: &Request,
        mode: BodyMode,
        grants: Option<&synra_capability::CapabilitySet>,
    ) -> Result<Fetched, Refusal> {
        if request.method.trim().is_empty() {
            return Err(Refusal::new(ErrorCode::InvalidArgument, "the method is empty"));
        }
        let body = request.body.as_deref().unwrap_or_default();
        if body.len() > self.limits.max_request_bytes {
            return Err(Refusal::new(
                ErrorCode::PayloadTooLarge,
                format!(
                    "the body is {} bytes and this host sends at most {}",
                    body.len(),
                    self.limits.max_request_bytes
                ),
            ));
        }

        // ★ Taken **after** the cheap refusals and **before** anything that can block. A request refused for a bad URL
        // must not hold a slot, or a plugin sending rubbish would exhaust its own concurrency with work it never started.
        let slot = self.take_slot()?;
        let outcome = self.send(request, body, mode, grants);
        drop(slot);

        outcome
    }

    /// Claims one of the plugin's in-flight slots.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::RateLimited`] when they are all taken. A separate code from `quotaExceeded` because the plugin's next
    /// step differs: this one is answered by waiting for its own earlier request, and that one by storing less.
    fn take_slot(&self) -> Result<Slot, Refusal> {
        let mut in_flight = self.in_flight.lock();
        if *in_flight >= self.limits.max_concurrent {
            return Err(Refusal::new(
                ErrorCode::RateLimited,
                format!(
                    "{} requests are already in flight, which is this plugin's limit",
                    self.limits.max_concurrent
                ),
            ));
        }
        *in_flight += 1;
        drop(in_flight);
        Ok(Slot { counter: Arc::clone(&self.in_flight) })
    }
}

/// One of a plugin's in-flight slots, released when it is dropped.
///
/// A guard object rather than an increment and a matching decrement, because the decrement has to happen on the error
/// paths too — and one that is forgotten there is a plugin that slowly loses the ability to make any request at all.
#[derive(Debug)]
struct Slot {
    /// The counter it was taken from.
    counter: Arc<Mutex<usize>>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut in_flight = self.counter.lock();
        *in_flight = in_flight.saturating_sub(1);
    }
}
