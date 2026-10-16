//! Fetching a URL on a plugin's behalf, safely enough to be worth doing.
//!
//! # Why this is a crate of its own
//!
//! Because it is the one capability that reaches the public internet for a plugin, and reaching it needs a TLS stack.
//! `synra-net` states that it handles *"two devices, once a socket exists"* and performs no IO, so an HTTP client does not
//! belong there; `synra-core` is cross-compiled for Android by `matrix`, and putting `rustls` and a crypto backend into
//! the kernel's dependency graph for a capability the kernel never uses is the wrong trade. So the **hosts** depend on
//! this, and the kernel does not.
//!
//! # What a plugin sends, and what it gets back
//!
//! The WIT declares `network-fetch: func(request-json: string) -> outcome` and says nothing about the shape — so it is
//! decided here, `camelCase` like every other payload in this workspace:
//!
//! ```json
//! { "url": "https://api.example.com/v1", "method": "GET",
//!   "headers": { "accept": "application/json" }, "body": null }
//! ```
//!
//! and the answer
//!
//! ```json
//! { "status": 200, "headers": { "content-type": "application/json" }, "body": "{…}" }
//! ```
//!
//! The **body is a string**, not parsed JSON, because a response is not always JSON — a plugin fetching a CSV or a web
//! page is doing something ordinary, and a host that parsed the body would be a host that refused most of the web.
//!
//! # The order of the checks, which is the whole design
//!
//! `10 §4.4` names seven steps and this module is the first four; the remaining three are limits, and they are
//! [`Limits`]. The order matters and is not rearranged here:
//!
//! 1. the scheme and the host, by [`synra_core::network::NetworkGuard::check_url`];
//! 2. the addresses the name resolved to, by `check_resolved` — **every** one of them;
//! 3. the request, with redirects followed **by this module** rather than by the client, so each hop goes back through
//!    `check_url`;
//! 4. the response size.
//!
//! # Why the redirects are followed here
//!
//! Because the design requires each hop to be re-validated, and an HTTP client that follows redirects internally offers a
//! hop *count* and nothing else — no hook at which a second hop can be refused. So the client is configured to follow
//! none, and [`Client::fetch`] loops: read the `Location`, ask [`synra_core::network::NetworkGuard::next_hop`], repeat. A
//! redirect to a host nobody granted is refused at that moment, which is the only moment it can be.
//!
//! # Why the addresses are resolved here rather than by the client
//!
//! Because of DNS rebinding, which `10 §4.4` names: a name that answers with a public address when it is checked and a
//! private one when it is connected to defeats the entire IP policy. The defence is to connect to **the address that was
//! checked**, and that is what [`FixedResolver`] does — the client is handed the approved addresses and is not allowed to
//! look the name up again. The `Host` header and the certificate still carry the name, so this is not "connect to an IP":
//! the name is what is verified, and the address is what was approved.
//!
//! # What this is not
//!
//! It is not a sandbox for the *content*. A plugin that fetches a web page gets the web page; the capability is about
//! **where** the request may go, which is the part the kernel can decide on the user's behalf.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
//
// ★ And this was missing at first, which is why the tests below trip `expect_used` while every other crate's do not. The
// exemption is per crate and has to be repeated, so a new crate is a crate whose tests are held to the production rules —
// which is not wrong, but it is not what the rest of the workspace does, and the difference would have been invisible
// until somebody copied a test.
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

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use synra_core::network::{Checked, NetworkGuard, Refusal};
use synra_protocol::error::ErrorCode;

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
    /// The response headers, lowercased.
    pub headers: std::collections::BTreeMap<String, String>,
    /// The body, as text.
    ///
    /// # Why this is not parsed
    ///
    /// Because a response is not always JSON. A plugin fetching a CSV or a page is doing something ordinary, and a host
    /// that parsed every body would refuse most of the web — and would then have to decide what to do with a body that is
    /// not UTF-8, which is a question the plugin's own code is better placed to answer.
    pub body: String,
}

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
        let outcome = self.send(request, body);
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

    /// The request itself, with the redirect loop.
    fn send(&self, request: &Request, body: &str) -> Result<Response, Refusal> {
        let started = Instant::now();
        let mut url = request.url.clone();

        for hop in 0..=self.limits.max_redirects {
            // ★ The clock starts once, at the first hop, and every hop spends from what is left. A timeout per hop would
            // let a chain of five redirects take five times the budget the caller was promised — and a chain a name
            // controls is exactly how a plugin would be made to hold one.
            let remaining = self
                .limits
                .timeout
                .checked_sub(started.elapsed())
                .ok_or_else(|| timeout_refusal(&request.url, self.limits.timeout))?;

            let checked = self.guard.check_url(&url)?;
            let addresses = self.resolve(&checked)?;
            let agent = self.agent(&addresses, remaining)?;

            let mut response = self.one_request(&agent, request, body, &url)?;

            let status = response.status().as_u16();
            let headers: std::collections::BTreeMap<String, String> = response
                .headers()
                .iter()
                .map(|(name, value)| {
                    (name.as_str().to_ascii_lowercase(), value.to_str().unwrap_or_default().to_owned())
                })
                .collect();

            // A redirect is a second request to a URL nobody authorised, so it goes back through the guard — and through
            // the resolver with it, which is why the loop starts again rather than reusing this agent.
            if (300..400).contains(&status) {
                let Some(location) = headers.get("location") else {
                    return Err(Refusal::new(
                        ErrorCode::ProtocolViolation,
                        format!("{status} without a `location` header, so there is nowhere to follow"),
                    ));
                };
                let _ = self.guard.next_hop(hop, location)?;
                url = location.clone();
                continue;
            }

            // ★ The body is read only here, and read **with the ceiling applied at the read** rather than after it.
            // A limit checked once the bytes are in memory is a limit that has already been exceeded, which is the shape
            // of enforcement that does not enforce anything.
            // ★ One more than the limit, and the reason is an off-by-one in the client.
            //
            // Its reader errors when a read is attempted with nothing left, and `read_to_string` always attempts one more
            // read to see the end — so a body of **exactly** the limit is refused, and the ceiling a plugin is told about
            // is one byte tighter than the one it is held to. Passing `limit + 1` makes "more than the limit is refused"
            // mean what it says, at both boundaries.
            let ceiling = self.limits.max_response_bytes.saturating_add(1);
            let body = response
                .body_mut()
                .with_config()
                .limit(ceiling)
                .read_to_string()
                .map_err(|error| body_refusal(&url, self.limits.max_response_bytes, &error))?;

            return Ok(Response { status, headers, body });
        }

        // The loop returns on the last iteration's non-redirect, so this is reached only when every hop redirected —
        // which `next_hop` refuses before the counter gets here. A refusal rather than a panic, because this workspace
        // denies `panic` in production code and an unreachable branch is not a licence to break that.
        Err(Refusal::new(
            ErrorCode::RedirectBlocked,
            format!("more than {} redirects", self.limits.max_redirects),
        ))
    }

    /// Resolves a checked URL and refuses unless **every** address may be reached.
    ///
    /// # The order, and why it is this way round
    ///
    /// The lookup happens here, once, and its answer is what [`NetworkGuard::check_resolved`] judges and what
    /// [`FixedResolver`] then hands the client. Looking the name up a second time inside the client would be the
    /// rebinding window this design exists to close.
    fn resolve(&self, checked: &Checked) -> Result<Vec<SocketAddr>, Refusal> {
        let host = format!("{}:{}", checked.host, checked.port_or_default());
        let resolved: Vec<SocketAddr> = host
            .to_socket_addrs()
            .map_err(|error| {
                Refusal::new(
                    ErrorCode::HostNotAllowed,
                    format!("`{}` could not be looked up: {error}", checked.host),
                )
            })?
            .collect();

        let addresses: Vec<std::net::IpAddr> = resolved.iter().map(SocketAddr::ip).collect();
        self.guard.check_resolved(checked, &addresses)?;
        Ok(resolved)
    }

    /// An agent that will connect only to the addresses that were approved.
    fn agent(&self, addresses: &[SocketAddr], remaining: Duration) -> Result<ureq::Agent, Refusal> {
        let config = ureq::Agent::config_builder()
            // ★ Followed by this module, not by the client. The design requires each hop to be re-validated and an HTTP
            // client offers a hop *count* with no hook to refuse one, so it is told to follow none.
            .max_redirects(0)
            .max_redirects_will_error(false)
            // A 404 is an answer, not a transport failure: a plugin asking about something that is not there has to be
            // able to read the status and the body, and a client that turned it into an `Err` would take that away.
            .http_status_as_error(false)
            .timeout_global(Some(remaining))
            .build();

        Ok(ureq::Agent::with_parts(
            config,
            ureq::unversioned::transport::DefaultConnector::default(),
            FixedResolver { addresses: addresses.to_vec() },
        ))
    }

    /// One request, without following anything.
    ///
    /// # Why this builds a request rather than calling `agent.get`/`agent.post`
    ///
    /// Because the method is a string the plugin chose, and the client's typed helpers each name one. `run` takes a
    /// request built from parts, which is what a method that arrived as data needs.
    fn one_request(
        &self,
        agent: &ureq::Agent,
        request: &Request,
        body: &str,
        url: &str,
    ) -> Result<ureq::http::Response<ureq::Body>, Refusal> {
        let mut builder = ureq::http::Request::builder().method(request.method.as_str()).uri(url);

        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }

        let built = builder.body(body.to_owned()).map_err(|error| {
            // A method or header the protocol cannot express is the plugin's mistake, and it is refused before anything
            // is sent.
            Refusal::new(ErrorCode::InvalidArgument, format!("`{url}` could not be built: {error}"))
        })?;

        // ★ The upstream client is wrapped, because a **reponse with too many headers panics it**.
        //
        // `ureq-proto` 0.6.4 collects something about a response into an `ArrayVec<_, 16>` whose `push` "panics if the array
        // is already full" — so a server that answers with more of whatever that is does not produce a refusal, it produces a
        // panic. It was found by fetching `https://registry.npmjs.org/%40acme/chat`: an unresolvable host errors cleanly and
        // a resolvable one reached the bug, which is why the plugin host's own tests never saw it — they all use
        // `127.0.0.1:<port>` against a fixture this process writes.
        //
        // The two rules this follows are the codebase's own: a host function that panics is caught and the instance is
        // destroyed, never the kernel; and a *server's* behaviour must never be able to do that from the far end. A plugin
        // fetching an ordinary URL does not choose how many headers come back.
        //
        // The panic is reported rather than swallowed: a refusal saying the client panicked is a bug report, and one that
        // said "the network failed" would send the next reader looking at the network.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            agent.run(built).map_err(|error| transport_refusal(url, &error))
        }))
        .unwrap_or_else(|_| {
            Err(Refusal::new(
                ErrorCode::Internal,
                format!("the HTTP client panicked while fetching `{url}`"),
            ))
        })
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

/// A resolver that answers with the addresses the guard approved.
///
/// # ★ The reason this exists
///
/// DNS rebinding: a name that answers with a public address when it is checked and a private one when it is connected to
/// defeats the whole IP policy. The client asks this instead of the system resolver, and this has no opinion — it returns
/// what [`synra_core::network::NetworkGuard::check_resolved`] already passed.
///
/// The `Host` header and the certificate still carry the **name**, so this is not "connect to an IP and hope": the name is
/// what is verified and the address is what was approved, which is the pair the design asks for.
#[derive(Debug)]
struct FixedResolver {
    /// The addresses, in the order they were resolved.
    addresses: Vec<SocketAddr>,
}

impl ureq::unversioned::resolver::Resolver for FixedResolver {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        // The client's own filter, so this cannot disagree with what the connection layer expects.
        // The family is held in a binding: `keep_wanted` borrows it, and a temporary would be freed at the end of the
        // statement that created the iterator.
        let family = config.ip_family();
        let wanted = family.keep_wanted(self.addresses.iter().copied());
        let mut answer = self.empty();
        for address in wanted {
            answer.push(address);
        }
        if answer.is_empty() {
            // ★ Not "the host was not found": the host was found and **refused**. The distinction is made by
            // `check_resolved`, which ran before this and produced the refusal the caller actually reports — this is only
            // the shape the client requires.
            return Err(ureq::Error::HostNotFound);
        }
        Ok(answer)
    }
}


/// A transport failure, as a code a plugin can branch on.
fn transport_refusal(url: &str, error: &ureq::Error) -> Refusal {
    match error {
        ureq::Error::Timeout(_) => timeout_refusal(url, DEFAULT_TIMEOUT),
        ureq::Error::Io(_) | ureq::Error::ConnectionFailed => {
            Refusal::new(ErrorCode::TransportNotOpen, format!("`{url}` could not be reached: {error}"))
        }
        // A host that no longer resolves gets the code that says so, rather than a generic failure: it is the one
        // transport error a plugin can act on by asking about something else.
        ureq::Error::HostNotFound => {
            Refusal::new(ErrorCode::HostNotAllowed, format!("`{url}` no longer resolves"))
        }
        _ => Refusal::new(ErrorCode::Internal, format!("`{url}` failed: {error}")),
    }
}

/// The refusal for a request that ran out of time.
fn timeout_refusal(url: &str, limit: Duration) -> Refusal {
    Refusal::new(
        ErrorCode::Timeout,
        format!("`{url}` did not finish within {} seconds", limit.as_secs()),
    )
}

/// The refusal for a body that could not be read, or was too large.
///
/// # Why the size is distinguished from every other read failure
///
/// Because it is the only one the plugin can act on. "The response was larger than this host will read" is answered by
/// asking for less — a range, a page, a narrower query — while a connection that dropped mid-body is answered by trying
/// again. Folding them into one code would take away the distinction the plugin needs.
fn body_refusal(url: &str, limit: u64, error: &ureq::Error) -> Refusal {
    match error {
        ureq::Error::BodyExceedsLimit(_) => Refusal::new(
            ErrorCode::ResponseTooLarge,
            format!("`{url}` answered with more than {limit} bytes"),
        ),
        ureq::Error::Timeout(_) => timeout_refusal(url, DEFAULT_TIMEOUT),
        _ => Refusal::new(
            ErrorCode::TransportNotOpen,
            format!("`{url}` answered but its body could not be read: {error}"),
        ),
    }
}

#[cfg(test)]
mod tests;
