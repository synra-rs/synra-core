use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use synra_core::network::{Checked, Refusal};
use synra_protocol::error::ErrorCode;

use crate::DEFAULT_TIMEOUT;

use super::{Client, Request};

impl Client {
    /// Resolves a checked URL and refuses unless **every** address may be reached.
    ///
    /// # The order, and why it is this way round
    ///
    /// The lookup happens here, once, and its answer is what [`synra_core::network::NetworkGuard::check_resolved`] judges and what
    /// [`FixedResolver`] then hands the client. Looking the name up a second time inside the client would be the
    /// rebinding window this design exists to close.
    pub(super) fn resolve(&self, checked: &Checked) -> Result<Vec<SocketAddr>, Refusal> {
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
    pub(super) fn agent(&self, addresses: &[SocketAddr], remaining: Duration) -> Result<ureq::Agent, Refusal> {
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
    pub(super) fn one_request(
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
pub(super) fn timeout_refusal(url: &str, limit: Duration) -> Refusal {
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
pub(super) fn body_refusal(url: &str, limit: u64, error: &ureq::Error) -> Refusal {
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
