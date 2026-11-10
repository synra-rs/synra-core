use synra_protocol::error::ErrorCode;

use crate::{ChannelError, Decoder, PROTOCOL_VERSION, Request, Response, check_version};

use super::{Kernel, Refusal};

/// What the handler decided about a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionState {
    /// The connection may continue.
    Open,
    /// The connection is finished and the caller should close it.
    ///
    /// Set after a version mismatch, because the client and the kernel cannot talk and every further request would be
    /// another refusal. Reading a pipelined stream after that is reading requests nobody can answer.
    Close,
}

/// A conversation with one client.
///
/// # Why one handler per connection rather than one per kernel
///
/// The handshake is per connection: a client that has not said hello may not ask anything else, and a second client's
/// hello must not satisfy the first's. State shared between connections would make whether a request is answered depend
/// on what some other client did.
#[derive(Debug)]
pub struct Server {
    /// Whether a valid handshake has happened on this connection.
    handshook: bool,
    /// Bytes from the client that are not yet a whole message.
    decoder: Decoder,
    /// How many requests this connection has answered.
    answered: u64,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// A handler for a connection that has said nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handshook: false,
            decoder: Decoder::new(),
            answered: 0,
        }
    }

    /// Whether a valid handshake has happened.
    #[must_use]
    pub const fn handshook(&self) -> bool {
        self.handshook
    }

    /// How many requests this connection has been answered.
    ///
    /// For a log line, and for the one assertion that a pipelined batch was answered in full.
    #[must_use]
    pub const fn answered(&self) -> u64 {
        self.answered
    }

    /// Takes bytes from the client and appends the answers to `out`.
    ///
    /// # The order is the guarantee
    ///
    /// Answers are appended in the order the requests arrived, one per request. A client that pipelined three requests
    /// reads three answers and matches them positionally, so a handler that answered out of order — or answered one
    /// request with two responses — would make a script read the status report as the device list.
    ///
    /// # Errors
    ///
    /// A [`ChannelError`] when the stream cannot be framed. That is fatal for the connection: the caller closes it,
    /// because a framing error leaves the stream in a position nobody can vouch for.
    pub fn feed(
        &mut self,
        bytes: &[u8],
        kernel: &impl Kernel,
        out: &mut Vec<u8>,
    ) -> Result<SessionState, ChannelError> {
        self.decoder.push(bytes);

        let mut state = SessionState::Open;
        loop {
            let request: Request = match self.decoder.next_message() {
                Ok(Some(request)) => request,
                // Not yet a whole message. The client may be mid-write, and waiting is what a socket requires.
                Ok(None) => return Ok(state),
                // A framing error is fatal: the bytes after a length that was wrong are not where the next header is.
                Err(error) => return Err(error),
            };

            let response = self.handle(&request, kernel);
            out.extend_from_slice(&crate::encode(&response)?);
            self.answered = self.answered.saturating_add(1);

            if self.should_close(&request) {
                state = SessionState::Close;
                // The rest of the buffer is dropped: it is requests this connection will never answer, and answering
                // them would be answering a client that has already been told to go away.
                return Ok(state);
            }
        }
    }

    /// Whether the connection ends after this request.
    const fn should_close(&self, request: &Request) -> bool {
        // A handshake that failed leaves the two unable to talk, and every further request would be another refusal.
        if request.is_handshake() && !self.handshook {
            return true;
        }
        false
    }

    /// Answers one request.
    fn handle(&mut self, request: &Request, kernel: &impl Kernel) -> Response {
        // ★ The handshake first, and it is the one request answered before the version is checked — its answer is *how*
        // a client learns the version it should have sent. A handler that checked first would answer a version mismatch
        // with a version mismatch, and the client would have nothing to compare against.
        if let Request::Hello { version } = request {
            return match check_version(*version) {
                Ok(()) => {
                    self.handshook = true;
                    Response::Hello {
                        version: PROTOCOL_VERSION,
                        kernel: kernel.version(),
                    }
                }
                Err(error) => {
                    Response::failed("protocol_version_unsupported", error.to_string(), false)
                }
            };
        }

        if !self.handshook {
            // ★ A request before the handshake is refused rather than served. A kernel that served it would be one whose
            // behaviour depends on a version it never established — and the client would be reading answers to a
            // protocol it never agreed to.
            return Response::failed(
                "invalid_argument",
                "send Hello before any other request",
                false,
            );
        }

        let result = match request {
            Request::Status => kernel.status(),
            Request::Devices {
                include_unpaired,
                scan_ms,
            } => kernel.devices(*include_unpaired, *scan_ms),
            Request::SendText { to, text } => kernel.send_text(to, text),
            Request::SendFile { to, path } => kernel.send_file(to, path),
            Request::Plugins => kernel.plugins(),
            Request::PluginPublishers => kernel.plugin_publishers(),
            Request::PluginPublisherDecide {
                publisher_id,
                fingerprint,
                trust,
            } => kernel.plugin_publisher_decide(publisher_id, fingerprint, trust),
            Request::PluginRegistry { urls } => kernel.plugin_registry(urls.as_deref()),
            Request::PluginUpdatePolicy { policy } => {
                kernel.plugin_update_policy(policy.as_deref())
            }
            Request::PluginCheckUpdates { plugin_id } => {
                kernel.plugin_check_updates(plugin_id.as_deref())
            }
            Request::PluginUpdate { plugin_id, version } => {
                kernel.plugin_update(plugin_id, version.as_deref())
            }
            Request::CatalogSearch { package } => kernel.catalog_search(package),
            Request::PluginSetEnabled { plugin_id, enabled } => {
                kernel.plugin_set_enabled(plugin_id, *enabled)
            }
            Request::PluginInstall { path } => kernel.plugin_install(path),
            Request::PluginInstallPackage { package, version } => {
                kernel.plugin_install_package(package, version.as_deref())
            }
            Request::PluginConsent { plugin_id, granted } => {
                kernel.plugin_consent(plugin_id, granted)
            }
            Request::PluginRemove {
                plugin_id,
                remove_data,
            } => kernel.plugin_remove(plugin_id, *remove_data),
            Request::IntentDispatch { mime, text } => kernel.intent_dispatch(mime, text),
            Request::IntentSnapshot { intent } => kernel.intent_snapshot(intent),
            Request::IntentDecide {
                intent,
                plugin_id,
                target,
            } => kernel.intent_decide(intent, plugin_id.as_deref(), target.as_deref()),
            Request::IntentCancel { intent } => kernel.intent_cancel(intent),
            Request::Logs {
                lines,
                verbose,
                trace,
            } => kernel.logs(*lines, *verbose, trace.as_deref()),
            // Answered above, and unreachable here. Written as a refusal rather than a `panic!` because a handler that
            // can panic on a request is one a hostile client can take down — and this channel is reachable by anything
            // that can open the socket.
            Request::Hello { .. } => Err(Refusal::new(
                ErrorCode::Internal,
                "the handshake was not handled",
            )),
        };

        match result {
            Ok(value) => Response::ok(value),
            Err(refusal) => refusal.into(),
        }
    }
}
