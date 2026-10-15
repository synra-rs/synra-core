//! What the kernel does when a client asks it something.
//!
//! # Why this is a trait here rather than a method on the daemon
//!
//! A command handler that read a socket, called a kernel and wrote a socket would be one whose tests needed all three.
//! Splitting it means the *protocol* half — which requests are answered, in what order, and how a failure becomes a
//! response — is testable against a fake kernel, and the daemon supplies the real one.
//!
//! That split is where the interesting bugs live. A handler that answered a second request before the first would
//! reorder a script's output; one that answered after the client had gone would write to a closed socket; one that let a
//! failure end the connection would make every subsequent request in a pipeline fail with a framing error rather than
//! its own answer.
//!
//! # What is deliberately not here
//!
//! No sockets, no threads and no async. [`Server`] takes bytes and produces bytes, so its tests are a few lines each
//! and do not flake.

use crate::{
    ChannelError, Decoder, PROTOCOL_VERSION, Request, Response, check_version,
};
use synra_protocol::error::ErrorCode;

/// A refusal the kernel is reporting.
///
/// # Why the code is the protocol's `ErrorCode` rather than a string
///
/// Because a string is a second spelling of a name that already exists, and the two drift at the first rename — with
/// the failure landing in a client that branches on a code the kernel no longer sends. Using the protocol's type also
/// gives the *retryable* flag for free: whether a failure is worth repeating is a property of the code, and a kernel
/// that decided for itself would be a second opinion that can contradict the one every other part of the system uses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct Refusal {
    /// The kernel's stable error code.
    pub code: ErrorCode,
    /// A sentence for a person.
    ///
    /// # Why a sentence here and a key at the interface
    ///
    /// The interface renders a *message key* because it knows the user's language. A command-line client does not: it
    /// prints, and its output goes to a terminal rather than to a translated screen. So the sentence is composed here,
    /// where the detail is, and the interface's boundary keeps its keys.
    pub message: String,
}

impl Refusal {
    /// A refusal with a sentence.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// Whether repeating the request as it was could succeed.
    ///
    /// Read from the code rather than stored, so a refusal cannot claim to be retryable when its code says otherwise.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.code.retryable()
    }
}

impl From<Refusal> for Response {
    fn from(refusal: Refusal) -> Self {
        // Read before the message is moved out: `is_retryable` borrows the refusal, and the message is a field of it.
        let retryable = refusal.is_retryable();
        // ★ The code's wire spelling, which is the same string the interface, the device protocol and the plugin
        // boundary use. A second spelling here would be a code a script matches on that appears nowhere else.
        Self::failed(refusal.code.as_str(), refusal.message, retryable)
    }
}

/// What the kernel can be asked.
///
/// # Why the log is not a method
///
/// The log is the kernel's own, and a kernel that served it would be reading a file it is writing. The daemon supplies
/// it from [`synra_observe`]'s log directory, which is why it is a method here rather than a field: it may need to
/// re-read.
///
/// [`synra_observe`]: https://docs.rs/synra-observe
pub trait Kernel {
    /// The kernel's own version, for a bug report.
    fn version(&self) -> String;

    /// The kernel's state and its links, as one JSON value.
    ///
    /// # Errors
    ///
    /// A [`Refusal`] when the kernel cannot answer — which is not "the kernel is not running", because a running kernel
    /// is the only thing that could have been asked.
    fn status(&self) -> Result<serde_json::Value, Refusal>;

    /// The devices the kernel has seen, as one JSON value.
    ///
    /// `scan_ms` is how long to look on the network before answering, and `None` means "answer from what you already
    /// know". It is a parameter rather than something the caller does because only the kernel holds a discovery socket.
    ///
    /// # Errors
    ///
    /// As [`Kernel::status`].
    fn devices(
        &self,
        include_unpaired: bool,
        scan_ms: Option<u64>,
    ) -> Result<serde_json::Value, Refusal>;

    /// Sends text to a device.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::DeviceOffline`] and friends: the refusals a send produces are the kernel's, not this channel's.
    fn send_text(&self, to: &str, text: &str) -> Result<serde_json::Value, Refusal>;

    /// Sends a file to a device.
    ///
    /// # Errors
    ///
    /// As [`Kernel::send_text`], plus [`ErrorCode::InvalidArgument`] for a path that is not a readable file.
    fn send_file(&self, to: &str, path: &str) -> Result<serde_json::Value, Refusal>;

    /// The installed plugins, as one JSON value.
    ///
    /// # Errors
    ///
    /// As [`Kernel::status`].
    fn plugins(&self) -> Result<serde_json::Value, Refusal>;

    /// Hands the kernel something to route.
    ///
    /// # ★ Why this is the method that makes the kernel do its job
    ///
    /// Because routing is what the product is: something arrives — a link, a file, a line of text — and a plugin that
    /// can act on it is found, offered to the user, and run. `synra-core` implements every part of that and **nothing
    /// could reach it**: the control protocol had no intent request, so the matcher had no production caller, and a share
    /// that arrived became a file in an inbox rather than an action.
    ///
    /// # What the answer carries
    ///
    /// The candidates the plugins offered, plus the pass's own report — how many were asked, how many declined, and
    /// which of them misbehaved. Those together are what distinguish "nothing is installed" from "everything crashed",
    /// which look identical from a candidate list alone.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the item cannot be read into the shape a plugin is asked about.
    fn intent_dispatch(&self, mime: &str, text: &str) -> Result<serde_json::Value, Refusal>;

    /// What has become of an intent.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the identifier is not one, or names an intent this kernel never raised or has already forgotten.
    fn intent_snapshot(&self, intent: &str) -> Result<serde_json::Value, Refusal>;

    /// Applies the user's answer to a prompt, and runs what they chose.
    ///
    /// # ★ Why this is where an action finally happens
    ///
    /// Because everything before it is a question. `intent_dispatch` asks every plugin whether it can handle a share;
    /// this is the one place where the answer becomes an action, and it happens only for the plugin the user picked.
    /// Keeping the two apart is what stops "what can handle this?" from running third-party code as a side effect.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the intent is unknown, is not in a state that can be decided, or names a plugin that was not
    /// among the candidates — a choice that was never offered must not run.
    fn intent_decide(
        &self,
        intent: &str,
        plugin_id: Option<&str>,
    ) -> Result<serde_json::Value, Refusal>;

    /// The user changed their mind.
    ///
    /// # Errors
    ///
    /// [`Refusal`] when the intent is unknown or has already finished. Cancelling something that is over is not a
    /// failure a user should see, but it is also not a cancellation, and the answer says which happened.
    fn intent_cancel(&self, intent: &str) -> Result<serde_json::Value, Refusal>;

    /// The tail of the kernel's log.
    ///
    /// # Errors
    ///
    /// As [`Kernel::status`].
    fn logs(&self, lines: usize, verbose: bool, trace: Option<&str>) -> Result<serde_json::Value, Refusal>;

    /// Asks a device to pair, and waits for the other user's answer.
    ///
    /// # Why this returns rather than starting something
    ///
    /// Because the caller's next step depends on the outcome: a user who was accepted has a device to list, and one who
    /// was refused has a reason to read. The wait is bounded by the session's pairing window — the same clock the
    /// receiving side uses — so this cannot hold a caller for ever, and the kernel clears its waiting state when the
    /// window closes rather than hanging.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::DeviceOffline`] and friends from resolving and dialling the device, plus
    /// [`ErrorCode::InvalidArgument`] for a device that cannot be found at all.
    fn pair(&self, device: &str) -> Result<serde_json::Value, Refusal>;

    /// Answers a pairing request a device is waiting on.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidArgument`] when nothing is waiting under that request — answered twice, or expired before the
    /// user decided. The distinction matters to a caller: "there is nothing to answer" is a prompt that has gone, not a
    /// failure of the answer.
    fn pair_answer(&self, request_id: &str, accepted: bool) -> Result<serde_json::Value, Refusal>;
}

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
        Self { handshook: false, decoder: Decoder::new(), answered: 0 }
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
                    Response::Hello { version: PROTOCOL_VERSION, kernel: kernel.version() }
                }
                Err(error) => Response::failed("protocol_version_unsupported", error.to_string(), false),
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
            Request::Devices { include_unpaired, scan_ms } => kernel.devices(*include_unpaired, *scan_ms),
            Request::SendText { to, text } => kernel.send_text(to, text),
            Request::SendFile { to, path } => kernel.send_file(to, path),
            Request::Plugins => kernel.plugins(),
            Request::IntentDispatch { mime, text } => kernel.intent_dispatch(mime, text),
            Request::IntentSnapshot { intent } => kernel.intent_snapshot(intent),
            Request::IntentDecide { intent, plugin_id } => {
                kernel.intent_decide(intent, plugin_id.as_deref())
            }
            Request::IntentCancel { intent } => kernel.intent_cancel(intent),
            Request::Logs { lines, verbose, trace } => kernel.logs(*lines, *verbose, trace.as_deref()),
            Request::Pair { device } => kernel.pair(device),
            Request::PairAnswer { request_id, accepted } => kernel.pair_answer(request_id, *accepted),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MAX_MESSAGE_LEN, Response};

    /// A kernel whose every answer a test chose.
    struct Fake {
        status: Result<serde_json::Value, Refusal>,
        devices: Result<serde_json::Value, Refusal>,
        send_text: Result<serde_json::Value, Refusal>,
        send_file: Result<serde_json::Value, Refusal>,
        plugins: Result<serde_json::Value, Refusal>,
        logs: Result<serde_json::Value, Refusal>,
        /// What `devices` was asked, so a test can assert the flag arrived.
        asked: std::cell::RefCell<Vec<(bool, usize, bool)>>,
    }

    impl Fake {
        fn ok() -> Self {
            Self {
                status: Ok(serde_json::json!({"state": "running"})),
                devices: Ok(serde_json::json!({"devices": []})),
                send_text: Ok(serde_json::json!({"sent": true})),
                send_file: Ok(serde_json::json!({"sent": true})),
                plugins: Ok(serde_json::json!({"plugins": []})),
                logs: Ok(serde_json::json!({"lines": []})),
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn refusing(code: ErrorCode) -> Self {
            let error = Refusal::new(code, "the fake refuses");
            Self {
                status: Err(error.clone()),
                devices: Err(error.clone()),
                send_text: Err(error.clone()),
                send_file: Err(error.clone()),
                plugins: Err(error.clone()),
                logs: Err(error),
                asked: std::cell::RefCell::new(Vec::new()),
            }
        }
    }

    impl Kernel for Fake {
        fn version(&self) -> String {
            "0.1.0-test".to_owned()
        }
        fn status(&self) -> Result<serde_json::Value, Refusal> {
            self.status.clone()
        }
        fn devices(&self, include_unpaired: bool, scan_ms: Option<u64>) -> Result<serde_json::Value, Refusal> {
            self.asked.borrow_mut().push((include_unpaired, scan_ms.unwrap_or(0) as usize, false));
            self.devices.clone()
        }
        fn send_text(&self, _to: &str, _text: &str) -> Result<serde_json::Value, Refusal> {
            self.send_text.clone()
        }
        fn send_file(&self, _to: &str, _path: &str) -> Result<serde_json::Value, Refusal> {
            self.send_file.clone()
        }
        /// Refused: this double answers nothing about routing.
    ///
    /// ★ A double that returned an empty candidate list would be worse than this: "nothing can handle it" and "this is
    /// not implemented here" are different facts, and a test that could not tell them apart would be asserting about the
    /// double rather than about the code.
    fn intent_snapshot(&self, _intent: &str) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(
            synra_protocol::ErrorCode::Internal,
            "this kernel does not route intents",
        ))
    }

    fn intent_decide(
        &self,
        _intent: &str,
        _plugin_id: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(
            synra_protocol::ErrorCode::Internal,
            "this kernel does not route intents",
        ))
    }

    fn intent_cancel(&self, _intent: &str) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(
            synra_protocol::ErrorCode::Internal,
            "this kernel does not route intents",
        ))
    }

    fn intent_dispatch(&self, _mime: &str, _text: &str) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(
            synra_protocol::ErrorCode::Internal,
            "this kernel does not route intents",
        ))
    }

    fn plugins(&self) -> Result<serde_json::Value, Refusal> {
            self.plugins.clone()
        }
        fn logs(
            &self,
            lines: usize,
            verbose: bool,
            _trace: Option<&str>,
        ) -> Result<serde_json::Value, Refusal> {
            self.asked.borrow_mut().push((false, lines, verbose));
            self.logs.clone()
        }
        fn pair(&self, _device: &str) -> Result<serde_json::Value, Refusal> {
            self.asked.borrow_mut().push((false, 0, false));
            Ok(serde_json::json!({ "paired": true }))
        }
        fn pair_answer(&self, request_id: &str, accepted: bool) -> Result<serde_json::Value, Refusal> {
            self.asked.borrow_mut().push((accepted, request_id.len(), false));
            Ok(serde_json::json!({ "requestId": request_id, "accepted": accepted }))
        }
    }

    /// Runs a batch of requests through a fresh handler and returns the answers.
    fn run(kernel: &impl Kernel, requests: &[Request]) -> (Vec<Response>, SessionState) {
        let mut server = Server::new();
        let mut input = Vec::new();
        for request in requests {
            input.extend_from_slice(&crate::encode(request).expect("encodes"));
        }
        let mut out = Vec::new();
        let state = server.feed(&input, kernel, &mut out).expect("no framing error");

        let mut decoder = Decoder::new();
        decoder.push(&out);
        let mut responses = Vec::new();
        while let Some(response) = decoder.next_message::<Response>().expect("no error") {
            responses.push(response);
        }
        (responses, state)
    }

    fn hello() -> Request {
        Request::Hello { version: PROTOCOL_VERSION }
    }

    // ── The handshake ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_hello_is_answered_with_the_versions() {
        let (responses, state) = run(&Fake::ok(), &[hello()]);
        assert_eq!(state, SessionState::Open);
        match &responses[0] {
            Response::Hello { version, kernel } => {
                assert_eq!(*version, PROTOCOL_VERSION);
                assert_eq!(kernel, "0.1.0-test");
            }
            other => panic!("expected a hello, got {other:?}"),
        }
    }

    #[test]
    fn a_mismatched_version_is_refused_and_the_connection_closes() {
        // ★ A client and a kernel are separate binaries that may be upgraded separately. Once the versions disagree
        // there is nothing to say, so the connection ends rather than answering every further request with the same
        // refusal — and the client learns both versions from the one answer.
        let (responses, state) = run(&Fake::ok(), &[Request::Hello { version: 99 }]);
        assert_eq!(state, SessionState::Close);
        assert_eq!(responses[0].error_code(), Some("protocol_version_unsupported"));
        match &responses[0] {
            Response::Failed { message, .. } => {
                assert!(message.contains("99"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_request_before_the_handshake_is_refused() {
        // ★ A kernel that served it would be one whose behaviour depends on a version it never established — and the
        // client would be reading answers to a protocol it never agreed to.
        let (responses, state) = run(&Fake::ok(), &[Request::Status]);
        assert_eq!(state, SessionState::Open);
        assert_eq!(responses[0].error_code(), Some("invalid_argument"));
        match &responses[0] {
            Response::Failed { message, .. } => assert!(message.contains("Hello"), "{message}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_handshake_opens_the_connection_for_what_follows() {
        let (responses, _) = run(&Fake::ok(), &[hello(), Request::Status, Request::Plugins]);
        assert_eq!(responses.len(), 3);
        assert!(matches!(responses[0], Response::Hello { .. }));
        assert!(responses[1].is_ok());
        assert!(responses[2].is_ok());
    }

    #[test]
    fn a_second_hello_is_answered_rather_than_refused() {
        // A client that re-sends the handshake — a retry after a half-open connection — gets the same answer rather
        // than an error, because the request is well-formed and the kernel knows its own version.
        let (responses, state) = run(&Fake::ok(), &[hello(), hello(), Request::Status]);
        assert_eq!(state, SessionState::Open);
        assert!(matches!(responses[0], Response::Hello { .. }));
        assert!(matches!(responses[1], Response::Hello { .. }));
        assert!(responses[2].is_ok());
    }

    #[test]
    fn a_failed_handshake_does_not_open_the_connection() {
        // The version check failed, so `handshook` stays false. A handler that set it anyway would serve requests over a
        // protocol mismatch — the one thing the handshake exists to prevent.
        let mut server = Server::new();
        let kernel = Fake::ok();
        let mut out = Vec::new();
        server
            .feed(&crate::encode(&Request::Hello { version: 99 }).expect("encodes"), &kernel, &mut out)
            .expect("no framing error");
        assert!(!server.handshook());
    }

    // ── Routing ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn each_request_reaches_its_own_kernel_method() {
        // A `match` with a copy-paste mistake routes two requests to one method, and the symptom is a client that asks
        // for the log and gets the device list.
        let kernel = Fake::ok();
        let (responses, _) = run(
            &kernel,
            &[
                hello(),
                Request::Devices { include_unpaired: true, scan_ms: Some(750) },
                Request::Logs { lines: 25, verbose: true, trace: None },
            ],
        );
        assert_eq!(responses[1], Response::ok(serde_json::json!({"devices": []})));
        assert_eq!(responses[2], Response::ok(serde_json::json!({"lines": []})));

        // And the operands arrived rather than being dropped by the routing.
        let asked = kernel.asked.borrow();
        assert_eq!(asked[0], (true, 750, false), "devices did not get its flag and its scan budget");
        assert_eq!(asked[1], (false, 25, true), "logs did not get its operands");
    }

    #[test]
    fn every_request_is_answerable_after_the_handshake() {
        // Every variant, because a `match` that forgot one would answer it with the `Internal` fallback — and the
        // request a user happened to send is the one that breaks.
        let (responses, state) = run(
            &Fake::ok(),
            &[
                hello(),
                Request::Status,
                Request::Devices { include_unpaired: false, scan_ms: None },
                Request::SendText { to: "dev_a".to_owned(), text: "hi".to_owned() },
                Request::SendFile { to: "dev_a".to_owned(), path: "/tmp/a".to_owned() },
                Request::Plugins,
                Request::Logs { lines: 10, verbose: false, trace: None },
            ],
        );
        assert_eq!(state, SessionState::Open);
        assert_eq!(responses.len(), 7);
        for (index, response) in responses.iter().enumerate().skip(1) {
            assert!(response.is_ok(), "request {index} was refused: {response:?}");
        }
    }

    #[test]
    fn a_kernels_refusal_becomes_a_response_with_its_code_and_retryability() {
        // ★ The code and the retryable flag both come from the protocol's `ErrorCode`, so a kernel cannot report a code
        // whose retryability disagrees with what every other part of the system believes about it.
        for code in [ErrorCode::DeviceOffline, ErrorCode::NotPaired, ErrorCode::Internal] {
            let (responses, state) = run(&Fake::refusing(code), &[hello(), Request::Status]);
            assert_eq!(state, SessionState::Open, "a refusal is not a reason to close");
            match &responses[1] {
                Response::Failed { code: reported, retryable, .. } => {
                    assert_eq!(reported, code.as_str());
                    assert_eq!(*retryable, code.retryable(), "{} retryability", code.as_str());
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_refusal_does_not_end_the_connection() {
        // ★ One failing command must not take the connection with it: a script that runs five commands and gets a
        // refusal for the third has to be able to read the other four answers. A handler that closed on a refusal would
        // leave the client with a framing error for the message it never received.
        let (responses, state) = run(
            &Fake::refusing(ErrorCode::DeviceOffline),
            &[hello(), Request::Status, Request::Plugins, Request::Logs { lines: 1, verbose: false, trace: None }],
        );
        assert_eq!(state, SessionState::Open);
        assert_eq!(responses.len(), 4);
        assert!(responses[0].is_ok(), "the handshake should not be refused: {:?}", responses[0]);
        for response in &responses[1..] {
            assert!(!response.is_ok(), "{response:?}");
        }
    }

    #[test]
    fn a_path_that_is_not_a_file_is_the_kernels_refusal_rather_than_the_channels() {
        // The channel carries a string and does not look at the filesystem: whether a path is readable is the kernel's
        // question, because the kernel is what knows which directories a client may name.
        let (responses, _) = run(
            &Fake::refusing(ErrorCode::InvalidArgument),
            &[hello(), Request::SendFile { to: "d".to_owned(), path: "nope".to_owned() }],
        );
        assert_eq!(responses[1].error_code(), Some("invalid_argument"));
    }

    // ── Pipelining and framing ────────────────────────────────────────────────────────────────────

    #[test]
    fn a_pipelined_batch_is_answered_in_order() {
        // ★ Answers are appended in the order the requests arrived, one per request. A client that pipelined three reads
        // three positionally, so a handler that answered out of order would make a script read the status report as the
        // device list.
        let kernel = Fake::ok();
        let mut server = Server::new();
        let mut input = Vec::new();
        for request in [hello(), Request::Status, Request::Plugins] {
            input.extend_from_slice(&crate::encode(&request).expect("encodes"));
        }
        let mut out = Vec::new();
        server.feed(&input, &kernel, &mut out).expect("no error");

        let mut decoder = Decoder::new();
        decoder.push(&out);
        let first: Response = decoder.next_message().expect("no error").expect("one");
        let second: Response = decoder.next_message().expect("no error").expect("two");
        let third: Response = decoder.next_message().expect("no error").expect("three");
        assert!(matches!(first, Response::Hello { .. }));
        assert_eq!(second, Response::ok(serde_json::json!({"state": "running"})));
        assert_eq!(third, Response::ok(serde_json::json!({"plugins": []})));
        assert_eq!(server.answered(), 3);
    }

    #[test]
    fn a_partial_request_produces_no_answer_yet() {
        // A socket delivers bytes, not messages. A handler that answered a half-arrived request would answer something
        // nobody asked.
        let kernel = Fake::ok();
        let mut server = Server::new();
        let bytes = crate::encode(&hello()).expect("encodes");
        let mut out = Vec::new();
        let state = server
            .feed(&bytes[..bytes.len() - 1], &kernel, &mut out)
            .expect("no error");

        assert_eq!(state, SessionState::Open);
        assert!(out.is_empty(), "answered a partial request");
        assert_eq!(server.answered(), 0);
    }

    #[test]
    fn a_request_split_across_reads_is_answered_once() {
        let kernel = Fake::ok();
        let mut server = Server::new();
        let bytes = crate::encode(&hello()).expect("encodes");
        let mut out = Vec::new();

        let split = bytes.len() / 2;
        server.feed(&bytes[..split], &kernel, &mut out).expect("no error");
        assert!(out.is_empty());
        server.feed(&bytes[split..], &kernel, &mut out).expect("no error");

        assert_eq!(server.answered(), 1);
        let mut decoder = Decoder::new();
        decoder.push(&out);
        assert!(matches!(
            decoder.next_message::<Response>().expect("no error"),
            Some(Response::Hello { .. })
        ));
    }

    #[test]
    fn an_oversized_length_is_a_framing_error_the_caller_closes_on() {
        // The ceiling is enforced by the decoder, and the handler propagates it rather than swallowing it: a caller that
        // continued after this would be reading a stream whose position nobody can vouch for.
        let kernel = Fake::ok();
        let mut server = Server::new();
        let mut input = Vec::new();
        let huge = u32::try_from(MAX_MESSAGE_LEN + 1).expect("fits");
        input.extend_from_slice(&huge.to_be_bytes());

        let mut out = Vec::new();
        assert!(server.feed(&input, &kernel, &mut out).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn a_malformed_body_is_a_framing_error_and_nothing_is_answered() {
        let kernel = Fake::ok();
        let mut server = Server::new();
        let body = b"{not json";
        let mut input = Vec::new();
        input.extend_from_slice(&u32::try_from(body.len()).expect("fits").to_be_bytes());
        input.extend_from_slice(body);

        let mut out = Vec::new();
        assert!(server.feed(&input, &kernel, &mut out).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn a_request_after_a_version_mismatch_is_not_answered() {
        // ★ The rest of the buffer is dropped. Answering it would be answering a client that has already been told to go
        // away — and the answers would be read by a client that has stopped reading.
        let kernel = Fake::ok();
        let mut server = Server::new();
        let mut input = Vec::new();
        for request in [Request::Hello { version: 99 }, Request::Status] {
            input.extend_from_slice(&crate::encode(&request).expect("encodes"));
        }
        let mut out = Vec::new();
        let state = server.feed(&input, &kernel, &mut out).expect("no error");

        assert_eq!(state, SessionState::Close);
        assert_eq!(server.answered(), 1, "answered a request after closing");
        let mut decoder = Decoder::new();
        decoder.push(&out);
        assert!(decoder.next_message::<Response>().expect("no error").is_some());
        assert!(decoder.next_message::<Response>().expect("no error").is_none());
    }

    #[test]
    fn a_new_handler_starts_unhandshook_and_has_answered_nothing() {
        // The state is per connection, so a second client's handshake cannot satisfy the first's.
        let server = Server::new();
        assert!(!server.handshook());
        assert_eq!(server.answered(), 0);
        assert!(!Server::default().handshook());
    }

    #[test]
    fn one_clients_handshake_does_not_open_another_connection() {
        // ★ The state is per connection. A kernel with one shared flag would let any client that said hello open the
        // door for every other — and the version check would then be something a client could skip by waiting.
        let kernel = Fake::ok();
        let mut first = Server::new();
        let mut out = Vec::new();
        first.feed(&crate::encode(&hello()).expect("encodes"), &kernel, &mut out).expect("no error");
        assert!(first.handshook());

        let mut second = Server::new();
        let mut out = Vec::new();
        second
            .feed(&crate::encode(&Request::Status).expect("encodes"), &kernel, &mut out)
            .expect("no error");
        assert!(!second.handshook());

        let mut decoder = Decoder::new();
        decoder.push(&out);
        let response: Response = decoder.next_message().expect("no error").expect("one");
        assert_eq!(response.error_code(), Some("invalid_argument"));
    }

    // ── The refusal type ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_refusal_reads_its_retryability_from_its_code() {
        // Stored rather than derived, a refusal could claim to be retryable when its code says otherwise — and a script
        // would repeat a call that cannot succeed.
        assert!(Refusal::new(ErrorCode::DeviceOffline, "gone").is_retryable());
        assert!(!Refusal::new(ErrorCode::NotPaired, "not paired").is_retryable());
        // `Internal` is retryable in the kernel, and this is where that shows.
        assert!(Refusal::new(ErrorCode::Internal, "unexpected").is_retryable());
    }

    #[test]
    fn a_refusal_converts_to_the_response_a_client_reads() {
        let response: Response = Refusal::new(ErrorCode::NotPaired, "pair first").into();
        match response {
            Response::Failed { code, message, retryable } => {
                assert_eq!(code, ErrorCode::NotPaired.as_str());
                assert_eq!(message, "pair first");
                assert!(!retryable);
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_refusal_explains_itself() {
        let text = Refusal::new(ErrorCode::DeviceOffline, "the device is not reachable").to_string();
        assert!(text.contains("not reachable"), "{text}");
        assert!(!text.contains('{'), "{text}");
    }


    // ── Answering a pairing prompt ────────────────────────────────────────────────────────────────

    #[test]
    fn a_pair_answer_reaches_the_kernel_with_the_request_and_the_decision() {
        // The whole point of the command: the decision is made by a user on this channel and carried out on the desk,
        // which the connection that asked is blocked on.
        let kernel = Fake::ok();
        let (responses, _) = run(
            &kernel,
            &[
                hello(),
                Request::PairAnswer { request_id: "01a139a9-8f3c-72ce-9c96-2b2c81f14551".to_owned(), accepted: true },
            ],
        );
        assert_eq!(
            responses[1],
            Response::ok(serde_json::json!({
                "requestId": "01a139a9-8f3c-72ce-9c96-2b2c81f14551",
                "accepted": true
            }))
        );
    }

    #[test]
    fn a_pair_answer_carries_a_refusal_too() {
        // A refusal is an answer, not an error: declining is a decision a user made, and the requesting device's link is
        // not ended by it.
        let kernel = Fake::ok();
        let (responses, _) = run(
            &kernel,
            &[hello(), Request::PairAnswer { request_id: "01a139a9-8f3c-72ce-9c96-2b2c81f14551".to_owned(), accepted: false }],
        );
        assert_eq!(
            responses[1],
            Response::ok(serde_json::json!({
                "requestId": "01a139a9-8f3c-72ce-9c96-2b2c81f14551",
                "accepted": false
            }))
        );
    }

    #[test]
    fn a_pair_answer_before_the_handshake_is_refused() {
        let (responses, _) = run(
            &Fake::ok(),
            &[Request::PairAnswer { request_id: "01a139a9-8f3c-72ce-9c96-2b2c81f14551".to_owned(), accepted: true }],
        );
        assert!(matches!(responses[0], Response::Failed { .. }), "{:?}", responses[0]);
    }

    #[test]
    fn a_pair_answer_names_itself_in_a_log_line() {
        assert_eq!(
            Request::PairAnswer { request_id: String::new(), accepted: true }.kind(),
            "pairAnswer"
        );
    }

    #[test]
    fn a_pair_answer_round_trips_through_the_wire() {
        let request = Request::PairAnswer {
            request_id: "01a139a9-8f3c-72ce-9c96-2b2c81f14551".to_owned(),
            accepted: true,
        };
        let bytes = crate::encode(&request).expect("encodes");
        let mut decoder = Decoder::new();
        decoder.push(&bytes);
        let back: Request = decoder.next_message().expect("no error").expect("one message");
        assert_eq!(back, request);
    }
}
