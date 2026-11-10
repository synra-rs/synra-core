use synra_protocol::error::ErrorCode;

use crate::{Decoder, PROTOCOL_VERSION, Request, Response};

use super::{Kernel, Refusal, Server, SessionState};

mod framing;
mod handshake;
mod refusals;
mod routing;

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
    fn devices(
        &self,
        include_unpaired: bool,
        scan_ms: Option<u64>,
    ) -> Result<serde_json::Value, Refusal> {
        self.asked
            .borrow_mut()
            .push((include_unpaired, scan_ms.unwrap_or(0) as usize, false));
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
            ErrorCode::Internal,
            "this kernel does not route intents",
        ))
    }

    fn intent_decide(
        &self,
        _intent: &str,
        _plugin_id: Option<&str>,
        _target: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(
            ErrorCode::Internal,
            "this kernel does not route intents",
        ))
    }

    fn intent_cancel(&self, _intent: &str) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(
            ErrorCode::Internal,
            "this kernel does not route intents",
        ))
    }

    fn intent_dispatch(&self, _mime: &str, _text: &str) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(
            ErrorCode::Internal,
            "this kernel does not route intents",
        ))
    }

    fn plugin_set_enabled(
        &self,
        _plugin_id: &str,
        _enabled: bool,
    ) -> Result<serde_json::Value, Refusal> {
        Err(Refusal::new(
            ErrorCode::Internal,
            "this kernel keeps no plugin records",
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
}

/// Runs a batch of requests through a fresh handler and returns the answers.
fn run(kernel: &impl Kernel, requests: &[Request]) -> (Vec<Response>, SessionState) {
    let mut server = Server::new();
    let mut input = Vec::new();
    for request in requests {
        input.extend_from_slice(&crate::encode(request).expect("encodes"));
    }
    let mut out = Vec::new();
    let state = server
        .feed(&input, kernel, &mut out)
        .expect("no framing error");

    let mut decoder = Decoder::new();
    decoder.push(&out);
    let mut responses = Vec::new();
    while let Some(response) = decoder.next_message::<Response>().expect("no error") {
        responses.push(response);
    }
    (responses, state)
}

fn hello() -> Request {
    Request::Hello {
        version: PROTOCOL_VERSION,
    }
}
