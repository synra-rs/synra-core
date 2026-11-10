use std::cell::RefCell;
use std::path::{Path, PathBuf};

use synra_protocol::error::ErrorCode;

use crate::Refusal;

use super::{Listener, SocketError};

mod address;
mod handshake;
mod session;

struct Fake {
    asked: RefCell<Vec<String>>,
    fail: Option<ErrorCode>,
}

impl Fake {
    fn new() -> Self {
        Self {
            asked: RefCell::new(Vec::new()),
            fail: None,
        }
    }

    fn refusing(code: ErrorCode) -> Self {
        Self {
            asked: RefCell::new(Vec::new()),
            fail: Some(code),
        }
    }

    fn answer(&self, kind: &str) -> Result<serde_json::Value, Refusal> {
        self.asked.borrow_mut().push(kind.to_owned());
        match self.fail {
            Some(code) => Err(Refusal::new(code, "the fake refuses")),
            None => Ok(serde_json::json!({"kind": kind})),
        }
    }
}

impl crate::Kernel for Fake {
    fn version(&self) -> String {
        "0.1.0-test".to_owned()
    }
    fn status(&self) -> Result<serde_json::Value, Refusal> {
        self.answer("status")
    }
    fn devices(
        &self,
        _include_unpaired: bool,
        _scan_ms: Option<u64>,
    ) -> Result<serde_json::Value, Refusal> {
        self.answer("devices")
    }
    fn send_text(&self, _to: &str, _text: &str) -> Result<serde_json::Value, Refusal> {
        self.answer("sendText")
    }
    fn send_file(&self, _to: &str, _path: &str) -> Result<serde_json::Value, Refusal> {
        self.answer("sendFile")
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
        self.answer("plugins")
    }
    fn logs(
        &self,
        _lines: usize,
        _verbose: bool,
        _trace: Option<&str>,
    ) -> Result<serde_json::Value, Refusal> {
        self.answer("logs")
    }
}

/// A temporary directory that removes itself.
///
/// The name carries the process id and the test's own name, because a test binary runs its tests in parallel and two
/// of them binding the same path would fail with "address in use" for a reason that has nothing to do with what is
/// being tested.
///
/// It is kept as short as those two allow: a unix socket path has a hard limit, and a directory name long enough to
/// approach it would make the tests fail for a reason that has nothing to do with the code.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs a server for one connection on its own thread, and returns the handle.
fn serve_in_background(
    listener: Listener,
    kernel: Fake,
) -> std::thread::JoinHandle<Result<(), SocketError>> {
    std::thread::spawn(move || listener.serve_one(&kernel))
}
