//! What a command asks the kernel, and how the answer becomes output.
//!
//! # Why this is separate from the command line's own types
//!
//! A command's arguments are the user's words — `--all`, `--text`, `--lines` — and a request's operands are the
//! kernel's. Mapping one to the other is a small function per command, and the smallness is the point: everything that
//! can be *decided* here is decided here, so the binary stays a thing you can read in one go.
//!
//! # Why the mapping is asserted rather than eyeballed
//!
//! A `--all` that did not reach `include_unpaired`, or a `--lines` that arrived as the default, is a command whose flag
//! is silently ignored — and the user's evidence is output that looks plausible. Each mapping has a test that asserts the
//! operand arrived, because that is the failure this layer can have.

use synra_control::Client;
use synra_protocol::error::ErrorCode;

mod devices;
mod plugin_updates;
mod publishers;
mod question;
mod reinstall;
mod response;

pub use question::{Question, Shape, question_for};
pub use reinstall::reinstall;
pub use response::outcome_of;

/// Runs a question against a kernel and turns the answer into output.
///
/// # Why the handshake is here and not in the caller
///
/// Every command needs it, and a caller that forgot it would get a refusal about the handshake rather than about its
/// command — a message that names the wrong problem. Doing it here means the only way to ask a question is a way that
/// has said hello first.
#[must_use]
pub fn ask(question: &Question, client: &mut Client) -> crate::session::CommandOutcome {
    if let Err(error) = client.handshake() {
        return transport_failure(&error);
    }
    match client.ask(&question.request) {
        Ok(response) => outcome_of(&response, question.shape),
        Err(error) => transport_failure(&error),
    }
}

/// What the user sees when the kernel could not be reached.
///
/// # Why the error's own sentence is used
///
/// It names the path and says what to start, which is what the user needs. A generic "no kernel" would hide the fact
/// that the client looked somewhere specific — and the commonest cause is that it looked in the wrong place, which is
/// exactly what `SYNRA_DATA_DIR` is for.
#[must_use]
pub fn transport_failure(error: &synra_control::SocketError) -> crate::session::CommandOutcome {
    crate::session::CommandOutcome::json_failure(
        serde_json::json!({
            "code": ErrorCode::TransportNotOpen.as_str(),
            "message": error.to_string(),
            "retryable": error.is_retryable(),
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use synra_protocol::error::ErrorCode;

    use super::transport_failure;

    #[test]
    fn a_transport_failure_names_the_path_the_client_looked_at() {
        // ★ A generic "no kernel" would hide the fact that the client looked somewhere specific — and the commonest
        // cause is that it looked in the wrong place, which is exactly what `SYNRA_DATA_DIR` is for.
        let error = synra_control::SocketError::Connect {
            path: std::path::PathBuf::from("/tmp/synra/kernel.sock"),
            why: "no such file".to_owned(),
        };
        match transport_failure(&error) {
            crate::session::CommandOutcome::Json { body, ok } => {
                assert!(!ok);
                assert!(body.contains("kernel.sock"), "{body}");
                assert!(body.contains("transport_not_open"), "{body}");
            }
            other => panic!("expected JSON, got {other:?}"),
        }
    }

    #[test]
    fn a_transport_failure_is_retryable_which_is_why_a_script_should_wait() {
        // `transport_not_open` is retryable in the kernel, and the client reads that rather than deciding. A kernel that
        // is still starting is the ordinary case.
        assert!(ErrorCode::TransportNotOpen.retryable());
    }
}
