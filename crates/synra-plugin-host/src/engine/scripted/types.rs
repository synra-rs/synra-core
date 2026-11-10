//! Scripted answers and their compile failures.

use super::super::types::CallOutcome;

/// Why a scripted backend would not compile an artifact.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScriptError {
    /// The artifact is empty.
    ///
    /// The one input a real engine also refuses, and the one worth keeping: a test that passes an empty artifact by
    /// mistake should learn about it here rather than from a call that mysteriously succeeds.
    #[error("the artifact is empty")]
    Empty,

    /// The artifact is not the magic a component starts with.
    ///
    /// A real component begins with the Wasm header and a component-model layer. Checking the header is what makes this
    /// backend refuse a text file, a tarball or a truncated download — the inputs a *host* must refuse, whatever the
    /// engine does with them.
    #[error("the artifact does not begin with the WebAssembly header")]
    NotWasm,
}

/// What one entry point answers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scripted {
    /// Return this payload.
    Ok(String),
    /// Return this structured failure.
    Failed {
        /// The stable error code.
        code: String,
        /// The sentence.
        message: String,
        /// Optional details, matching the real engine's WIT result.
        details: Option<String>,
    },
    /// Trap.
    Trap {
        /// What the engine "said".
        detail: String,
    },
    /// ★ Panic inside the host, rather than a trap reported by the guest.
    ///
    /// The distinction is the point: a trap is a value the engine returns, and a panic is an unwind that has to be
    /// caught before it reaches the thread that dispatched the call. A host function that indexes out of bounds, or
    /// unwraps a `None`, produces this one.
    Panic {
        /// The message the panic carries, which is what the boundary should report.
        message: String,
    },
    /// Time out, whatever the budget says.
    ///
    /// # Why a script may ignore the budget
    ///
    /// Because some of the conditions the host must handle cannot be produced by a well-behaved backend at all — a
    /// guest wedged inside a host call is the one that matters, and it consumes no instructions while it is wedged. A
    /// script that always honoured its budget could not express it, and the host's handling of it would be untested.
    Timeout,
    /// Report the memory limit as reached.
    MemoryExceeded,
    /// Report the fuel as exhausted.
    FuelExhausted,
}

/// Raises the panic that [`Scripted::Panic`] asks for.
///
/// # Why this is a function with an `allow` on it
///
/// The workspace denies `clippy::panic`, everywhere and for good reason: a library that panics turns a caller's mistake
/// into a crash. This is the one place where panicking is the *point* rather than an accident — the variant exists
/// solely so a test can make the host unwind, and a function that returned instead would be a test double that cannot
/// produce the condition it is named after.
///
/// The `allow` is on this function rather than on `call`, so it covers the one statement that means to panic and not
/// the eleven match arms around it.
#[allow(
    clippy::panic,
    reason = "this is the only way to raise the host panic that Scripted::Panic exists to produce, and the allow is \
              scoped to this function so the rest of the double stays under the workspace's rule"
)]
pub(super) fn raise(message: &str) -> CallOutcome {
    panic!("{message}")
}


