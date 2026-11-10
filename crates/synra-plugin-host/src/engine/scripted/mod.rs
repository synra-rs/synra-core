//! A backend that runs no code, and why having one is not a shortcut.
//!
//! # What this is
//!
//! A [`WasmBackend`] whose answers come from a table: each entry names the work it answers and what the call produces.
//! It compiles anything, instantiates anything, and — the part that matters — produces *trap*, *timeout*, *fuel
//! exhausted* and *memory exceeded* on demand.
//!
//! # Why the crate has one at all
//!
//! An engine is a large dependency with a C toolchain under it, and the questions this crate gets wrong are not the
//! questions an engine answers. Which instance a call gets, whether a budget was armed, what a run of traps does to a
//! plugin's health, whether a saturated pool refuses instead of queueing for ever — none of those needs a guest, and a
//! test that needs one is a test that only runs where the engine builds.
//!
//! # What it deliberately does not prove
//!
//! That a real engine enforces a budget. That is the engine's job and its own test's, which is why
//! [`Enforcement`](crate::engine::types::Enforcement) is *reported by the backend* rather than assumed: this one reports
//! what it can do honestly, and a caller that needs a limit it cannot enforce is a caller that refuses the plugin.

mod backend;
mod instance;
mod types;

pub use backend::ScriptedBackend;
pub use instance::{ScriptedArtifact, ScriptedInstance};
pub use types::{ScriptError, Scripted};

/// A digest of a plugin's artifact, as hex.
///
/// The same shape as a sha256 digest — sixty-four hex characters — because that is what a real backend reports and what
/// a cache key is built from, and a fixture whose digest had a different shape would test a key no running kernel ever
/// builds.
#[must_use]
pub fn digest_of(plugin_id: &str, wasm: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(plugin_id.as_bytes());
    hasher.update(b":");
    hasher.update(wasm);
    let digest = hasher.finalize();
    let mut text = String::with_capacity(64);
    for byte in digest {
        let _ = std::fmt::Write::write_fmt(&mut text, format_args!("{byte:02x}"));
    }
    text
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use super::super::types::{
        Backend, BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, Enforcement,
        WasmBackend, Work,
    };

    fn work() -> Work {
        Work::CanHandle {
            item_json: "{}".to_owned(),
        }
    }

    fn compiled(backend: &ScriptedBackend) -> Box<dyn CompiledArtifact> {
        backend
            .compile(b"\0asm\x01\0\0\0", "@acme/hello")
            .expect("compiles")
    }

    /// The handle an instance is made from.
    ///
    /// Through the erasing constructor, which is the path a running kernel takes: a test that built the instance
    /// another way would not exercise the conversion the host depends on.
    fn handle(backend: &ScriptedBackend) -> Backend {
        Backend::new(Arc::new(backend.clone()))
    }

    #[test]
    fn an_empty_artifact_is_refused() {
        let backend = ScriptedBackend::new();
        assert!(matches!(
            backend.compile(b"", "@acme/hello"),
            Err(BackendError::Compile { .. })
        ));
    }

    #[test]
    fn an_artifact_that_is_not_wasm_is_refused() {
        // A host refuses a tarball, a text file and a truncated download whatever the engine would do with them, and
        // the check that catches all three is the header.
        let backend = ScriptedBackend::new();
        for bytes in [
            &b"not wasm at all"[..],
            &b"{\"json\":true}"[..],
            // A header and nothing behind it: accepted by the header check, and refused by a real engine. The scripted
            // backend's job is the host's own refusal, which is the header — the engine's is its own test's.
            &b"\0as"[..],
        ] {
            let refused = matches!(
                backend.compile(bytes, "p"),
                Err(BackendError::Compile { .. })
            );
            assert!(refused, "{bytes:?} was accepted");
        }
    }

    #[test]
    fn the_digest_is_sixty_four_hex_characters() {
        // The shape matters: it is a cache key part, and the safety check on a key insists on hex.
        let digest = digest_of("@acme/hello", b"\0asm\x01\0\0\0");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        );
    }

    #[test]
    fn two_plugins_sharing_an_artifact_do_not_share_a_digest() {
        let backend = ScriptedBackend::new();
        let first = backend
            .compile(b"\0asm\x01\0\0\0", "@acme/one")
            .expect("compiles");
        let second = backend
            .compile(b"\0asm\x01\0\0\0", "@acme/two")
            .expect("compiles");
        assert_ne!(first.digest(), second.digest());
    }

    #[test]
    fn a_scripted_answer_reaches_the_caller() {
        let backend =
            ScriptedBackend::answering(&work(), Scripted::Ok("{\"handled\":true}".to_owned()));
        let artifact = compiled(&backend);
        let mut instance = handle(&backend)
            .instantiate(artifact.as_ref())
            .expect("an instance");

        let outcome = instance
            .call(&work(), CallBudget::unlimited())
            .expect("a call");
        assert_eq!(outcome.payload(), Some("{\"handled\":true}"));
        assert!(outcome.is_ok());
        assert!(!outcome.is_misbehaviour());
    }

    #[test]
    fn a_structured_failure_is_not_misbehaviour() {
        // ★ The distinction the health model is built on: a plugin that reports a failure is working.
        let backend = ScriptedBackend::answering(
            &work(),
            Scripted::Failed {
                code: "device_offline".to_owned(),
                message: "the peer went away".to_owned(),
                details: Some(r#"{"peer":"laptop"}"#.to_owned()),
            },
        );
        let artifact = compiled(&backend);
        let mut instance = handle(&backend)
            .instantiate(artifact.as_ref())
            .expect("an instance");

        let outcome = instance
            .call(&work(), CallBudget::unlimited())
            .expect("a call");
        assert!(!outcome.is_ok());
        assert!(!outcome.is_misbehaviour(), "{outcome:?}");
        assert_eq!(outcome.as_str(), "failed");
        assert_eq!(
            outcome,
            CallOutcome::Failed {
                code: "device_offline".to_owned(),
                message: "the peer went away".to_owned(),
                details: Some(r#"{"peer":"laptop"}"#.to_owned()),
            }
        );
    }

    #[test]
    fn a_trap_is_misbehaviour() {
        let backend = ScriptedBackend::answering(
            &work(),
            Scripted::Trap {
                detail: "unreachable".to_owned(),
            },
        );
        let artifact = compiled(&backend);
        let mut instance = handle(&backend)
            .instantiate(artifact.as_ref())
            .expect("an instance");

        let outcome = instance
            .call(&work(), CallBudget::unlimited())
            .expect("a call");
        assert!(outcome.is_misbehaviour());
        assert_eq!(outcome.as_str(), "trap");
    }

    #[test]
    fn a_timeout_reports_the_budget_it_was_given() {
        let backend = ScriptedBackend::answering(&work(), Scripted::Timeout);
        let artifact = compiled(&backend);
        let mut instance = handle(&backend)
            .instantiate(artifact.as_ref())
            .expect("an instance");

        let budget = CallBudget {
            fuel: Some(1),
            timeout: Some(std::time::Duration::from_millis(250)),
            max_memory_growth: Some(1024),
        };
        let outcome = instance.call(&work(), budget).expect("a call");
        assert_eq!(
            outcome,
            CallOutcome::Timeout {
                after: std::time::Duration::from_millis(250)
            }
        );
    }

    #[test]
    fn a_limit_that_was_not_asked_for_is_not_reported() {
        // ★ Otherwise a test could assert "it timed out" against a call the host never bounded, and the host's handling
        // of a timeout would be tested by an outcome nothing would ever produce in a running kernel.
        let backend = ScriptedBackend::answering(&work(), Scripted::Timeout);
        let artifact = compiled(&backend);
        let mut instance = handle(&backend)
            .instantiate(artifact.as_ref())
            .expect("an instance");

        assert!(
            instance
                .call(&work(), CallBudget::unlimited())
                .expect("a call")
                .is_ok()
        );
    }

    #[test]
    fn the_backend_is_honest_about_what_it_cannot_enforce() {
        let backend = ScriptedBackend::new();
        let enforcement = backend.enforcement();
        assert!(!enforcement.fuel);
        assert!(!enforcement.epoch);
        assert!(enforcement.memory);
        assert!(!enforcement.precompile);
        // And the gap is named rather than answered as a boolean, so a refusal can say which control is missing.
        let bounded = CallBudget {
            fuel: Some(1),
            timeout: Some(std::time::Duration::from_millis(1)),
            max_memory_growth: None,
        };
        assert_eq!(
            enforcement.first_gap(&bounded),
            Some("an instruction budget")
        );
    }

    #[test]
    fn a_full_engine_has_no_gap() {
        let enforcement = Enforcement::full();
        assert_eq!(
            enforcement.first_gap(&CallBudget::from_quota(&crate::quota::Quota::default())),
            None
        );
    }

    #[test]
    fn an_artefact_from_another_backend_is_refused() {
        // A handle from a different engine is not an artefact this one can instantiate, and the failure has to name
        // both rather than trap inside the engine.
        struct Foreign;
        impl CompiledArtifact for Foreign {
            fn kind(&self) -> BackendKind {
                BackendKind::Wasmi
            }
            fn digest(&self) -> &str {
                "00"
            }
        }

        let backend = ScriptedBackend::new();
        assert!(matches!(
            handle(&backend).instantiate(&Foreign),
            Err(BackendError::Engine { .. })
        ));
    }
}

