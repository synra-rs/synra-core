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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use super::types::{
    Backend, BackendError, BackendKind, CallBudget, CallOutcome, CompiledArtifact, Enforcement,
    PluginInstance, WasmBackend, Work,
};

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
fn raise(message: &str) -> CallOutcome {
    panic!("{message}")
}

/// The backend.
///
/// Cheap to clone — it holds a table and counters behind one `Arc` — because one instance is shared by every plugin in
/// a test run.
#[derive(Debug, Clone)]
pub struct ScriptedBackend {
    shared: Arc<Shared>,
    version: String,
    /// The host functions this backend's artifacts claim to import.
    ///
    /// # Why the double needs this at all
    ///
    /// Because the kernel now checks, at load, that everything an artifact imports is covered by the capabilities it was
    /// granted — and a double that always reported "no imports" could not express the condition being checked. A test
    /// would then be unable to show that an artifact importing an undeclared function is refused, which is the whole
    /// point of the check existing.
    ///
    /// Empty by default: an artifact with no imports is the ordinary case, and a test that does not care says nothing.
    imports: Vec<String>,
}

/// What the backend and every instance of it share.
///
/// # Why this is a type of its own
///
/// Because an instance needs the script table, and the only handle an instance has is the backend trait object it was
/// made from. Reading the table through a shared value keeps the two in step without an instance having to downcast the
/// engine it came from — which would work, and would be a downcast in the one path a test can least afford to have a
/// hidden failure mode.
#[derive(Debug)]
struct Shared {
    /// The answers, by `interface.function`, e.g. `share.can-handle`.
    answers: Mutex<std::collections::HashMap<String, Scripted>>,
    /// The answers for one plugin, by `interface.function` — the exception, not the rule.
    ///
    /// # Why a per-plugin table exists at all
    ///
    /// Because one table cannot express the property that matters most on a matching pass: *one plugin failing must not
    /// cost the user the others.* With a single table every plugin answers the same thing, so a test can only ever
    /// prove that two plugins behave alike — and the bug this table lets a test catch is two plugins behaving differently
    /// in the one way that hurts. See [`ScriptedBackend::script_for`].
    per_plugin:
        Mutex<std::collections::HashMap<String, std::collections::HashMap<String, Scripted>>>,
    /// The answer for a call with no entry, which is `Ok("")` unless a caller says otherwise.
    fallback: Mutex<Scripted>,
    /// How many calls have been made, across every instance.
    calls: AtomicU64,
}

/// The key a script is stored under.
///
/// # ★ Why this is not `Work`'s `Display`
///
/// Because `Display` is `interface.function` — `share.execute` — which is the right label for a log line and the wrong
/// key for a fixture. Two calls to `share.execute` with different actions, or two `can-handle` calls about different
/// shares, collapsed onto one entry, so a script could not say what it was an answer *to* and a test could not tell
/// whether the arguments it expected were the ones sent.
///
/// That is not hypothetical: `share.execute` was called with `null` for every action in the system, and no fixture could
/// observe it, because every `execute` call had the same key. A test that cannot see its input cannot check it.
///
/// The payload is part of the key, so a script states the call it answers — and a call whose arguments differ from every
/// script falls through to the fallback, which is a failure a test notices rather than a silent match.
///
/// There is deliberately no wildcard arm. `Work` is `#[non_exhaustive]`, which binds callers outside this crate and not
/// this one: a variant added later is a compile error here, which is where the decision about how it should key belongs.
/// A wildcard would let it key on its name alone, quietly, and the fixture would stop distinguishing its payload.
fn key_for(work: &Work) -> String {
    let payload = match work {
        Work::Activate { config_json } => config_json.as_str(),
        Work::Deactivate => "",
        Work::Migrate { from_version, to_version } => {
            return format!("{work}|{from_version}|{to_version}");
        }
        Work::Tick { tick_json } => tick_json.as_str(),
        Work::CanHandle { item_json } => item_json.as_str(),
        Work::Execute { action, args_json } => return format!("{work}|{action}|{args_json}"),
        Work::InvokeAction { name, args_json } => return format!("{work}|{name}|{args_json}"),
    };
    format!("{work}|{payload}")
}

impl ScriptedBackend {
    /// A backend whose calls all succeed with an empty payload.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Shared {
                answers: Mutex::new(std::collections::HashMap::new()),
                per_plugin: Mutex::new(std::collections::HashMap::new()),
                fallback: Mutex::new(Scripted::Ok(String::new())),
                calls: AtomicU64::new(0),
            }),
            version: "scripted-1".to_owned(),
            imports: Vec::new(),
        }
    }

    /// Declares the host functions this backend's artifacts import.
    ///
    /// A builder rather than a constructor argument, because almost no test cares: an artifact that imports nothing is
    /// the ordinary case, and this is for the one test that has to show an undeclared import being refused at load.
    #[must_use]
    pub fn importing(mut self, imports: &[&str]) -> Self {
        self.imports = imports.iter().map(|import| (*import).to_owned()).collect();
        self
    }

    /// Sets what one plugin's copy of one entry point answers.
    ///
    /// # Why this exists
    ///
    /// Because the shared table is keyed by entry point alone, so every plugin answers the same thing and a test cannot
    /// set up the case where one plugin traps while another works. That case is the one a matching pass most needs to
    /// be checked against: a share offered to nine plugins must still reach the user when one of them is broken, and
    /// with one table there is no way to write that test at all.
    ///
    /// It shadows [`ScriptedBackend::script`] for this plugin and nothing else.
    pub fn script_for(&self, plugin_id: &str, work: &Work, answer: Scripted) {
        let _ = self
            .shared
            .per_plugin
            .lock()
            .entry(plugin_id.to_owned())
            .or_default()
            .insert(key_for(work), answer);
    }

    /// A backend with one answer already in it.
    #[must_use]
    pub fn answering(work: &Work, answer: Scripted) -> Self {
        let backend = Self::new();
        backend.script(work, answer);
        backend
    }

    /// Sets what one entry point answers.
    pub fn script(&self, work: &Work, answer: Scripted) {
        let _ = self.shared.answers.lock().insert(key_for(work), answer);
    }

    /// Sets what a call with no entry of its own answers.
    pub fn fallback(&self, answer: Scripted) {
        *self.shared.fallback.lock() = answer;
    }

    /// How many calls have been made.
    #[must_use]
    pub fn calls(&self) -> u64 {
        self.shared.calls.load(Ordering::Acquire)
    }
}

impl Shared {
    /// What an entry point answers for one plugin.
    ///
    /// # The order of the three lookups
    ///
    /// Per-plugin first, then the shared table, then the fallback. Per-plugin first because it is the most specific
    /// answer and the only one that can make two plugins differ; the shared table exists so a test that cares about one
    /// plugin does not have to repeat the id for every entry point it scripts.
    fn answer_for(&self, plugin_id: &str, work: &Work) -> Scripted {
        let key = key_for(work);
        let per_plugin = {
            let tables = self.per_plugin.lock();
            tables
                .get(plugin_id)
                .and_then(|table| table.get(&key))
                .cloned()
        };
        if let Some(answer) = per_plugin {
            return answer;
        }
        let found = self.answers.lock().get(&key).cloned();
        found.unwrap_or_else(|| self.fallback.lock().clone())
    }
}

impl Default for ScriptedBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// A compiled artefact this backend made.
#[derive(Debug)]
pub struct ScriptedArtifact {
    digest: String,
    plugin_id: String,
    /// What this artifact claims to import, for the kernel's load-time coverage check.
    imports: Vec<String>,
}

impl CompiledArtifact for ScriptedArtifact {
    fn kind(&self) -> BackendKind {
        BackendKind::Scripted
    }

    fn digest(&self) -> &str {
        &self.digest
    }

    fn imports(&self) -> &[String] {
        &self.imports
    }
}

/// An instance of a scripted component.
#[derive(Debug)]
pub struct ScriptedInstance {
    shared: Arc<Shared>,
    memory: u64,
    host_calls: u64,
    /// The epoch of the most recent call's deadline, which is what a test reads to prove one was armed.
    deadline_epoch: Option<u64>,
    /// Which plugin this instance belongs to, so per-plugin scripts are found.
    plugin_id: String,
}

impl PluginInstance for ScriptedInstance {
    fn kind(&self) -> BackendKind {
        BackendKind::Scripted
    }

    fn memory_bytes(&self) -> u64 {
        self.memory
    }

    fn host_calls(&self) -> u64 {
        self.host_calls
    }

    fn deadline_epoch(&self) -> Option<u64> {
        self.deadline_epoch
    }

    fn call(&mut self, work: &Work, budget: CallBudget) -> Result<CallOutcome, BackendError> {
        let _ = self.shared.calls.fetch_add(1, Ordering::AcqRel);
        self.host_calls = self.host_calls.saturating_add(1);
        // A token amount of memory, so a test that watches growth sees something move rather than a constant zero that
        // would also satisfy an untouched instance.
        self.memory = self.memory.saturating_add(4096);

        Ok(match self.shared.answer_for(&self.plugin_id, work) {
            Scripted::Ok(payload) => CallOutcome::Ok(payload),
            Scripted::Failed {
                code,
                message,
                details,
            } => CallOutcome::Failed {
                code,
                message,
                details,
            },
            Scripted::Trap { detail } => CallOutcome::Trap { detail },
            // ★ A panic in the host, which is a different failure from a trap the *guest* produced.
            //
            // A `Trap` is the engine reporting that the guest broke a rule, and it arrives here as an ordinary
            // `CallOutcome`. This one unwinds. It exists so the boundary in `synra-core`'s `PluginSet::run_on` — the
            // `catch_unwind` that `[profile.release] panic = "unwind"` is configured for — can be tested at all: before
            // this variant there was no way to raise a panic from behind the `WasmBackend` trait, so the claim that a
            // plugin cannot take the kernel down with it had nothing behind it.
            Scripted::Panic { message } => raise(&message),
            // Both of these are the *budget* being reported, so a call that asked for no limit cannot produce them:
            // a script that ignored that would let a test assert a timeout on a call the host never bounded.
            Scripted::Timeout => match budget.timeout {
                Some(after) => CallOutcome::Timeout { after },
                None => CallOutcome::Ok(String::new()),
            },
            Scripted::FuelExhausted => match budget.fuel {
                Some(fuel) => CallOutcome::FuelExhausted { fuel },
                None => CallOutcome::Ok(String::new()),
            },
            Scripted::MemoryExceeded => match budget.max_memory_growth {
                Some(limit) => CallOutcome::MemoryExceeded { limit },
                None => CallOutcome::Ok(String::new()),
            },
        })
    }
}

impl WasmBackend for ScriptedBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Scripted
    }

    fn enforcement(&self) -> Enforcement {
        // Honest about itself: it has no engine, so it has no instruction counting, no interruption and no
        // precompilation. The one thing it can do is report a memory limit it was given — which is what `memory: true`
        // means here, and why the flag is about the *budget* being answerable rather than about a real linear memory.
        Enforcement {
            fuel: false,
            epoch: false,
            memory: true,
            precompile: false,
        }
    }

    fn engine_version(&self) -> &str {
        &self.version
    }

    fn compile(
        &self,
        wasm: &[u8],
        plugin_id: &str,
    ) -> Result<Box<dyn CompiledArtifact>, BackendError> {
        if wasm.is_empty() {
            return Err(BackendError::Compile {
                detail: ScriptError::Empty.to_string(),
            });
        }
        if !wasm.starts_with(b"\0asm") {
            return Err(BackendError::Compile {
                detail: ScriptError::NotWasm.to_string(),
            });
        }
        // The digest mixes the plugin id with the bytes, so two plugins given the same fixture artifact do not share a
        // cache entry — which would be a real bug in a cache keyed on bytes alone if a build ever shipped one artifact
        // for several plugins.
        let digest = digest_of(plugin_id, wasm);
        Ok(Box::new(ScriptedArtifact {
            digest,
            plugin_id: plugin_id.to_owned(),
            imports: self.imports.clone(),
        }))
    }

    fn instantiate(
        &self,
        backend: &Backend,
        compiled: &dyn CompiledArtifact,
    ) -> Result<Box<dyn PluginInstance>, BackendError> {
        if compiled.kind() != BackendKind::Scripted {
            return Err(BackendError::Engine {
                detail: format!(
                    "a {} artefact cannot be run by the {} backend",
                    compiled.kind(),
                    self.kind()
                ),
            });
        }
        // The table an instance reads is this backend's, found through the handle. A mistake here would be a call that
        // quietly succeeds against an empty table, which is the failure a test can least afford — so the fallback is
        // this backend's own table rather than a fresh one.
        let shared = backend.concrete::<Self>().map_or_else(
            || Arc::clone(&self.shared),
            |concrete| Arc::clone(&concrete.shared),
        );
        // Which plugin this instance is for, so a per-plugin script can be found. Taken from the artifact rather than
        // from `&self` because a backend holds every plugin's scripts and only the artifact says which one this is.
        let plugin_id = (compiled as &dyn std::any::Any)
            .downcast_ref::<ScriptedArtifact>()
            .map_or_else(String::new, |artifact| artifact.plugin_id.clone());
        Ok(Box::new(ScriptedInstance {
            shared,
            plugin_id,
            memory: 0,
            host_calls: 0,
            deadline_epoch: None,
        }))
    }
}

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
