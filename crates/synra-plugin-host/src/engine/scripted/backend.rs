//! Shared scripted backend configuration and WasmBackend implementation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use super::super::types::{Backend, BackendError, BackendKind, CompiledArtifact, Enforcement, PluginInstance, WasmBackend, Work};
use super::types::{ScriptError, Scripted};
use super::instance::{ScriptedArtifact, ScriptedInstance};

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
pub(super) struct Shared {
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
    pub(super) calls: AtomicU64,
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
        Work::Event { event_json } => event_json,
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
    pub(super) fn answer_for(&self, plugin_id: &str, work: &Work) -> Scripted {
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
        let digest = super::digest_of(plugin_id, wasm);
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




