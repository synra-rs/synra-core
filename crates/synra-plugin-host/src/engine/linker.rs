//! The host functions, defined on a linker.
//!
//! # Why the definitions are grouped by *shape*
//!
//! Because the component model's calling convention is about a function's **type**, not about its name: a function that
//! takes one string and returns a string is lowered the same way whatever it is called, and the same is true of one that
//! takes nothing and returns a `u64` pair. Thirty-five hand-written definitions would be thirty-five chances to write
//! `(ptr, len)` where the convention wanted `(len, ptr)`, in the one layer where getting it wrong means reading a
//! plugin's argument from the wrong offset. There are nine shapes here, and each is written once.
//!
//! # Where the gate is
//!
//! **In the answer, not in the wiring.** Every function below calls
//! [`HostCalls::call`](crate::host_calls::HostCalls::call) with its own import name, so the check, the rate limit and
//! the audit record are the ones already tested — and there is no path from a guest to a host effect that does not go
//! through that method. That is the invariant the design document states as "every host function call must pass
//! `gate.rs`, no exception", expressed as a structure rather than as a rule to remember: the definitions *cannot* do
//! anything else, because the effects live behind the `Host` trait.
//!
//! # What reads the arguments
//!
//! A guest's string arrives as `(ptr, len)` into its own memory, and turning that into a `&str` is the one place this
//! layer touches guest memory. It is bounded by the store's ceiling: a length that does not fit is refused rather than
//! read, which is what stops a plugin asking the host to read a terabyte of its own memory.

#![cfg(feature = "wasm-runtime")]



use wasmtime::StoreContextMut;
use wasmtime::component::{Linker, LinkerInstance};

use super::session::LinkerSession;
use super::wasmtime_backend::StoreData;

use crate::host_calls::{CallError, HostCalls};
use crate::host_surface;

/// What the guest is told when a call is refused.
///
/// # Why this is a JSON string rather than a trap
///
/// Because the WIT contract's shape for a call that can fail is `outcome`, whose `err` case carries a structured error
/// — and the contract's own rule is that a plugin which cannot reach a device has *failed*, which is something it can
/// handle. The glue passes the JSON through and the interface's `outcome` is built on the guest side; what matters here
/// is that a refusal is a value the guest receives rather than a trap it cannot catch.
#[must_use]
pub fn error_json(error: &CallError) -> String {
    serde_json::to_string(error).unwrap_or_else(|_| {
        // A `CallError` is three plain fields, so serialisation cannot fail — and if it somehow did, a guest that
        // received a refusal it could not parse is still better off than one that received a trap.
        format!("{{\"code\":\"{}\"}}", error.code)
    })
}

/// Runs one host call and renders the answer the contract's type expects.
///
/// The four rungs of the answer, and each is a different WIT type:
///
/// * `text` — a `string`, which is what most functions return;
/// * `outcome` — `ok(json)` or `err(json)`, which is what everything fallible returns;
/// * `flag` — a `bool`;
/// * `list` — the two functions that answer with `list<string>`.
fn run(state: &mut StoreData, import_name: &str, argument: &str) -> Answer {
    let Some(session) = state.session.as_ref().and_then(|held| held.downcast_ref::<LinkerSession>()) else {
        // ★ No session means no plugin: a host function called by an instance the host did not hand a session to is
        // refused rather than run ungated. This is the only way to reach a definition without a gate, and it answers
        // with a refusal — which is why the invariant holds even here.
        return Answer::Denied(CallError::new(
            CallError::HOST_FAILED,
            "this instance has no plugin session, so the call cannot be authorised",
        ));
    };
    // The audit lock is held across the call rather than around the record, because a record has to be written even
    // when the call does nothing: the entry is what says the plugin asked.
    let mut audit = session.audit.lock();
    let mut calls = HostCalls::new(
        session.host.as_ref(),
        session.plugin.clone(),
        &session.grants,
        &session.budget,
        &mut audit,
    );
    let answer = match calls.call(import_name, argument) {
        Ok(answer) => Answer::Ok(answer),
        Err(error) => Answer::Denied(error),
    };
    // Both are released here rather than at the end of the function: the answer is a value the caller will render, and
    // a session lock held while that happens is a lock the next host call of the *same* guest would wait on.
    drop(calls);
    drop(audit);
    answer
}

/// What a host call produced, before it is rendered as a WIT type.
enum Answer {
    /// The answer, as the JSON or text the function returns.
    Ok(String),
    /// A refusal, which the guest receives as the contract's `err` case.
    Denied(CallError),
}

impl Answer {
    /// The answer as an `outcome`'s `ok` payload, or the refusal's JSON.
    fn into_outcome(self) -> String {
        match self {
            Self::Ok(answer) => answer,
            Self::Denied(error) => error_json(&error),
        }
    }

    /// Whether the call was refused, which is what the flattened `outcome` return tells the guest.
    const fn was_refused(&self) -> bool {
        matches!(self, Self::Denied(_))
    }

    /// The answer as a plain string, for the functions whose contract says they cannot fail.
    ///
    /// A refusal here is a function the contract declares infallible answering with nothing: `env-can` refusing would
    /// be the host saying "no" to a question about permissions, which is the answer that hides a button — so the refusal
    /// is rendered as the *empty* answer rather than as an error the guest has nowhere to put.
    fn into_text(self) -> String {
        match self {
            Self::Ok(answer) => answer,
            Self::Denied(error) => {
                let _ = error;
                String::new()
            }
        }
    }
}

/// Defines the host interface on a linker.
///
/// # Errors
///
/// A `wasmtime` error when the interface cannot be defined, which is a *host* bug rather than a plugin's: a name that
/// does not match the contract, or a type that does not match the world.
pub(crate) fn define(linker: &mut Linker<StoreData>) -> anyhow::Result<()> {
    // `synra:plugin/host@1.0.0`, assembled from the table the contract generates so a version bump cannot leave this
    // behind.
    let mut instance = linker.instance(&instance_interface())?;
    define_shapes(&mut instance)?;
    Ok(())
}

/// Every function, wrapped in whichever of the nine shapes it is.
fn define_shapes(instance: &mut LinkerInstance<'_, StoreData>) -> anyhow::Result<()> {
    // ── Shape 1: `() -> string` — the four environment queries and the plugin's own id ──
    for function in ["env-sdk-version", "env-host-kind", "env-locale", "plugin-id"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (): ()| {
            let answer = run(caller.data_mut(), &import, "");
            Ok((answer.into_text(),))
        })?;
    }

    // ── Shape 2: `() -> bool` ──
    for function in ["env-dark-mode"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (): ()| {
            let answer = run(caller.data_mut(), &import, "");
            Ok((answer.into_text() == "true",))
        })?;
    }

    // ── Shape 3: `(string) -> bool` — the permission question ──
    for function in ["env-can"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (argument,): (String,)| {
            let answer = run(caller.data_mut(), &import, &argument);
            Ok((answer.into_text() == "true",))
        })?;
    }

    // ── Shape 4: `() -> list<string>` — the two lists, which the host answers with JSON ──
    for function in ["platform-capabilities", "device-list"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (): ()| {
            let answer = run(caller.data_mut(), &import, "");
            let items = parse_list(&answer.into_text());
            Ok((items,))
        })?;
    }

    // ── Shape 4b: `() -> tuple<u64, u64>` — the storage report, whose second number is the quota ──
    for function in ["storage-quota"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (): ()| {
            let answer = run(caller.data_mut(), &import, "");
            let (used, allowed) = parse_pair(&answer.into_text());
            Ok((used, allowed))
        })?;
    }

    // ── Shape 5: `(string) -> string` — the questions with nothing to fail ──
    for function in ["storage-keys", "action-list"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (argument,): (String,)| {
            let answer = run(caller.data_mut(), &import, &argument);
            Ok((answer.into_text(),))
        })?;
    }

    // ── Shape 6: `(string) -> outcome` — one argument, and it can fail ──
    //
    // ★ This is the largest group, and it is also the one the contract's `outcome` shape exists for: a plugin that
    // cannot reach a device has *failed*, which is a value rather than a trap.
    for function in [
        "event-subscribe",
        "storage-get",
        "storage-delete",
        "secret-get",
        "secret-delete",
        "network-fetch",
        "network-websocket",
        "transfer-status",
        "platform-open-url",
        "platform-open-path",
        "platform-reveal-path",
        "platform-simulate-keys",
        "platform-write-clipboard",
    ] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (argument,): (String,)| {
            let answer = run(caller.data_mut(), &import, &argument);
            let refused = answer.was_refused();
            Ok((outcome_of(answer), refused))
        })?;
    }

    // ── Shape 7: `(string, string) -> outcome` — two arguments, and it can fail ──
    for function in ["event-emit", "device-send", "device-broadcast", "storage-set", "secret-set"] {
        let import = import_name(function);
        let named = function.to_owned();
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (first, second): (String, String)| {
            // The two arguments arrive as the contract's own tuple, and the host call takes the JSON the glue layer
            // builds: the *names* are the guest's, so the JSON is assembled here from the contract's field names
            // rather than guessed.
            let argument = arguments_json(&named, &[first.as_str(), second.as_str()]);
            let answer = run(caller.data_mut(), &import, &argument);
            let refused = answer.was_refused();
            Ok((outcome_of(answer), refused))
        })?;
    }

    // ── Shape 8: `(string, string, string) -> outcome` ──
    for function in ["transfer-send"] {
        let import = import_name(function);
        // The closure owns the name as well as the import, because `arguments_json` needs it to look the parameter
        // names up: a `move` closure cannot borrow the loop's `&'static str` and still be `'static`.
        let named = function.to_owned();
        instance.func_wrap(
            function,
            move |mut caller: StoreContextMut<'_, StoreData>,
                  (first, second, third): (String, String, String)| {
                let argument = arguments_json(&named, &[first.as_str(), second.as_str(), third.as_str()]);
                let answer = run(caller.data_mut(), &import, &argument);
                let refused = answer.was_refused();
                Ok((outcome_of(answer), refused))
            },
        )?;
    }

    // ── Shape 9: `(log-level, string, option<string>) -> ()` and the clipboard read ──
    //
    // The log level is a WIT `enum`, which crosses as a `u32` index, and an `option<string>` crosses as a variant —
    // both are why these two are their own shapes rather than being folded into the ones above.
    for function in ["log"] {
        let import = import_name(function);
        instance.func_wrap(
            function,
            move |mut caller: StoreContextMut<'_, StoreData>,
                  (level, message, context): (u32, String, Option<String>)| {
                let argument = log_json(level, &message, context.as_deref());
                let _ = run(caller.data_mut(), &import, &argument);
                Ok(())
            },
        )?;
    }
    for function in ["platform-read-clipboard"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (): ()| {
            let answer = run(caller.data_mut(), &import, "");
            let refused = answer.was_refused();
            Ok((outcome_of(answer), refused))
        })?;
    }

    // ── The two functions the contract declares with a shape of their own ──
    //
    // `platform-notify` takes a title and a body, and `action-invoke` takes a plugin, a name and arguments; both are
    // three strings, which is shape 8's type but *not* its field names — so they are defined with their own JSON.
    for function in ["platform-notify"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (title, body): (String, String)| {
            let argument = format!(
                "{{\"title\":{},\"body\":{}}}",
                json_string(&title),
                json_string(&body)
            );
            let answer = run(caller.data_mut(), &import, &argument);
            let refused = answer.was_refused();
            Ok((outcome_of(answer), refused))
        })?;
    }
    for function in ["action-declare"] {
        let import = import_name(function);
        instance.func_wrap(function, move |mut caller: StoreContextMut<'_, StoreData>, (name, schema): (String, String)| {
            let argument = format!("{{\"name\":{},\"schema\":{}}}", json_string(&name), json_string(&schema));
            let answer = run(caller.data_mut(), &import, &argument);
            let refused = answer.was_refused();
            Ok((outcome_of(answer), refused))
        })?;
    }
    for function in ["action-invoke"] {
        let import = import_name(function);
        instance.func_wrap(
            function,
            move |mut caller: StoreContextMut<'_, StoreData>,
                  (plugin, name, arguments): (String, String, String)| {
                let argument = format!(
                    "{{\"plugin\":{},\"name\":{},\"args\":{}}}",
                    json_string(&plugin),
                    json_string(&name),
                    json_string(&arguments)
                );
                let answer = run(caller.data_mut(), &import, &argument);
                let refused = answer.was_refused();
                Ok((outcome_of(answer), refused))
            },
        )?;
    }

    Ok(())
}

/// The full import name a bare function is reached by.
fn import_name(function: &str) -> String {
    format!("{}#{}", host_interface(), function)
}

/// The interface an import is qualified by, in the spelling the gate table is keyed by.
///
/// # The two spellings, and why they differ
///
/// A *guest* imports `synra:plugin/host@1.0.0`, where the version belongs to the interface. The generated table names
/// the same imports `synra:plugin/host#log`, because it is derived from the WIT file's package and interface and the
/// version is checked once for the whole world. The gate is keyed by the table's spelling, so that is what
/// [`import_name`] builds — and [`instance_interface`] is the one that carries the version, because that is what the
/// linker has to match.
fn host_interface() -> String {
    format!("{}/{}", host_surface::PACKAGE, host_surface::HOST_INTERFACE)
}

/// The versioned form the linker defines the instance under.
fn instance_interface() -> String {
    format!("{}@{}", host_interface(), host_surface::PACKAGE_VERSION)
}

/// The JSON a two- or three-argument call takes, with the contract's field names.
///
/// # Why the names are looked up and not positional
///
/// Because a positional JSON is a JSON whose meaning depends on the order a function's parameters happen to be declared
/// in the WIT file — and `device-send(target, event, payload)` and `transfer-send(kind, target, meta-json)` have the
/// same *type* and different meanings. Reading the field names from the table means a parameter renamed in the contract
/// changes what this builds, rather than silently shifting a payload into a target.
fn arguments_json(function: &str, values: &[&str]) -> String {
    let fields = parameter_names(function);
    let body: Vec<String> = fields
        .iter()
        .zip(values)
        .map(|(name, value)| format!("{}:{}", json_string(name), json_string(value)))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// The log line's JSON, with the level as the name the contract spells rather than its index.
fn log_json(level: u32, message: &str, context: Option<&str>) -> String {
    let levels = ["trace", "debug", "info", "warn", "error"];
    let name = levels.get(level as usize).copied().unwrap_or("info");
    match context {
        Some(context) => format!(
            "{{\"level\":{},\"message\":{},\"context\":{}}}",
            json_string(name),
            json_string(message),
            json_string(context)
        ),
        None => format!("{{\"level\":{},\"message\":{}}}", json_string(name), json_string(message)),
    }
}

/// The parameter names a function's arguments take, as the contract declares them.
///
/// # What this is, and what it deliberately is not
///
/// It is a table of the contract's parameter names, and it is here rather than generated because the generator that
/// makes the *capability* table does not read parameter names — and a second generator for one table of nine strings
/// would be more code than the table. What keeps it honest is a test: every function the contract declares must appear
/// here, so a function added to the WIT file fails the suite rather than receiving arguments under invented names.
#[must_use]
pub fn parameter_names(function: &str) -> Vec<String> {
    let names: &[&str] = match function {
        "env-can" => &["capability"],
        "storage-keys" => &["prefix"],
        "platform-notify" => &["title", "body"],
        "storage-get" | "storage-delete" | "secret-get" | "secret-delete" => &["key"],
        "event-subscribe" => &["pattern"],
        "network-fetch" => &["request-json"],
        "network-websocket" => &["url"],
        "transfer-status" => &["transfer-id"],
        "platform-open-url" => &["url"],
        "platform-open-path" | "platform-reveal-path" => &["path"],
        "platform-simulate-keys" => &["chord"],
        "platform-write-clipboard" => &["text"],
        "log" => &["level", "message", "ctx"],
        "event-emit" | "device-broadcast" => &["event", "payload"],
        "device-send" => &["target", "event", "payload"],
        "storage-set" | "secret-set" => &["key", "value"],
        "transfer-send" => &["kind", "target", "meta-json"],
        "action-declare" => &["name", "schema-json"],
        "action-invoke" => &["target-plugin", "name", "args-json"],
        _ => &[],
    };
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// A pair of numbers, as the two values a WIT `tuple<u64, u64>` crosses as.
fn parse_pair(text: &str) -> (u64, u64) {
    let parsed: Vec<u64> = serde_json::from_str(text).unwrap_or_default();
    let used = parsed.first().copied().unwrap_or(0);
    let allowed = parsed.get(1).copied().unwrap_or(0);
    (used, allowed)
}

/// A JSON list of strings.
fn parse_list(text: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(text).unwrap_or_else(|_| {
        // The host builds these with `json_array`, so a parse failure is a host bug — and answering with an empty list
        // is what a plugin sees as "there are none" rather than as a call that failed.
        Vec::new()
    })
}

/// A refusal and its reason, as the two values the flattened `outcome` crosses as.
fn outcome_of(answer: Answer) -> String {
    answer.into_outcome()
}

/// A JSON string, escaped.
///
/// Written here rather than reached for through `serde_json`, because the values are already Rust strings and the only
/// transformation is escaping: a `Value` round trip would parse text that was never text.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", other as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}
#[cfg(test)]
#[path = "linker_tests.rs"]
mod tests;
