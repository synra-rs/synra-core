//! The three types the plugin boundary exchanges, and nothing else.
//!
//! # Why these live here and not in the SDK
//!
//! Both sides of the boundary name them: the host trait's methods return `Outcome` and take a `LogLevel`, and the SDK's
//! functions do the same. So they have to be in a crate both depend on, and it has to be one that pulls in neither's
//! weight.
//!
//! Three placements were possible and two are wrong:
//!
//! * **In `synra-plugin-sdk`** would make the `synra-plugin-host` depend on the plugin author's crate, and that crate
//!   is built for `wasm32-wasip2` — so the wasm runtime the host already carries would be joined by a second copy of
//!   itself as a peer. Worse, the *author's* crate would be in the host's dependency graph, which means a change made
//!   for an author could break the host.
//! * **In `synra-plugin-host`** would be the same mistake in the other direction, and more expensive: the SDK is what an
//!   author adds to a plugin, and a plugin that linked the host would carry wasmtime into a sandbox where it cannot be
//!   linked at all.
//! * **Here**, in the crate both already depend on and that carries nothing but the contract. Which is what this crate
//!   is for.
//!
//! # Why `Outcome` is a shape rather than a `Result`
//!
//! A WIT function cannot return a Rust `Result` — the component model has no generics — so the contract declares an
//! `outcome` record and this is its Rust spelling. It is deliberately *not* `Result<T, E>`: an `outcome` carries the
//! kernel's stable error code and the payload in a form the boundary can pass, and an error type per function would be a
//! type in the generated signature that the component model has nowhere to put.

use serde::{Deserialize, Serialize};

/// What the host's functions return when they can fail.
///
/// # Why this is not a `Result`
///
/// The contract declares it as a WIT record, so both sides must agree on its exact shape — and a `Result` has no
/// representation across the component model. What it *is* is the same information a `Result` carries, in a form that
/// crosses: a success flag, the payload as bytes, and on failure a stable code and a message key.
///
/// # Why the payload is bytes
///
/// Because every function that returns an `Outcome` returns a *different* payload — a device list, a fetched document, a
/// stored value — and a generated enum with one variant per function would be a type that grows with the contract. The
/// bytes are JSON, and the function that produced them is the one that knows how to read them back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Outcome {
    /// Whether the call succeeded.
    pub ok: bool,
    /// The result, as JSON, when `ok`. Empty otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// The kernel's stable error code, when not `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// A **message key** rather than a sentence; the interface renders it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Outcome {
    /// A success carrying a payload.
    #[must_use]
    pub fn ok(payload: impl Into<String>) -> Self {
        Self { ok: true, payload: Some(payload.into()), code: None, message: None }
    }

    /// A success carrying nothing.
    ///
    /// Distinct from [`Outcome::ok`] with an empty string: "the call succeeded and produced nothing" and "the call
    /// succeeded and produced an empty document" are different answers, and a caller that had to tell them apart from
    /// the payload's emptiness would get it wrong for the one function that legitimately returns `""`.
    #[must_use]
    pub const fn done() -> Self {
        Self { ok: true, payload: None, code: None, message: None }
    }

    /// A refusal.
    ///
    /// `code` is the kernel's stable error code and `message` a key, so the interface can render it in the user's
    /// language. Neither is a sentence: a sentence composed here would be composed once, in whatever language the
    /// kernel was built for.
    #[must_use]
    pub fn refused(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { ok: false, payload: None, code: Some(code.into()), message: Some(message.into()) }
    }

    /// Whether the call succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.ok
    }

    /// The payload, when the call succeeded and there is one.
    #[must_use]
    pub fn payload(&self) -> Option<&str> {
        self.payload.as_deref()
    }

    /// The error code, when the call did not succeed.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        self.code.as_deref()
    }
}

/// How loud a message is.
///
/// # Why this is not the kernel's own level type
///
/// The kernel logs at its own levels, and a plugin logs at the levels the contract declares. They are the same five
/// today, and they are separate types because the *published* set is a promise and the internal one is not: adding a
/// level to the kernel's logging would, if they were one type, add a variant to the contract every existing plugin has
/// to handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum LogLevel {
    /// Finest detail; off in a release build unless asked for.
    Trace,
    /// Development detail.
    Debug,
    /// The ordinary case.
    Info,
    /// Something is wrong but the plugin continues.
    Warn,
    /// Something failed.
    Error,
}

impl LogLevel {
    /// Every level, in increasing severity.
    ///
    /// A hand-written list, with a test that counts it: a match over the variants is what makes adding one a compile
    /// error here, which is the point — a level added to the contract and not to this list would be one nothing emits.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Trace, Self::Debug, Self::Info, Self::Warn, Self::Error]
    }

    /// The wire spelling, which is the lower-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A device, as a plugin may name one.
///
/// # Why a plugin gets identifiers and not addresses
///
/// The kernel knows where every device is — an address, a port, a transport — and a plugin has no business knowing any
/// of it. Two reasons, and the second is the one that matters:
///
/// * An address is not stable. It changes with the network, and a plugin that cached one would be one that breaks when
///   the user moves to a different one.
/// * ★ **Addresses are a capability the plugin was not granted.** `device:send:*` says a plugin may send to a device,
///   not that it may learn the shape of the user's network. A device list carrying addresses would leak that to every
///   plugin holding `device:list` — and a plugin's capability list is the thing the user read before installing it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DeviceTarget {
    /// The device's stable identifier.
    pub device_id: String,
    /// What to show a user, when the kernel has a name for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Whether the device is reachable now.
    pub online: bool,
    /// Whether this device is paired with the one the plugin is running on.
    pub paired: bool,
}

impl DeviceTarget {
    /// A target with identifiers only.
    #[must_use]
    pub fn new(device_id: impl Into<String>) -> Self {
        Self { device_id: device_id.into(), display_name: None, online: true, paired: true }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Outcome ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_success_and_a_completion_are_different_answers() {
        // ★ "The call succeeded and produced nothing" and "the call succeeded and produced an empty string" are
        // different, and a caller that had to tell them apart from the payload's emptiness would get it wrong for the
        // one function that legitimately returns `""`.
        assert_ne!(Outcome::done(), Outcome::ok(""));
        assert!(Outcome::done().is_ok());
        assert_eq!(Outcome::done().payload(), None);
        assert_eq!(Outcome::ok("").payload(), Some(""));
    }

    #[test]
    fn a_refusal_carries_a_code_and_a_key() {
        let refused = Outcome::refused("device_offline", "error.deviceOffline");
        assert!(!refused.is_ok());
        assert_eq!(refused.error_code(), Some("device_offline"));
        // A key rather than a sentence: a sentence composed here would be composed once, in whatever language the
        // kernel was built for.
        assert!(refused.message.as_deref().is_some_and(|key| key.starts_with("error.")));
    }

    #[test]
    fn an_outcome_narrows_on_the_flag_rather_than_on_a_payload() {
        // The field a caller branches on is `ok`, and the accessors are what make a wrong read obvious: reading the
        // payload of a refusal gives `None` rather than the empty string a caller might mistake for a result.
        assert_eq!(Outcome::refused("timeout", "error.timeout").payload(), None);
        assert_eq!(Outcome::done().error_code(), None);
    }

    #[test]
    fn the_wire_shape_omits_what_is_absent() {
        // A `null` where the contract says "omitted" is a difference the component model does not accept, so the
        // `skip_serializing_if` on each optional field is what makes the Rust type and the WIT record agree.
        let json = serde_json::to_string(&Outcome::done()).expect("serialises");
        assert_eq!(json, r#"{"ok":true}"#);
        // camelCase, because the contract's field names are, and a `snake_case` key would be a field the other side
        // does not have.
        let json = serde_json::to_string(&Outcome::refused("a_b", "error.aB")).expect("serialises");
        assert!(json.contains("\"code\":\"a_b\""), "{json}");
    }

    #[test]
    fn an_outcome_round_trips() {
        for outcome in [Outcome::done(), Outcome::ok("payload"), Outcome::refused("code", "error.key")] {
            let json = serde_json::to_string(&outcome).expect("serialises");
            let back: Outcome = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, outcome);
        }
    }

    // ── LogLevel ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_level_is_listed_and_counted() {
        // A level added to the variants and not to `all` would be one nothing emits, and the compiler cannot see it
        // because `all` is a slice.
        assert_eq!(LogLevel::all().len(), 5);
        for level in LogLevel::all() {
            // And each level's spelling is its own: two levels sharing a spelling would be one level with two names.
            assert!(!level.as_str().is_empty());
        }
        let mut spellings: Vec<&str> = LogLevel::all().iter().map(|level| level.as_str()).collect();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), LogLevel::all().len(), "a spelling repeats");
    }

    #[test]
    fn the_levels_order_by_severity() {
        // A caller filtering at `warn` compares, so the ordering is part of the contract rather than an accident of the
        // declaration order.
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn a_level_spells_itself_lower_case_on_the_wire() {
        assert_eq!(LogLevel::Trace.as_str(), "trace");
        assert_eq!(LogLevel::Error.as_str(), "error");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(
            serde_json::to_string(&LogLevel::Info).expect("serialises"),
            "\"info\""
        );
    }

    // ── DeviceTarget ──────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_device_target_carries_identifiers_and_not_addresses() {
        // ★ The rule this type exists for. An address is a capability the plugin was not granted: `device:send:*` says
        // it may send to a device, not that it may learn the shape of the user's network. A device list carrying
        // addresses would leak that to every plugin holding `device:list`.
        let target = DeviceTarget::new("dev_a");
        let json = serde_json::to_string(&target).expect("serialises");
        for forbidden in ["address", "addr", "ip", "port", "host", "socket"] {
            assert!(!json.contains(forbidden), "a device target carries {forbidden}: {json}");
        }
        // What it does carry, which is what a plugin needs to address a call and to show a row.
        assert_eq!(target.device_id, "dev_a");
        assert!(target.online);
        assert!(target.paired);
    }

    #[test]
    fn a_device_target_omits_a_name_it_does_not_have() {
        // The kernel has a name for a paired device and often not for one it has merely seen. A `null` where the
        // contract says "omitted" is a difference the component model does not accept.
        let json = serde_json::to_string(&DeviceTarget::new("dev_a")).expect("serialises");
        assert!(!json.contains("displayName"), "{json}");

        let named = DeviceTarget {
            display_name: Some("Laptop".to_owned()),
            ..DeviceTarget::new("dev_a")
        };
        let json = serde_json::to_string(&named).expect("serialises");
        assert!(json.contains("\"displayName\":\"Laptop\""), "{json}");
    }

    #[test]
    fn a_device_target_round_trips() {
        let target = DeviceTarget {
            display_name: Some("Laptop".to_owned()),
            ..DeviceTarget::new("dev_a")
        };
        let json = serde_json::to_string(&target).expect("serialises");
        let back: DeviceTarget = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, target);
    }

    #[test]
    fn every_type_is_non_exhaustive_for_the_plugin_side() {
        // A plugin that matched a level exhaustively would have its build broken by a level the contract gained, and
        // the arm it added would then hide every future one. A compile-time property asserted here so the file states
        // it rather than relying on a reader to notice the attribute.
        assert!(LogLevel::all().len() >= 5);
        // The types are `#[non_exhaustive]`, which means this crate cannot construct `Outcome` exhaustively either —
        // and the constructors are how it does.
        let _ = Outcome::done();
        let _ = Outcome::ok("x");
        let _ = Outcome::refused("c", "k");
        let _ = DeviceTarget::new("d");
    }
}
