//! The plugin sandbox: what a plugin may do, how much of it, and what state it is in.
//!
//! # Three questions, and this crate is where they are answered
//!
//! A plugin is code from a stranger that runs inside the user's application and can talk to the user's other
//! devices. Three separate mechanisms keep that from being a mistake, and they fail in different ways:
//!
//! * **Capability gates** — *what* a plugin may do. The DSL, the matching and the three-layer enforcement live in
//!   [`synra_capability`] and [`synra_plugin_api`], because they are contracts a plugin author has to be held to and
//!   a contract belongs where it can be read without the host. This crate holds the host-side decision: whether a
//!   *specific call*, with all its arguments, is one the plugin was granted.
//! * **Quotas** ([`quota`]) — *how much*. Static limits and rate limits need different answers: one is a refusal with
//!   no retry, the other says when to try again. The escalation ladder is here because "this plugin is asking too
//!   often" has to become visible before it becomes a plugin that is disabled.
//! * **Lifecycle** ([`lifecycle`]) — *what it is currently doing*. The state machine's value is in the transitions it
//!   refuses: a plugin may not run before its grants are decided, may not be reactivated while faulted, and may not be
//!   uninstalled while running.
//!
//! # What is deliberately not here
//!
//! **No Wasmtime.** The design document puts the engine in this crate, and the engine belongs in the application
//! layer instead — for one reason that matters: a crate carrying a C dependency and a large engine cannot be checked
//! by `cargo test` alone, and the parts of this crate that get the answers *wrong* are not the parts that call into an
//! engine. [`pool`] decides which instance a call gets and when an instance may be recycled; the engine is what sits
//! behind a handle. Testing the decision without the engine is what makes the decision testable at all.
//!
//! # The pool's one hard rule
//!
//! A plugin that declares itself `stateful` keeps memory between calls, so its instances are **not**
//! interchangeable. Round-robin would silently lose its state, and the symptom would be a plugin that works when only
//! one thing is happening — which is the hardest kind of bug to be told about.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod host_surface;
pub mod lifecycle;
pub mod pool;
pub mod quota;

pub use host_surface::{
    HostGate, CAPABILITIES, EXPORTED_INTERFACES, HOST_FUNCTIONS, HOST_INTERFACE, PACKAGE, PACKAGE_VERSION,
    gate, gated, is_declared_capability, permits, provided, provides, required_capabilities, undeclared_imports,
    ungated,
};
pub use lifecycle::{
    Lifecycle, State, StopRecord, Transition, TransitionError, UNSTABLE_THRESHOLD,
};
pub use pool::{
    IDLE_EVICT_AFTER, InstancePolicy, InstancePool, InstanceRecord, PoolRefusal, PoolReport,
    RECYCLE_AFTER_CALLS,
};
pub use quota::{
    Budget, DEGRADE_AFTER_WINDOWS, FAULT_AFTER_WINDOWS, Health, PERSISTENCE_WINDOW,
    PERSISTENT_REFUSALS, Quota, QuotaReport, RateKind, RateLimited, StaticRefusal, TokenBucket,
};
