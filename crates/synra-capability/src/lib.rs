//! The capability model: what a plugin is allowed to do.
//!
//! A Wasm sandbox answers "what *can* this code do to the host?" — it cannot read host memory and it
//! cannot make a syscall. It does not answer any of the questions that actually decide whether a
//! plugin is trustworthy:
//!
//! * Which host functions may it call?
//! * Which hosts may it reach over the network?
//! * Which directories may it touch?
//! * Which devices may it send to?
//!
//! Those are *authorisation* questions, and they are answered here. The sandbox and the capability
//! system are complementary, not alternatives: the sandbox bounds the damage a bug can do, and the
//! capability set decides what the plugin was ever allowed to attempt.
//!
//! # The DSL
//!
//! ```text
//! capability := prefix (":" prefix)* qualifier?
//! prefix     := [a-z][a-z0-9-]{0,63} | "*" | "**"
//! qualifier  := domain-specific, see [`Capability::parse`]
//! ```
//!
//! Three prefixes at most, then a qualifier. So `domain:resource:action` is a capability, and
//! `network:fetch:api.github.com:POST` is that capability with a qualifier. The shape is fixed
//! because it is what makes a capability comparable: matching happens prefix by prefix, and a
//! grammar that allowed arbitrary nesting would make "is this capability a subset of that one"
//! undecidable by reading it.
//!
//! Some real capabilities:
//!
//! ```text
//! log:debug
//! device:send:@synra-pc
//! network:fetch:api.github.com:POST
//! fs:read:/data/**
//! platform:clipboard:read
//! event:emit:_plugin.chat.*
//! ```
//!
//! # What is deliberately not allowed
//!
//! * **A bare `*`.** It would mean "every capability", and a grammar that can express that will
//!   eventually be used to express it. A wildcard has to be part of a longer capability, and the
//!   user granting one sees exactly which domain it covers.
//! * **Empty segments.** `ui::navigate` is a typo, not a capability, and accepting it would create a
//!   second spelling of `ui:navigate` — so two capabilities that mean the same thing would compare
//!   unequal.
//! * **Mid-string wildcards.** Only a whole prefix may be `*` or `**`. `api.*.com` is not a pattern
//!   anyone can reason about, and the matching code would have to become a general glob engine.
//!
//! # Order independence is a hard requirement
//!
//! [`CapabilitySet::contains`] runs on **every host call**. Two properties are therefore not
//! aspirational but tested:
//!
//! 1. It allocates nothing.
//! 2. Its answer does not depend on the order capabilities were inserted in, nor on which pattern
//!    happened to match first.
//!
//! The second is easy to get wrong by accident: an implementation that returns as soon as any
//! pattern matches looks correct, and is, until someone adds a *negative* pattern or reorders the
//! list. `contains` is a pure predicate over a set, so it is written and tested as one.

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

pub mod capability;
pub mod domain;
pub mod gate;
pub mod set;

pub use capability::{Capability, CapabilityError, Segment};
pub use domain::{Domain, DomainId, DomainMask};
pub use gate::{CallGate, GateOutcome, GateRefusal};
pub use set::{CapabilitySet, EffectiveCaps, ImportSet, VerifyError, verify_effective_caps};
