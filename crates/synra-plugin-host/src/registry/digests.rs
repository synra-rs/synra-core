//! A set of artifact digests a registry declares, by file name.
//!
//! # Why this is an alias and not a second type
//!
//! Because it is the same fact the signature covers — a file name and the digest its bytes must hash to — and two types
//! for one fact would be two places to change when the shape does. A registry's `synra.artifacts` and the subject a
//! publisher signed are compared to each other, so a type that differed between them would be a conversion at the one
//! place where a mistake means installing bytes nobody signed.
//!
//! The alias exists so this crate's public signature does not name a standard container: what a consumer sees is
//! `Digests`, whose meaning is the contract's.

pub use synra_plugin_api::Digests as ArtifactDigests;
