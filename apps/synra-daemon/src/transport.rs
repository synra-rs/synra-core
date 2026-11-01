//! The listening half, as this host reaches it.
//!
//! # Why this is only a re-export
//!
//! The accept loop lives in [`synra_core::listener`], where both hosts can reach it. The tests that used to sit here drove
//! a real connection through this host's plugin boundary; they built their rig on device certificates and a pairing desk,
//! so they went with that layer ([ADR-025](../../../../design-docs/20-adr.md)). The handshake and framing they covered are
//! still tested in `synra_core`, against the same plaintext link this host now uses.

pub use synra_core::listener::*;