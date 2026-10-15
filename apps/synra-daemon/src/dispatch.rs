//! The inbound state, as this host reaches it.
//!
//! # Why this is a shim
//!
//! Because it was written here \u2014 **inside a binary** \u2014 and a second host needs it. The desktop shell's kernel runs in
//! process (05 \u00a72.1) and must accept connections too, so the state a connection carries while a file arrives cannot live
//! in one host's tree. It is [`synra_core::inbound`] now; what remains here is the path, so the transport that has not moved
//! yet keeps compiling against `crate::dispatch`.
//!
//! # Why the re-export is the whole file
//!
//! Because nothing here was ever daemon-specific: the module's own imports were `synra_core::link`, `synra_core::session`
//! and `synra_core::Inbound`, and the only edit the move needed was making those `crate::`.

pub use synra_core::inbound::*;
