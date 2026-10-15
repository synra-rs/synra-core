//! The listening half, as this host reaches it.
//!
//! # Why this is a shim, and why the tests stayed
//!
//! The accept loop was written here \u2014 **inside a binary** \u2014 and the design puts it in the desktop app's kernel too
//! (05 \u00a72.1). It is [`synra_core::listener`] now, where both hosts can reach it.
//!
//! The tests stayed, and that is deliberate rather than unfinished: they drive a real connection through a real
//! [`KernelHost`](crate::runtime::plugin_host::KernelHost), which is this host's implementation of the plugin boundary. A
//! library-side copy would have had to invent a second host to test with \u2014 and a listener tested against a host the
//! library made up is a listener tested against nothing the product runs.

pub use synra_core::listener::*;

#[cfg(test)]
mod tests;
