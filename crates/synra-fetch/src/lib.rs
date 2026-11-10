//! Fetching a URL on a plugin's behalf, safely enough to be worth doing.
//!
//! # Why this is a crate of its own
//!
//! Because it is the one capability that reaches the public internet for a plugin, and reaching it needs a TLS stack.
//! `synra-net` states that it handles *"two devices, once a socket exists"* and performs no IO, so an HTTP client does not
//! belong there; `synra-core` is cross-compiled for Android by `matrix`, and putting `rustls` and a crypto backend into
//! the kernel's dependency graph for a capability the kernel never uses is the wrong trade. So the **hosts** depend on
//! this, and the kernel does not.
//!
//! # What a plugin sends, and what it gets back
//!
//! The WIT declares `network-fetch: func(request-json: string) -> outcome` and says nothing about the shape — so it is
//! decided here, `camelCase` like every other payload in this workspace:
//!
//! ```json
//! { "url": "https://api.example.com/v1", "method": "GET",
//!   "headers": { "accept": "application/json" }, "body": null }
//! ```
//!
//! and the answer
//!
//! ```json
//! { "status": 200, "headers": { "content-type": "application/json" }, "body": "{…}" }
//! ```
//!
//! The **body is a string**, not parsed JSON, because a response is not always JSON — a plugin fetching a CSV or a web
//! page is doing something ordinary, and a host that parsed the body would be a host that refused most of the web.
//!
//! # Two entries, one body policy
//!
//! [`Client::fetch`] is the plugin-facing one: text, lossy UTF-8 at the edge. [`Client::fetch_bytes`] answers raw bytes
//! for the cases where decoding is corruption — a registry tarball (16 §4.1). Both go through the same guard, the same
//! redirect loop and the same ceiling; the only difference is the last step.
//!
//! # The order of the checks, which is the whole design
//!
//! `10 §4.4` names seven steps and this module is the first four; the remaining three are limits, and they are
//! [`Limits`]. The order matters and is not rearranged here:
//!
//! 1. the scheme and the host, by [`synra_core::network::NetworkGuard::check_url`];
//! 2. the addresses the name resolved to, by `check_resolved` — **every** one of them;
//! 3. the request, with redirects followed **by this module** rather than by the client, so each hop goes back through
//!    `check_url`;
//! 4. the response size.
//!
//! # Why the redirects are followed here
//!
//! Because the design requires each hop to be re-validated, and an HTTP client that follows redirects internally offers a
//! hop *count* and nothing else — no hook at which a second hop can be refused. So the client is configured to follow
//! none, and [`Client::fetch`] loops: read the `Location`, ask [`synra_core::network::NetworkGuard::next_hop`], repeat. A
//! redirect to a host nobody granted is refused at that moment, which is the only moment it can be.
//!
//! # Why the addresses are resolved here rather than by the client
//!
//! Because of DNS rebinding, which `10 §4.4` names: a name that answers with a public address when it is checked and a
//! private one when it is connected to defeats the entire IP policy. The defence is to connect to **the address that was
//! checked**, and that is what `FixedResolver` does — the client is handed the approved addresses and is not allowed to
//! look the name up again. The `Host` header and the certificate still carry the name, so this is not "connect to an IP":
//! the name is what is verified, and the address is what was approved.
//!
//! # What this is not
//!
//! It is not a sandbox for the *content*. A plugin that fetches a web page gets the web page; the capability is about
//! **where** the request may go, which is the part the kernel can decide on the user's behalf.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
//
// ★ And this was missing at first, which is why the tests below trip `expect_used` while every other crate's do not. The
// exemption is per crate and has to be repeated, so a new crate is a crate whose tests are held to the production rules —
// which is not wrong, but it is not what the rest of the workspace does, and the difference would have been invisible
// until somebody copied a test.
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

mod client;
mod types;

pub use client::Client;
pub use types::{BinaryResponse, DEFAULT_TIMEOUT, Limits, Request, Response};

#[cfg(test)]
mod tests;
