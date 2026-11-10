//! The local command channel and kernel control endpoint.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
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

pub mod endpoint;
pub mod server;

mod channel;

pub use channel::*;
pub use endpoint::{Client, Listener, SocketError, serve_stream, socket_path};
pub use server::{Kernel, Refusal, Server, SessionState};
