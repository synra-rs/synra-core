//! What a registry publishes, and how to open it safely.
//!
//! # Two jobs, one crate
//!
//! The design (16 §4) has an install read a **packument** — npm's per-package metadata document — and then fetch the
//! tarball its chosen version names. Both steps are about untrusted bytes: the packument is JSON a server chose, and the
//! tarball is an archive it chose. Putting the parsing rules next to the extraction rules keeps "what a hostile registry
//! can do" in one file rather than spread between a command and an installer.
//!
//! # Why the crate is not inside the app
//!
//! Because the rules are testable without a window, a database or a socket: a `Vec<u8>` in, a directory out. The app
//! supplies the network and the paths; this crate supplies the decisions.
//!
//! # What is deliberately absent
//!
//! No verification. A packument digest is a claim until the signature check compares it with the bytes, and that check
//! belongs to the install pipeline ([`synra_plugin_api`] and the host's verifier) where a single implementation already
//! exists. A second one here would be the place a package slips through.
//!
//! # Panic policy
//!
//! This crate inherits the workspace's denial of `unwrap`/`expect`/`panic`. Tests are exempt for the same reason as
//! everywhere else: a test that cannot fail loudly is not a test.

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

pub mod extract;
pub mod packument;
pub mod static_index;

pub use extract::{ExtractError, Limits, extract_tgz};
pub use packument::{Dist, Packument, Version};
pub use static_index::parse as parse_static_index;
