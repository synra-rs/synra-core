//! Spike 4 — does `rusqlite` with `bundled` cross-compile to `aarch64-linux-android`?
//!
//! The assumption under test: the kernel's persistence layer is SQLite compiled from source, identically on every
//! platform, because a kernel that used whatever SQLite the machine happened to have would behave differently across
//! versions — and `foreign_keys`, the pragma the schema's `ON DELETE CASCADE` depends on, is exactly the sort of thing
//! a version changes. The cost of that decision is a C toolchain on every build host, which is what this spike pays.
//!
//! The roadmap's fallback is `redb`, a pure Rust store. That is a large change to `synra-store`'s schema layer, so the
//! answer here is worth half a day to get right.

/// Opens an in-memory database.
///
/// Nothing here is executed — this is a `cargo check`, which never links and never runs. The function exists so the
/// spike reaches the public API the store uses rather than only proving that a `Cargo.toml` resolves.
pub fn open() -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open_in_memory()
}
