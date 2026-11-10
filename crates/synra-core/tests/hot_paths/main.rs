//! The hot paths, asserted to allocate nothing.
//!
//! # Why an allocation count rather than a benchmark
//!
//! The design document specifies two paths as **zero allocation**: decoding a frame, and matching a capability. Both
//! run per frame or per call, so an allocation on either is a lock, a branch and a possible failure inside the
//! allocator, multiplied by the rate.
//!
//! A benchmark measures time, and time varies with the machine, the compiler and what else is running — so an
//! assertion on it is either flaky or so loose that it catches nothing. An allocation count is exact, and "this
//! allocates nothing" is a statement a reviewer can check.
//!
//! # Why it is a test and not a lint
//!
//! A lint would have to see through the generic code that makes these paths allocation-free — a `Bytes` clone, a
//! `CapabilitySet` bit test — and a lint that guessed would either miss the real case or refuse a legitimate one. What
//! is being asserted is about *runtime* behaviour, so it is asserted at runtime.
//!
//! # What the counter does not see
//!
//! Allocations on **another thread**. A test that moved the work to a worker would read zero and pass while the hot
//! path allocated freely, so these tests do the work on their own thread and the counter's own documentation says so.

// A file under `tests/` is its own crate, so the crate root's test exemption does not reach it — and everything here is
// a test. `expect` on a fixture that is wrong is the right failure: it says which fixture.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

#[cfg(test)]
mod tests;
