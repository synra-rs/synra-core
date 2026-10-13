//! Test fixtures, shared by every crate in the workspace.
//!
//! # Why these live together rather than in each crate's `tests/`
//!
//! Four things are needed by more than one crate's tests, and each of them is a *design decision* the kernel makes
//! rather than a convenience:
//!
//! * [`clock`] — the `Clock` trait and a mock. The kernel takes a clock rather than reading one, so a timeout can be
//!   tested by moving time rather than by sleeping. That decision is what makes the trait exist, and the fixture is
//!   what makes it usable.
//! * an allocation counter, so "this hot path allocates nothing" is a test rather than a benchmark. A benchmark's
//!   number varies with the machine; an allocation count does not. The counter lives in `synra-testkit-alloc`, because
//!   the allocator hook is `unsafe` and this workspace forbids `unsafe` everywhere else.
//! * [`transport`] — an in-memory transport, so two kernels can be linked in one process with no sockets. This is
//!   what makes the end-to-end tests of §4.3 possible without a network.
//! * [`pair`] — two kernels wired together and already paired, which is the starting point of every integration test.
//!
//! # The crate is not published
//!
//! `publish = false`. It is a fixture, so its API is allowed to change whenever a test needs it, and a published
//! crate's API is a promise. The workspace's `STABILITY` document places it in the internal layer for the same
//! reason.
//!
//! # What it is not
//!
//! No fake kernel, no stub of the aggregates, and no mocking framework. A fixture that reimplemented the kernel
//! would test itself; these are the *seams* the kernel was designed with — a clock, a transport — plus the counters
//! that make a performance claim checkable. A test that stubbed the kernel's logic would be testing the stub.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning. This crate consists almost
// entirely of test code, so the relaxation covers most of it — which is worth stating, because a fixture that
// panicked only under a condition nobody tests would be a fixture that fails mysteriously.
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

pub mod clock;
pub mod pair;
pub mod transport;

// The allocation counter lives in its own crate, because it is the workspace's only `unsafe` code and `forbid` cannot
// be relaxed locally. Re-exported here so a test that uses the fixture has one import.
pub use synra_testkit_alloc::{
    AllocationBudget, AllocationCount, CounterGuard, SeededRng, record_allocation, record_free,
};
pub use clock::{Clock, ClockError, Deadline, MockClock, SystemClock};
pub use pair::{ExpectationError, KernelPair, PairedKernel};
pub use transport::{MemoryTransport, MemoryTransportLink, TransportError};
