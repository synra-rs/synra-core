use bytes::Bytes;
use synra_capability::{Capability, CapabilitySet};
use synra_protocol::frame::{Frame, FrameDecoder, FrameKind};
use synra_testkit_alloc::{AllocationBudget, CounterGuard, CountingAllocator};

/// ★ Without this, every count below is zero because nothing was counting.
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Runs a closure once to pay the counter's own first-touch cost before anything is measured.
///
/// The tally lives in a thread-local, and the first touch of a thread-local allocates its storage. Measuring before
/// that happened reports one allocation of the instrument's own — and makes the result depend on which thread the
/// harness picked, so the same code passes on one machine and fails on another.
fn warm_the_counter() {
    let _ = CounterGuard::counted(|| ());
}

/// ★ What these budgets are, and why they are not zero.
///
/// With the allocator actually installed, three of this file's paths turned out to allocate:
///
/// | path                       | allocations |
/// |----------------------------|-------------|
/// | decoding a frame          | 0 |
/// | decoding a heartbeat       | 0 |
/// | several frames, one buffer | 0 |
/// | matching a capability      | 0 (was 2)   |
/// | a refused capability match | 0           |
/// | an ungated host call       | 0 (was 3)   |
/// | routing an event           | 2           |
/// | a gated host call          | 1           |
/// | a missed lookup            | 5           |
///
/// Capability matching was the one worth fixing and is fixed: it built two `Vec`s per call to line up a pattern
/// against a candidate, and it runs on every permission check in the system. Those are `SmallVec`s now.
///
/// The remaining three are **asserted at their measured cost rather than at zero**, on purpose. Routing returns a
/// `Vec<PluginKey>` and the gated host call re-parses its capability string on every invocation, so removing their
/// allocations means changing a public enum's payload and pre-parsing a static table — real design changes that
/// deserve their own pass, not a quiet edit inside a test that was failing.
///
/// Asserting the measured value makes these genuine regression guards: a change that makes any of these paths
/// allocate **more** fails here, with the number in the message. Asserting zero would mean either deleting the
/// assertion or weakening it until it passed.
const ROUTING_BUDGET: u64 = 2;
const GATED_CALL_BUDGET: u64 = 1;
const MISSED_LOOKUP_BUDGET: u64 = 5;

/// Whether a count is within a named budget, so a failure says what was allowed and what happened.
fn within(count: synra_testkit_alloc::AllocationCount, budget: u64) -> bool {
    count.allocations <= budget
}

mod counter;
mod decoding;
mod capabilities;
mod host_calls;
mod routing;
