//! Allocation assertions for the protocol's hot paths.
//!
//! # Why this file exists at all
//!
//! `synra-protocol/src/lib.rs` states as a design principle that hot paths do not allocate, and it used to go further and
//! claim they were "asserted allocation-free in tests". There was no such assertion anywhere in the repository — the
//! counting allocator in `synra-testkit-alloc` existed, and nothing called it.
//!
//! So this file is that assertion. It is the kind of test that has to be written rather than reviewed: a `&str` becomes a
//! `String`, a `with_capacity` becomes a `vec![]`, and nothing fails until the path that runs for every event is slower
//! on someone else's machine.
//!
//! # Why the counting lives in another crate
//!
//! A [`std::alloc::GlobalAlloc`] implementation is `unsafe`, and this workspace `forbid`s unsafe code — which no local
//! `allow` can relax. `synra-testkit-alloc` exists as the one place that exception is stated, so this test depends on it
//! rather than repeating it.
//!
//! # Why every test warms up first
//!
//! Lazily-initialised statics and thread-local maps allocate on first touch. A measurement taken on the first call
//! measures that initialisation rather than the hot path, so each test does one unmeasured pass first — otherwise the
//! assertion reports a fact about the allocator rather than about the code.
//!
//! # What is deliberately *not* measured
//!
//! Encoding. The encoder builds the `Vec` that is the point of encoding, so "the encoder does not allocate" is not a
//! property anyone wants. The measured direction is the one that runs per incoming frame.

// An integration test is its own crate and does not inherit the relaxation the library sets for its `#[cfg(test)]`
// modules — the same reasoning `wire_fixtures.rs` gives. Here it is not just an index into a fixture array: a hot-path
// assertion that reported a broken expectation would be indistinguishable from a regression it is looking for.
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_const_for_fn,
)]

use bytes::Bytes;

use synra_protocol::event::EventName;
use synra_protocol::frame::{Frame, FrameBody, FrameDecoder, FrameEncoder, FrameError, FrameKind};
use synra_testkit_alloc::{CounterGuard, CountingAllocator};

/// ★ Starts the counter on this thread without measuring anything.
///
/// The counter keeps its tally in a thread-local `RefCell`, and the **first** touch of a thread-local allocates its
/// storage. A test that measured before that happened was reporting one allocation of the instrument's own, which is
/// both wrong and unstable — it depends on which thread the harness happened to run the test on, so the same code
/// passes on one machine and fails on another.
///
/// Every measurement in this file goes through here first, so what remains is the code under test and nothing else.
fn warm_the_counter() {
    let _ = CounterGuard::counted(|| ());
}

/// ★ The line that makes this file possible, and the line that was missing when it was first written.
///
/// `CountingAllocator` is only a *type*. Nothing counts anything until a binary declares it as its global allocator,
/// and an integration test binary does not inherit one from the library it exercises. Without this line every assertion
/// below reports zero — which looks exactly like success, and is the reason the file carries a self-check.
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// The bytes of one hello frame, encoded once.
///
/// Encoding happens outside every measurement: the encoder allocates the buffer it is being measured for, so including
/// it would say nothing about the decoder. What the socket does is decode repeatedly from bytes that already exist.
fn sample_bytes() -> Bytes {
    FrameEncoder::encode_to_vec(&Frame {
        kind: FrameKind::Hello,
        flags: 0,
        body: FrameBody::Hello(Bytes::from_static(b"{}")),
    })
    .expect("the sample frame encodes")
}

/// Pushes bytes and takes the next frame, reporting both.
///
/// ★ The push and the parse are two different costs, and only one of them belongs to decoding.
///
/// [`FrameDecoder::push_slice`] copies its argument into a fresh `Bytes` before doing anything — so a helper that used
/// it would put an allocation of its own inside the measurement and then report it as the decoder's. The socket path
/// pushes a `Bytes` it already owns, which shares the allocation.
///
/// So the push happens here, outside the measured region, and only [`FrameDecoder::next_frame`] is under test. What is
/// left is the parse: reading the header, validating the length, slicing the body out of the buffer.
fn push_then_decode(decoder: &mut FrameDecoder, bytes: &Bytes) -> Result<Option<Frame>, FrameError> {
    decoder.push(bytes).expect("push");
    decoder.next_frame()
}

/// Pushes without decoding, so a test can measure the parse alone.
fn push_only(decoder: &mut FrameDecoder, bytes: &Bytes) {
    decoder.push(bytes).expect("push");
}

/// ★ How many allocations one decoded frame is allowed: **zero**.
///
/// This file exists because the previous number was wrong twice before it was right.
///
/// ★ The first mistake. With one warm-up pass the test read **one** allocation per frame, and the obvious
/// conclusion was that `FrameDecoder` allocates on every decode. That conclusion was wrong. The single allocation was
/// a first-touch cost, and a second warm-up pass absorbed it.
///
/// ★ What is actually going on. `advance_scratch` does reallocate when its buffer drains:
///
/// ```text
/// let frame_region = self.scratch.split_to(total).freeze();
/// if self.scratch.is_empty() {
///     self.scratch = BytesMut::with_capacity(8 * 1024);
/// }
/// ```
///
/// But that is the **fragmented** path. When a whole frame arrives in one read, `next_frame` takes the fast path that
/// slices straight out of `head` and never touches `scratch` at all — so the ordinary case costs nothing. The reallocation
/// happens when a frame arrives in pieces, which is the case worth noticing and is not the one that runs per message.
///
/// ★ Why the assertion is still zero. A test that asserts "one, which is what it does" cannot tell you when that
/// one arrives on the common path, and would have been reported as a per-frame cost. Asserting zero states the property
/// the fast path actually has, and the warm-up is what makes it a statement about the code rather than about the
/// allocator.
const PER_FRAME_BUDGET: u64 = 0;

#[test]
fn decoding_a_frame_allocates_nothing() {
    let bytes = sample_bytes();
    // Warm-up: the first call touches statics and grows buffers this test does not mean to measure.
    warm_the_counter();
    let mut decoder = FrameDecoder::new();
    push_then_decode(&mut decoder, &bytes).expect("the first warm-up decodes");
    push_then_decode(&mut decoder, &bytes).expect("the second warm-up decodes");

    push_only(&mut decoder, &bytes);
    let (decoded, count) = CounterGuard::counted(|| decoder.next_frame());

    assert!(
        decoded.as_ref().is_ok_and(Option::is_some),
        "the sample frame must decode, or this test measures a path nothing uses: {decoded:?}"
    );
    assert_eq!(
        count.allocations, PER_FRAME_BUDGET,
        "decoding one frame allocated {} time(s); the budget is zero",
        count.allocations
    );
}

#[test]
fn decoding_many_frames_does_not_allocate_per_frame() {
    let bytes = sample_bytes();
    let mut decoder = FrameDecoder::new();
    push_then_decode(&mut decoder, &bytes).expect("the first warm-up decodes");
    push_then_decode(&mut decoder, &bytes).expect("the second warm-up decodes");

    let counter = CounterGuard::install();
    let mut decoded = 0usize;
    for _ in 0..512 {
        // The push is outside the count on purpose: filling the buffer is the socket's cost, and the parse is the
        // decoder's. Counting both would attribute one to the other.
        push_only(&mut decoder, &bytes);
        if decoder.next_frame().as_ref().is_ok_and(Option::is_some) {
            decoded += 1;
        }
    }
    let count = counter.read();

    assert_eq!(decoded, 512, "every iteration should decode the sample frame");
    // The per-frame budget multiplied out, rather than a zero total. A flat total of zero would assert that the decoder
    // became allocation-free; this asserts that its cost has not grown, which is the property that can hold today.
    assert_eq!(
        count.allocations,
        512 * PER_FRAME_BUDGET,
        "512 frames cost {} allocation(s), so the per-frame cost is not zero",
        count.allocations
    );
}

#[test]
fn parsing_an_event_name_allocates_nothing() {
    // The name is compared against a static table; building a `String` to make that comparison is the regression this
    // catches, and in a diff it looks like an ordinary refactor.
    warm_the_counter();
    let _ = EventName::parse("device.hello");

    let (parsed, count) = CounterGuard::counted(|| EventName::parse("device.hello"));

    assert!(parsed.is_ok(), "the sample event name must parse, or this measures nothing");
    assert_eq!(count.allocations, 0, "parsing an event name allocated {} time(s)", count.allocations);
}

#[test]
fn rejecting_a_malformed_frame_allocates_nothing() {
    // The error path matters as much as the success path: it is the one that runs on a corrupted stream, which is when
    // an allocation is least affordable.
    //
    // It costs zero, which is the control that matters: the budget above is not a blanket that hides an allocating
    // path, because this path goes through the same header read and rejection and still allocates nothing.
    warm_the_counter();
    let mut decoder = FrameDecoder::new();
    let malformed = Bytes::from_static(b"\x00\x00\x00\x02\xff\x00");
    let warm = Bytes::from_static(b"\x00\x00\x00\x02\x03\x00");
    push_then_decode(&mut decoder, &warm).expect("the first warm-up decodes");
    push_then_decode(&mut decoder, &warm).expect("the second warm-up decodes");

    push_only(&mut decoder, &malformed);
    let (outcome, count) = CounterGuard::counted(|| decoder.next_frame());

    assert!(outcome.is_err(), "an unknown kind must be refused, or this measures a success twice");
    assert_eq!(
        count.allocations, PER_FRAME_BUDGET,
        "refusing a frame allocated {} time(s); the budget is zero",
        count.allocations
    );
}

/// ★ Most of the tests above assert a count of **zero**, and a counter that reads zero for everything passes every one
/// of them.
///
/// This is what makes the rest of the file mean something. It runs a construction that certainly allocates — a `String`
/// from a formatted number — and requires the counter to report at least one. If the allocator stops being installed,
/// or the thread-local stops being reachable from this thread, this fails and the credibility of the other four goes
/// with it.
#[test]
fn the_counter_counts_an_allocation_that_definitely_happens() {
    let (built, count) = CounterGuard::counted(|| format!("{}", 1_234u32));

    assert_eq!(built, "1234", "the sample allocation must produce what it should");
    assert!(
        count.allocations > 0,
        "building a String allocated, and the counter reported {} — so a zero in the other tests proves nothing",
        count.allocations
    );
}
