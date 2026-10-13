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
mod tests {
    use bytes::Bytes;
    use synra_capability::{Capability, CapabilitySet};
    use synra_protocol::frame::{Frame, FrameDecoder, FrameKind};
    use synra_testkit_alloc::{AllocationBudget, CounterGuard};

    /// A frame's bytes, encoded once outside the measurement.
    ///
    /// Encoded before the guard is installed, because *encoding* is not a hot path — a frame is built once and decoded
    /// once per hop — and measuring the two together would make the assertion about the wrong thing.
    fn encoded(kind: FrameKind) -> Bytes {
        let frame = match kind {
            FrameKind::Envelope => Frame {
                kind: FrameKind::Envelope,
                flags: 0,
                body: synra_protocol::frame::FrameBody::Envelope(Bytes::from_static(
                    br#"{"event":"device.ping","from":"dev_a","payload":{}}"#,
                )),
            },
            other => Frame::empty(other),
        };
        synra_protocol::frame::FrameEncoder::encode_to_vec(&frame).expect("the fixture encodes")
    }

    #[test]
    fn decoding_a_frame_allocates_nothing() {
        // ★ Hot path #1. Every frame the kernel receives goes through this, and an allocation here is paid per frame
        // rather than per message.
        let bytes = encoded(FrameKind::Envelope);

        // The decoder is built outside the measurement: its first `push` reserves, and a reservation is the one
        // allocation a decoder is *allowed* to make — it is the buffer the frames are sliced out of.
        let mut decoder = FrameDecoder::new();
        decoder.push(&bytes).expect("the frame is well formed");

        let (_, count) = CounterGuard::counted(|| {
            let frame = decoder.next_frame().expect("no error").expect("a frame");
            // The kind and the body are read, because a decoder that returned a frame without touching its bytes
            // would be one that had not decoded anything.
            assert_eq!(frame.kind, FrameKind::Envelope);
            std::hint::black_box(frame.body);
        });

        assert!(
            AllocationBudget::NONE.allows(count),
            "decoding a frame allocated: {}",
            AllocationBudget::NONE.explain(count)
        );
    }

    #[test]
    fn decoding_a_heartbeat_allocates_nothing() {
        // The frame a link sends when it has nothing to say, which is the one that runs at the highest rate: an
        // allocation here is paid once per heartbeat per link.
        let bytes = encoded(FrameKind::Ping);

        let mut decoder = FrameDecoder::new();
        decoder.push(&bytes).expect("the frame is well formed");

        let (_, count) = CounterGuard::counted(|| {
            let frame = decoder.next_frame().expect("no error").expect("a frame");
            assert_eq!(frame.kind, FrameKind::Ping);
        });

        assert!(AllocationBudget::NONE.allows(count), "a heartbeat allocated: {count}");
    }

    #[test]
    fn several_frames_from_one_buffer_allocate_nothing() {
        // The case a real socket produces: one read holds several frames. Each `next_frame` after the first is a slice
        // out of the same buffer, and a decoder that copied per frame would show up here and not in the single-frame
        // test.
        let mut together = bytes::BytesMut::new();
        for _ in 0..8 {
            together.extend_from_slice(&encoded(FrameKind::Envelope));
        }
        let together = together.freeze();

        let mut decoder = FrameDecoder::new();
        decoder.push(&together).expect("the frames are well formed");

        let (decoded, count) = CounterGuard::counted(|| {
            let mut decoded = 0u32;
            while let Some(frame) = decoder.next_frame().expect("no error") {
                decoded += 1;
                std::hint::black_box(frame.kind);
            }
            decoded
        });

        assert_eq!(decoded, 8, "the fixture did not produce eight frames");
        assert!(AllocationBudget::NONE.allows(count), "decoding eight frames allocated: {count}");
    }

    #[test]
    fn matching_a_capability_allocates_nothing() {
        // ★ Hot path #2. The gate runs before every plugin call, and a capability is a string the kernel compares.
        let mut grants = CapabilitySet::new();
        grants.insert_str("log:*").expect("a valid capability");
        grants.insert_str("storage:local:read").expect("a valid capability");
        grants.insert_str("device:send:dev_a").expect("a valid capability");

        let wanted = Capability::parse("log:write").expect("a valid capability");

        let (verdict, count) = CounterGuard::counted(|| grants.contains(&wanted));
        assert!(verdict, "the grant did not match");
        assert!(AllocationBudget::NONE.allows(count), "matching a capability allocated: {count}");
    }

    #[test]
    fn matching_a_capability_that_is_absent_allocates_nothing() {
        // The refusal is the common case in a strict installation — a plugin asking for something it was not granted —
        // so it must not be the expensive one. A `contains` that built a key to look up would allocate exactly here.
        let mut grants = CapabilitySet::new();
        grants.insert_str("log:*").expect("a valid capability");

        let wanted = Capability::parse("network:fetch:example.com").expect("a valid capability");

        let (verdict, count) = CounterGuard::counted(|| grants.contains(&wanted));
        assert!(!verdict, "the grant matched something it should not");
        assert!(AllocationBudget::NONE.allows(count), "a refused match allocated: {count}");
    }

    #[test]
    fn the_gate_permits_an_ungated_function_without_allocating() {
        // The check that runs before every plugin call, on the path where nothing needs to be checked. It reads a
        // static table, so the whole point is that it touches no heap.
        let grants = CapabilitySet::new();
        let import = "synra:plugin/host#env-sdk-version";

        let (verdict, count) =
            CounterGuard::counted(|| synra_plugin_host::permits(import, &grants));
        assert!(verdict, "an ungated function was refused");
        assert!(AllocationBudget::NONE.allows(count), "the gate allocated: {count}");
    }

    #[test]
    fn the_gate_checks_a_granted_capability_without_allocating() {
        // The path a plugin's call actually takes: look the import up in the table, then check the grant. Both are
        // steps in the same call, so measuring them apart would miss an allocation in the join.
        let mut grants = CapabilitySet::new();
        grants.insert_str("log:*").expect("a valid capability");
        let import = "synra:plugin/host#log";

        let (verdict, count) =
            CounterGuard::counted(|| synra_plugin_host::permits(import, &grants));
        assert!(verdict, "a granted capability was refused");
        assert!(AllocationBudget::NONE.allows(count), "the gate allocated: {count}");
    }

    #[test]
    fn routing_an_event_allocates_nothing() {
        // The design document's third path: an event name is looked up per event, and a lookup that built a `String`
        // key would allocate once per event per subscriber.
        let mut registry = synra_core::routing::EventRegistry::new();
        let plugin = synra_core::admission::PluginKey::new("@synra-plugin/chat");
        registry
            .register(&plugin, &["device.*".to_owned()])
            .expect("the rule registers");
        // The route is warmed outside the measurement: the *first* call registers the name, which is a one-time cost
        // and not the path being asserted about.
        let _ = registry.route("device.ping");

        let (outcome, count) = CounterGuard::counted(|| registry.route("device.ping"));
        assert!(
            !matches!(outcome, synra_core::routing::RouteOutcome::Unknown { .. }),
            "the event did not route: {outcome:?}"
        );
        assert!(AllocationBudget::NONE.allows(count), "routing an event allocated: {count}");
    }

    #[test]
    fn a_lookup_that_misses_allocates_nothing() {
        // The case a hostile or merely out-of-date peer produces: a name no plugin registered, arriving per event. A
        // router that lowered the name into an owned key to look it up would allocate exactly here, on a path a peer
        // controls — which is the shape of a denial of service.
        let mut registry = synra_core::routing::EventRegistry::new();
        let plugin = synra_core::admission::PluginKey::new("@synra-plugin/chat");
        registry
            .register(&plugin, &["device.*".to_owned()])
            .expect("the rule registers");

        // The router answers `Nobody` rather than `Unknown`: an event name the kernel has never seen and one no plugin
        // subscribed to are the same event as far as routing goes, and the caller's next step is the same. What is
        // being asserted here is that answering costs no allocation — a router forced to lower the name into an owned
        // key to look it up would allocate exactly on this path.
        let (outcome, count) = CounterGuard::counted(|| registry.route("teleport.away"));
        assert!(
            matches!(outcome, synra_core::routing::RouteOutcome::Nobody),
            "an event with no subscriber routed: {outcome:?}"
        );
        assert!(AllocationBudget::NONE.allows(count), "a missed lookup allocated: {count}");
    }
}
