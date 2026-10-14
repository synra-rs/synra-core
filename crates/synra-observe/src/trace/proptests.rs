use super::*;
use proptest::prelude::*;
use synra_protocol::TraceId;

proptest! {
    /// Every step of a trace agrees on whether it is recorded. This is the property that keeps a
    /// sampled trace whole: a hole in a trace is worse than no trace, because it reads as "nothing
    /// happened here".
    #[test]
    fn sampling_is_uniform_across_a_trace(
        rate in 0u32..=1_000_000,
        depth in 1usize..40,
    ) {
        let sampler = Sampler::with_rate_ppm(rate);
        let root = TraceContext::start(&sampler, true);
        let mut current = root;
        for _ in 0..depth {
            current = current.child();
            prop_assert_eq!(current.sampled, root.sampled);
            prop_assert_eq!(current.trace_id, root.trace_id);
        }
    }

    /// A child's parent is always its immediate parent, and its span differs from it. A self-parenting
    /// span makes a tree that cannot be walked.
    #[test]
    fn a_child_links_to_exactly_one_distinct_parent(depth in 1usize..30) {
        let mut current = TraceContext::start(&Sampler::everything(), true);
        for _ in 0..depth {
            let child = current.child();
            prop_assert_eq!(child.parent_span, Some(current.span_id));
            prop_assert_ne!(child.span_id, current.span_id);
            current = child;
        }
    }

    /// The ring never holds more than its capacity, whatever order spans arrive in. An unbounded trace
    /// buffer is a second copy of the log, in memory.
    #[test]
    fn the_ring_never_exceeds_its_capacity(
        capacity in 0usize..16,
        count in 0usize..40,
        trace_count in 1usize..4,
    ) {
        let ring = TraceRing::with_capacity(capacity);
        let contexts: Vec<TraceContext> = (0..trace_count)
            .map(|_| TraceContext::always(TraceId::new()))
            .collect();

        for index in 0..count {
            let context = contexts[index % contexts.len()];
            ring.record(Span::start(context, format!("s{index}"), index as u64));
        }
        prop_assert!(ring.len() <= capacity);
        prop_assert_eq!(ring.len() + ring.dropped() as usize, count);
    }

    /// A trace's steps come back in the order they started, whatever order they were recorded in.
    #[test]
    fn recorded_order_does_not_determine_replay_order(
        times in proptest::collection::vec(0u64..10_000, 1..20)
    ) {
        let ring = TraceRing::with_capacity(64);
        let context = TraceContext::always(TraceId::new());
        for time in &times {
            ring.record(Span::start(context, "step", *time));
        }

        let steps = ring.steps_for(context.trace_id);
        prop_assert_eq!(steps.len(), times.len());
        prop_assert!(steps.windows(2).all(|pair| pair[0].started_at_ms <= pair[1].started_at_ms));
    }

    /// A span's duration is never negative, whatever the two clock readings are.
    #[test]
    fn a_duration_is_never_negative(start in 0u64..10_000, end in 0u64..10_000) {
        let context = TraceContext::always(TraceId::new());
        let mut span = Span::start(context, "s", start);
        span.finish(end, false);
        let elapsed = span.elapsed_ms.expect("finished");
        prop_assert!(elapsed <= 10_000, "{elapsed}");
        if end >= start {
            prop_assert_eq!(elapsed, end - start);
        }
        else {
            prop_assert_eq!(elapsed, 0);
        }
    }
}
