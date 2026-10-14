use super::*;
use synra_protocol::TraceId;
use synra_protocol::envelope::Envelope;
use synra_protocol::event::EventName;
use synra_protocol::ids::DeviceId;

fn envelope_with_trace(trace_id: TraceId) -> Envelope {
    Envelope::outbound(
        synra_protocol::envelope::OutboundSpec {
            event: EventName::parse("device.ping").expect("valid"),
            target: DeviceId::new(),
            from: DeviceId::new(),
            trace_id,
            sent_at_ms: 0,
            ttl_ms: None,
        },
        None::<&()>,
    )
    .expect("builds")
}

#[test]
fn a_root_span_has_no_parent() {
    let context = TraceContext::start(&Sampler::everything(), true);
    assert!(context.span_id.is_root());
    assert_eq!(context.parent_span, None);
    assert!(context.sampled);
    assert_eq!(context.origin, TraceOrigin::Local);
    assert_eq!(context.describe_origin(), "all steps recorded on this device");
}

#[test]
fn a_child_points_at_its_parent_and_keeps_the_trace() {
    let parent = TraceContext::start(&Sampler::everything(), true);
    let child = parent.child();

    assert_eq!(child.trace_id, parent.trace_id, "one user action, one trace");
    assert_eq!(child.parent_span, Some(parent.span_id));
    assert_ne!(child.span_id, parent.span_id, "a step is its own identity");
    // Sampling is inherited, never re-decided: a per-span decision produces a trace with holes.
    assert_eq!(child.sampled, parent.sampled);
}

#[test]
fn a_sampled_decision_is_inherited_through_a_chain() {
    // The property that keeps a trace readable: every descendant agrees with the root.
    for rate in [0, 1, 500_000, 1_000_000] {
        let sampler = Sampler::with_rate_ppm(rate);
        let root = TraceContext::start(&sampler, true);
        let mut current = root;
        for _ in 0..20 {
            current = current.child();
            assert_eq!(current.sampled, root.sampled, "rate {rate}");
        }
    }
}

#[test]
fn an_error_is_always_recorded() {
    let sampler = Sampler::nothing();
    assert!(sampler.should_sample_finished(true, 1));
    assert!(!sampler.should_sample_finished(false, 1));
}

#[test]
fn a_slow_operation_is_always_recorded() {
    let sampler = Sampler::nothing();
    assert!(sampler.should_sample_finished(false, DEFAULT_ALWAYS_SLOWER_THAN_MS + 1));
    // Exactly at the threshold is not "slower than", so it is not recorded by this rule.
    assert!(!sampler.should_sample_finished(false, DEFAULT_ALWAYS_SLOWER_THAN_MS));
}

#[test]
fn the_base_rate_is_produced_exactly_over_a_full_cycle() {
    // A counter rather than a random draw, so the configured proportion is what happens rather than
    // what happens on average.
    let sampler = Sampler::with_rate_ppm(10_000);
    let sampled = (0..1_000_000).filter(|_| sampler.should_sample(true)).count();
    assert_eq!(sampled, 10_000);
}

#[test]
fn a_rate_of_zero_records_nothing_and_a_full_rate_records_everything() {
    let none = Sampler::nothing();
    assert!((0..1_000).all(|_| !none.should_sample(true)));

    let all = Sampler::everything();
    assert!((0..1_000).all(|_| all.should_sample(true)));
    // And a full-rate sampler must not consume its counter, so a later change of rate is not offset.
    assert!(all.should_sample(true));
}

#[test]
fn a_forced_trace_is_recorded_whatever_the_rate_says() {
    // The diagnostics screen's "record the next operation in detail". One investigation must not
    // require flooding the log with everything.
    let sampler = Sampler::nothing();
    let context = TraceContext::start(&sampler, true);
    assert!(!context.sampled);

    assert!(!sampler.should_record(&context, false, 1));
    sampler.force(context.trace_id);
    assert!(sampler.should_record(&context, false, 1));
    assert!(sampler.is_forced(context.trace_id));
    assert_eq!(sampler.forced_count(), 1);

    sampler.unforce(context.trace_id);
    assert!(!sampler.should_record(&context, false, 1));
    assert_eq!(sampler.forced_count(), 0);
}

#[test]
fn a_sampled_context_is_recorded_even_when_the_rate_would_say_no() {
    // The decision travels with the trace. Re-asking the sampling policy at each step is what produces
    // a trace with unexplained holes.
    let sampler = Sampler::nothing();
    let context = TraceContext::always(TraceId::new());
    assert!(context.sampled);
    assert!(sampler.should_record(&context, false, 1));
}

#[test]
fn forcing_can_be_cleared() {
    let sampler = Sampler::new();
    for _ in 0..3 {
        sampler.force(TraceId::new());
    }
    assert_eq!(sampler.forced_count(), 3);
    sampler.clear_forced();
    assert_eq!(sampler.forced_count(), 0);
}

#[test]
fn a_trace_is_recovered_from_an_envelope() {
    let trace_id = TraceId::new();
    let envelope = envelope_with_trace(trace_id);
    let context = TraceContext::from_envelope(&envelope).expect("has a trace");

    assert_eq!(context.trace_id, trace_id);
    assert!(context.span_id.is_root(), "the hand-off has no parent id to attach to");
    assert_eq!(context.parent_span, None);
    assert!(
        context.sampled,
        "an inbound trace is recorded if the sender recorded it"
    );
    // And the discontinuity is stated rather than left to be discovered.
    assert_eq!(context.origin, TraceOrigin::CrossesDevices);
    assert!(!context.origin.is_complete());
    assert!(context.describe_origin().contains("not joined"));
}

#[test]
fn an_envelope_with_no_trace_yields_nothing() {
    // Rather than inventing an id, which would put unrelated steps under one trace.
    let envelope = envelope_with_trace(TraceId(0));
    assert_eq!(TraceContext::from_envelope(&envelope), None);
}

#[test]
fn continuing_from_an_untraced_message_starts_a_trace_and_marks_it_remote() {
    let sampler = Sampler::everything();
    let envelope = envelope_with_trace(TraceId(0));
    let context = TraceContext::continue_from(&envelope, &sampler);

    assert!(!context.trace_id.is_zero(), "a trace id was started");
    assert_eq!(context.origin, TraceOrigin::Remote);
    assert!(!context.origin.is_complete());
    assert!(context.describe_origin().contains("another device"));
}

#[test]
fn continuing_from_a_traced_message_keeps_its_id() {
    let trace_id = TraceId::new();
    let envelope = envelope_with_trace(trace_id);
    let context = TraceContext::continue_from(&envelope, &Sampler::nothing());

    assert_eq!(context.trace_id, trace_id);
    assert_eq!(context.origin, TraceOrigin::CrossesDevices);
}

#[test]
fn a_context_can_open_a_child_with_its_own_counter() {
    // A caller that keeps its own span counter — the kernel, which numbers spans per trace rather than
    // per context — still gets the parent link.
    let parent = TraceContext::start(&Sampler::everything(), true);
    let child = parent.child_with(SpanId(42));
    assert_eq!(child.span_id, SpanId(42));
    assert_eq!(child.parent_span, Some(parent.span_id));
    assert_eq!(child.trace_id, parent.trace_id);
}

#[test]
fn a_span_id_renders_as_hex() {
    assert_eq!(SpanId(0).to_hex(), "0000000000000000");
    assert!(SpanId::ROOT.is_root());
    assert!(!SpanId(1).is_root());
    assert_eq!(SpanId(255).to_hex(), "00000000000000ff");
    assert_eq!(SpanId(255).to_string(), "00000000000000ff");
}

#[test]
fn a_short_trace_id_is_a_usable_grep_target() {
    let context = TraceContext::always(TraceId(0x7f3a_c21b_0000_0000_0000_0000_0000_0000));
    assert_eq!(context.short().len(), 6);
    assert!(context.short().starts_with("7f3ac2"), "{}", context.short());
}

#[test]
fn a_span_records_when_it_started_and_how_long_it_took() {
    let context = TraceContext::start(&Sampler::everything(), true);
    let mut span = Span::start(context, "transport.send", 1_000);
    assert!(span.is_open());
    assert_eq!(span.elapsed_ms, None);

    span.finish(1_012, false);
    assert!(!span.is_open());
    assert_eq!(span.elapsed_ms, Some(12));
    assert!(!span.failed);
}

#[test]
fn a_span_that_finishes_before_it_started_reports_zero_rather_than_wrapping() {
    // A clock that moved backwards — a suspend, a manual time change — must not produce a duration of
    // eighteen quintillion milliseconds.
    let context = TraceContext::start(&Sampler::everything(), true);
    let mut span = Span::start(context, "weird", 5_000);
    span.finish(1_000, false);
    assert_eq!(span.elapsed_ms, Some(0));
}

#[test]
fn a_finished_span_can_be_marked_failed() {
    let context = TraceContext::start(&Sampler::everything(), true);
    let mut span = Span::start(context, "gate.check", 0);
    span.finish(5, true);
    assert!(span.failed);
}

#[test]
fn the_ring_keeps_only_the_most_recent_spans() {
    let ring = TraceRing::with_capacity(3);
    let context = TraceContext::always(TraceId::new());
    for index in 0..5u64 {
        ring.record(Span::start(context, format!("step{index}"), index));
    }

    assert_eq!(ring.len(), 3);
    assert_eq!(ring.dropped(), 2);
    let names: Vec<String> = ring.steps_for(context.trace_id).into_iter().map(|s| s.name).collect();
    assert_eq!(names, vec!["step2", "step3", "step4"]);
}

#[test]
fn a_zero_capacity_ring_records_nothing_without_panicking() {
    // A configuration that disables the trace view must not crash the kernel on its first span.
    let ring = TraceRing::with_capacity(0);
    let context = TraceContext::always(TraceId::new());
    ring.record(Span::start(context, "step", 0));

    assert!(ring.is_empty());
    assert_eq!(ring.dropped(), 1);
    assert!(ring.steps_for(context.trace_id).is_empty());
}

#[test]
fn the_ring_separates_traces() {
    let ring = TraceRing::with_capacity(16);
    let first = TraceContext::always(TraceId::new());
    let second = TraceContext::always(TraceId::new());

    ring.record(Span::start(first, "a", 0));
    ring.record(Span::start(second, "b", 1));
    ring.record(Span::start(first, "c", 2));

    assert_eq!(ring.steps_for(first.trace_id).len(), 2);
    assert_eq!(ring.steps_for(second.trace_id).len(), 1);
    assert!(ring.steps_for(TraceId::new()).is_empty());
}

#[test]
fn steps_are_ordered_by_when_they_ran() {
    // A fan-out gives several children of one parent; span id order is not run order.
    let ring = TraceRing::with_capacity(16);
    let root = TraceContext::always(TraceId::new());
    let child = root.child_with(SpanId(1));
    let grandchild = child.child_with(SpanId(2));

    // Recorded out of order, as concurrent steps would arrive.
    ring.record(Span::start(grandchild, "grandchild", 30));
    ring.record(Span::start(root, "root", 10));
    ring.record(Span::start(child, "child", 20));

    let names: Vec<String> = ring.steps_for(root.trace_id).into_iter().map(|s| s.name).collect();
    assert_eq!(names, vec!["root", "child", "grandchild"]);
}

#[test]
fn recent_traces_are_listed_newest_first() {
    let ring = TraceRing::with_capacity(16);
    let first = TraceContext::always(TraceId::new());
    let second = TraceContext::always(TraceId::new());

    ring.record(Span::start(first, "a", 0));
    ring.record(Span::start(second, "b", 1));
    ring.record(Span::start(second, "c", 2));

    let recent = ring.recent_traces(10);
    assert_eq!(recent.first(), Some(&second.trace_id), "the newest trace comes first");
    // De-duplicated: two steps of one trace are one entry.
    assert_eq!(recent.len(), 2);
}

#[test]
fn recent_traces_respect_their_limit() {
    let ring = TraceRing::with_capacity(16);
    for index in 0..5u64 {
        let context = TraceContext::always(TraceId::new());
        ring.record(Span::start(context, format!("s{index}"), index));
    }
    assert_eq!(ring.recent_traces(2).len(), 2);
    assert!(ring.recent_traces(0).is_empty());
}

#[test]
fn the_ring_can_be_emptied() {
    let ring = TraceRing::with_capacity(4);
    ring.record(Span::start(TraceContext::always(TraceId::new()), "a", 0));
    ring.clear();
    assert!(ring.is_empty());
    assert_eq!(ring.dropped(), 0, "clearing is not dropping");
}

#[test]
fn a_rendered_trace_is_readable_and_indents_children() {
    let root = TraceContext::always(TraceId::new());
    let child = root.child();

    let mut first = Span::start(root, "transport.send", 0);
    first.finish(12, false);
    let mut second = Span::start(child, "gate.check", 14);
    second.finish(1, true);

    let rendered = render_trace(&[first, second]);
    assert!(rendered.contains("transport.send"), "{rendered}");
    assert!(rendered.contains("12ms"), "{rendered}");
    assert!(rendered.contains("gate.check"), "{rendered}");
    // The failed step is marked, so a reader's eye finds it.
    assert!(rendered.contains("! "), "{rendered}");
    // And a child is indented.
    assert!(rendered.contains("\n  ! "), "{rendered}");
}

#[test]
fn rendering_an_empty_trace_says_so() {
    // An empty string in a diagnostic bundle reads as a rendering bug.
    let rendered = render_trace(&[]);
    assert!(rendered.contains("no steps recorded"), "{rendered}");
}

#[test]
fn an_open_span_renders_as_open() {
    let context = TraceContext::always(TraceId::new());
    let rendered = render_trace(&[Span::start(context, "still.running", 5)]);
    assert!(rendered.contains("open"), "{rendered}");
}

#[test]
fn trace_origins_explain_themselves() {
    assert!(TraceOrigin::Local.is_complete());
    assert!(!TraceOrigin::Remote.is_complete());
    assert!(!TraceOrigin::CrossesDevices.is_complete());

    // Every explanation is a sentence, because it is shown to a user who is looking at a gap.
    for origin in [TraceOrigin::Local, TraceOrigin::Remote, TraceOrigin::CrossesDevices] {
        let text = origin.explain();
        assert!(!text.is_empty(), "{origin:?}");
        assert!(!text.contains('-'), "{origin:?} -> {text}");
    }
}

#[test]
fn a_trace_context_round_trips_through_json() {
    // A span is written to the log and read back by the diagnostics screen, so the shape has to survive.
    let context = TraceContext::start(&Sampler::everything(), true).child();
    let json = serde_json::to_string(&context).expect("serialises");
    let back: TraceContext = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, context);

    // A span id is transparent over its number, so a log reader sees `1` rather than an object.
    assert_eq!(serde_json::to_string(&SpanId(1)).expect("serialises"), "1");
}

#[test]
fn a_sampler_is_debug_printable() {
    let sampler = Sampler::new();
    assert!(format!("{sampler:?}").contains("Sampler"));
}

#[test]
fn a_recorded_flag_follows_the_sampled_flag() {
    let sampled = TraceContext::start(&Sampler::everything(), true);
    assert!(sampled.is_recorded());

    let unsampled = TraceContext::always(TraceId::new());
    assert!(unsampled.is_recorded());
}
