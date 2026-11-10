use super::*;

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
