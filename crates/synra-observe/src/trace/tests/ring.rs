use super::*;

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
