use super::*;

#[test]
fn a_series_key_sorts_its_labels() {
    // Two call sites that pass the same labels in a different order must be the same series, or the
    // same measurement appears twice and both halves look half as large.
    let a = labelled("frames", &[("event", "ping"), ("peer", "abc")]);
    let b = labelled("frames", &[("peer", "abc"), ("event", "ping")]);
    assert_eq!(a, b);
    assert_eq!(a.render(), "frames{event=ping,peer=abc}");
}

#[test]
fn a_series_key_renders_without_labels_too() {
    assert_eq!(key("uptime").render(), "uptime");
}

#[test]
fn an_overflowed_key_keeps_its_label_names() {
    // The names are what tell a reader which dimension was folded. Replacing them entirely would
    // produce a series that looks like it belongs to a metric with different labels.
    let overflowed = labelled("frames", &[("event", "a"), ("peer", "b")]).overflowed();
    assert_eq!(overflowed.render(), "frames{event=overflow,peer=overflow}");
}

#[test]
fn a_counter_accumulates() {
    let recorder = RingRecorder::new();
    let frames = key("frames_sent_total");
    recorder.counter_inc(&frames);
    recorder.counter_add(&frames, 4);

    assert_eq!(recorder.snapshot().get("frames_sent_total"), Some(&Value::Counter(5)));
    assert_eq!(recorder.len(), 1, "a counter is one series");
}

#[test]
fn a_gauge_takes_its_last_value() {
    let recorder = RingRecorder::new();
    let links = key("links_open");
    recorder.gauge_set(&links, 3);
    recorder.gauge_set(&links, 1);

    assert_eq!(recorder.snapshot().get("links_open"), Some(&Value::Gauge(1)));
}

#[test]
fn a_gauge_may_go_negative() {
    // A gauge that could not go negative would be useless for the things gauges are for: a delta, a
    // queue depth after a drain.
    let recorder = RingRecorder::new();
    recorder.gauge_set(&key("delta"), -5);
    assert_eq!(recorder.snapshot().get("delta"), Some(&Value::Gauge(-5)));
}
