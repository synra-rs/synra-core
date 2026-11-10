use super::*;

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
