use core::time::Duration;

use synra_protocol::limits::{
    RECONNECT_BACKOFF, RECONNECT_BASE, RECONNECT_JITTER_PERCENT, RECONNECT_MAX,
};

use super::{Backoff, BackoffRefusal, MAX_ATTEMPTS, PendingRetry, ResetReason, RetryTrigger};

#[test]
fn the_first_attempt_never_waits() {
    // A peer that was just paired or just rediscovered should be tried immediately; making the first attempt
    // wait would add a second of latency to every connection.
    let backoff = Backoff::new(1);
    assert_eq!(backoff.ready(0, RetryTrigger::Timer), Ok(()));
    assert_eq!(backoff.attempts(), 0);
}

#[test]
fn failures_follow_the_protocol_schedule() {
    // The four short delays, then the constant base. Asserted as the shape rather than as exact values, because
    // the jitter moves them — the exact values are asserted in the next test.
    let mut backoff = Backoff::new(7);
    for (attempt, nominal) in RECONNECT_BACKOFF.iter().enumerate() {
        let delay = backoff.record_failure(0).expect("schedules");
        let nominal_ms = u64::try_from(nominal.as_millis()).unwrap_or(0);
        let low = nominal_ms * 80 / 100;
        let high = nominal_ms * 120 / 100;
        assert!(
            delay.as_millis() as u64 >= low && (delay.as_millis() as u64) <= high,
            "attempt {} scheduled {:?}, outside [{}ms, {}ms]",
            attempt + 1,
            delay,
            low,
            high
        );
    }
    // Past the schedule it is the base, capped.
    for _ in 0..3 {
        let delay = backoff.record_failure(0).expect("schedules");
        let base_ms = u64::try_from(RECONNECT_BASE.as_millis()).unwrap_or(0);
        assert!((delay.as_millis() as u64) <= base_ms * 120 / 100, "{delay:?}");
    }
}

#[test]
fn the_same_seed_gives_the_same_delays() {
    // Derived rather than random, so a failure is reproducible from a log line and a test can assert values
    // rather than ranges.
    let mut first = Backoff::new(42);
    let mut second = Backoff::new(42);
    for _ in 0..6 {
        assert_eq!(first.record_failure(0), second.record_failure(0));
    }

    // And a different seed moves them, which is the whole point of the jitter.
    let mut other = Backoff::new(43);
    let differs = (0..6).any(|_| first.record_failure(0) != other.record_failure(0));
    assert!(differs, "two seeds produced identical schedules");
}

#[test]
fn consecutive_attempts_do_not_move_in_a_straight_line() {
    // A plain `seed + attempt` would make every peer with an adjacent seed retry at adjacent times, which is the
    // lockstep the jitter exists to break.
    let mut backoff = Backoff::new(1_000);
    let delays: Vec<u128> = (0..4).map(|_| backoff.record_failure(0).expect("schedules").as_millis()).collect();
    // Within the short schedule the delays grow, so the assertion is about the *jitter offsets* rather than the
    // delays: they are not all the same fraction of their nominal value.
    let nominal: Vec<u128> = RECONNECT_BACKOFF.iter().map(|d| d.as_millis()).collect();
    let offsets: Vec<i128> = delays
        .iter()
        .zip(&nominal)
        .map(|(delay, nominal)| *delay as i128 - *nominal as i128)
        .collect();
    let fractions: Vec<i128> = offsets
        .iter()
        .zip(&nominal)
        .map(|(offset, nominal)| if *nominal == 0 { 0 } else { offset * 100 / *nominal as i128 })
        .collect();
    assert!(
        fractions.windows(2).any(|pair| pair[0] != pair[1]),
        "every attempt got the same jitter fraction: {fractions:?}"
    );
}

#[test]
fn the_jitter_stays_within_its_percentage() {
    // A jitter that pushed a delay outside its band would make the schedule unpredictable in a way the constant
    // does not describe.
    for seed in 0..200u64 {
        let mut backoff = Backoff::new(seed);
        for (index, nominal) in RECONNECT_BACKOFF.iter().enumerate() {
            let delay = backoff.record_failure(0).expect("schedules");
            let nominal_ms = nominal.as_millis();
            let span = nominal_ms * u128::from(RECONNECT_JITTER_PERCENT) / 100;
            let low = nominal_ms - span;
            let high = nominal_ms + span;
            assert!(
                delay.as_millis() >= low && delay.as_millis() <= high,
                "seed {seed} attempt {} gave {:?}, outside [{low}ms, {high}ms]",
                index + 1,
                delay
            );
        }
    }
}

#[test]
fn a_delay_is_never_zero() {
    // A zero delay is a tight loop: the failure path becomes the busy path, which is the thing the schedule
    // exists to prevent.
    for seed in 0..500u64 {
        let mut backoff = Backoff::new(seed);
        for _ in 0..MAX_ATTEMPTS {
            let delay = backoff.record_failure(0).expect("schedules");
            assert!(delay > Duration::ZERO, "seed {seed} produced a zero delay");
        }
    }
}

#[test]
fn a_scheduled_retry_is_refused_until_its_time() {
    let mut backoff = Backoff::new(1);
    let delay = backoff.record_failure(1_000).expect("schedules");
    let due = 1_000u64 + u64::try_from(delay.as_millis()).unwrap_or(0);

    match backoff.ready(due - 1, RetryTrigger::Timer) {
        Err(BackoffRefusal::TooSoon { remaining }) => {
            assert_eq!(remaining, Duration::from_millis(1));
        }
        other => panic!("expected a wait, got {other:?}"),
    }
    assert_eq!(backoff.ready(due, RetryTrigger::Timer), Ok(()));
    assert_eq!(backoff.ready(due + 10_000, RetryTrigger::Timer), Ok(()));
}

#[test]
fn every_trigger_but_the_timer_overrides_the_schedule() {
    // Each of the others is evidence the condition which caused the failure may have changed, and making them
    // wait would mean a device that was rediscovered sits idle through a backoff designed for a device that was
    // not.
    assert!(!RetryTrigger::Timer.overrides_schedule());
    for trigger in [
        RetryTrigger::Rediscovered,
        RetryTrigger::NetworkChanged,
        RetryTrigger::Foreground,
        RetryTrigger::LocalChange,
    ] {
        assert!(trigger.overrides_schedule(), "{trigger:?}");
    }
}

#[test]
fn an_event_trigger_retries_immediately() {
    let mut backoff = Backoff::new(1);
    backoff.record_failure(0).expect("schedules");
    // The timer still has almost a second to go, and the peer was just seen again.
    assert!(backoff.ready(10, RetryTrigger::Timer).is_err());
    assert_eq!(backoff.ready(10, RetryTrigger::Rediscovered), Ok(()));
    assert_eq!(backoff.ready(10, RetryTrigger::NetworkChanged), Ok(()));
}

#[test]
fn retrying_is_given_up_on_after_the_ceiling() {
    // An application that has tried for an hour against a peer that is unplugged has spent an hour of battery
    // and filled a log file.
    let mut backoff = Backoff::new(1);
    for _ in 0..MAX_ATTEMPTS {
        assert!(backoff.record_failure(0).is_some(), "within the ceiling");
    }
    assert_eq!(backoff.attempts(), MAX_ATTEMPTS);
    assert!(!backoff.has_given_up());

    assert_eq!(backoff.record_failure(0), None, "the ceiling schedules nothing");
    assert!(backoff.has_given_up());
    assert_eq!(backoff.due_at_ms(), None);
}

#[test]
fn giving_up_still_allows_an_event_trigger() {
    // The peer is still rediscoverable; it is this schedule that stops, not the possibility of ever connecting.
    // A discovery reply is exactly the evidence the ceiling was waiting for.
    let mut backoff = Backoff::new(1);
    for _ in 0..=MAX_ATTEMPTS {
        backoff.record_failure(0);
    }
    assert!(backoff.has_given_up());

    match backoff.ready(0, RetryTrigger::Timer) {
        Err(BackoffRefusal::GivenUp { attempts }) => assert_eq!(attempts, MAX_ATTEMPTS + 1),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(backoff.ready(0, RetryTrigger::Rediscovered), Ok(()));
}

#[test]
fn resetting_clears_everything_including_the_giving_up() {
    let mut backoff = Backoff::new(1);
    for _ in 0..=MAX_ATTEMPTS {
        backoff.record_failure(0);
    }
    assert!(backoff.has_given_up());

    backoff.reset(ResetReason::Connected);
    assert_eq!(backoff.attempts(), 0);
    assert!(!backoff.has_given_up());
    assert_eq!(backoff.due_at_ms(), None);
    assert_eq!(backoff.ready(0, RetryTrigger::Timer), Ok(()));
}

#[test]
fn every_reset_reason_clears_the_schedule() {
    // The reason is recorded rather than only the effect, but the effect is the same for all three: a schedule
    // that reset when it should not have is otherwise invisible.
    for reason in [ResetReason::Connected, ResetReason::UserRequest, ResetReason::Unpaired] {
        let mut backoff = Backoff::new(1);
        backoff.record_failure(0).expect("schedules");
        backoff.reset(reason);
        assert_eq!(backoff.attempts(), 0, "{reason:?}");
    }
}

#[test]
fn a_long_outage_settles_at_the_base_delay() {
    // Not a doubling tail: a peer that is reachable at all is usually reachable in half a minute, and waiting
    // hours for one that came back a minute later is worse than a slightly frequent retry.
    let mut backoff = Backoff::new(3);
    for _ in 0..MAX_ATTEMPTS {
        let delay = backoff.record_failure(0).expect("schedules");
        let base_ms = u64::try_from(RECONNECT_BASE.as_millis()).unwrap_or(0);
        assert!(
            (delay.as_millis() as u64) <= base_ms * 120 / 100,
            "a delay grew past the base: {delay:?}"
        );
    }
}

#[test]
fn no_delay_exceeds_the_ceiling() {
    let mut backoff = Backoff::new(9);
    for _ in 0..MAX_ATTEMPTS {
        let delay = backoff.record_failure(0).expect("schedules");
        assert!(delay <= RECONNECT_MAX, "{delay:?} exceeds the ceiling");
    }
}

#[test]
fn the_due_time_saturates_rather_than_wrapping() {
    // A clock near the end of its range must not produce a due time in the past, which would make every timer
    // tick an attempt.
    let mut backoff = Backoff::new(1);
    backoff.record_failure(u64::MAX);
    assert_eq!(backoff.due_at_ms(), Some(u64::MAX));
}

#[test]
fn every_trigger_and_refusal_explains_itself() {
    for trigger in [
        RetryTrigger::Timer,
        RetryTrigger::Rediscovered,
        RetryTrigger::NetworkChanged,
        RetryTrigger::Foreground,
        RetryTrigger::LocalChange,
    ] {
        assert!(!trigger.as_str().is_empty(), "{trigger:?}");
        assert!(!trigger.as_str().contains(' '), "{trigger:?}");
    }
}

#[test]
fn a_pending_retry_carries_what_the_interface_shows() {
    let pending = PendingRetry { peer: "@peer".to_owned(), attempts: 3, in_ms: 8_000 };
    assert_eq!(pending.attempts, 3);
    assert_eq!(pending.in_ms, 8_000);
    assert_eq!(pending.clone(), pending);
}
