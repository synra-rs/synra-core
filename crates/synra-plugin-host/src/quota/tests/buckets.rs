use super::super::TokenBucket;

#[test]
fn a_new_bucket_is_full() {
    // A plugin that just started should not be throttled before it has done anything.
    let bucket = TokenBucket::new(100, 200, 0);
    assert_eq!(bucket.available(), 200);
    assert_eq!(bucket.capacity(), 200);
}

#[test]
fn taking_tokens_reduces_what_is_available() {
    let mut bucket = TokenBucket::new(100, 200, 0);
    assert_eq!(bucket.try_consume(50, 0), Ok(()));
    assert_eq!(bucket.available(), 150);
}

#[test]
fn a_bucket_refills_continuously_rather_than_in_ticks() {
    // A tick-based bucket gives a plugin nothing for the rest of the second after it exhausts one, which turns a
    // burst into a stall and makes the observed rate depend on where in the second the burst started.
    let mut bucket = TokenBucket::new(100, 1, 0);
    assert_eq!(bucket.try_consume(1, 0), Ok(()));
    assert_eq!(bucket.available(), 0);

    // Ten milliseconds later, one token's worth has accumulated.
    assert_eq!(bucket.try_consume(1, 10), Ok(()));
    // And again.
    assert_eq!(bucket.try_consume(1, 20), Ok(()));
}

#[test]
fn an_exhausted_bucket_says_how_long_to_wait() {
    let mut bucket = TokenBucket::new(10, 1, 0);
    assert_eq!(bucket.try_consume(1, 0), Ok(()));

    match bucket.try_consume(1, 0) {
        Err(refusal) => {
            // Ten per second means one token per 100 ms.
            assert_eq!(refusal.retry_after_ms, 100);
            assert_eq!(refusal.shortfall, TokenBucket::SCALE);
        }
        Ok(()) => panic!("the bucket should be empty"),
    }
}

#[test]
fn a_bucket_never_fills_past_its_capacity() {
    // A bucket that accumulated while a plugin was idle would let it release a whole minute's worth of events at
    // once, which is the burst the capacity exists to bound.
    let mut bucket = TokenBucket::new(100, 10, 0);
    let _ = bucket.try_consume(10, 0);
    assert_eq!(bucket.available(), 0);

    // An hour later it is still only as full as its capacity.
    bucket.try_consume(0, 3_600_000).expect("zero costs nothing");
    assert_eq!(bucket.available(), 10);
}

#[test]
fn a_clock_that_moves_backwards_does_not_remove_tokens() {
    // A bucket that lost tokens on a backwards reading would refuse a call it had already earned.
    let mut bucket = TokenBucket::new(100, 200, 1_000);
    assert_eq!(bucket.try_consume(100, 1_000), Ok(()));
    let after = bucket.available();

    // A refill at an earlier time adds nothing and takes nothing.
    assert_eq!(bucket.try_consume(0, 500), Ok(()));
    assert_eq!(bucket.available(), after);
}

#[test]
fn a_bucket_with_no_refill_waits_forever_rather_than_dividing_by_zero() {
    // A caller showing this says "not for a very long time" rather than hanging on an arithmetic error.
    let mut bucket = TokenBucket::new(0, 1, 0);
    assert_eq!(bucket.try_consume(1, 0), Ok(()));
    match bucket.try_consume(1, 0) {
        Err(refusal) => assert_eq!(refusal.retry_after_ms, u64::MAX),
        Ok(()) => panic!("the bucket should be empty"),
    }
}

#[test]
fn refilling_fully_resets_a_bucket() {
    let mut bucket = TokenBucket::new(10, 100, 0);
    assert_eq!(bucket.try_consume(100, 0), Ok(()));
    assert_eq!(bucket.available(), 0);

    bucket.refill_fully(500);
    assert_eq!(bucket.available(), 100);
}

#[test]
fn consuming_more_than_the_capacity_is_refused() {
    // A single call that asks for more tokens than the bucket can ever hold would otherwise be admitted once and
    // then wedge the bucket at zero forever.
    let mut bucket = TokenBucket::new(100, 10, 0);
    assert!(bucket.try_consume(11, 0).is_err());
    // The bucket is untouched.
    assert_eq!(bucket.available(), 10);
}
