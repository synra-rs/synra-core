//! A dial that is allowed to fail before it is allowed to give up.
//!
//! # Why this is shared
//!
//! Because two callers need the same decision and only the failure types differ: the listener delivering a late answer
//! dials the device that is already listening (and keeps its pointer), and the daemon dialling a peer for a send does the
//! same. Both were one attempt, and one attempt is wrong for the ordinary reason a dial fails — a listener that is still
//! closing the previous connection. A second implementation would be a second place to get the bound wrong.
//!
//! # What this is not
//!
//! A reconnect mechanism and not a queue: nothing survives the process, and a peer gone for longer than the pauses is
//! still unreachable. The counters that name this (`late_delivery_attempts_total`) are deliberately not called
//! `reconnect_attempts_total`.

/// How many times a dial is attempted before the failure is reported.
pub const ATTEMPTS: usize = 3;

/// Runs `attempt` up to `attempts` times, pausing between failures.
///
/// `pause` receives the zero-based index of the failure that just happened, so a caller can back off without this function
/// owning a clock. The last failure is the error returned: it is the one that describes the state after every retry.
///
/// # Errors
///
/// The error of the final attempt, unchanged. A caller that needs the earlier ones has the counters.
pub fn with_retries<T, E>(
    attempts: usize,
    mut attempt: impl FnMut(usize) -> Result<T, E>,
    mut pause: impl FnMut(usize),
) -> Result<T, E> {
    // At least one attempt, even for a caller that passed zero: "no attempt" has no error to return, and every call site
    // uses the shared bound anyway.
    let attempts = attempts.max(1);
    let mut last: Option<E> = None;
    for index in 0..attempts {
        match attempt(index) {
            Ok(value) => return Ok(value),
            Err(error) => {
                last = Some(error);
                if index + 1 < attempts {
                    pause(index);
                }
            }
        }
    }
    // The loop ran at least once, so `last` is `Some`; the fallback exists because the compiler cannot see that and the
    // workspace forbids `unwrap`.
    match last {
        Some(error) => Err(error),
        None => attempt(0),
    }
}

#[cfg(test)]
mod tests {
    use super::with_retries;

    #[test]
    fn a_dial_is_retried_before_it_gives_up() {
        // ★ The decision under test: a first failure is not a final one, and the number of attempts is bounded.
        let mut attempts = 0;
        let succeeded = with_retries(
            3,
            |_| {
                attempts += 1;
                if attempts < 3 {
                    Err("the listener was busy".to_owned())
                }
                else {
                    Ok(42)
                }
            },
            |_| {},
        );
        assert_eq!(succeeded, Ok(42));
        assert_eq!(attempts, 3, "the third attempt is the one that reached it");

        let mut attempts = 0;
        let failed = with_retries(
            3,
            |_| {
                attempts += 1;
                Err::<u8, _>("still gone".to_owned())
            },
            |_| {},
        );
        assert_eq!(failed, Err("still gone".to_owned()));
        assert_eq!(attempts, 3, "a permanent failure stops at the bound, not at one attempt");
    }

    #[test]
    fn a_first_success_is_not_retried() {
        let mut attempts = 0;
        let succeeded = with_retries(
            3,
            |_| {
                attempts += 1;
                Ok::<u8, String>(1)
            },
            |_| panic!("a pause must not follow a success"),
        );
        assert_eq!(succeeded, Ok(1));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn the_pauses_are_indexed_by_the_failure_that_just_happened() {
        // The caller backs off from the pause's argument, so it has to be the failure's index rather than the attempt's:
        // a first failure pauses 100 ms and a second 200, not the other way round.
        let mut pauses = Vec::new();
        let _ = with_retries(
            3,
            |_| Err::<(), _>("no".to_owned()),
            |index| pauses.push(index),
        );
        assert_eq!(pauses, vec![0, 1], "the last failure is not followed by a pause");
    }
}
