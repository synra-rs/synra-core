use super::*;

/// The control, and the half that matters: an ordinary compile error must **not** be read as this machine's fault.
///
/// Without this, a classifier that answered `Some` for everything would pass every other test here and quietly turn
/// every real failure into a `SKIP` — which is the one outcome this tool exists to prevent.
#[test]
fn a_real_error_is_not_environmental() {
    let stderr = b"error[E0308]: mismatched types\n  --> src/lib.rs:3:5\nerror: could not compile";
    assert_eq!(environmental(stderr), None);
}

#[test]
fn every_environmental_failure_is_recognised_and_named() {
    // Each pattern, so an arm that stops matching is a failing test rather than a row that silently starts failing
    // the build on a machine that was never going to pass it.
    let cases: [&[u8]; 6] = [
        b"error[E0463]: can't find crate for `core`",
        b"error[E0463]: can't find crate for `std`",
        b"error: failed to find tool: aarch64-linux-android-clang",
        b"error: linker `aarch64-linux-android-clang` not found",
        b"error: No space left on device (os error 112)",
        b"error: failed to write: StorageFull",
    ];

    for stderr in cases {
        let reason = environmental(stderr)
            .unwrap_or_else(|| panic!("{:?} should be environmental", String::from_utf8_lossy(stderr)));
        // And the remedy is stated rather than the row being skipped in silence.
        assert!(reason.len() > 20, "{reason}");
    }
}

#[test]
fn only_error_lines_are_reported_and_at_most_six() {
    let mut stderr = String::from("warning: unused variable\n");
    for number in 0..9 {
        stderr.push_str(&format!("error: number {number}   \n"));
    }
    stderr.push_str("note: something\n");

    let found = errors(stderr.as_bytes());
    assert_eq!(found.len(), 6, "{found:?}");
    assert!(found.iter().all(|line| line.starts_with("error")), "{found:?}");
    // Trailing whitespace is stripped, which is what makes the printed block line up.
    assert_eq!(found[0], "error: number 0");
}

#[test]
fn a_failure_with_no_error_lines_reports_nothing() {
    // A build that died to a signal prints no `error` line at all. Reporting an empty list is right; inventing a line
    // would be worse, because it would read as the compiler having said something.
    assert!(errors(b"").is_empty());
    assert!(errors(b"warning: nothing to do\n").is_empty());
}

#[test]
fn wrapping_never_splits_a_word_and_never_drops_one() {
    let reason = "a reason long enough to need more than one line, because a single two-hundred-character line is not read at all";
    let lines = wrap(reason);

    assert!(lines.len() > 1, "{lines:?}");
    for line in &lines {
        assert!(line.chars().count() <= 76, "{line:?} is too long");
    }
    // ★ Nothing is lost in the folding, which is the property a wrapping bug breaks quietly.
    let rejoined = lines.join(" ");
    assert_eq!(rejoined, reason);
}

#[test]
fn wrapping_a_long_word_keeps_it_rather_than_truncating_it() {
    // A 100-character token cannot be folded, and dropping or cutting it would hide part of a compiler's message.
    let long = "x".repeat(100);
    let lines = wrap(Box::leak(long.clone().into_boxed_str()));

    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0], long);
}

#[test]
fn an_empty_reason_still_produces_one_line() {
    // The fallback branch: a `SKIP` heading with nothing under it reads as a formatting bug rather than as silence.
    assert_eq!(wrap(""), vec![String::new()]);
}
