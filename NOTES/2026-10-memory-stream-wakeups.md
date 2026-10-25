# A wakeup is not a read deadline

The pinned-toolchain workspace run exposed a cancellation test timing out while its peer waited for
the terminal abort. The development compiler reported the same version and compiler commit as the previous
global stable installation, so the failure was not evidence of a compiler regression.

Inspection found that MemoryStream waited once and returned WouldBlock whenever the queue was still
empty after that wait. A condition-variable notification can arrive without new data, including a
spurious wakeup; it does not prove that the timeout expired. Closure was also protected by a separate
mutex, allowing a close notification to race the reader entering its wait.

A controlled regression holds the predicate mutex while announcing readiness. The notifier acquires
that same mutex, proving the waiter has registered before sending a notification without data.
With the old single-wait behavior the test returned immediately and failed; with predicate-based
waiting it remains pending until the actual byte is written. Do not replace this ordering with a
sleep or move the readiness announcement outside the lock to satisfy a lint.

The pipe now keeps bytes and closure in one mutex and uses wait_while / wait_timeout_while.
The latter retains one overall timeout across wakeups. Closing either endpoint wakes its reader and
blocked writer; queued bytes still drain before EOF. Zero-length IO does not wait on an empty or full
pipe. Tests cover these behaviors through the memory stream as well as the controlled wait.

The readiness test has a function-scoped significant_drop_tightening exception because the guard
must span the announcement. A binding-scoped exception did not affect the lint emitted for the
closure; broadening it to a file would hide unrelated lock-scope mistakes.

Diagnosis order for another timeout:

1. Identify whether the wait actually expired, the stream closed, or only a notification arrived.
2. Check the predicate and closure are protected by the same mutex used by the condition variable.
3. Reproduce the ordering explicitly, before changing operation budgets or rerunning a large suite.
4. Recheck the complete business flow after fixing the primitive; a passing transport unit test alone
   does not prove cancellation or final confirmation works.

The local record and the remaining validation limits are in the design repository's
history/2026-10-26-toolchains.md.
