# A 6-second transfer, and four rounds spent looking in the wrong place

This is a record of a real bug and of the *debugging* failure around it, because the second was more expensive
than the first. It is written to be read before the next investigation rather than after.

## What was wrong

A file transfer between two daemons took **exactly six seconds no matter how small the file was**, and a 5 MB
file hung until the sender's 300-second deadline.

The cause was one missing call:

```rust
// apps/synra-daemon/src/dispatch.rs — the branch that stores a block
Received::Block { index, duplicate } => {
    session::report_progress(link, receiving.receiver(), self.trace, now_ms)?;  // ← this was absent
    Ok(Decision::Stored { index, duplicate })
}
```

The sender writes a window of blocks and then **blocks on a read**, waiting for the receiver's progress report.
The receiver never sent one, so the wait ended only when the socket's own read timeout expired — `HELLO_TIMEOUT`,
six seconds. A small file needs one window, so it paid six seconds; a 5 MB file needs about five, and the
multiples ran past the sender's 300-second ceiling.

`report_progress` existed, was correct, and had tests. **It had no caller in production code.** The engine's
unit tests called it; the daemon — the only thing that runs a real transfer — did not.

## Why that took four rounds to find

### The timing was the answer, and it was on screen four times

6074 ms. 6114 ms. 6088 ms. 6103 ms.

Six seconds is not a round number that occurs in nature; it is `HELLO_TIMEOUT`, a constant written throughout
this workspace. A duration that does **not vary with the size of the input** cannot be data-dependent — it is a
timer, and the job is to find which one. That was visible from the first measurement and was read as "probably
startup overhead" four times.

**A fixed cost is a constant. Look it up.**

### "Fixed it twice, nothing changed" is a statement about reachability

Two successive changes to the sender's retransmission logic produced **no change in the six seconds at all**.
That was explained as "I changed the wrong thing". The better explanation, and the true one, is that **the code
being changed was not on the path that was running**. A change with zero effect on the symptom is evidence about
*reachability* before it is evidence about logic.

### One grep would have shown it

```
$ grep -rn "report_progress" crates apps
crates/synra-core/src/session.rs:450   pub fn report_progress(          ← definition
crates/synra-core/src/session.rs:1198  report_progress(&mut side_b, …    ← test
crates/synra-core/src/session.rs:1322  report_progress(&mut side_b, …    ← test
apps/synra-daemon/src/dispatch.rs:190  session::report_progress(link, …  ← added during this investigation
```

Before it was added, the production call sites numbered zero. **A function that only tests call looks exactly
like a function that works.**

## The observation channels were broken, and that is what made it a guessing game

Four separate instrumentation failures, in sequence:

| Failure | Consequence |
| --- | --- |
| The probe used `OpenOptions::new().append(true)`, which on Windows asks for a share mode that lets other processes **read** the file but not write it | Two daemons appending to one log had most of their lines silently dropped, so the receiver appeared to do nothing at all while it was in fact working |
| A PowerShell here-string replacement silently did not apply | A probe was never compiled in, while being believed to be running |
| A cleanup regex was too broad | The observation points were deleted along with the probe, and several rounds were spent reasoning half-blind |
| The daemon's `stderr` was not reaching the console or a redirected file | Two early rounds looked for logs in a channel that did not exist |

The measurement that finally located the bug — a timestamped line per read and per write, in one shared file —
took minutes to write and settled the question on the first run.

## Checklist for the next one

**Before changing anything**

1. **Quantify the symptom.** Constant, or proportional to the input? A constant points at a timer; a proportion
   points at work per unit.
2. **Prove the code runs.** Search for its call sites. Then put a line at the function's entry and watch it
   appear. "It is correct" and "it is called" are independent facts.
3. **Verify the observation channel first.** Write a line, read it back, see it — *then* start investigating.

**After changing something**

4. **The symptom must move.** If it does not move at all, go back to step 2 rather than changing a second thing.
5. **One hypothesis at a time.** Two edits at once means not knowing which one mattered.

**Mechanics that cost real time here**

- On Windows, a file appended to by two processes needs `read(true).write(true)` **and** `append(true)`.
  `append(true)` alone silently loses writes from the second writer.
- Rust sources are edited with the editor tool and every edit is confirmed with a search afterwards. Shell
  string replacement on multi-line Rust fails quietly, and a silent failure looks like success.

## Result, for the record

| Size | Before | After | Duplicate blocks |
| --- | --- | --- | --- |
| 2 KB | 6074 ms | **61 ms** | 0 |
| 300 KB | 6114 ms | **120 ms** | 0 |
| 5 MB | 300 s timeout | **1.19 s** | 0 |
| 19 MB | — | **4.50 s** | 0 |

Two further defects were found and fixed in the same pass, both visible only once the reports actually flowed:

- The receiver's report is a *snapshot* and names as "missing" every block still crossing the network.
  Rewriting those wasted the link — 54 duplicate blocks on a 5 MB transfer. Repair is now limited to blocks
  **below the receiver's watermark**, which is what an in-order reader has genuinely passed over.
- `mark_sent` was called after the write, leaving a window in which a block was on the wire and still counted
  as unsent. It is now called before.

## In one line

> The bug was a function nobody called. I did not find it by reading code, and I could not find it by reading
> code — only runtime evidence could show it, and my runtime evidence was broken for four rounds. **Fix the
> observation first, and check that the code under suspicion is reachable, before reasoning about what it does.**
