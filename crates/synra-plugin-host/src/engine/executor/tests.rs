use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use super::{Epoch, ExecutorRefusal, WasmExecutor, next_tick};

#[test]
fn a_job_runs_on_another_thread_and_answers() {
    let executor = WasmExecutor::start(2, 4).expect("a pool");
    let caller = thread::current().id();
    let (answer, thread) = executor
        .run(move || (7_u32 * 6, thread::current().id()))
        .expect("a thread");
    assert_eq!(answer, 42);
    assert_ne!(thread, caller, "the job must not have run on the caller's thread");
}

#[test]
fn the_epoch_advances_which_is_what_arms_a_deadline() {
    let executor = WasmExecutor::start(1, 1).expect("a pool");
    let before = executor.epoch().now();
    let tick = next_tick(executor.epoch())
        .recv_timeout(Duration::from_secs(2))
        .expect("the ticker advances");
    assert!(tick > before);
    assert!(executor.enforces_timeouts());
}

#[test]
fn an_observer_moves_when_the_epoch_does() {
    // ★ The primitive the engine join is built on. Before `observe` existed, `Epoch` was a counter that only this
    // crate could see — wasmtime measures its own, and no call ever moved it.
    let epoch = Epoch::new();
    let seen = Arc::new(AtomicU64::new(0));
    {
        let seen = Arc::clone(&seen);
        epoch.observe(move |tick| {
            seen.store(tick, Ordering::Release);
        });
    }

    assert_eq!(epoch.advance(), 1);
    assert_eq!(seen.load(Ordering::Acquire), 1, "the observer did not see the advance");
    assert_eq!(epoch.advance(), 2);
    assert_eq!(seen.load(Ordering::Acquire), 2);
}

#[test]
fn every_observer_is_called_and_none_needs_the_lock_to_be_free() {
    // Two properties in one, because they are the same bug seen twice: an observer list where only the first entry
    // runs, and one where an observer that touches the epoch deadlocks the ticker thread.
    let epoch = Epoch::new();
    let first = Arc::new(AtomicU64::new(0));
    let second = Arc::new(AtomicU64::new(0));
    {
        let first = Arc::clone(&first);
        epoch.observe(move |tick| {
            first.store(tick, Ordering::Release);
        });
    }
    {
        // ★ This one reads the epoch it is observing. With the lock held across the notification this would hang
        // forever, on the thread that advances every timeout in the process — a deadlock that only appears once
        // something registers a second observer.
        let second = Arc::clone(&second);
        let inner = epoch.clone();
        epoch.observe(move |tick| {
            // `inner` rather than `epoch`: registering borrows the epoch, so the closure cannot also capture it.
            second.store(tick + inner.now(), Ordering::Release);
        });
    }

    epoch.advance();

    assert_eq!(first.load(Ordering::Acquire), 1, "the first observer did not run");
    // 1 (the tick) + 1 (the epoch's own value, read from inside the observer).
    assert_eq!(second.load(Ordering::Acquire), 2, "the second observer did not run");
}

#[test]
fn a_deadline_lands_after_the_budget_and_never_at_once() {
    let epoch = Epoch::new();
    // A budget shorter than one tick still gets one tick: the alternative is a deadline of "now", which every call
    // fails against — the intermittent timeout that only shows up under load.
    assert_eq!(epoch.deadline_in(Duration::from_millis(1)), 1);
    assert_eq!(epoch.deadline_in(Duration::from_millis(10)), 1);
    // Rounded up, so a call given 11ms gets two ticks rather than 10ms.
    assert_eq!(epoch.deadline_in(Duration::from_millis(11)), 2);
    assert_eq!(epoch.deadline_in(Duration::from_millis(25)), 3);
}

#[test]
fn stopping_the_ticker_is_visible() {
    let executor = WasmExecutor::start(1, 1).expect("a pool");
    assert!(executor.enforces_timeouts());
    executor.stop_ticker();
    // ★ The host asks this before running untrusted code. A value that stayed true after the ticker stopped would
    // make every timeout a budget with nothing behind it.
    assert!(!executor.enforces_timeouts());
    // And the pool is still usable, because a stopped ticker is a degraded executor rather than a dead one.
    assert_eq!(executor.run(|| 1_u8).expect("a thread"), 1);
}

#[test]
fn the_pool_runs_more_than_one_job_at_a_time() {
    let executor = Arc::new(WasmExecutor::start(4, 8).expect("a pool"));
    let concurrent = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let executor = Arc::clone(&executor);
        let concurrent = Arc::clone(&concurrent);
        let peak = Arc::clone(&peak);
        handles.push(thread::spawn(move || {
            let _ = executor.run(move || {
                let live = concurrent.fetch_add(1, Ordering::AcqRel) + 1;
                peak.fetch_max(live, Ordering::AcqRel);
                thread::sleep(Duration::from_millis(30));
                concurrent.fetch_sub(1, Ordering::AcqRel);
            });
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    // One thread would give a peak of 1 and still pass every other test here, so the concurrency is the assertion.
    assert!(peak.load(Ordering::Acquire) > 1, "the pool ran jobs one at a time");
}

#[test]
fn a_saturated_pool_refuses_rather_than_queueing_for_ever() {
    // One thread, one queued job: the third call has nowhere to go, and the answer is a refusal the caller can
    // report rather than a wait with no bound.
    let executor = Arc::new(WasmExecutor::start(1, 1).expect("a pool"));
    let (release, hold) = std::sync::mpsc::channel::<()>();
    let busy = {
        let executor = Arc::clone(&executor);
        thread::spawn(move || {
            let _ = executor.run(move || {
                let _ = hold.recv();
            });
        })
    };
    // Long enough for the first job to take the only thread.
    thread::sleep(Duration::from_millis(50));
    // The second fills the queue.
    let queued = {
        let executor = Arc::clone(&executor);
        thread::spawn(move || executor.run(|| ()))
    };
    thread::sleep(Duration::from_millis(50));
    // The third is refused.
    let refused = executor.run(|| ());
    assert!(
        matches!(refused, Err(ExecutorRefusal::Saturated { threads: 1, .. })),
        "{refused:?}"
    );

    drop(release);
    let _ = busy.join();
    let _ = queued.join();
}

#[test]
fn dropping_the_executor_lets_running_jobs_finish() {
    // A pool that killed its threads would leave a plugin's activation half-written, and the next start would read
    // whatever it found.
    let finished = Arc::new(AtomicBool::new(false));
    {
        let executor = WasmExecutor::start(2, 2).expect("a pool");
        let flag = Arc::clone(&finished);
        let _ = executor.run(move || {
            thread::sleep(Duration::from_millis(30));
            flag.store(true, Ordering::Release);
        });
    }
    assert!(finished.load(Ordering::Acquire), "the job did not run to completion");
}
