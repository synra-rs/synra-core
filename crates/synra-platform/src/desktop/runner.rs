//! Bounded synchronous command requests and shared admission, including unfinished IO cleanup.

use std::process::Child;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::CommandRunner;
use crate::{MAX_CLIPBOARD_BYTES, PlatformError};

mod process;
mod streams;
#[cfg(all(
    test,
    any(
        target_os = "windows",
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )
))]
mod tests;

#[cfg(all(test, any(target_os = "android", target_os = "ios")))]
#[test]
fn mobile_targets_refuse_desktop_command_execution() {
    let runner = SystemRunner::default();
    assert!(!runner.is_available());
    assert!(matches!(
        runner.run("not-a-command", &[], None),
        Err(PlatformError::Unsupported(_))
    ));
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_TIMEOUT: Duration = Duration::from_millis(500);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_COMMANDS: usize = 8;
const MAX_OUTPUT: usize = 2 * 1024 * 1024;
const MAX_ERROR_OUTPUT: usize = 16 * 1024;
const MAX_ARGUMENTS: usize = 32;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

/// A synchronous process runner with bounded launch, IO, execution and cleanup waits.
///
/// All default instances share eight job slots. A slot remains occupied until the direct child
/// and every pipe worker have finished, even after the caller's deadline. Inherited pipes cannot
/// cause unbounded detached threads: later requests fail closed when those slots are occupied.
/// No runtime is required, including when called from a host's async runtime.
/// Default budgets are five seconds plus 500 ms cleanup, 256 KiB UTF-8 input, 2 MiB stdout,
/// 16 KiB stderr and 32 arguments totalling 64 KiB. Process arguments never include stdin data.
/// Mobile targets report unsupported until the host supplies a native platform implementation.
#[derive(Debug, Clone)]
pub struct SystemRunner {
    timeout: Duration,
    gate: Arc<Gate>,
}

impl Default for SystemRunner {
    fn default() -> Self {
        static GATE: OnceLock<Arc<Gate>> = OnceLock::new();
        Self {
            timeout: DEFAULT_TIMEOUT,
            gate: Arc::clone(GATE.get_or_init(|| Arc::new(Gate::new(MAX_COMMANDS)))),
        }
    }
}

impl SystemRunner {
    /// Shorten the five-second command budget; cleanup has a separate 500 ms allowance.
    /// A zero budget refuses before launching anything. Longer budgets are clamped to five seconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.min(DEFAULT_TIMEOUT);
        self
    }

    /// Jobs still owning a process or pipe worker, including unfinished timed-out jobs.
    #[must_use]
    pub fn active_commands(&self) -> usize {
        self.gate.reap();
        self.gate.active.load(Ordering::Acquire)
    }

    /// Timed-out or failed jobs whose process or pipe cleanup has not finished.
    #[must_use]
    pub fn pending_cleanup(&self) -> usize {
        self.gate.reap();
        self.gate.retired.load(Ordering::Acquire)
    }
}

impl CommandRunner for SystemRunner {
    fn is_available(&self) -> bool {
        cfg!(any(
            target_os = "windows",
            target_os = "macos",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))
    }
    fn run(
        &self,
        program: &str,
        arguments: &[&str],
        input: Option<&str>,
    ) -> Result<String, PlatformError> {
        validate(program, arguments, input)?;
        if !self.is_available() {
            return Err(PlatformError::Unsupported(
                "execute desktop commands on this host",
            ));
        }
        if self.timeout.is_zero() {
            return Err(timed_out(program, self.timeout, false));
        }
        let lease = self.gate.acquire()?;
        let request = Request {
            program: program.to_owned(),
            arguments: arguments.iter().map(|arg| (*arg).to_owned()).collect(),
            input: input.map(str::to_owned),
            timeout: self.timeout,
            deadline: Instant::now() + self.timeout,
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker_lease = Arc::clone(&lease);
        let worker = std::thread::Builder::new()
            .name("synra-command".to_owned())
            .spawn(move || {
                let result = process::run(request, &worker_lease);
                drop(worker_lease);
                let _ = sender.send(result);
            })
            .map_err(|error| {
                failed(
                    program,
                    &format!("could not start command worker ({:?})", error.kind()),
                )
            })?;
        // Waiting for a thread blocked inside an OS call would defeat the deadline. Its shared lease
        // retains admission until it finishes; normal completed workers are joined below.
        let result = match receiver.recv_timeout(self.timeout + CLEANUP_TIMEOUT) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                lease.cancelled.store(true, Ordering::Release);
                lease.retire();
                Err(timed_out(program, self.timeout, true))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(failed(program, "command worker ended without a result"))
            }
        };
        if worker.is_finished() {
            let _ = worker.join();
        }
        result
    }
}

fn validate(program: &str, arguments: &[&str], input: Option<&str>) -> Result<(), PlatformError> {
    for (field, len, max) in [
        ("command program in UTF-8 bytes", program.len(), 4096),
        ("command argument count", arguments.len(), MAX_ARGUMENTS),
        (
            "command input in UTF-8 bytes",
            input.map_or(0, str::len),
            MAX_CLIPBOARD_BYTES,
        ),
    ] {
        if len > max {
            return Err(PlatformError::TooLong { field, len, max });
        }
    }
    let mut bytes = 0usize;
    for argument in arguments {
        bytes = bytes.saturating_add(argument.len());
        if bytes > MAX_ARGUMENT_BYTES {
            return Err(PlatformError::TooLong {
                field: "command arguments in UTF-8 bytes",
                len: bytes,
                max: MAX_ARGUMENT_BYTES,
            });
        }
    }
    Ok(())
}

struct Gate {
    active: AtomicUsize,
    retired: AtomicUsize,
    limit: usize,
    unreaped: Mutex<Vec<(Child, Arc<Lease>)>>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let unreaped = self.unreaped.lock().len();
        formatter
            .debug_struct("CommandGate")
            .field("active", &self.active.load(Ordering::Acquire))
            .field("retired", &self.retired.load(Ordering::Acquire))
            .field("limit", &self.limit)
            .field("unreaped", &unreaped)
            .finish()
    }
}

impl Gate {
    const fn new(limit: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            retired: AtomicUsize::new(0),
            limit,
            unreaped: Mutex::new(Vec::new()),
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<Arc<Lease>, PlatformError> {
        self.reap();
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.limit {
                return Err(PlatformError::RunnerBusy { limit: self.limit });
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => active = current,
            }
        }
        Ok(Arc::new(Lease {
            gate: Arc::clone(self),
            cancelled: AtomicBool::new(false),
            retired: AtomicBool::new(false),
        }))
    }

    fn retain(&self, child: Child, lease: &Arc<Lease>) {
        lease.retire();
        self.unreaped.lock().push((child, Arc::clone(lease)));
    }

    fn reap(&self) {
        // Never hold the admission lock during an OS call or while dropping a job lease.
        let children = std::mem::take(&mut *self.unreaped.lock());
        let pending: Vec<_> = children
            .into_iter()
            .filter_map(|(mut child, lease)| {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    None
                } else {
                    Some((child, lease))
                }
            })
            .collect();
        if !pending.is_empty() {
            self.unreaped.lock().extend(pending);
        }
    }
}

#[derive(Debug)]
struct Lease {
    gate: Arc<Gate>,
    cancelled: AtomicBool,
    retired: AtomicBool,
}

impl Lease {
    fn retire(&self) {
        if !self.retired.swap(true, Ordering::AcqRel) {
            self.gate.retired.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.retired.load(Ordering::Acquire) {
            self.gate.retired.fetch_sub(1, Ordering::AcqRel);
        }
        self.gate.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Request {
    program: String,
    arguments: Vec<String>,
    input: Option<String>,
    timeout: Duration,
    deadline: Instant,
}

fn failed(program: &str, reason: &str) -> PlatformError {
    PlatformError::RunnerFailed {
        program: program.to_owned(),
        reason: reason.to_owned(),
    }
}

fn timed_out(program: &str, timeout: Duration, cleanup_pending: bool) -> PlatformError {
    PlatformError::RunnerTimedOut {
        program: program.to_owned(),
        timeout_ms: timeout.as_millis().try_into().unwrap_or(u64::MAX),
        cleanup_pending,
    }
}
