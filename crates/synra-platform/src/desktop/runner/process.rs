//! A request coordinator owns the direct child, its deadline and bounded cleanup.

use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, atomic::Ordering, mpsc};
use std::thread::JoinHandle;
use std::time::Instant;

use super::{CLEANUP_TIMEOUT, Lease, POLL_INTERVAL, Request, failed, streams, timed_out};
use crate::PlatformError;

pub(super) fn run(mut request: Request, lease: &Arc<Lease>) -> Result<String, PlatformError> {
    if Instant::now() >= request.deadline || lease.cancelled.load(Ordering::Acquire) {
        return Err(timed_out(&request.program, request.timeout, false));
    }
    let mut command = Command::new(&request.program);
    command
        .args(&request.arguments)
        .stdin(if request.input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        // CREATE_NO_WINDOW: desktop actions never need a visible helper console.
        command.creation_flags(0x0800_0000);
    }
    let child = command.spawn().map_err(|error| {
        failed(
            &request.program,
            &format!("could not launch process ({:?})", error.kind()),
        )
    })?;
    let mut child = OwnedChild {
        child: Some(child),
        reaped: false,
        lease: Arc::clone(lease),
    };
    let mut workers = Vec::with_capacity(3);
    let (sender, receiver) = mpsc::sync_channel(3);
    let has_input = request.input.is_some();
    let result = child
        .get()
        .and_then(|child| {
            streams::start(
                child,
                request.input.take(),
                &sender,
                lease,
                &mut workers,
                &request.program,
            )
        })
        .and_then(|()| {
            drop(sender);
            collect(&mut child, &request, lease, has_input, &receiver)
        });
    let until = Instant::now() + CLEANUP_TIMEOUT;
    let reaped = child.finish(until);
    let drained = join_finished(&mut workers, until);
    if !reaped || !drained {
        lease.retire();
    }
    if !reaped {
        return Err(PlatformError::RunnerCleanupFailed {
            program: request.program,
        });
    }
    match result {
        Err(PlatformError::RunnerTimedOut { .. }) => {
            Err(timed_out(&request.program, request.timeout, !drained))
        }
        other => other,
    }
}

fn collect(
    child: &mut OwnedChild,
    request: &Request,
    lease: &Lease,
    has_input: bool,
    receiver: &mpsc::Receiver<streams::Message>,
) -> Result<String, PlatformError> {
    let mut output = None;
    let mut error_done = false;
    let mut input_done = !has_input;
    let mut status = None;
    loop {
        if Instant::now() >= request.deadline || lease.cancelled.load(Ordering::Acquire) {
            return Err(timed_out(&request.program, request.timeout, false));
        }
        if status.is_none() {
            status = child.poll(&request.program)?;
        }
        if let Some(status) = status {
            if !status.success() {
                return Err(failed(
                    &request.program,
                    &format!("process exited with {status}"),
                ));
            }
            if error_done
                && input_done
                && let Some(output) = output.take()
            {
                return String::from_utf8(output)
                    .map_err(|_| failed(&request.program, "stdout is not valid UTF-8"));
            }
        }
        let wait = request
            .deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_INTERVAL);
        match receiver.recv_timeout(wait) {
            Ok(message) => {
                let bytes = message
                    .result
                    .map_err(|error| streams::refusal(&request.program, message.stream, error))?;
                match message.stream {
                    streams::Stream::Input => input_done = true,
                    streams::Stream::Output => output = Some(bytes),
                    streams::Stream::Error => error_done = true,
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected)
                if output.is_some() && error_done && input_done =>
            {
                std::thread::sleep(wait)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(failed(
                    &request.program,
                    "pipe worker ended without a result",
                ));
            }
        }
    }
}

fn join_finished(workers: &mut Vec<JoinHandle<()>>, until: Instant) -> bool {
    loop {
        let mut index = 0;
        while index < workers.len() {
            if workers.get(index).is_some_and(JoinHandle::is_finished) {
                let _ = workers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        if workers.is_empty() {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

struct OwnedChild {
    child: Option<Child>,
    reaped: bool,
    lease: Arc<Lease>,
}

impl OwnedChild {
    fn get(&mut self) -> Result<&mut Child, PlatformError> {
        self.child
            .as_mut()
            .ok_or_else(|| failed("command", "owned child is missing"))
    }

    fn poll(&mut self, program: &str) -> Result<Option<ExitStatus>, PlatformError> {
        let status = self.get()?.try_wait().map_err(|error| {
            failed(
                program,
                &format!("could not poll process ({:?})", error.kind()),
            )
        })?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    fn finish(&mut self, until: Instant) -> bool {
        if self.reaped {
            return true;
        }
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        let _ = child.kill();
        loop {
            if matches!(child.try_wait(), Ok(Some(_))) {
                self.reaped = true;
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped
            && let Some(mut child) = self.child.take()
        {
            drop(child.stdin.take());
            drop(child.stdout.take());
            drop(child.stderr.take());
            let _ = child.kill();
            self.lease.gate.retain(child, &self.lease);
        }
    }
}
