//! Pipe workers each retain the command's shared admission lease until their OS IO finishes.

use std::io::{self, Read, Write};
use std::process::Child;
use std::sync::{Arc, mpsc::SyncSender};
use std::thread::JoinHandle;

use super::{Lease, MAX_ERROR_OUTPUT, MAX_OUTPUT, failed};
use crate::PlatformError;

#[derive(Debug, Clone, Copy)]
pub(super) enum Stream {
    Input,
    Output,
    Error,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Failure {
    Io(io::ErrorKind),
    Limit(usize),
}

pub(super) struct Message {
    pub stream: Stream,
    pub result: Result<Vec<u8>, Failure>,
}

pub(super) fn start(
    child: &mut Child,
    input: Option<String>,
    sender: &SyncSender<Message>,
    lease: &Arc<Lease>,
    workers: &mut Vec<JoinHandle<()>>,
    program: &str,
) -> Result<(), PlatformError> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| failed(program, "stdout pipe is missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| failed(program, "stderr pipe is missing"))?;
    spawn(workers, sender, lease, Stream::Output, program, move || {
        read(stdout, MAX_OUTPUT)
    })?;
    spawn(workers, sender, lease, Stream::Error, program, move || {
        read(stderr, MAX_ERROR_OUTPUT)
    })?;
    if let Some(input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| failed(program, "stdin pipe is missing"))?;
        spawn(workers, sender, lease, Stream::Input, program, move || {
            stdin
                .write_all(input.as_bytes())
                .map_err(|error| Failure::Io(error.kind()))?;
            drop(stdin);
            Ok(Vec::new())
        })?;
    }
    Ok(())
}

fn spawn(
    workers: &mut Vec<JoinHandle<()>>,
    sender: &SyncSender<Message>,
    lease: &Arc<Lease>,
    stream: Stream,
    program: &str,
    operation: impl FnOnce() -> Result<Vec<u8>, Failure> + Send + 'static,
) -> Result<(), PlatformError> {
    let sender = sender.clone();
    let lease = Arc::clone(lease);
    let worker = std::thread::Builder::new()
        .name(format!("synra-command-{stream:?}"))
        .spawn(move || {
            let _lease = lease;
            let result = operation();
            let _ = sender.send(Message { stream, result });
        })
        .map_err(|error| {
            failed(
                program,
                &format!("could not start pipe worker ({:?})", error.kind()),
            )
        })?;
    workers.push(worker);
    Ok(())
}

fn read(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::with_capacity(limit.min(4096));
    let mut buffer = [0u8; 4096];
    loop {
        let remaining = limit.saturating_sub(bytes.len());
        let count = remaining.saturating_add(1).min(buffer.len());
        let target = buffer
            .get_mut(..count)
            .ok_or(Failure::Io(io::ErrorKind::InvalidInput))?;
        let read = match reader.read(target) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Failure::Io(error.kind())),
        };
        if read == 0 {
            return Ok(bytes);
        }
        if read > remaining {
            return Err(Failure::Limit(limit));
        }
        bytes.extend_from_slice(
            buffer
                .get(..read)
                .ok_or(Failure::Io(io::ErrorKind::InvalidInput))?,
        );
    }
}

pub(super) fn refusal(program: &str, stream: Stream, failure: Failure) -> PlatformError {
    let name = match stream {
        Stream::Input => "stdin",
        Stream::Output => "stdout",
        Stream::Error => "stderr",
    };
    match failure {
        Failure::Limit(max) => PlatformError::RunnerOutputTooLong {
            program: program.to_owned(),
            stream: name,
            max,
        },
        Failure::Io(kind) => failed(program, &format!("{name} IO failed ({kind:?})")),
    }
}
