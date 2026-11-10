//! The paired-kernel harness's tests.

use super::*;
use bytes::Bytes;
use synra_protocol::frame::Frame;

use core::time::Duration;

use crate::clock::MockClock;
use crate::transport::{Fault, MemoryTransportLink};

use synra_protocol::frame::{FrameBody, FrameKind};
use crate::transport::TransportError;
use crate::clock::Clock;

/// A kernel for the fixture, which is just a name — the pair's job is the connection, not the kernel's logic.
///
/// The name is read by one test, which asserts that both kernels came from the closure. Without a reader the
/// field would be a reminder that the fixture does not care what a kernel is.
#[derive(Debug)]
struct FakeKernel {
    name: &'static str,
}

impl FakeKernel {
    /// What this kernel was named.
    fn name(&self) -> &'static str {
        self.name
    }
}

fn pair() -> KernelPair<FakeKernel> {
    KernelPair::with_clock(|_clock, _link| {
        (FakeKernel { name: "near" }, FakeKernel { name: "far" })
    })
}

/// An envelope frame carrying an event.
///
/// Built directly rather than through a constructor, because the frame layer deliberately leaves the body
/// unparsed: its job is boundaries, and a fixture that parsed would be testing something the protocol does not do.
fn envelope(event: &str) -> Frame {
    Frame {
        kind: FrameKind::Envelope,
        flags: 0,
        body: FrameBody::Envelope(Bytes::from(format!(r#"{{"event":"{event}"}}"#))),
    }
}

mod connection;
mod expectations;
mod records;
