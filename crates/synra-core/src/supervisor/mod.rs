//! Long-running work: what may run, what happens when it stops, and how the kernel shuts down.
//!
//! # Why a supervisor rather than `spawn`
//!
//! Because a task that stopped is the most expensive thing to *not* notice. A discovery listener that died silently
//! leaves a device that is on the network appearing absent; a heartbeat that died leaves links that look up and
//! time out one message at a time. Neither is a crash, and neither produces a log line unless something is watching
//! — which is what this is: a registry of what should be running, and a decision, made when something stops, about
//! whether it should be running again.
//!
//! # What is here, and what is deliberately not
//!
//! This is the **synchronous** half: the registry, the restart decision, cancellation, the shutdown order, and the
//! report a caller gets afterwards. It runs on a thread of its own, which is the model the plugin executor already
//! uses and the reason nothing here needs an asynchronous runtime.
//!
//! What is not here is the drive loop that would *run* asynchronous factories — `BoxFuture` and the joining of
//! several futures at shutdown need an executor, and the kernel's own runtime is not part of this crate. A caller
//! with one supplies the tasks through [`Supervisor::run_task`], which is the entry point that exists for it.
//!
//! # The rule that shapes the decision
//!
//! **A task that fails the same way for ever is a task that should stop.** An exponential-free, bounded schedule
//! plus a ceiling is what turns "the network is down" into a device that stops trying and says so, rather than one
//! that has spent an hour of battery by the time the user looks at it. And giving up is never permanent: a task may
//! be started again deliberately — by the user, by a plugin being enabled, by a network change — which is what
//! [`Supervisor::start`] does.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use parking_lot::Mutex;

mod cancellation;
pub use cancellation::Cancellation;

/// Restart policies and task criticality.
mod policy;
/// Task records and restart decisions.
mod records;
/// Task registry and shutdown coordination.
mod registry;
/// Shutdown results.
mod report;
/// Thread runner.
mod run;

pub use policy::*;
use records::decide_for;
pub use records::*;
pub use registry::Supervisor;
pub use report::ShutdownReport;
pub use run::run_task;

#[cfg(test)]
mod tests;
