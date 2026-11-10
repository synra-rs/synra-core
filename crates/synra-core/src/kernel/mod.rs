//! The kernel: one value that owns everything, built in one order, and the events an interface reads it through.
//!
//! # Why the order is the point
//!
//! Every step of [`Kernel::bootstrap`] depends on the ones before it, and the dependency is not a preference:
//!
//! * the store has to exist before an identity can be read or created, because the identity *is* a row;
//! * the identity has to exist before the host is built, because a host that announces itself needs to know what to
//!   announce;
//! * the grants have to be loaded before a plugin is started, because a plugin that ran first and asked later would
//!   have taken its first action without permission;
//! * and a failure has to be reported through the layer that already works, which is why tracing comes first.
//!
//! A caller that assembled these itself would eventually assemble them in a different order, and the symptom of an
//! out-of-order start is not a crash — it is a device with two identities, or a plugin running ungranted.
//!
//! # Why this is synchronous
//!
//! The design document's signatures are `async`, and the reason they are is that they were written for a runtime that
//! owns every task. This kernel does not: [`crate::Supervisor`] runs its tasks on threads of their own, the plugin
//! executor has its own threads, and the store is blocking by nature — so there is nothing here to await, and an
//! `async fn` that never awaits would make every caller's signature `async` for nothing. The caller with a runtime
//! owns the loop; this owns the decisions.
//!
//! # What an interface reads
//!
//! Two things, and the design document is emphatic about why they must agree:
//!

mod bootstrap;
mod model;
mod runtime;
mod snapshot;

use std::sync::Arc;

use parking_lot::Mutex;
use synra_observe::audit::AuditRing;
use synra_observe::crash::StartupVerdict;
use synra_store::sqlite::SynraDb;

use crate::bus::{Delivery, EventBus, SubscriberId};
use crate::config::Config;
use crate::host::Host;
use crate::identity::Identity;
use crate::supervisor::{Supervisor, TaskSpec};
use synra_protocol::ids::DeviceId;

pub use model::{KernelConfig, KernelError, KernelEvent, NodeRole};
pub use snapshot::KernelSnapshot;

/// The kernel.
///
/// Everything a running kernel owns, behind one value: the store, this device's identity, the settings, the discovery
/// table and the open links, the event bus an interface reads, and the supervisor that watches the long-running tasks.
///
/// # Why the store is behind a lock and the rest is not
///
/// Because `rusqlite`'s connection is not `Sync` — one connection, one thread at a time — and every decision built on
/// top of it is made under that lock, which is what makes "the identity and the row it came from cannot disagree" a
/// property rather than a hope. The host has its own lock for the same reason.
pub struct Kernel {
    store: Mutex<SynraDb>,
    identity: Identity,
    config: Config,
    host: Mutex<Host>,
    events: EventBus<KernelEvent>,
    supervisor: Arc<Supervisor>,
    role: NodeRole,
    started: std::sync::atomic::AtomicBool,
    audit: Mutex<AuditRing>,
    /// What the last run left behind, read before anything else happened.
    verdict: StartupVerdict,
    created_at_ms: i64,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Kernel")
            .field("device_id", &self.identity.device_id)
            .field("role", &self.role)
            .field("started", &self.is_started())
            .field("subscribers", &self.events.subscriber_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
