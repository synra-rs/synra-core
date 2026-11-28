use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::dispatch::orchestrate::Router;
use crate::host::Host;
use crate::inbound::OfferCallback;
use crate::pairing::Service;

use super::{CancelCallback, FinishedCallback, KernelEventCallback, ProgressCallback};

/// Resources shared by the message loop and handlers on an authenticated connection.
pub(super) struct TrafficContext<'a> {
    pub(super) host: &'a Arc<Mutex<Host>>,
    pub(super) data_dir: &'a Path,
    pub(super) router: &'a Router,
    pub(super) timeout: Duration,
    pub(super) desk: &'a Arc<Service>,
}

/// Host callbacks used while a connection is being served.
pub(super) struct TrafficCallbacks<'a> {
    pub(super) on_finished: &'a FinishedCallback,
    pub(super) on_progress: &'a Arc<ProgressCallback>,
    pub(super) offer: &'a Arc<OfferCallback>,
    pub(super) should_cancel: &'a Arc<CancelCallback>,
    pub(super) on_kernel_events: &'a Arc<KernelEventCallback>,
}
