use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use synra_protocol::ids::DeviceId;

use crate::dispatch::orchestrate::Router;
use crate::host::Host;
use crate::inbound::Inbox;
use crate::link::PeerLink;
use crate::pairing::Service;
use crate::session::InboundProgress;

use super::messages;
use super::{
    CancelCallback, FinishedCallback, FinishedTransfer, KernelEventCallback, ProgressCallback,
    Served,
};

pub(super) fn run(
    host: &Arc<Mutex<Host>>,
    link: PeerLink,
    peer: DeviceId,
    peer_address: String,
    data_dir: &Path,
    router: &Arc<Router>,
    timeout: Duration,
    on_finished: &FinishedCallback,
    on_progress: &Arc<ProgressCallback>,
    offer: &Arc<crate::inbound::OfferCallback>,
    should_cancel: &Arc<CancelCallback>,
    on_kernel_events: &Arc<KernelEventCallback>,
    events: Vec<String>,
    finished: Vec<FinishedTransfer>,
    inbox: Inbox,
    last_progress: Option<InboundProgress>,
    desk: Arc<Service>,
) -> Served {
    messages::run_loop(
        host,
        link,
        peer,
        peer_address,
        data_dir,
        router,
        timeout,
        on_finished,
        on_progress,
        offer,
        should_cancel,
        on_kernel_events,
        events,
        finished,
        inbox,
        last_progress,
        desk,
    )
}
