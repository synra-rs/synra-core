use super::{
    Absorbed, Arc, AtomicI64, DiscoveryService, DiscoveryTable, Host, Instant, Mutex, Ordering,
    POLL_INTERVAL,
};

/// Holds the service and runs it until asked to stop.
///
/// Stops when its supervisor cancellation token is set.
pub fn run(
    service: &Arc<Mutex<DiscoveryService>>,
    host: &Arc<Mutex<Host>>,
    on_demand: &Arc<AtomicI64>,
    cancel: &crate::supervisor::Cancellation,
    now_ms: impl Fn() -> i64 + Send + 'static,
) {
    run_recording(service, host, on_demand, cancel, now_ms, |_| {});
}

/// [`run`], which hands every candidate it has just heard to a callback.
///
/// # Why a callback rather than a database
///
/// Because this crate knows nothing about storage — that is the kernel's rule, and a worker that wrote rows would make
/// `cargo check` of this crate pull in a database for a loop that only ever listens on a socket. The caller owns the
/// write, and gets to decide what "remembered" means: the daemon writes to `devices_seen`, a test collects into a vector,
/// and neither makes the other possible.
///
/// # Why the callback is called with a slice and not per candidate
///
/// Because it is called on every tick and the candidate list is usually empty. A signature that took one candidate would
/// have to be called in a loop to decide there was nothing to say, and a caller that forgot the loop would simply never
/// be told anything.
pub fn run_recording(
    service: &Arc<Mutex<DiscoveryService>>,
    host: &Arc<Mutex<Host>>,
    on_demand: &Arc<AtomicI64>,
    cancel: &crate::supervisor::Cancellation,
    now_ms: impl Fn() -> i64 + Send + 'static,
    heard: impl Fn(&[crate::discovery::Candidate]) + Send + 'static,
) {
    let mut present = std::collections::BTreeSet::new();
    // ★ The loop stops now, and its own doc used to say it could not.
    //
    // It read: "there is no stop flag ... the thread's work is *inbound*, so ending it early would only be to save a thread
    // on a process that is exiting anyway". That was true of a worker nobody supervised. A worker run under
    // [`crate::supervisor::run_task`] is *given* a token and is required to honour it — a closure that ignores one leaves a
    // thread running after the supervisor has recorded the task as stopped, which is a report that lies.
    //
    // The check is at the top rather than after the sleep: a stop request that arrives while the loop is asleep is seen on
    // the next turn, and `POLL_INTERVAL` is the longest anything waits.
    while !cancel.is_cancelled() {
        let now = Instant::now();
        let wall = now_ms();

        // ★ The two locks are taken **one at a time, never nested**. The table is behind the host's lock and the sockets
        // are behind the service's, and holding both while sending would mean a device listing waits for a network. The
        // tick takes the host and releases it; the answering takes the service alone.
        let ticked = {
            let deadline = on_demand.load(Ordering::Relaxed);
            let mut service = service.lock();
            let mut host = host.lock();
            service.tick(&mut host, wall, now, deadline)
        };

        // ★ The callback runs with **no lock held**. It is a caller-supplied closure that will usually write to a
        // database, and nesting a third lock inside this loop — which the daemon's control socket also takes — is how a
        // worker ends up blocking a device listing behind a write.
        //
        let candidates = presence_changes(&host.lock(), &ticked.absorbed, wall, &mut present);
        if !candidates.is_empty() {
            heard(&candidates);
        }

        let service = service.lock();
        for (address, result) in service.answer_pending(&ticked) {
            if let Err(error) = result {
                // Reported rather than retried: the device that asked will ask again on its next broadcast, and a kernel
                // that stopped its loop for one failed send would stop discovering entirely.
                eprintln!("synra-daemon: could not answer {address}: {error}");
            }
        }
        drop(service);

        std::thread::sleep(POLL_INTERVAL);
    }
}

/// The candidates one tick just heard, for the callback that remembers them.
///
/// ★ **What this is not, and what it used to be.**
///
/// It was `host.usable(...)`, which is `current ∧ displayable` — and `displayable` starts at [`TrustLevel::Handshaked`], so
/// a caller's callback never saw a device that had merely **announced itself**. That is right for a screen, which shows
/// peers under their own heading, and wrong for this: [`Ticked::absorbed`] is "what did you hear", and the table both hosts
/// write from this callback (`devices_seen`) says in its own documentation that it holds *"a sighting of a device this
/// kernel has not paired with"*. Fed from `usable`, it stayed empty for exactly the devices it exists for — the reader
/// existed, the writer existed, and nothing it was ever told about was a sighting.
///
/// A caller that wants the connectable subset can filter this; a caller that was never told about a sighting cannot
/// un-forget it.
///
/// Repeated announcements refresh last-seen time; goodbyes publish the transition to offline.
pub(super) fn heard_now(host: &Host, absorbed: &[Absorbed]) -> Vec<crate::discovery::Candidate> {
    absorbed
        .iter()
        .filter_map(|event| match event {
            Absorbed::New { device_id }
            | Absorbed::Updated { device_id, .. }
            | Absorbed::Unchanged { device_id }
            | Absorbed::Offline { device_id } => host.discovery().get(*device_id).cloned(),
            _ => None,
        })
        .collect()
}

/// Whether the table would show a device, for a caller reporting a tick.
#[must_use]
pub fn is_visible(table: &DiscoveryTable, now_ms: i64) -> bool {
    table.displayable(now_ms).next().is_some()
}

/// Reports new sightings, refreshes, departures and one transition when a peer goes silent.
pub(super) fn presence_changes(
    host: &Host,
    absorbed: &[Absorbed],
    now_ms: i64,
    present: &mut std::collections::BTreeSet<synra_protocol::DeviceId>,
) -> Vec<crate::discovery::Candidate> {
    let current: std::collections::BTreeSet<_> = host
        .discovery()
        .iter()
        .filter(|candidate| host.recent_address(candidate.device_id, now_ms).is_some())
        .map(|candidate| candidate.device_id)
        .collect();
    let mut changed: std::collections::BTreeMap<_, _> = heard_now(host, absorbed)
        .into_iter()
        .map(|candidate| (candidate.device_id, candidate))
        .collect();
    for id in present.difference(&current) {
        if let Some(candidate) = host.discovery().get(*id) {
            changed.insert(*id, candidate.clone());
        }
    }
    *present = current;
    changed.into_values().collect()
}
