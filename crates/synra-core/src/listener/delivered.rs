use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use synra_protocol::ids::DeviceId;

use crate::dispatch::orchestrate::Router;
use crate::host::Host;
use crate::inbound::Decision;
use crate::link::PeerLink;
use crate::pairing::Service;

use super::{FinishedTransfer, KernelEventCallback, Served};
use super::{events, pairing};

pub(super) fn handle(
    decision: Decision,
    host: &Arc<Mutex<Host>>,
    link: &mut PeerLink,
    peer: DeviceId,
    data_dir: &Path,
    router: &Arc<Router>,
    timeout: Duration,
    on_kernel_events: &Arc<KernelEventCallback>,
    pairing_db: &Result<synra_store::SynraDb, synra_store::DbError>,
    desk: &Arc<Service>,
    events: &mut Vec<String>,
    finished: &mut Vec<FinishedTransfer>,
) -> Option<Served> {
    let Decision::Delivered {
        event,
        share,
        request,
    } = decision
    else {
        return None;
    };
    if let Some(envelope) = request.as_ref()
        && crate::input::serve_if_requested(host, link, envelope)
    {
        return Some(Served {
            peer: Some(peer),
            events: std::mem::take(events),
            finished: std::mem::take(finished),
            ended: None,
        });
    }
    // ★ `frames_received_total{event}` is recorded by the link's `receive_inbound`, not here. This branch
    // sees only the frames a listener *delivered*; an answer on a dialled link — a pairing response, a
    // plugin list — never reaches a listener, and those were invisible. The link is the one place every
    // received frame passes, so the count lives there and this branch would double it.
    // ★ Recorded as well as reported. A message this kernel received has arrived, and a log that looked
    // the same whether it arrived or was lost in the network would be one a user cannot investigate with.
    events.push(event.clone());
    // ★ And routed, which is what a share is *for*.
    //
    // This used to end at the line below: a peer's shared text was reported and dropped, so a share could
    // arrive and nothing would ask a plugin whether it could handle it. The design calls this routing the
    // kernel's most central orchestration, and until here the inbound half of it did not exist.
    match share {
        Some(item) => {
            match router.route(&item, synra_store::sqlite::now_ms()) {
                // ★ The typed report rather than a JSON lookup. The value is a `Routed` now,
                // and walking it as JSON would have been the library's shape leaking into a log line.
                Ok(routed) => eprintln!(
                    "synra-daemon: {peer} shared something — {} plugin(s) offered",
                    routed.report.offered
                ),
                // A routing failure is reported and does not end the link: the message arrived, and
                // closing the connection would take down a transfer for a reason the peer cannot see.
                Err(refusal) => {
                    eprintln!("synra-daemon: {peer}'s share could not be routed: {refusal}")
                }
            }
        }
        // ★ A kernel event that runs an action, withdraws one, or reports an outcome. It is answered
        // **here**, on the connection that asked, because the answer is a reply: a host that ran the action
        // and sent the result on a second connection would be answering a question nobody is listening for.
        None if event == synra_protocol::event::events::INTENT_INVOKE
            || event == synra_protocol::event::events::INTENT_CANCEL
            || event == synra_protocol::event::events::INTENT_RESULT
            || event.starts_with(synra_protocol::event::PLUGIN_PREFIX) =>
        {
            let Some(envelope) = request else {
                eprintln!("synra-daemon: {peer} sent {event} without an envelope to answer");
                return None;
            };
            events::answer_kernel_event(host, link, &envelope, on_kernel_events, events, data_dir);
        }
        // ★ **A question this kernel can answer by itself.** "What plugins do you have" is a read of
        // this device's own store — `plugins` joined to the active row of `plugin_versions` — and the
        // answer is what the asker's plan compares. It is answered here rather than by a host callback
        // because the kernel owns the tables: two hosts answering it separately would be two answers to
        // one question, and the sync decision would inherit the difference.
        // ★ 配对：这条连接会**停下来等人**，而这是整条链路上唯一允许停的地方。
        //
        // 配对请求没有别的意义——不像插件列表或意图，它不是「问一句、答一句」就结束的事，
        // 而是两个人要各看一眼屏幕。每连接一个线程，所以停下来不挡 accept 循环。
        None if event == synra_protocol::pairing::PAIR_REQUEST => {
            let Some(envelope) = request else {
                eprintln!("synra-daemon: {peer} asked to pair without an envelope");
                return None;
            };
            pairing::answer_pairing(link, desk, &envelope, data_dir, &peer);
            // ★ 配对期间为了听见对面撤回，读超时被调到 50ms；
            // 这条连接之后还要按正常节奏工作，得把超时还回去。
            link.set_read_timeout(Some(timeout));
        }
        None if event == synra_protocol::event::events::PLUGIN_LIST_REQUEST => {
            let answer = match (&pairing_db, request) {
                (Ok(db), Some(request)) => crate::plugin_sync::answer_plugin_list(
                    db,
                    &request,
                    link.local(),
                    synra_store::sqlite::now_ms(),
                ),
                (Ok(_), None) => {
                    eprintln!(
                        "synra-daemon: {peer} asked what plugins this device has, without an envelope to answer"
                    );
                    return None;
                }
                (Err(error), _) => {
                    eprintln!(
                        "synra-daemon: {peer} asked what plugins this device has, and the database could not be read: {error}"
                    );
                    return None;
                }
            };
            match answer {
                Ok(reply) => {
                    if let Err(error) = link.send(&reply) {
                        eprintln!(
                            "synra-daemon: the plugin list could not be sent to {peer}: {error}"
                        );
                    }
                }
                // A failure to answer does not end the link, the same choice the pairing answer makes:
                // the dialer's own deadline already covers giving up, and closing the connection would
                // take a transfer down for a reason the peer cannot see.
                Err(error) => eprintln!(
                    "synra-daemon: the plugin list for {peer} could not be built: {error}"
                ),
            }
        }
        // Not a share, so there is still no event bus to deliver it to — and saying so is the honest
        // answer rather than an empty one.
        None => eprintln!("synra-daemon: {peer} sent {event} — nothing is wired up to deliver it",),
    }
    None
}
