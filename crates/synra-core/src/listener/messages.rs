use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use synra_protocol::ids::DeviceId;

use crate::SessionError;
use crate::dispatch::orchestrate::Router;
use crate::host::Host;
use crate::inbound::{Decision, Inbox};
use crate::link::{LinkError, PeerLink};
use crate::pairing::Service;
use crate::session::InboundProgress;

use super::close_reason;
use super::delivered;
use super::{
    CancelCallback, FinishedCallback, FinishedTransfer, InboundProgressEvent, KernelEventCallback,
    PATIENCE, ProgressCallback, Served,
};

pub(super) fn run_loop(
    host: &Arc<Mutex<Host>>,
    mut link: PeerLink,
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
    mut events: Vec<String>,
    mut finished: Vec<FinishedTransfer>,
    mut inbox: Inbox,
    mut last_progress: Option<InboundProgress>,
    desk: Arc<Service>,
) -> Served {
    let pairing_db = synra_store::SynraDb::open(&data_dir.join(synra_store::DB_FILE_NAME));
    loop {
        // ★ Checked between messages, because the link belongs to this loop. A cancel that took effect only after the
        // next block would still write a block the user said they did not want; one that sent the abort from the command
        // thread would race this one for the same socket.
        if let Some(progress) = inbox.progress()
            && should_cancel(&progress.transfer_id.to_string())
        {
            match inbox.cancel(&mut link, synra_store::sqlite::now_ms()) {
                Ok(Some(cancelled)) => {
                    events.push(format!("cancelled {cancelled}"));
                    if let Some(progress) = last_progress.clone() {
                        on_progress(&InboundProgressEvent {
                            peer,
                            progress,
                            aborted: true,
                        });
                    }
                }
                Ok(None) => {}
                Err(error) => eprintln!("synra-daemon: the cancel could not be sent: {error}"),
            }
        }
        match inbox.absorb_with(
            &mut link,
            synra_store::sqlite::now_ms(),
            PATIENCE,
            &peer_address,
            offer.as_ref(),
        ) {
            Ok(decision) => match decision {
                decision @ Decision::Delivered { .. } => {
                    if let Some(served) = delivered::handle(
                        decision,
                        host,
                        &mut link,
                        peer,
                        data_dir,
                        router,
                        timeout,
                        on_kernel_events,
                        &pairing_db,
                        &desk,
                        &mut events,
                        &mut finished,
                    ) {
                        return served;
                    }
                }
                Decision::Ignored => {}
                // Nothing arrived and the wait is over. The connection ends quietly: a peer that has gone silent has not
                // done anything wrong, and `Served::ended` is for faults.
                Decision::Idle => {
                    // The ordinary, quiet end. Counted with its own reason so a panel can tell "the peer finished and
                    // hung up" from "the peer went silent" and from a fault.
                    host.lock().count_link_closed("idle");
                    return Served {
                        peer: Some(peer),
                        events,
                        finished: finished.clone(),
                        ended: None,
                    };
                }
                Decision::Accepted {
                    transfer_id,
                    file_name,
                } => {
                    events.push(format!("accepted {transfer_id}"));
                    println!("receiving {file_name} from {peer}");
                    // ★ The proposal is the first moment a row can exist: the sender has declared a size, and the file is
                    // being created. A reporter that waited for the first block would show nothing for a slow link.
                    last_progress = inbox.progress();
                    if let Some(progress) = &last_progress {
                        on_progress(&InboundProgressEvent {
                            peer,
                            progress: progress.clone(),
                            aborted: false,
                        });
                    }
                }
                Decision::Stored { index, duplicate } => {
                    // Per-block logging would be enormous for a real file, so only the interesting case is said: a block
                    // that arrived twice is a resumption working, and one that is logged is one a developer can see.
                    if duplicate {
                        eprintln!(
                            "synra-daemon: {peer} re-sent block {index}, which was already held"
                        );
                    }
                    last_progress = inbox.progress();
                    if let Some(progress) = &last_progress {
                        on_progress(&InboundProgressEvent {
                            peer,
                            progress: progress.clone(),
                            aborted: false,
                        });
                    }
                }
                Decision::Finished {
                    path,
                    byte_length,
                    bundle,
                    digest,
                    version,
                    request_id,
                    sync_session_id,
                    trace_id,
                } => {
                    events.push("finished".to_owned());
                    // ★ The three facts travel together, and `bundle` is the one that says which of them this is.
                    // ★ 先造出来交给回调，再收进列表：回调的答案属于**这个**传输，而它已经被移走了就没有了。
                    let transfer = FinishedTransfer {
                        transfer_id: last_progress.as_ref().map(|progress| progress.transfer_id),
                        path: path.clone(),
                        byte_length,
                        bundle: bundle.clone(),
                        peer,
                        digest: digest.clone(),
                        version,
                        sync_session_id,
                    };
                    // ★ 收到、检查、装完 —— 现在告诉对端。第 133 轮的 `sync_result` 与第 134 轮的
                    // `apply_result` 等的就是这一行，而它只能在连接还活着的时候发。
                    if let Some(outcome) = on_finished(&transfer) {
                        let context = synra_protocol::envelope::ReplyContext {
                            request_id,
                            target: transfer.peer,
                            from: host.lock().device_id(),
                            trace_id,
                            ttl_ms: None,
                        };
                        if let Ok(reply) = crate::messaging::sync_result(
                            context,
                            &outcome,
                            synra_store::sqlite::now_ms(),
                        ) {
                            let _ = link.send(&reply);
                        }
                    }
                    finished.push(transfer);
                    // ★ A bundle is said out loud rather than printed as another file. The kernel does not install one
                    // yet, and a line that reads like every other received file is how "not installed yet" becomes
                    // "somebody will notice later" — the state this codebase keeps replacing with a sentence that says
                    // which half is missing.
                    match bundle {
                        Some(plugin_id) => println!(
                            "received {byte_length} bytes into {} — a plugin bundle for {plugin_id}, which this kernel does not install yet",
                            path.display()
                        ),
                        None => println!("received {byte_length} bytes into {}", path.display()),
                    }
                }
                Decision::Failed { why } => {
                    events.push("failed".to_owned());
                    eprintln!("synra-daemon: a transfer from {peer} failed: {why}");
                    // ★ The row this connection opened has to be closed, and a failure is still an event. Without this a
                    // peer's abort left the interface showing a transfer arriving for ever.
                    if let Some(progress) = &last_progress {
                        on_progress(&InboundProgressEvent {
                            peer,
                            progress: progress.clone(),
                            aborted: true,
                        });
                    }
                }
            },
            // A `Bye` is the ordinary end, and so is a peer that hung up. Neither is a fault, and both end the loop.
            Err(SessionError::Link(LinkError::Closed)) => {
                host.lock().count_link_closed("closed");
                return Served {
                    peer: Some(peer),
                    events,
                    finished: finished.clone(),
                    ended: None,
                };
            }
            Err(error) => {
                host.lock().count_link_closed(close_reason(&error));
                return Served {
                    peer: Some(peer),
                    events,
                    finished: Vec::new(),
                    ended: Some(error.to_string()),
                };
            }
        }
    }
}
