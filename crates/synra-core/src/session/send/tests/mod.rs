//! Failure, cancellation and backpressure tests of the complete shared sender.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use synra_protocol::ids::{DeviceId, TraceId};
use synra_protocol::session::{
    ProgressBitmap, TransferAbortReason, TransferComplete, TransferProgress,
};

use crate::link::{Inbound, PeerLink, memory::MemoryStream};
use crate::peer::Flags;
use crate::session::wire::{Message, envelope_for};
use crate::session::{Received, Receiving, SessionError, SessionEvent};
use crate::transfer::TransferSender;

use super::{SendOptions, WINDOW_BLOCKS, report_progress, send_prepared};

fn links() -> (PeerLink, PeerLink) {
    let (near, far) = MemoryStream::pair_with_capacity(4096);
    let local = DeviceId::new();
    let peer = DeviceId::new();
    let agreed = synra_protocol::handshake::Agreed {
        common: vec![],
        missing_required: vec![],
    };
    (
        PeerLink::new(near, local, peer, agreed.clone(), Flags::production()),
        PeerLink::new(far, peer, local, agreed, Flags::production()),
    )
}

fn options() -> SendOptions {
    SendOptions::new(TraceId::new(), 123, Instant::now() + Duration::from_secs(3))
}

fn sender(root: &tempfile::TempDir, size: usize) -> TransferSender {
    let path = root.path().join("source.bin");
    std::fs::write(&path, vec![9; size]).unwrap();
    TransferSender::open(&path, 1024).unwrap()
}

/// A deliberately uncooperative receiver: acknowledge blocks but let the test control confirmation.
fn receive_body(peer: &mut PeerLink) -> synra_protocol::envelope::Envelope {
    let proposal = peer.receive().unwrap();
    let request: synra_protocol::session::TransferRequest =
        serde_json::from_str(proposal.payload.unwrap().get()).unwrap();
    let total = crate::transfer::plan_blocks(request.byte_length, request.chunk_size)
        .unwrap()
        .len();
    let total = u32::try_from(total).unwrap();
    let mut bitmap = ProgressBitmap::empty(total);
    loop {
        match peer.receive_inbound().unwrap() {
            Inbound::Block { chunk_id, .. } => {
                bitmap.set(chunk_id);
                let progress = TransferProgress {
                    transfer_id: request.transfer_id,
                    received: bitmap.as_bytes().to_vec(),
                    total_blocks: total,
                    bytes_received: request.byte_length,
                };
                let reply = envelope_for(
                    Message::Progress,
                    peer.local(),
                    peer.peer(),
                    proposal.trace_id,
                    123,
                    &progress,
                )
                .unwrap();
                peer.send(&reply).unwrap();
            }
            Inbound::Envelope(envelope) => {
                assert_eq!(envelope.event.as_str(), Message::Complete.name());
                return *envelope;
            }
        }
    }
}

mod window;
mod confirmation;
mod deadlines;
