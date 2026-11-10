use synra_protocol::DeviceId;

use super::super::{SendFileRequest, TransferSnapshot};
use super::{fixed_device_id, fixed_transfer_id};

pub(super) fn transfer(received: u64, total: u64) -> TransferSnapshot {
    TransferSnapshot {
        transfer_id: fixed_transfer_id("018f2b40-0000-7000-8000-000000000001"),
        peer_device: fixed_device_id("018f2b40-0000-7000-8000-000000000002"),
        peer_name: "My PC".to_owned(),
        direction: "send".to_owned(),
        kind: "attachment".to_owned(),
        state: "transferring".to_owned(),
        file_name: "report.pdf".to_owned(),
        received_bytes: received,
        total_bytes: total,
        blocks_done: 0,
        blocks_total: 0,
        abort_reason: None,
        started_at_ms: 0,
    }
}

#[test]
fn progress_is_a_fraction() {
    assert_eq!(transfer(0, 100).progress(), 0.0);
    assert_eq!(transfer(50, 100).progress(), 0.5);
    assert_eq!(transfer(100, 100).progress(), 1.0);
}

#[test]
fn progress_of_an_empty_transfer_is_zero_rather_than_nan() {
    // A `NaN` in a progress bar renders at whatever width the platform's arithmetic produces.
    assert_eq!(transfer(0, 0).progress(), 0.0);
    assert!(transfer(0, 0).progress().is_finite());
}

#[test]
fn progress_never_exceeds_one() {
    // A resumed transfer can report more received than the total it was created with, because the file changed
    // size on the sender. A progress of 1.4 would render outside its bar.
    assert_eq!(transfer(140, 100).progress(), 1.0);
}

#[test]
fn a_transfer_round_trips() {
    let json = serde_json::to_string(&transfer(1, 2)).expect("serialises");
    assert!(json.contains("transferId"), "{json}");
    assert!(json.contains("blocksTotal"), "{json}");
    let back: TransferSnapshot = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, transfer(1, 2));
}

#[test]
fn a_send_request_round_trips() {
    let request = SendFileRequest {
        to: DeviceId::new(),
        path: "/tmp/x.pdf".to_owned(),
        context_id: Some("c1".to_owned()),
    };
    let json = serde_json::to_string(&request).expect("serialises");
    assert!(json.contains("contextId"), "{json}");
    let back: SendFileRequest = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, request);
}
