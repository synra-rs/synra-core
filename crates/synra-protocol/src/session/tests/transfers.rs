use crate::ids::{PluginId, SessionId, TransferId};
use crate::limits;
use super::super::{
    DigestAlgorithm, ProgressBitmap, SriDigest, TransferAbortReason, TransferKind, TransferMeta,
    TransferProgress, TransferRequest, TransferWindow,
};

fn digest() -> SriDigest {
    // 32 bytes of zeros, base64 without padding, is 43 'A' characters.
    SriDigest::new(DigestAlgorithm::Sha256, "A".repeat(43)).expect("valid")
}

#[test]
fn a_transfer_request_round_trips_with_flattened_metadata() {
    let request = TransferRequest {
        transfer_id: TransferId::new(),
        kind: TransferKind::PluginBundle,
        byte_length: 1024,
        chunk_size: 256,
        digest: digest(),
        sync_session_id: None,
        meta: TransferMeta::PluginBundle {
            plugin_id: PluginId::parse("@synra-plugin/chat").expect("valid"),
            version: "1.2.0".to_owned(),
        },
    };

    let json = serde_json::to_string(&request).expect("serialises");
    // `flatten` lifts the metadata's own fields to the top level, tagged so a reader knows which
    // variant it is without inferring it from which fields happen to be present.
    assert!(json.contains("\"metaKind\":\"plugin-bundle\""), "{json}");
    assert!(json.contains("\"pluginId\""), "{json}");

    let back: TransferRequest = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, request);
}

#[test]
fn an_attachment_metadata_round_trips() {
    let request = TransferRequest {
        transfer_id: TransferId::new(),
        kind: TransferKind::Attachment,
        byte_length: 10,
        chunk_size: 4,
        digest: digest(),
        sync_session_id: Some(SessionId::new()),
        meta: TransferMeta::Attachment {
            file_name: "report.pdf".to_owned(),
            mime_type: Some("application/pdf".to_owned()),
            context_id: None,
        },
    };

    let json = serde_json::to_string(&request).expect("serialises");
    let back: TransferRequest = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, request);
}

#[test]
fn an_unknown_transfer_kind_is_refused_rather_than_ignored() {
    // A receiver that accepted an unknown kind would have to guess where to put the bytes.
    let json = r#"{"transferId":"0193abcd-0000-7000-8000-000000000000","kind":"mystery",
        "byteLength":1,"chunkSize":1,"digest":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "metaKind":"attachment","fileName":"x"}"#;
    assert!(serde_json::from_str::<TransferRequest>(json).is_err());
}

#[test]
fn a_digest_carries_its_algorithm() {
    let digest = digest();
    assert_eq!(digest.algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(digest.to_string().len(), "sha256-".len() + 43);

    // A digest whose algorithm has to be inferred is one that will eventually be checked with
    // the wrong one, so an unknown prefix is refused.
    assert!(SriDigest::try_from("md5-abc".to_owned()).is_err());
    assert!(SriDigest::try_from("noprefix".to_owned()).is_err());
    assert!(SriDigest::try_from("sha256-tooshort".to_owned()).is_err());
    assert!(SriDigest::try_from(format!("sha256-{}", "!".repeat(43))).is_err());

    let json = serde_json::to_string(&digest).expect("serialises");
    let back: SriDigest = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, digest);
}

#[test]
fn a_progress_bitmap_counts_only_real_blocks() {
    // 10 blocks occupy two bytes, and the second byte's six padding bits must not count as
    // received blocks — otherwise a transfer would look complete before it was.
    let mut bitmap = ProgressBitmap::empty(10);
    assert_eq!(bitmap.received_count(), 0);
    assert!(!bitmap.is_complete());

    bitmap.set(0);
    bitmap.set(9);
    assert_eq!(bitmap.received_count(), 2);
    assert!(bitmap.contains(0));
    assert!(bitmap.contains(9));
    assert!(!bitmap.contains(5));

    // Out-of-range writes are ignored rather than panicking.
    bitmap.set(10);
    bitmap.set(u32::MAX);
    assert_eq!(bitmap.received_count(), 2);
    assert!(!bitmap.contains(10));
}

#[test]
fn a_full_bitmap_is_complete_at_every_boundary() {
    // The byte boundary is where a bit-packing off-by-one hides.
    for total in [0u32, 1, 7, 8, 9, 15, 16, 17, 1000] {
        let bitmap = ProgressBitmap::full(total);
        assert!(bitmap.is_complete(), "total {total}");
        assert_eq!(bitmap.received_count(), total, "total {total}");
        assert!(bitmap.missing().is_empty(), "total {total}");
    }
}

#[test]
fn missing_blocks_are_reported_in_order() {
    let mut bitmap = ProgressBitmap::empty(5);
    bitmap.set(1);
    bitmap.set(3);
    assert_eq!(bitmap.missing(), vec![0, 2, 4]);
}

#[test]
fn a_bitmap_survives_a_trip_through_bytes() {
    let mut bitmap = ProgressBitmap::empty(20);
    for block in [1, 2, 7, 8, 19] {
        bitmap.set(block);
    }

    let restored =
        ProgressBitmap::from_bytes(bitmap.as_bytes().to_vec(), 20).expect("round trips");
    assert_eq!(restored, bitmap);
    assert_eq!(restored.received_count(), 5);

    // A length that disagrees with the block count means the two sides differ about the
    // transfer's size, which is not something to guess about.
    assert!(ProgressBitmap::from_bytes(vec![0; 3], 1000).is_err());
}

#[test]
fn progress_reports_round_trip() {
    let mut bitmap = ProgressBitmap::empty(8);
    bitmap.set(0);
    let progress = TransferProgress {
        transfer_id: TransferId::new(),
        received: bitmap.as_bytes().to_vec(),
        total_blocks: 8,
        bytes_received: 64,
    };

    let json = serde_json::to_string(&progress).expect("serialises");
    let back: TransferProgress = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, progress);
}

#[test]
fn abort_reasons_agree_with_their_retryability() {
    assert!(TransferAbortReason::IoError.is_retryable());
    assert!(TransferAbortReason::IdleTimeout.is_retryable());
    assert!(!TransferAbortReason::DigestMismatch.is_retryable());
    assert!(!TransferAbortReason::UserCancelled.is_retryable());

    for reason in [
        TransferAbortReason::UserCancelled,
        TransferAbortReason::DigestMismatch,
        TransferAbortReason::TooLarge,
        TransferAbortReason::IoError,
        TransferAbortReason::IdleTimeout,
        TransferAbortReason::TotalTimeout,
        TransferAbortReason::PeerRejected,
    ] {
        let json = serde_json::to_string(&reason).expect("serialises");
        assert_eq!(json, format!("\"{}\"", reason.as_str()));
        let back: TransferAbortReason = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, reason);
    }
}

#[test]
fn a_transfer_window_computes_its_block_count() {
    let window = TransferWindow { in_flight: 32, chunk_size: 256 * 1024 };
    assert_eq!(window.validate(), Ok(()));
    assert_eq!(window.bytes_in_flight(), 32 * 256 * 1024);

    assert_eq!(window.block_count(0), 0);
    assert_eq!(window.block_count(1), 1);
    assert_eq!(window.block_count(256 * 1024), 1);
    assert_eq!(window.block_count(256 * 1024 + 1), 2);
}

#[test]
fn a_degenerate_transfer_window_is_refused() {
    assert!(TransferWindow { in_flight: 0, chunk_size: 1024 }.validate().is_err());
    assert!(TransferWindow { in_flight: 1, chunk_size: 0 }.validate().is_err());
    assert!(
        TransferWindow { in_flight: 1, chunk_size: limits::MAX_CHUNK_LEN as u32 + 1 }
            .validate()
            .is_err()
    );
}
