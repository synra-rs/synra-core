//! Session payloads: pairing, intent and transfer.
//!
//! A session is a conversation with a beginning and an end, and the thing that most often goes wrong
//! in one is that it never ends. A pairing request whose answer is lost, an intent whose peer was
//! suspended mid-flight, a transfer interrupted by a laptop closing — each leaves the initiator
//! waiting forever unless something bounds it.
//!
//! So every session has a timeout, and they live in one place: [`SessionTimeouts`].
//!
//! # Why the initiator must time itself out
//!
//! Every payload here is *also* protected by the peer's own timeout, and that is not enough. If the
//! only timeout is on the receiving side, an initiator whose packet was dropped before it arrived
//! waits for an answer that was never coming — no error, no log, just a spinner. Each side bounds
//! its own wait independently.

mod pairing;
mod state;
mod transfer;

pub use pairing::{IntentDisplay, IntentInvocation, IntentOutcome, PeerProfile, PlatformKind, SessionTimeouts};
pub use state::{OutstandingRequests, PeerSnapshot, SessionState};
pub use transfer::{
    DigestAlgorithm, PluginList, PluginSummary, ProgressBitmap, SriDigest, TransferAbort,
    TransferAbortReason, TransferComplete, TransferKind, TransferMeta, TransferProgress, TransferRequest,
    TransferWindow,
};

#[cfg(test)]
use core::time::Duration;
#[cfg(test)]
use crate::error::SynraError;
#[cfg(test)]
use crate::ids::{DeviceId, IntentId, PluginId, RequestId, SessionId, TransferId};
#[cfg(test)]
use crate::limits;

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> SriDigest {
        // 32 bytes of zeros, base64 without padding, is 43 'A' characters.
        SriDigest::new(DigestAlgorithm::Sha256, "A".repeat(43)).expect("valid")
    }

    fn profile() -> PeerProfile {
        PeerProfile {
            device_id: DeviceId::new(),
            display_name: "imba97's laptop".to_owned(),
            platform: PlatformKind::Desktop,
            app_version: "1.0.0".to_owned(),
        }
    }

    #[test]
    fn default_timeouts_are_self_consistent() {
        assert_eq!(SessionTimeouts::default().validate(), Ok(()));
    }

    #[test]
    fn a_result_cache_shorter_than_the_dedup_window_is_refused() {
        let timeouts = SessionTimeouts {
            result_cache: limits::REQUEST_DEDUP_WINDOW - Duration::from_secs(1),
            ..SessionTimeouts::default()
        };
        assert!(timeouts.validate().is_err());
    }

    #[test]
    fn an_idle_timeout_longer_than_the_total_is_refused() {
        let timeouts = SessionTimeouts {
            transfer_idle: Duration::from_secs(3600),
            transfer_total: Duration::from_secs(60),
            ..SessionTimeouts::default()
        };
        assert!(timeouts.validate().is_err());
    }

    #[test]
    fn zero_session_timeouts_are_refused() {
        for timeouts in [
            SessionTimeouts { pairing: Duration::ZERO, ..SessionTimeouts::default() },
            SessionTimeouts { intent: Duration::ZERO, ..SessionTimeouts::default() },
        ] {
            assert!(timeouts.validate().is_err());
        }
    }

    #[test]
    fn a_profile_needs_a_usable_name() {
        let mut profile = profile();
        assert_eq!(profile.validate(), Ok(()));

        profile.display_name = "   ".to_owned();
        assert!(profile.validate().is_err());

        profile.display_name = "x".repeat(PeerProfile::MAX_DISPLAY_NAME + 1);
        assert!(profile.validate().is_err());

        // Counted in characters: a CJK name of the same character count is accepted.
        profile.display_name = "电".repeat(PeerProfile::MAX_DISPLAY_NAME);
        assert_eq!(profile.validate(), Ok(()));

        profile.app_version = String::new();
        assert!(profile.validate().is_err());
    }


    #[test]
    fn an_intent_invocation_round_trips_with_its_raw_args() {
        let invocation = IntentInvocation {
            intent_id: IntentId::new(),
            plugin_id: PluginId::parse("@synra-plugin/github-bridge").expect("valid"),
            action: "open-url".to_owned(),
            args: serde_json::value::to_raw_value(&serde_json::json!({ "url": "https://example.com" }))
                .expect("raw"),
            display: Some(IntentDisplay {
                title: "Open this link".to_owned(),
                detail: Some("https://example.com".to_owned()),
                source_display_name: "phone".to_owned(),
            }),
        };

        let json = serde_json::to_string(&invocation).expect("serialises");
        let back: IntentInvocation = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, invocation);
        // The args stay text until somebody reads them.
        assert!(invocation.args.get().contains("example.com"));
    }

    #[test]
    fn an_outcome_is_either_a_result_or_an_error() {
        let intent = IntentId::new();
        assert_eq!(IntentOutcome::ok(intent, None, 12).validate(), Ok(()));
        assert_eq!(
            IntentOutcome::failed(intent, SynraError::unsupported("x"), 5).validate(),
            Ok(())
        );

        // Both at once is refused: an interface that had to choose which to believe would
        // eventually meet a case where they disagree.
        let contradictory = IntentOutcome {
            intent_id: intent,
            ok: true,
            result: None,
            error: Some(SynraError::unsupported("x")),
            elapsed_ms: 5,
        };
        assert!(contradictory.validate().is_err());

        // And a failure with no error tells the user nothing.
        let mute = IntentOutcome {
            intent_id: intent,
            ok: false,
            result: None,
            error: None,
            elapsed_ms: 5,
        };
        assert!(mute.validate().is_err());
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

    #[test]
    fn session_states_know_which_are_terminal() {
        assert!(!SessionState::Open.is_terminal());
        for state in [
            SessionState::Succeeded,
            SessionState::Failed,
            SessionState::Expired,
            SessionState::Cancelled,
        ] {
            assert!(state.is_terminal(), "{state:?}");
        }
    }

    #[test]
    fn outstanding_requests_forget_what_has_expired() {
        let mut outstanding = OutstandingRequests::new(4, 1_000);
        let first = RequestId::new();
        outstanding.insert(first, 0);
        assert!(outstanding.contains(&first));

        outstanding.expire(999);
        assert!(outstanding.contains(&first));

        outstanding.expire(1_001);
        assert!(!outstanding.contains(&first));
        assert!(outstanding.is_empty());
    }

    #[test]
    fn outstanding_requests_stay_bounded() {
        // A record that grows without limit is a memory leak with a slow fuse.
        let mut outstanding = OutstandingRequests::new(2, 1_000_000);
        let ids: Vec<_> = (0..5).map(|_| RequestId::new()).collect();
        for (at, id) in ids.iter().enumerate() {
            outstanding.insert(*id, at as i64);
        }
        assert_eq!(outstanding.len(), 2);
        // The oldest are dropped: the newest requests are the ones whose replies have not yet had
        // time to arrive.
        assert!(!outstanding.contains(&ids[0]));
        assert!(outstanding.contains(&ids[4]));
    }

    #[test]
    fn a_answered_request_stops_being_outstanding() {
        let mut outstanding = OutstandingRequests::new(4, 1_000_000);
        let id = RequestId::new();
        outstanding.insert(id, 0);
        assert!(outstanding.contains(&id));

        outstanding.remove(&id);
        assert!(!outstanding.contains(&id));
        assert!(outstanding.is_empty());
    }

    #[test]
    fn platform_kinds_report_mobility() {
        assert!(!PlatformKind::Desktop.is_mobile());
        assert!(PlatformKind::Android.is_mobile());
        assert!(PlatformKind::Ios.is_mobile());
        assert_eq!(PlatformKind::Desktop.to_string(), "desktop");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A bitmap built by setting blocks individually reports exactly those blocks. Bit packing
        /// is where an off-by-one hides, so this exercises boundaries as well as the middle.
        #[test]
        fn a_bitmap_reports_exactly_what_was_set(
            total in 1u32..200,
            blocks in proptest::collection::vec(0u32..400, 0..40),
        ) {
            let mut bitmap = ProgressBitmap::empty(total);
            let mut expected = std::collections::BTreeSet::new();
            for block in &blocks {
                bitmap.set(*block);
                if *block < total {
                    expected.insert(*block);
                }
            }

            prop_assert_eq!(bitmap.received_count(), expected.len() as u32);
            for block in 0..total {
                prop_assert_eq!(bitmap.contains(block), expected.contains(&block));
            }
            prop_assert_eq!(bitmap.is_complete(), expected.len() as u32 == total);
        }

        /// The block count is the ceiling of the division, never the floor. Rounding down would
        /// silently drop a trailing partial block.
        #[test]
        fn block_count_always_covers_every_byte(
            byte_length in 0u64..10_000_000,
            chunk_size in 1u32..(limits::MAX_CHUNK_LEN as u32),
        ) {
            let window = TransferWindow { in_flight: 1, chunk_size };
            let blocks = u64::from(window.block_count(byte_length));
            prop_assert!(blocks * u64::from(chunk_size) >= byte_length);
            if blocks > 0 {
                prop_assert!((blocks - 1) * u64::from(chunk_size) < byte_length);
            }
        }

        /// A digest built from a well-formed pair survives the wire; anything else is refused.
        #[test]
        fn digests_are_strict(value in "[A-Za-z0-9+/]{0,60}") {
            let built = SriDigest::new(DigestAlgorithm::Sha256, value.clone());
            if value.len() == 43 {
                let digest = built.expect("43 base64 characters is a sha256 digest");
                let back = SriDigest::try_from(digest.to_string()).expect("round trips");
                prop_assert_eq!(back, digest);
            }
            else {
                prop_assert!(built.is_err());
            }
        }
    }
}

