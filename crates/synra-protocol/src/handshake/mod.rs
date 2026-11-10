//! Link establishment: what two devices say to each other before anything else.
//!
//! A `Hello` is the first frame on every connection, in both directions. It carries the protocol
//! version, what each side can do, and enough evidence for the receiving side to decide whether it
//! already trusts the caller.
//!
//! # The handshake exists to fail early
//!
//! Everything checked here is something that would otherwise fail later, after the user has already
//! asked for something:
//!
//! * **Protocol version** — a peer from a different major version would send frames this build
//!   cannot read. Refusing at `Hello` turns that into one clear message instead of a stream of
//!   unreadable frames.
//! * **Features** — a peer that cannot do `TransferResume` would strand a partially transferred
//!   file. The intersection is computed once, here, so no later code has to ask.
//!   rest of the kernel can assume every message on an established link came from a paired device.
//!
use serde::{Deserialize, Serialize};

use crate::ids::DeviceId;
use crate::limits;
use crate::session::PlatformKind;

/// The only protocol version this build speaks.
///
/// A single version with no compatibility layer. Two builds that disagree here do not talk; they
/// report it, and one of them is updated.
pub const PROTOCOL_VERSION: u16 = 1;

/// Identifies a protocol version this build cannot speak.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("peer speaks protocol {theirs}, this build speaks {ours}")]
pub struct VersionMismatch {
    /// The version this build speaks.
    pub ours: u16,
    /// The version the peer announced.
    pub theirs: u16,
}

/// A per-connection random value, so two connections are never confusable.
///
/// Sent by the dialer and echoed by the acceptor. Proves the reply belongs to *this* attempt rather
/// than to a delayed one, and gives every link a value that cannot be predicted from the last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionNonce(pub u128);

impl SessionNonce {
    /// A fresh nonce.
    #[must_use]
    pub fn random() -> Self {
        Self(uuid::Uuid::now_v7().as_u128())
    }

    /// Whether this is the all-zero value, which is never a valid nonce.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(self) -> String {
        format!("{:032x}", self.0)
    }
}

mod features;
mod hello;
mod state;

pub use features::{Agreed, Feature, negotiate};
pub use hello::{Hello, HelloAck, HelloError, RefusalReason};
pub use state::{HandshakeBudget, LinkAgreement, NextStep, ReplayError, SequenceGuard, next_step};

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    fn hello() -> Hello {
        Hello {
            protocol: PROTOCOL_VERSION,
            device_id: DeviceId::new(),
            display_name: "laptop".to_owned(),
            platform: PlatformKind::Desktop,
            app_version: "1.0.0".to_owned(),
            nonce: SessionNonce(1),
            features: Feature::ALL.to_vec(),
            requires: Vec::new(),
            sequence: 1,
            endpoints: Vec::new(),
        }
    }

    fn accepted_ack(nonce: SessionNonce) -> HelloAck {
        HelloAck {
            protocol: PROTOCOL_VERSION,
            device_id: DeviceId::new(),
            display_name: "phone".to_owned(),
            platform: PlatformKind::Android,
            app_version: "1.0.0".to_owned(),
            nonce,
            features: Feature::ALL.to_vec(),
            requires: Vec::new(),
            refusal: None,
            sequence: 1,
            endpoints: Vec::new(),
        }
    }

    #[test]
    fn a_valid_hello_passes_validation() {
        assert_eq!(hello().validate(), Ok(()));
    }

    #[test]
    fn a_hello_from_another_protocol_version_is_refused() {
        let mut hello = hello();
        hello.protocol = 2;
        assert!(matches!(hello.validate(), Err(HelloError::Version(_))));
    }

    #[test]
    fn a_hello_missing_essentials_is_refused() {
        /// Mutates one field of a hello, so a table of negative cases can be one loop.
        type Mutate = fn(&mut Hello);
        let cases: &[(&str, Mutate)] = &[
            ("nil device", |h| h.device_id = DeviceId::from_uuid(uuid::Uuid::nil())),
            ("zero nonce", |h| h.nonce = SessionNonce(0)),
            ("blank name", |h| h.display_name = "  ".to_owned()),
            ("long name", |h| h.display_name = "x".repeat(Hello::MAX_DISPLAY_NAME + 1)),
            ("blank version", |h| h.app_version = String::new()),
        ];

        for (label, mutate) in cases {
            let mut hello = hello();
            mutate(&mut hello);
            assert!(hello.validate().is_err(), "{label} should be refused");
        }
    }

    #[test]
    fn too_many_endpoints_is_refused() {
        // The list drives connection attempts on the receiver, so it is bounded input.
        let mut hello = hello();
        hello.endpoints = (0..=Hello::MAX_ENDPOINTS)
            .map(|i| format!("10.0.0.{i}:32100"))
            .collect();
        assert!(hello.validate().is_err());

        hello.endpoints.truncate(Hello::MAX_ENDPOINTS);
        assert_eq!(hello.validate(), Ok(()));
    }

    #[test]
    fn a_required_feature_must_also_be_offered() {
        // Otherwise the announcement contradicts itself, and negotiation would report a feature as
        // missing that the peer never claimed to have.
        let mut hello = hello();
        hello.features = vec![Feature::EventStream];
        hello.requires = vec![Feature::TransferResume];
        assert!(hello.validate().is_err());

        hello.requires = vec![Feature::EventStream];
        assert_eq!(hello.validate(), Ok(()));
    }

    #[test]
    fn negotiation_intersects_the_two_lists() {
        let ours = [Feature::EventStream, Feature::ClipboardSync, Feature::LanDiscovery];
        let theirs = [Feature::EventStream, Feature::LanDiscovery, Feature::TransferResume];
        let agreed = negotiate(&ours, &theirs, &[]);

        assert!(agreed.is_usable());
        assert!(agreed.supports(Feature::EventStream));
        assert!(agreed.supports(Feature::LanDiscovery));
        assert!(!agreed.supports(Feature::ClipboardSync), "the peer does not offer it");
        assert!(!agreed.supports(Feature::TransferResume), "we do not offer it");
    }

    #[test]
    fn a_missing_required_feature_makes_the_link_unusable() {
        let agreed = negotiate(&[Feature::EventStream], &[Feature::TransferResume], &[Feature::EventStream]);

        assert!(!agreed.is_usable());
        assert_eq!(agreed.missing_required, vec![Feature::EventStream]);
        // And it is not in `common`, so a caller that forgot to check `is_usable` still cannot
        // accidentally use it.
        assert!(!agreed.supports(Feature::EventStream));
    }

    #[test]
    fn duplicates_in_either_list_are_harmless() {
        let agreed = negotiate(
            &[Feature::EventStream, Feature::EventStream],
            &[Feature::EventStream, Feature::EventStream],
            &[],
        );
        assert_eq!(agreed.common, vec![Feature::EventStream]);
    }

    #[test]
    fn negotiation_does_not_depend_on_list_order() {
        // The list is stored on the link and compared when a second connection is considered, so an
        // order that depended on which side dialled would make identical links look different.
        let a = negotiate(
            &[Feature::EventStream, Feature::LanDiscovery],
            &[Feature::LanDiscovery, Feature::EventStream],
            &[],
        );
        let b = negotiate(
            &[Feature::LanDiscovery, Feature::EventStream],
            &[Feature::EventStream, Feature::LanDiscovery],
            &[],
        );
        assert_eq!(a.common, b.common);
        assert_eq!(
            a.common,
            vec![Feature::EventStream, Feature::LanDiscovery],
            "sorted by wire name: event-stream before lan-discovery"
        );
    }

    #[test]
    fn an_empty_intersection_is_not_an_error_by_itself() {
        // Two devices with nothing in common can still exchange messages; they just cannot use any
        // optional capability. Only a *required* feature makes the link unusable.
        let agreed = negotiate(&[Feature::EventStream], &[Feature::ClipboardSync], &[]);
        assert!(agreed.is_usable());
        assert!(agreed.common.is_empty());
    }

    #[test]
    fn feature_list_is_exhaustive() {
        // A variant added without a wire name, or two sharing one, makes the format ambiguous. This
        // is the guard for a `#[non_exhaustive]` enum, where the compiler cannot help.
        let mut seen = std::collections::HashSet::new();
        for feature in Feature::ALL {
            assert!(seen.insert(feature.as_str()), "duplicate wire name for {feature:?}");
            assert_eq!(Feature::from_str_opt(feature.as_str()), Some(*feature));
            assert_eq!(feature.to_string(), feature.as_str());

            let json = serde_json::to_string(feature).expect("serialises");
            assert_eq!(json, format!("\"{}\"", feature.as_str()));
            let back: Feature = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, *feature);
        }
        assert_eq!(Feature::from_str_opt("teleportation"), None);
        assert_eq!(Feature::ALL.len(), seen.len());
    }

    #[test]
    fn a_hello_round_trips_through_json() {
        let mut hello = hello();
        hello.features = vec![Feature::EventStream, Feature::TransferResume];
        hello.requires = vec![Feature::EventStream];
        hello.endpoints = vec!["192.168.1.5:32100".to_owned(), "[::1]:32100".to_owned()];

        let json = serde_json::to_string(&hello).expect("serialises");
        assert!(json.contains("\"deviceId\""), "{json}");
        let back: Hello = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, hello);
    }

    #[test]
    fn optional_hello_fields_are_omitted_not_null() {
        let json = serde_json::to_string(&hello()).expect("serialises");
        for absent in ["\"requires\"", "\"endpoints\""] {
            assert!(!json.contains(absent), "{absent} should be omitted: {json}");
        }
    }

    #[test]
    fn an_unknown_hello_field_is_refused() {
        let mut value = serde_json::to_value(hello()).expect("value");
        value
            .as_object_mut()
            .expect("an object")
            .insert("extra".to_owned(), serde_json::json!(1));
        assert!(serde_json::from_value::<Hello>(value).is_err());
    }

    #[test]
    fn an_ack_must_echo_the_nonce() {
        let nonce = SessionNonce(0x1234);
        let ack = accepted_ack(nonce);
        assert_eq!(ack.validate(nonce), Ok(()));

        // A reply to a different attempt must not reach any other conclusion — including "the peer
        // refused us", which is why this check comes first.
        assert!(matches!(
            ack.validate(SessionNonce(0x9999)),
            Err(HelloError::Malformed(_))
        ));
    }

    #[test]
    fn a_refusal_acknowledges_the_attempt_without_being_trusted() {
        let nonce = SessionNonce(1);
        let ack = HelloAck::refuse(
            DeviceId::new(),
            "phone",
            PlatformKind::Android,
            "1.0.0",
            nonce,
            RefusalReason::TooManyLinks,
        );

        assert!(!ack.is_accepted());
        assert!(ack.validate(nonce).is_err(), "the caller must be told");
    }

    #[test]
    fn a_retryable_refusal_asks_for_a_retry_and_a_block_does_not() {
        let nonce = SessionNonce(1);

        let busy = HelloAck::refuse(
            DeviceId::new(),
            "phone",
            PlatformKind::Android,
            "1.0.0",
            nonce,
            RefusalReason::TooManyLinks,
        );
        assert!(matches!(
            next_step(&busy, Feature::ALL, &[]),
            NextStep::Retry { reason: RefusalReason::TooManyLinks }
        ));

        // Retrying a block is not a transient failure; it is the user's decision ignored once a
        // second.
        let blocked = HelloAck::refuse(
            DeviceId::new(),
            "phone",
            PlatformKind::Android,
            "1.0.0",
            nonce,
            RefusalReason::Blocked,
        );
        assert!(matches!(
            next_step(&blocked, Feature::ALL, &[]),
            NextStep::Refused(RefusalReason::Blocked)
        ));
    }




    #[test]
    fn a_peer_that_cannot_meet_our_requirement_is_refused_before_use() {
        let nonce = SessionNonce(1);
        let mut ack = accepted_ack(nonce);
        ack.features = vec![Feature::ClipboardSync];

        // Without a requirement the link is fine.
        assert!(matches!(next_step(&ack, Feature::ALL, &[]), NextStep::Established(_)));

        // With one it is not, and the failure surfaces here rather than at the moment the missing
        // capability was first needed.
        assert!(matches!(
            next_step(&ack, Feature::ALL, &[Feature::EventStream]),
            NextStep::Refused(RefusalReason::MissingRequiredFeature)
        ));
    }

    #[test]
    fn a_sequence_guard_accepts_only_newer_values() {
        let mut guard = SequenceGuard::new();
        assert_eq!(guard.accept(1), Ok(()));
        assert_eq!(guard.highest(), 1);

        assert_eq!(guard.accept(2), Ok(()));
        assert!(guard.accept(2).is_err(), "the same value again is a replay");
        assert!(guard.accept(1).is_err(), "an older value is a replay");

        assert_eq!(guard.accept(100), Ok(()));
        assert_eq!(guard.highest(), 100);
    }

    #[test]
    fn a_sequence_guard_resumes_from_a_persisted_value() {
        // After a restart the guard must not accept what it accepted before, or every attempt
        // recorded during the previous run becomes replayable.
        let mut guard = SequenceGuard::resume(500);
        assert!(guard.accept(500).is_err());
        assert!(guard.accept(499).is_err());
        assert_eq!(guard.accept(501), Ok(()));
    }

    #[test]
    fn replay_errors_name_both_values() {
        let mut guard = SequenceGuard::resume(10);
        let error = guard.accept(3).expect_err("a replay");
        assert_eq!(error.sequence, 3);
        assert_eq!(error.seen, 10);
        assert!(error.to_string().contains("replay"));
    }

    #[test]
    fn handshake_budgets_must_bound_every_phase() {
        assert_eq!(HandshakeBudget::default().validate(), Ok(()));

        for budget in [
            HandshakeBudget { await_hello: Duration::ZERO, ..HandshakeBudget::default() },
            HandshakeBudget { await_ack: Duration::ZERO, ..HandshakeBudget::default() },
            HandshakeBudget { await_pairing: Duration::ZERO, ..HandshakeBudget::default() },
        ] {
            assert!(budget.validate().is_err());
        }
    }

    #[test]
    fn the_default_hello_timeout_matches_the_protocol_limit() {
        // Two sources for the same number is how they drift apart.
        assert_eq!(HandshakeBudget::default().await_hello, limits::HELLO_TIMEOUT);
        assert_eq!(HandshakeBudget::default().await_ack, limits::HELLO_TIMEOUT);
    }

    #[test]
    fn refusal_reasons_round_trip_and_report_retryability() {
        for reason in [
            RefusalReason::ProtocolMismatch,
            RefusalReason::MissingRequiredFeature,
            RefusalReason::Blocked,
            RefusalReason::TooManyLinks,
            RefusalReason::Malformed,
        ] {
            let json = serde_json::to_string(&reason).expect("serialises");
            assert_eq!(json, format!("\"{}\"", reason.as_str()));
            let back: RefusalReason = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, reason);
        }

        assert!(RefusalReason::TooManyLinks.is_retryable());
        assert!(!RefusalReason::Blocked.is_retryable());
        assert!(!RefusalReason::ProtocolMismatch.is_retryable());
        assert!(!RefusalReason::MissingRequiredFeature.is_retryable());
        assert!(!RefusalReason::Malformed.is_retryable());
    }


    #[test]
    fn session_nonces_are_never_zero() {
        for _ in 0..64 {
            assert!(!SessionNonce::random().is_zero());
        }
        assert!(SessionNonce(0).is_zero());
        assert_eq!(SessionNonce(0xFF).to_hex().len(), 32);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arbitrary_features() -> impl Strategy<Value = Vec<Feature>> {
        proptest::collection::vec(0usize..Feature::ALL.len(), 0..8).prop_map(|indexes| {
            indexes
                .into_iter()
                .filter_map(|index| Feature::ALL.get(index).copied())
                .collect()
        })
    }

    proptest! {
        /// Negotiation is commutative and never invents a feature. A link agreeing on something the
        /// peer cannot do is the failure this function exists to prevent.
        #[test]
        fn negotiation_is_commutative_and_sound(
            ours in arbitrary_features(),
            theirs in arbitrary_features(),
            required in arbitrary_features(),
        ) {
            let forward = negotiate(&ours, &theirs, &required);
            let backward = negotiate(&theirs, &ours, &required);

            prop_assert_eq!(forward.common.len(), backward.common.len());
            for feature in &forward.common {
                prop_assert!(theirs.contains(feature), "agreed to something the peer lacks");
                prop_assert!(ours.contains(feature), "agreed to something we lack");
            }

            // Every required feature is either available or reported missing, never both and never
            // neither.
            for feature in &required {
                let available = forward.supports(*feature);
                let missing = forward.missing_required.contains(feature);
                prop_assert!(available != missing, "a required feature must be one or the other");
            }
            prop_assert_eq!(forward.is_usable(), forward.missing_required.is_empty());
        }


        /// A rebuildable hello either validates or reports why. It never panics, and anything that
        /// validates survives a trip through JSON unchanged.
        #[test]
        fn hellos_validate_and_round_trip(
            protocol in 0u16..3,
            sequence in any::<u64>(),
            features in arbitrary_features(),
            name_len in 0usize..80,
        ) {
            let hello = Hello {
                protocol,
                device_id: DeviceId::new(),
                display_name: "x".repeat(name_len),
                platform: PlatformKind::Desktop,
                app_version: "1.0.0".to_owned(),
                nonce: SessionNonce(1),
                features,
                requires: Vec::new(),
                sequence,
                endpoints: Vec::new(),
            };

            if hello.validate().is_ok() {
                let json = serde_json::to_string(&hello).expect("serialises");
                let back: Hello = serde_json::from_str(&json).expect("deserialises");
                prop_assert_eq!(back, hello);
            }
            else {
                // A rejected hello is rejected for a reason, never by panicking.
                prop_assert!(hello.validate().is_err());
            }
        }

        /// A sequence guard accepts each value at most once, whatever order they arrive in.
        ///
        /// `SequenceGuard::new()` starts at zero and only accepts strictly greater values, so zero is
        /// legitimately rejected without ever having been accepted. The property tracks that
        /// baseline rather than assuming an empty history.
        #[test]
        fn a_sequence_guard_accepts_each_value_at_most_once(
            values in proptest::collection::vec(any::<u64>(), 0..40)
        ) {
            let mut guard = SequenceGuard::new();
            let mut accepted: std::collections::HashSet<u64> = std::collections::HashSet::new();
            for value in values {
                if guard.accept(value).is_ok() {
                    prop_assert!(accepted.insert(value), "accepted {value} twice");
                }
                else if value > 0 {
                    // A positive value can only be refused if it is not newer than the high-water
                    // mark, which means it was accepted before.
                    prop_assert!(
                        accepted.contains(&value) || value <= guard.highest(),
                        "rejected {value} for no reason",
                    );
                }
            }
            prop_assert_eq!(guard.highest(), accepted.iter().copied().max().unwrap_or(0));
        }
    }
}


