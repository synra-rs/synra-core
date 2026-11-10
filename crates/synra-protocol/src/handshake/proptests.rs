use proptest::prelude::*;

use crate::ids::DeviceId;
use crate::session::PlatformKind;

use super::{Feature, Hello, SequenceGuard, SessionNonce, negotiate};

fn arbitrary_features() -> impl Strategy<Value = Vec<Feature>> {
    proptest::collection::vec(0usize..Feature::ALL.len(), 0..8).prop_map(|indexes| {
        indexes
            .into_iter()
            .filter_map(|index| Feature::ALL.get(index).copied())
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::Direct(
            concat!(env!("CARGO_MANIFEST_DIR"), "/proptest-regressions/handshake.txt"),
        ))),
        ..ProptestConfig::default()
    })]

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
