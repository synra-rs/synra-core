use proptest::prelude::*;

use crate::limits;

use super::super::{DigestAlgorithm, ProgressBitmap, SriDigest, TransferWindow};

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
