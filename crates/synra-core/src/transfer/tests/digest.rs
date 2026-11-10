use synra_protocol::session::DigestAlgorithm;

use crate::test_support::{file, temp_dir};

use super::super::ObjectDigest;

#[test]
fn the_digest_matches_the_published_sha256_of_an_empty_input() {
    // ★ A published vector rather than this crate's own output: a hash implementation checked against itself proves
    // only that it is consistent. SHA-256 of the empty string is a well-known constant.
    let digest = ObjectDigest::of(b"");
    assert_eq!(
        digest.encoded(),
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
    );
}

#[test]
fn the_digest_matches_the_published_sha256_of_abc() {
    // The other classic vector, and the two together pin both the padding path and the short-input path.
    let digest = ObjectDigest::of(b"abc");
    assert_eq!(
        digest.encoded(),
        "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0"
    );
}

#[test]
fn the_digest_is_accepted_by_the_protocols_own_validator() {
    // ★ The value this crate produces has to satisfy `SriDigest`, which checks the length and the alphabet. A digest
    // that its own protocol refuses would make every transfer unproposable.
    let digest = ObjectDigest::of(b"anything");
    // Through the accessor, because `SriDigest`'s fields are private and the validation already happened in `of`.
    assert_eq!(digest.as_sri().algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(digest.encoded().len(), 43, "SHA-256 base64 without padding is 43 characters");
    assert!(!digest.encoded().contains('='), "padding is not part of the wire form");
}

#[test]
fn the_same_bytes_hash_the_same_way_twice() {
    let once = ObjectDigest::of(b"repeated");
    let twice = ObjectDigest::of(b"repeated");
    assert!(once.matches(twice.as_sri()));
}

#[test]
fn different_bytes_hash_differently() {
    let one = ObjectDigest::of(b"one");
    let other = ObjectDigest::of(b"two");
    assert!(!one.matches(other.as_sri()));
}

#[test]
fn streaming_a_file_hashes_the_whole_thing() {
    // A file larger than the streaming buffer, so the loop runs more than once and the tail is exercised.
    let dir = temp_dir("digest-stream");
    let bytes = vec![0xA5u8; 200 * 1024];
    let path = file(&dir, "big.bin", &bytes);

    let mut handle = std::fs::File::open(&path).expect("opens");
    let streamed = ObjectDigest::of_reader(&path, &mut handle).expect("hashes");
    // The streaming form and the one-shot form must agree, because a sender uses one and a receiver the other.
    assert!(streamed.matches(ObjectDigest::of(&bytes).as_sri()));
}
