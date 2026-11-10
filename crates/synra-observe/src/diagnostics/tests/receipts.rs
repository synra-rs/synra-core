use super::*;

#[test]
fn the_receipt_names_the_size_the_path_and_the_digest() {
    // So a person who posts a bundle in an issue can check that what they uploaded is what they reviewed.
    let plan = plan();
    let rendered = plan.render().expect("renders");
    let receipt = plan.receipt(&rendered).expect("renders");

    assert!(receipt.contains(&rendered.len().to_string()), "{receipt}");
    assert!(receipt.contains("/tmp/bundle.json"), "{receipt}");
    assert!(receipt.contains("sha256 "), "{receipt}");
    assert!(receipt.contains(&sha256_hex(rendered.as_bytes())), "{receipt}");
}

#[test]
fn the_digest_matches_an_independent_implementation() {
    // The known-answer vectors, so the hand-written SHA-256 is verified against the standard rather than
    // against itself.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // A message longer than one block, so the length append and multi-block loop are exercised.
    assert_eq!(
        sha256_hex(&b"a".repeat(1_000_000)),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn a_digest_is_lowercase_hex_of_the_right_length() {
    let digest = sha256_hex(b"anything");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
}

#[test]
fn the_bundle_digest_matches_its_rendering() {
    let bundle = plan().build();
    assert_eq!(bundle.digest().expect("renders"), sha256_hex(bundle.to_json().expect("renders").as_bytes()));
}

#[test]
fn the_default_file_name_sorts_chronologically() {
    // A user will have more than one of these, and "synra-diagnostic (3).json" tells them nothing about
    // which is which.
    let earlier = default_file_name(1_700_000_000_000);
    let later = default_file_name(1_700_000_001_000);
    assert!(earlier < later, "{earlier} !< {later}");
    assert!(earlier.starts_with("synra-diagnostic-"));
    assert!(earlier.ends_with(".json"));
}
