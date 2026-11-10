use super::super::SigningKeyFile;
use super::key;

#[test]
fn a_key_round_trips_through_its_hex() {
    let original = key(7);
    let again = SigningKeyFile::parse(&original.to_hex()).expect("parses");
    assert_eq!(again.to_hex(), original.to_hex());
    assert_eq!(again.public_hex(), original.public_hex());
    assert_eq!(again.fingerprint(), original.fingerprint());
    assert_eq!(original.to_hex().len(), 64);
    assert_eq!(original.public_hex().len(), 64);
}

#[test]
fn a_public_key_is_not_the_secret() {
    // The failure this asserts against: a `public_hex` that returned the secret would publish the key that signs.
    let signing = key(7);
    assert_ne!(signing.public_hex(), signing.to_hex());
    assert_ne!(signing.public_base64(), signing.to_hex());
}

#[test]
fn a_generated_key_is_a_key_and_is_not_the_same_twice() {
    let first = SigningKeyFile::generate().expect("randomness");
    let second = SigningKeyFile::generate().expect("randomness");
    assert_eq!(first.to_hex().len(), 64);
    assert_ne!(first.to_hex(), second.to_hex());
    assert_ne!(first.public_hex(), second.public_hex());
}

#[test]
fn a_key_file_that_is_not_a_key_is_refused_by_name() {
    for wrong in ["", "abc", "zz", &"a".repeat(62)] {
        match SigningKeyFile::parse(wrong) {
            Err(reason) => assert!(!reason.is_empty(), "{wrong}"),
            Ok(_) => panic!("{wrong} was accepted as a key"),
        }
    }
    // And hex is case-insensitive, because a key written down by hand may be either.
    assert_eq!(
        SigningKeyFile::parse(&key(7).to_hex().to_uppercase()).expect("parses").to_hex(),
        key(7).to_hex()
    );
}
