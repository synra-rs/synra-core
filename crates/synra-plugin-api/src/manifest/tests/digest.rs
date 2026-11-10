use super::super::types::manifest_digest;

#[test]
fn the_manifest_digest_is_sha256_of_the_bytes_it_was_given() {
    // ★ The expected value is the **published NIST vector** for SHA-256("abc"), not a value this build computed and
    // wrote down. That distinction is the whole test: a constant recorded from our own output would pass against a
    // wrong implementation just as happily, because it would have been produced by that implementation.
    //
    // The property being pinned is that two callers agree to the byte — the shell records a decision against this
    // value and the daemon refuses a plugin whose manifest no longer hashes to it. A construction that drifted (a
    // different algorithm, a prefix, a trailing newline) would mismatch on every plugin.
    assert_eq!(
        manifest_digest("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn two_manifests_that_differ_in_their_bytes_have_different_digests() {
    // The direction that makes the column useful: a plugin that ships an update declaring one more capability is a
    // different document, and the rows decided about the old one must be visibly older. Whitespace counts, because
    // the bytes are what the user's file actually says — and a digest over the *parsed* value would call these two
    // the same.
    let a = r#"{"capabilities":[{"cap":"log:*"}]}"#;
    let b = r#"{"capabilities":[{"cap":"log:*"},{"cap":"device:list"}]}"#;
    let c = r#"{"capabilities": [{"cap":"log:*"}]}"#;

    assert_ne!(
        manifest_digest(a),
        manifest_digest(b),
        "a capability was added"
    );
    assert_ne!(
        manifest_digest(a),
        manifest_digest(c),
        "the bytes differ, so the document differs"
    );
    assert_eq!(
        manifest_digest(a),
        manifest_digest(a),
        "and the same bytes always agree"
    );
}
