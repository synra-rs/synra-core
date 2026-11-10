//! Signing and verifying plugin packages.

use super::Outcome;

/// Signs a plugin, or checks a signature.
///
/// # Errors
///
/// The signing error, as a sentence: a key that cannot be read, a manifest that does not parse, an artifact that is
/// not there.
pub fn sign_plugin(args: &crate::args::SignArgs) -> Result<Outcome, String> {
    // Generating a key is its own command because there is nothing to sign yet: an author does this once, before the
    // first publish, and printing the secret is the point — a tool that hid it would be one whose keys they cannot back
    // up, and a publisher who loses theirs cannot ship an update to a plugin users already trust.
    if args.generate_key {
        let key = crate::sign::SigningKeyFile::generate()?;
        return Ok(Outcome::Reported {
            lines: vec![
                "a new signing key. Keep the secret somewhere you can restore it from, and publish the public half."
                    .to_owned(),
                String::new(),
                format!("secret  {}", key.to_hex()),
                format!("public  {}", key.public_hex()),
            ],
            code: 0,
            failure: false,
        });
    }

    let content = crate::sign::SignedContent::read(&args.dir).map_err(|error| error.to_string())?;

    if let Some(signature_path) = &args.verify {
        let document = std::fs::read_to_string(signature_path).map_err(|error| {
            format!("the signature at {} could not be read: {error}", signature_path.display())
        })?;

        // ★ The trust store is **empty** here, and that is the honest answer for this command: an author checking
        // their own package has not made a decision about their own publisher, and a tool that trusted whatever it was
        // given would be a tool that verified nothing about who signed. What this proves is that the signature matches
        // the bytes — which is what the author is asking.
        let store = synra_plugin_api::publisher::PublisherTrustStore::new();
        let outcome = crate::sign::verify(&document, &args.dir, &store);

        // The key the author keeps beside the package, when there is one, is what makes this a check rather than a
        // formality: a signature by a key that is not the one they wrote down is a signature by somebody else.
        let pinned = crate::sign::expected_fingerprint(&args.dir);
        let pinned_matches = match (&outcome, &pinned) {
            (Ok(verified), Some(expected)) => verified.fingerprint == *expected,
            _ => true,
        };

        let ok = outcome.is_ok() && pinned_matches;
        let line = match (&outcome, ok) {
            (Ok(verified), true) => format!(
                "{} {} is signed by {} ({})",
                verified.plugin_id, verified.version, verified.publisher_id, verified.fingerprint
            ),
            (Ok(verified), false) => format!(
                "{} {} is signed, but not by the key in public-key.txt ({})",
                verified.plugin_id, verified.version, verified.fingerprint
            ),
            (Err(error), _) => format!(
                "the signature does not verify against {} {}: {error}",
                content.plugin_id, content.version
            ),
        };

        return Ok(Outcome::Reported {
            lines: vec![line],
            code: if ok { 0 } else { 1 },
            failure: !ok,
        });
    }

    let Some(key_path) = &args.key else {
        return Err("a signature needs `--key <path>`, or `--generate-key` to make one first".to_owned());
    };
    let key = crate::sign::SigningKeyFile::read(key_path).map_err(|error| error.to_string())?;
    let signature = key.sign(&content, &signed_at_now());

    Ok(Outcome::Signature {
        path: args.dir.join(synra_plugin_api::publisher::SIGNATURE_FILE),
        signature,
        public: key.public_hex(),
        lines: vec![
            format!("signed {} {}", content.plugin_id, content.version),
            format!("publisher {}", content.publisher_id),
            format!("fingerprint {}", key.fingerprint()),
        ],
    })
}

/// The moment a signature was made, as the document records it.
///
/// # Why this is not trusted by anything
///
/// It is a claim by whoever signed: a verifier that used it to decide which of two packages is newer would be letting
/// the package choose its own ordering. It is here so a person reading a `signature.json` in a repository can see when
/// it was made.
fn signed_at_now() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    format!("unix-ms:{millis}")
}


