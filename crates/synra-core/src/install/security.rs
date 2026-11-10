use synra_plugin_api::publisher::{Fingerprint, PublisherTrustStore, SignatureFile, VerifyOutcome};

use super::*;

/// The publisher decisions this device has made, in the shape the verifier takes.
///
/// A malformed fingerprint is skipped rather than failing the install: the row is this device's own record, and a
/// package must not be refused because a storage row cannot be read — the signature was checked regardless.
pub(crate) fn trust_store(db: &synra_store::SynraDb) -> PublisherTrustStore {
    let mut store = PublisherTrustStore::new();
    for row in db.publishers().unwrap_or_default() {
        let Ok(fingerprint) = Fingerprint::parse(&row.fingerprint) else {
            continue;
        };
        match row.trust.as_str() {
            synra_store::TRUST_TRUSTED => store.trust(row.publisher_id, fingerprint),
            synra_store::TRUST_REVOKED => store.revoke(fingerprint, "the user revoked this key"),
            _ => {}
        }
    }
    store
}

/// The publisher of a signature this build verified, if it is one.
pub(crate) fn signed_publisher(signature: &str) -> Option<SignedPublisher> {
    let document = SignatureFile::parse(signature).ok()?;
    let VerifyOutcome::Good { fingerprint } = document.verify().ok()? else {
        return None;
    };
    Some(SignedPublisher {
        publisher_id: document.publisher.id.clone(),
        fingerprint: fingerprint.as_str().to_owned(),
        pubkey: document.pubkey,
    })
}
