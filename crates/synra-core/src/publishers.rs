//! Explicit decisions about publisher keys, shared by graphical and headless hosts.

use synra_plugin_api::publisher::Fingerprint;
use synra_protocol::error::ErrorCode;
use synra_store::{PublisherRow, SynraDb, TRUST_REVOKED, TRUST_SEEN, TRUST_TRUSTED};

/// Why a publisher decision could not be recorded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecisionError {
    /// The request does not identify a known key or a supported decision.
    #[error("{reason}")]
    Invalid {
        /// What the caller must correct.
        reason: String,
    },
    /// The store could not read or write the decision.
    #[error("could not record the publisher decision: {source}")]
    Storage {
        /// The store's failure.
        source: synra_store::DbError,
    },
}

impl DecisionError {
    /// The protocol classification both hosts report.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Invalid { .. } => ErrorCode::InvalidArgument,
            Self::Storage { .. } => ErrorCode::Internal,
        }
    }
}

/// Records a decision only for a previously recorded publisher and the fingerprint the user confirmed.
///
/// Trusting a publisher does not enable a plugin or grant capabilities. This does not approve a changed key: first
/// releases retain one key per publisher, and a trusted publisher's changed key still fails normal verification.
///
/// # Errors
/// [`DecisionError::Invalid`] for an unknown publisher, malformed or stale fingerprint, or unsupported trust value;
/// [`DecisionError::Storage`] when the database cannot be accessed.
pub fn decide(
    db: &SynraDb,
    publisher_id: &str,
    fingerprint: &str,
    trust: &str,
    now_ms: i64,
) -> Result<PublisherRow, DecisionError> {
    if publisher_id.is_empty() || publisher_id.len() > 256 {
        return Err(invalid("publisher id must be 1–256 bytes"));
    }
    if ![TRUST_SEEN, TRUST_TRUSTED, TRUST_REVOKED].contains(&trust) {
        return Err(invalid("trust must be seen, trusted or revoked"));
    }
    if !fingerprint
        .chars()
        .all(|character| character.is_ascii_hexdigit() || matches!(character, ' ' | ':' | '-'))
    {
        return Err(invalid(
            "fingerprint must contain 16 hex digits and optional separators",
        ));
    }
    let fingerprint =
        Fingerprint::parse(fingerprint).map_err(|error| invalid(error.to_string()))?;
    let mut row = db
        .publishers()
        .map_err(storage)?
        .into_iter()
        .find(|row| row.publisher_id == publisher_id)
        .ok_or_else(|| invalid("no verified signature from this publisher was recorded"))?;
    if row.fingerprint != fingerprint.as_str()
        || !db
            .set_publisher_trust(publisher_id, fingerprint.as_str(), trust, now_ms)
            .map_err(storage)?
    {
        return Err(invalid(
            "publisher key changed or the fingerprint does not match; list publishers again",
        ));
    }
    row.trust = trust.to_owned();
    row.decided_ms = Some(now_ms);
    Ok(row)
}

fn invalid(reason: impl Into<String>) -> DecisionError {
    DecisionError::Invalid {
        reason: reason.into(),
    }
}

const fn storage(error: synra_store::DbError) -> DecisionError {
    DecisionError::Storage { source: error }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_confirmed_key_can_receive_a_decision() {
        let mut db = SynraDb::open_in_memory().expect("database");
        db.migrate().expect("schema");
        db.record_publisher("@acme", "AB12 CD34 EF56 7890", "key", 1)
            .expect("sighting");
        for (id, fingerprint, trust) in [
            ("@ghost", "AB12 CD34 EF56 7890", "trusted"),
            ("@acme", "1111 2222 3333 4444", "trusted"),
            ("@acme", "", "trusted"),
            ("@acme", "AB12!CD34 EF56 7890", "trusted"),
            ("@acme", "AB12 CD34 EF56 7890", "maybe"),
        ] {
            assert_eq!(
                decide(&db, id, fingerprint, trust, 2)
                    .expect_err("refused")
                    .code(),
                ErrorCode::InvalidArgument
            );
            assert_eq!(db.publishers().expect("rows")[0].decided_ms, None);
        }
        for trust in [TRUST_TRUSTED, TRUST_REVOKED, TRUST_SEEN] {
            let row = decide(&db, "@acme", "ab12-cd34-ef56-7890", trust, 3).expect("decision");
            assert_eq!(row.trust, trust);
            assert_eq!(row.decided_ms, Some(3));
            assert_eq!(db.publishers().expect("rows")[0], row);
        }
    }
}
