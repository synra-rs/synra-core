use std::io::Read;
use std::path::Path;

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use synra_protocol::session::{DigestAlgorithm, SriDigest};

use super::error::TransferError;

/// A whole-object digest, as the wire carries it.
///
/// # Why this exists rather than a bare string
///
/// Because `SriDigest` holds an algorithm *and* a value, and the two have to agree — a 43-character base64 string means
/// SHA-256 and nothing else. Computing the value and the algorithm together is what stops a caller pairing a SHA-256 value
/// with a different algorithm name, which is a mistake that would only surface at the far end of a transfer.
#[derive(Debug, Clone)]
pub struct ObjectDigest {
    digest: SriDigest,
}

impl ObjectDigest {
    /// Hashes bytes that are already in memory.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self::from_hasher(hasher)
    }

    /// Streams a reader to the end, hashing as it goes.
    ///
    /// # Errors
    ///
    /// [`TransferError::Read`] when the reader fails. The digest of a file that could not be read is not a digest of the
    /// file, and returning one would make a truncated object look intact.
    pub fn of_reader(path: &Path, reader: &mut impl Read) -> Result<Self, TransferError> {
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer).map_err(|error| TransferError::Read {
                path: path.to_path_buf(),
                why: error.to_string(),
            })?;
            if read == 0 {
                break;
            }
            // The slice is bounded by the read count, which the reader guarantees is no more than the buffer.
            let chunk = buffer.get(..read).ok_or_else(|| TransferError::Read {
                path: path.to_path_buf(),
                why: "the reader reported more bytes than the buffer".to_owned(),
            })?;
            hasher.update(chunk);
        }
        Ok(Self::from_hasher(hasher))
    }

    fn from_hasher(hasher: Sha256) -> Self {
        let bytes = hasher.finalize();
        // Base64 **without padding**, which is the form `SriDigest` accepts: standard alphabet, no `=`.
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        // The value is 32 bytes encoded, so it has exactly the length SHA-256 declares — the constructor's only failure
        // here would be a bug in this crate, and a fallback that produced a wrong-length value would be worse than the
        // wrong answer being visible.
        match SriDigest::new(DigestAlgorithm::Sha256, encoded) {
            Ok(digest) => Self { digest },
            Err(why) => {
                debug_assert!(false, "this crate produced an unusable digest: {why}");
                // An empty SHA-256 digest is still 43 characters, so a caller that reaches this keeps a *value* of the
                // right shape rather than a panic in a library. The debug assertion above is where a developer sees it.
                Self::of(b"")
            }
        }
    }

    /// The wire form.
    #[must_use]
    pub const fn as_sri(&self) -> &SriDigest {
        &self.digest
    }

    /// The encoded value, without the algorithm prefix.
    #[must_use]
    pub fn encoded(&self) -> &str {
        self.digest.encoded()
    }

    /// Whether two digests name the same bytes.
    #[must_use]
    pub fn matches(&self, other: &SriDigest) -> bool {
        // Compared through the encoded form rather than through a derived `PartialEq`, because `SriDigest`'s equality is
        // the protocol's to define and this asks a narrower question: do these two describe the same bytes.
        self.digest.algorithm() == other.algorithm() && self.digest.encoded() == other.encoded()
    }
}
