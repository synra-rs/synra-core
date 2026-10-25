use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{RootCertStore, client::WebPkiServerVerifier, sign::CertifiedKey};
use sha2::{Digest, Sha256};
use synra_protocol::DeviceId;

use super::{AuthenticationError, MAX_CREDENTIAL_BYTES};

/// Long-lived local device credentials; deliberately neither serializable nor printable with `Debug`.
pub struct DeviceCredentials {
    peer: PeerIdentity,
    key: PrivatePkcs8KeyDer<'static>,
}

impl DeviceCredentials {
    /// Generates a new key and a self-signed certificate naming this device for ten years.
    ///
    /// Only call for explicit first enrollment or identity replacement, never as an automatic fallback
    /// when a previously enrolled device's private key is missing. `now_seconds` is Unix time.
    ///
    /// # Errors
    /// Returns an error for a nil id, invalid clock, unavailable randomness, or certificate generation failure.
    pub fn generate(device_id: DeviceId, now_seconds: u64) -> Result<Self, AuthenticationError> {
        let name = server_name(device_id)?;
        let mut params =
            rcgen::CertificateParams::new(vec![name.to_str().into_owned()]).map_err(invalid)?;
        let seconds = i64::try_from(now_seconds).map_err(invalid)?;
        let now = time::OffsetDateTime::from_unix_timestamp(seconds).map_err(invalid)?;
        params.not_before = now.checked_sub(time::Duration::days(1)).ok_or_else(|| {
            AuthenticationError::InvalidCredential("clock outside certificate range".to_owned())
        })?;
        params.not_after = now.checked_add(time::Duration::days(3650)).ok_or_else(|| {
            AuthenticationError::InvalidCredential("clock outside certificate range".to_owned())
        })?;
        let key = rcgen::KeyPair::generate().map_err(invalid)?;
        let certificate = params.self_signed(&key).map_err(invalid)?;
        Self::restore(
            device_id,
            certificate.der(),
            &key.serialize_der(),
            now_seconds,
        )
    }

    /// Restores the exact public certificate and PKCS#8 key from protected local storage.
    ///
    /// # Errors
    /// Rejects oversized or invalid credentials, a different device id, an expired certificate and a
    /// mismatched key; validation never generates replacement credentials.
    pub fn restore(
        device_id: DeviceId,
        certificate: &[u8],
        private_key: &[u8],
        now_seconds: u64,
    ) -> Result<Self, AuthenticationError> {
        check_size(private_key)?;
        let peer = PeerIdentity::from_certificate(device_id, certificate, now_seconds)?;
        let key = PrivatePkcs8KeyDer::from(private_key.to_vec());
        let certified = CertifiedKey::from_der(
            vec![peer.certificate.clone()],
            PrivateKeyDer::Pkcs8(key.clone_key()),
            &rustls::crypto::ring::default_provider(),
        )
        .map_err(invalid)?;
        // `from_der` accepts "consistency unknown"; this boundary requires a proven match.
        certified.keys_match().map_err(invalid)?;
        Ok(Self { peer, key })
    }

    /// The public credential that can be presented for out-of-band verification.
    #[must_use]
    pub const fn public_identity(&self) -> &PeerIdentity {
        &self.peer
    }

    /// The sensitive PKCS#8 bytes, for the protected secret backend only.
    #[must_use]
    pub fn private_key_der(&self) -> &[u8] {
        self.key.secret_pkcs8_der()
    }

    pub(super) fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key.clone_key())
    }
}

/// A validated public identity; the owning pairing service must separately establish user approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    device_id: DeviceId,
    pub(super) certificate: CertificateDer<'static>,
    fingerprint: [u8; 32],
}

impl PeerIdentity {
    /// Validates a certificate for the claimed device's DNS name and current Unix time.
    ///
    /// This checks a candidate credential, not the trustworthiness of the device presenting it.
    /// Use the certificate fingerprint in a verified pairing flow before approving this identity.
    ///
    /// # Errors
    /// Rejects nil device ids, oversized or malformed DER, expired certificates and wrong device names.
    pub fn from_certificate(
        device_id: DeviceId,
        certificate: &[u8],
        now_seconds: u64,
    ) -> Result<Self, AuthenticationError> {
        check_size(certificate)?;
        let name = server_name(device_id)?;
        let certificate = CertificateDer::from(certificate.to_vec());
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots(std::iter::once(certificate.clone()))?),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(invalid)?;
        verifier
            .verify_server_cert(
                &certificate,
                &[],
                &name,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(now_seconds)),
            )
            .map_err(invalid)?;
        let fingerprint = Sha256::digest(certificate.as_ref()).into();
        Ok(Self {
            device_id,
            certificate,
            fingerprint,
        })
    }

    /// Device id bound to this certificate during verification.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Public certificate DER, safe to store in the peer database.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    /// SHA-256 of the complete certificate DER; changing credentials requires a new approval.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

pub(super) fn roots(
    certificates: impl Iterator<Item = CertificateDer<'static>>,
) -> Result<RootCertStore, AuthenticationError> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(invalid)?;
    }
    Ok(roots)
}

pub(super) fn server_name(device_id: DeviceId) -> Result<ServerName<'static>, AuthenticationError> {
    if device_id.is_nil() {
        return Err(AuthenticationError::InvalidCredential(
            "nil device id".to_owned(),
        ));
    }
    ServerName::try_from(format!("{device_id}.synra.invalid")).map_err(invalid)
}

fn check_size(bytes: &[u8]) -> Result<(), AuthenticationError> {
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
        return Err(AuthenticationError::InvalidCredential(
            "credential size outside limit".to_owned(),
        ));
    }
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> AuthenticationError {
    AuthenticationError::InvalidCredential(error.to_string())
}
