//! Falsifies whether standard mutual TLS can authenticate a previously verified device identity.
//!
//! This detached spike does not implement initial pairing, credential storage policy or a production transport.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// A certificate and its private signing key; deliberately has no `Debug` implementation.
pub struct Identity {
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
}

impl Identity {
    /// Generates one device's self-signed credential using the library's random key generation.
    ///
    /// # Errors
    ///
    /// Returns the certificate generator's error if randomness or signing is unavailable.
    pub fn generate() -> Result<Self, rcgen::Error> {
        let generated = rcgen::generate_simple_self_signed(vec!["synra.device".to_owned()])?;
        Ok(Self {
            certificate: generated.cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()),
        })
    }

    /// The public credential approved out of band before configuring this spike's trusted connection.
    #[must_use]
    pub fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }

    fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key.clone_key())
    }
}

fn roots(peer: CertificateDer<'static>) -> Result<RootCertStore, rustls::Error> {
    let mut roots = RootCertStore::empty();
    roots.add(peer)?;
    Ok(roots)
}

/// Requires a client proving possession of the key belonging to the approved peer credential.
///
/// Uses the standard WebPKI verifier, TLS 1.3 only, and no resumable tickets or early application data.
///
/// # Errors
///
/// Returns an error for invalid or mismatched local credentials or an unusable peer trust anchor.
pub fn server(
    identity: &Identity,
    peer: CertificateDer<'static>,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots(peer)?),
        Arc::clone(&provider),
    )
    .build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.certificate()], identity.key())?;
    config.alpn_protocols = vec![b"synra/1".to_vec()];
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(config)
}

/// Authenticates the approved server and presents this device's credential when supplied.
///
/// `None` deliberately models an anonymous client for rejection tests, not a permitted business connection.
///
/// # Errors
///
/// Returns an error for invalid credentials or trust anchors.
pub fn client(
    identity: Option<&Identity>,
    peer: CertificateDer<'static>,
) -> Result<ClientConfig, rustls::Error> {
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots(peer)?);
    let mut config = match identity {
        Some(identity) => {
            builder.with_client_auth_cert(vec![identity.certificate()], identity.key())?
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"synra/1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

#[cfg(test)]
mod tests;
