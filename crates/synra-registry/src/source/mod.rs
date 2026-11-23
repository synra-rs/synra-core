//! Registry settings parsed before any request or configuration write.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};

/// The metadata protocol served by a configured source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RegistryKind {
    /// npm packuments and search endpoints at an origin.
    Npm,
    /// One JSON index per package under a directory prefix.
    Static,
}

/// Whether a normalized host names a loopback literal or the reserved localhost name.
#[must_use]
pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// A validated source. Credentials, query strings and insecure remote HTTP are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrySource {
    url: Url,
    host: String,
    secure: bool,
    loopback: bool,
    kind: RegistryKind,
}

/// A stable configuration failure, without embedding potentially secret input URLs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("registry source {index:?}: {reason}")]
pub struct ConfigError {
    /// Zero-based mirror position; absent for a scalar or whole-setting error.
    pub index: Option<usize>,
    /// The specific validation rule that failed.
    pub reason: ConfigReason,
}

/// Reasons a registry setting cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigReason {
    /// The whole value must be a URL string or an ordered array of URL strings.
    #[error("choose a URL string or an array of URL strings")]
    ValueType,
    /// Arrays cannot discard non-string members.
    #[error("every mirror must be a nonempty URL string")]
    MirrorType,
    /// The source is not a well-formed absolute URL.
    #[error("the registry must be a valid absolute URL with an authority")]
    InvalidUrl,
    /// Only the HTTP transports are registry protocols.
    #[error("the registry must use HTTPS or loopback HTTP")]
    Scheme,
    /// Credentials cannot be stored in a source URL.
    #[error("registry URLs must not contain credentials")]
    Credentials,
    /// Query and fragment data are not part of a registry base.
    #[error("registry URLs must not contain a query or fragment")]
    QueryOrFragment,
    /// npm endpoints are relative to an origin, not a custom path prefix.
    #[error("an npm registry must name only an origin")]
    NpmPath,
    /// HTTP is only for explicitly configured local mirrors.
    #[error("HTTP is permitted only for a loopback registry")]
    InsecureRemote,
}

/// Why npm metadata cannot select an artifact on the configured source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactError {
    /// Static metadata has its own relative artifact rules.
    #[error("the source does not use npm metadata")]
    NotNpm,
    /// The artifact address cannot be parsed.
    #[error("the artifact must name an absolute HTTP URL")]
    InvalidUrl,
    /// npm artifacts must remain on the configured origin.
    #[error("the artifact is not on the configured npm origin")]
    OriginMismatch,
    /// Credentials are not part of an artifact location.
    #[error("the artifact URL must not contain credentials")]
    Credentials,
    /// Fragments are not transmitted to an HTTP server.
    #[error("the artifact URL must not contain a fragment")]
    Fragment,
}

impl RegistrySource {
    /// Parse an npm URL or a `static:` URL with an optional directory prefix.
    ///
    /// # Errors
    /// Returns the failed source rule; parsing never contacts the source.
    pub fn parse(text: &str) -> Result<Self, ConfigReason> {
        let text = text.trim();
        let (text, kind) = text
            .strip_prefix("static:")
            .map_or((text, RegistryKind::Npm), |url| {
                (url.trim(), RegistryKind::Static)
            });
        if text
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
            || text.contains('\\')
        {
            return Err(ConfigReason::InvalidUrl);
        }
        let (_, authority) = text.split_once("://").ok_or(ConfigReason::InvalidUrl)?;
        if authority.is_empty() || authority.starts_with(['/', '?', '#']) {
            return Err(ConfigReason::InvalidUrl);
        }
        let parsed = Url::parse(text).map_err(|_| ConfigReason::InvalidUrl)?;
        let secure = match parsed.scheme() {
            "https" => true,
            "http" => false,
            _ => return Err(ConfigReason::Scheme),
        };
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ConfigReason::Credentials);
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ConfigReason::QueryOrFragment);
        }
        let host = match parsed.host().ok_or(ConfigReason::InvalidUrl)? {
            Host::Domain(host) => host.to_owned(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => ip.to_string(),
        };
        let loopback = is_loopback_host(&host);
        if !secure && !loopback {
            return Err(ConfigReason::InsecureRemote);
        }
        if kind == RegistryKind::Npm && !parsed.path().trim_matches('/').is_empty() {
            return Err(ConfigReason::NpmPath);
        }
        Ok(Self {
            url: parsed,
            host,
            secure,
            loopback,
            kind,
        })
    }

    /// The normalized address, without the `static:` discriminator or trailing slash.
    #[must_use]
    pub fn url(&self) -> &str {
        self.url.as_str().trim_end_matches('/')
    }

    /// Read an npm artifact's canonical path and query after checking the actual URL origin.
    /// Default ports, host casing and IPv6 are compared by the same URL parser as configuration.
    ///
    /// # Errors
    /// Refuses cross-origin metadata, credentials, fragments, malformed URLs or non-npm sources.
    pub fn npm_artifact_path(&self, text: &str) -> Result<String, ArtifactError> {
        if self.kind != RegistryKind::Npm {
            return Err(ArtifactError::NotNpm);
        }
        let parsed = Url::parse(text).map_err(|_| ArtifactError::InvalidUrl)?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ArtifactError::Credentials);
        }
        if parsed.fragment().is_some() {
            return Err(ArtifactError::Fragment);
        }
        if parsed.origin() != self.url.origin() {
            return Err(ArtifactError::OriginMismatch);
        }
        let mut path = parsed.path().to_owned();
        if let Some(query) = parsed.query() {
            path.push('?');
            path.push_str(query);
        }
        Ok(path)
    }

    /// The normalized host without IPv6 brackets, suitable for a network capability.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether this source uses HTTPS.
    #[must_use]
    pub const fn secure(&self) -> bool {
        self.secure
    }

    /// Whether the configured host is a loopback literal or `localhost`.
    #[must_use]
    pub const fn loopback(&self) -> bool {
        self.loopback
    }

    /// Which metadata protocol to use.
    #[must_use]
    pub const fn kind(&self) -> RegistryKind {
        self.kind
    }
}

/// Ordered source configuration; an empty source list explicitly means no source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistryConfig {
    sources: Vec<RegistrySource>,
}

impl RegistryConfig {
    /// Read the existing string/array setting without dropping malformed array members.
    /// Missing settings, blank scalar strings and empty arrays mean unconfigured.
    ///
    /// # Errors
    /// Returns the whole-setting or zero-based mirror error before any network request.
    pub fn parse(value: Option<&Value>) -> Result<Self, ConfigError> {
        let parse = |text: &str, index| {
            RegistrySource::parse(text).map_err(|reason| ConfigError { index, reason })
        };
        let sources = match value {
            None => Vec::new(),
            Some(Value::String(text)) if text.trim().is_empty() => Vec::new(),
            Some(Value::String(text)) => vec![parse(text, None)?],
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let text = item.as_str().filter(|text| !text.trim().is_empty()).ok_or(
                        ConfigError {
                            index: Some(index),
                            reason: ConfigReason::MirrorType,
                        },
                    )?;
                    parse(text, Some(index))
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(ConfigError {
                    index: None,
                    reason: ConfigReason::ValueType,
                });
            }
        };
        Ok(Self { sources })
    }

    /// Sources in the user's mirror order.
    #[must_use]
    pub fn sources(&self) -> &[RegistrySource] {
        &self.sources
    }
}

#[cfg(test)]
mod tests;
