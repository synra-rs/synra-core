//! Configured npm mirrors and static indexes, without silently choosing a public registry.

use synra_control::Refusal;
use synra_protocol::error::ErrorCode;
use synra_registry::{Packument, RegistryKind, RegistrySource as Base, Version};

use super::super::registry_install::NetworkFetch;

#[cfg(test)]
pub(super) use synra_core::plugin_updates::REGISTRY_KEY;

pub(super) struct Sources {
    bases: Vec<Base>,
}

pub(super) struct Document {
    pub(super) document: Packument,
    source: Base,
    index: Option<String>,
}

impl Sources {
    pub(super) fn parse(raw: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|error| error.to_string())?;
        let config = synra_registry::RegistryConfig::parse(Some(&value))
            .map_err(|error| error.to_string())?;
        let bases = config.sources().to_vec();
        if bases.is_empty() {
            return Err("plugins.registry names no registry".to_owned());
        }
        Ok(Self { bases })
    }

    pub(super) fn read(
        &self,
        package: &str,
        cancel: &synra_core::supervisor::Cancellation,
    ) -> Result<Document, String> {
        let mut failures = Vec::new();
        for base in &self.bases {
            if cancel.is_cancelled() {
                return Err("the update check was cancelled".to_owned());
            }
            let path = if base.kind() == RegistryKind::Static {
                format!("/{package}.json")
            } else {
                format!("/{}", package.replace('/', "%2F"))
            };
            let url = format!("{}{path}", base.url());
            let response = match (NetworkFetch {
                allow_loopback: base.loopback(),
            })
            .response(&url, 8 * 1024 * 1024)
            {
                Ok(response) => response,
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            };
            if !(200..300).contains(&response.status) {
                let error = format!("{url} answered {}", response.status);
                if retryable(response.status) {
                    failures.push(error);
                    continue;
                }
                return Err(error);
            }
            let parsed = std::str::from_utf8(&response.body)
                .map_err(|error| error.to_string())
                .and_then(|text| {
                    if base.kind() == RegistryKind::Static {
                        synra_registry::parse_static_index(text)
                            .map(|index| index.document)
                            .map_err(|error| error.to_string())
                    } else {
                        Packument::parse(text).map_err(|error| error.to_string())
                    }
                });
            let document = match parsed {
                Ok(document) => document,
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            };
            if document.name != package
                || document
                    .versions
                    .values()
                    .any(|entry| entry.name != package)
            {
                return Err("the registry answered for a different package".to_owned());
            }
            return Ok(Document {
                document,
                source: base.clone(),
                index: (base.kind() == RegistryKind::Static).then_some(url),
            });
        }
        Err(failures.join("; "))
    }

    pub(super) fn download(
        &self,
        document: &Document,
        chosen: &Version,
        staging: &std::path::Path,
        now_ms: i64,
        cancel: &synra_core::supervisor::Cancellation,
    ) -> Result<synra_core::install::UnpackedTarball, Refusal> {
        let urls = self
            .tarballs(document, &chosen.dist.tarball)
            .map_err(|error| Refusal::new(ErrorCode::InvalidArgument, error))?;
        let mut failures = Vec::new();
        for (url, loopback) in urls {
            if cancel.is_cancelled() {
                return Err(Refusal::new(
                    ErrorCode::InvalidArgument,
                    "the update download was cancelled",
                ));
            }
            let response = match (NetworkFetch {
                allow_loopback: loopback,
            })
            .response(&url, 64 * 1024 * 1024 + 1)
            {
                Ok(response) => response,
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            };
            if !(200..300).contains(&response.status) {
                let error = format!("{url} answered {}", response.status);
                if retryable(response.status) {
                    failures.push(error);
                    continue;
                }
                return Err(Refusal::new(ErrorCode::Unsupported, error));
            }
            // Integrity failures stop here; another mirror must never bypass the failed verification.
            return synra_core::install::unpack_published_tarball(
                &response.body,
                chosen.dist.integrity.as_deref(),
                &url,
                staging,
                now_ms,
            )
            .map_err(|error| {
                Refusal::new(error.code(), format!("{}: {}", error.stage, error.reason))
            });
        }
        Err(Refusal::new(ErrorCode::DeviceOffline, failures.join("; ")))
    }

    fn tarballs(&self, document: &Document, tarball: &str) -> Result<Vec<(String, bool)>, String> {
        if let Some(index) = &document.index {
            return Ok(vec![(resolve(index, tarball)?, document.source.loopback())]);
        }
        let path = document
            .source
            .npm_artifact_path(tarball)
            .map_err(|error| error.to_string())?;
        let mut urls = vec![(
            format!("{}{path}", document.source.url()),
            document.source.loopback(),
        )];
        urls.extend(
            self.bases
                .iter()
                .filter(|base| {
                    base.kind() == RegistryKind::Npm && base.url() != document.source.url()
                })
                .map(|base| (format!("{}{path}", base.url()), base.loopback())),
        );
        Ok(urls)
    }
}

fn resolve(index: &str, tarball: &str) -> Result<String, String> {
    if tarball.starts_with("https://") || tarball.starts_with("http://") {
        return Ok(tarball.to_owned());
    }
    if tarball.is_empty()
        || tarball.split('/').any(|part| part == "..")
        || tarball.contains([':', '?', '#'])
        || tarball.starts_with("//")
    {
        return Err("the index names an invalid relative tarball".to_owned());
    }
    if tarball.starts_with('/') {
        let (scheme, rest) = index
            .split_once("://")
            .ok_or("the index URL is not absolute")?;
        let authority = rest.split('/').next().ok_or("the index URL has no host")?;
        return Ok(format!("{scheme}://{authority}{tarball}"));
    }
    let (directory, _) = index
        .rsplit_once('/')
        .ok_or("the index URL is not absolute")?;
    Ok(format!("{directory}/{tarball}"))
}

const fn retryable(status: u16) -> bool {
    matches!(status, 404 | 408 | 429 | 500..=599)
}
