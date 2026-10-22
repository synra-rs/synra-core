//! Configured npm mirrors and static indexes, without silently choosing a public registry.

use synra_registry::{Packument, Version};

use super::super::registry_install::NetworkFetch;

#[cfg(test)]
pub(super) use synra_core::plugin_updates::REGISTRY_KEY;

#[derive(Debug)]
struct Base {
    url: String,
    is_static: bool,
    loopback: bool,
}

pub(super) struct Sources {
    bases: Vec<Base>,
}

pub(super) struct Document {
    pub(super) document: Packument,
    base: String,
    index: Option<String>,
    loopback: bool,
}

impl Sources {
    pub(super) fn parse(raw: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|error| error.to_string())?;
        let urls: Vec<String> = match value {
            serde_json::Value::String(url) => vec![url],
            serde_json::Value::Array(urls) => urls
                .into_iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "every registry must be a URL".to_owned())
                })
                .collect::<Result<_, _>>()?,
            _ => return Err("plugins.registry must be a URL or an array of URLs".to_owned()),
        };
        let bases = urls
            .iter()
            .map(|url| parse_base(url))
            .collect::<Result<Vec<_>, _>>()?;
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
            let path = if base.is_static {
                format!("/{package}.json")
            } else {
                format!("/{}", package.replace('/', "%2F"))
            };
            let url = format!("{}{path}", base.url);
            let response = match (NetworkFetch {
                allow_loopback: base.loopback,
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
                    if base.is_static {
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
                base: base.url.clone(),
                index: base.is_static.then_some(url),
                loopback: base.loopback,
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
    ) -> Result<synra_core::install::UnpackedTarball, String> {
        let urls = self.tarballs(document, &chosen.dist.tarball)?;
        let mut failures = Vec::new();
        for (url, loopback) in urls {
            if cancel.is_cancelled() {
                return Err("the update download was cancelled".to_owned());
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
                return Err(error);
            }
            // Integrity failures stop here; another mirror must never bypass the failed verification.
            return synra_core::install::unpack_published_tarball(
                &response.body,
                chosen.dist.integrity.as_deref(),
                &url,
                staging,
                now_ms,
            )
            .map_err(|error| format!("{}: {}", error.stage, error.reason));
        }
        Err(failures.join("; "))
    }

    fn tarballs(&self, document: &Document, tarball: &str) -> Result<Vec<(String, bool)>, String> {
        if let Some(index) = &document.index {
            return Ok(vec![(resolve(index, tarball)?, document.loopback)]);
        }
        let path = tarball
            .strip_prefix(&document.base)
            .filter(|path| path.starts_with('/'))
            .ok_or_else(|| "the tarball is not on the configured npm registry".to_owned())?;
        let mut urls = vec![(tarball.to_owned(), document.loopback)];
        urls.extend(
            self.bases
                .iter()
                .filter(|base| !base.is_static && base.url != document.base)
                .map(|base| (format!("{}{path}", base.url), base.loopback)),
        );
        Ok(urls)
    }
}

fn parse_base(text: &str) -> Result<Base, String> {
    let text = text.trim();
    let (url, is_static) = text
        .strip_prefix("static:")
        .map_or((text, false), |url| (url.trim(), true));
    let url = url.trim_end_matches('/');
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| "a registry must use https or loopback http".to_owned())?;
    if rest.is_empty() || rest.contains(['?', '#', '@']) || (!is_static && rest.contains('/')) {
        return Err("the registry URL contains an invalid authority or path".to_owned());
    }
    let parsed = synra_core::network::NetworkGuard::for_hosts(&[])
        .allowing_insecure(true)
        .parse(url)
        .map_err(|error| error.to_string())?;
    Ok(Base {
        url: url.to_owned(),
        is_static,
        loopback: parsed.host == "localhost"
            || parsed
                .host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
    })
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
