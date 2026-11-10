//! Reads published bytes back through the network guard and checks them against the local files.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use super::reference::{local_tarball, resolve_remote};

/// Reads the bucket back and compares it with the local files.
///
/// The remote document is parsed with the same parser the installing side uses, and the tarballs are compared by digest
/// rather than by size: a bucket that serves a different file of the same size is exactly the failure a size check misses.
pub(super) fn verify_remote(
    args: &crate::args::PublishArgs,
    index: &synra_registry::StaticIndex,
) -> Result<Vec<String>, Vec<String>> {
    let Some(base) = args.base.as_deref() else {
        return Err(vec!["  --verify needs --base: there is no address to read back from".to_owned()]);
    };
    let base = base.trim_end_matches('/');
    let index_url = format!("{base}/{}.json", index.document.name);
    let body = fetch(&index_url).map_err(|reason| vec![format!("  {reason}")])?;
    let remote = synra_registry::parse_static_index(&String::from_utf8_lossy(&body))
        .map_err(|error| vec![format!("  {index_url}: {error}")])?;

    let mut lines = vec![format!("  remote index  {}", index_url)];
    let mut failures = Vec::new();
    if remote.document.versions.len() != index.document.versions.len() {
        failures.push(format!(
            "  remote index lists {} version(s), the local index lists {}",
            remote.document.versions.len(),
            index.document.versions.len()
        ));
    }

    let directory = args.index.parent().unwrap_or_else(|| Path::new("."));
    for (version, local_entry) in &index.document.versions {
        let Some(remote_entry) = remote.document.at(version) else {
            failures.push(format!("  {version}  the remote index does not list it"));
            continue;
        };
        let remote_url = match resolve_remote(&index_url, &remote_entry.dist.tarball) {
            Ok(url) => url,
            Err(reason) => {
                failures.push(format!("  {version}  {reason}"));
                continue;
            }
        };
        let remote_bytes = match fetch(&remote_url) {
            Ok(bytes) => bytes,
            Err(reason) => {
                failures.push(format!("  {version}  {reason}"));
                continue;
            }
        };
        let local = match local_tarball(directory, args.base.as_deref(), &local_entry.dist.tarball) {
            Ok(path) => path,
            Err(reason) => {
                failures.push(format!("  {version}  {reason}"));
                continue;
            }
        };
        let local_bytes = match std::fs::read(&local) {
            Ok(bytes) => bytes,
            Err(error) => {
                failures.push(format!("  {version}  {}: {error}", local.display()));
                continue;
            }
        };
        if Sha256::digest(&remote_bytes) == Sha256::digest(&local_bytes) {
            lines.push(format!("  remote {version}  digest matches"));
        }
        else {
            failures.push(format!(
                "  {version}  the bucket serves different bytes than {}",
                local.display()
            ));
        }
    }

    if failures.is_empty() {
        return Ok(lines);
    }

    // ★ A failure is only half the answer: the author needs to know which file to upload where. The list names the local
    // path and the URL the index expects, so a re-upload is a copy of two values rather than a re-derivation.
    let mut reupload = Vec::new();
    for (version, entry) in &index.document.versions {
        if !failures.iter().any(|line| line.contains(version)) {
            continue;
        }
        let local = local_tarball(directory, args.base.as_deref(), &entry.dist.tarball);
        let tarball = remote
            .document
            .at(version)
            .map_or(&entry.dist.tarball, |served| &served.dist.tarball);
        let target = resolve_remote(&index_url, tarball);
        if let (Ok(local), Ok(target)) = (local, target) {
            reupload.push(format!("  re-upload  {version}  {}  ->  {target}", local.display()));
        }
    }
    if !reupload.is_empty() {
        failures.push("  upload these again:".to_owned());
        failures.extend(reupload);
    }
    Err(failures)
}

/// A URL's bytes, through the host's own network guard.
fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    }
    else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    }
    else {
        return Err(format!("{url}: it must start with https:// or http://"));
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|character| character.is_ascii_digit()) => host,
        _ => authority,
    };
    let host = host.trim_matches(['[', ']']).to_owned();

    let mut guard = synra_core::network::NetworkGuard::for_hosts(std::slice::from_ref(&host));
    if !secure {
        guard = guard.allowing_insecure(true).with_policy(synra_core::network::IpPolicy {
            allow_loopback: true,
            ..synra_core::network::IpPolicy::default()
        });
    }
    let client = synra_fetch::Client::new(
        guard,
        synra_fetch::Limits { max_response_bytes: 64 * 1024 * 1024 + 1, ..synra_fetch::Limits::default() },
    );
    let request = synra_fetch::Request {
        url: url.to_owned(),
        method: "GET".to_owned(),
        headers: std::collections::BTreeMap::new(),
        body: None,
    };
    let response = client.fetch_bytes(&request).map_err(|error| format!("{url}: {error}"))?;
    if !(200..300).contains(&response.status) {
        return Err(format!("{url}: answered {}", response.status));
    }
    Ok(response.body)
}
