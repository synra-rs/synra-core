//! Checking what a static bucket would serve, without uploading it.
//!
//! # Why a check rather than an upload
//!
//! Publishing to a bucket is `aws s3 cp` or a drag-and-drop; the failure this tool can prevent is not a refused upload but
//! a published shape the installing side cannot read — an index whose tarball path does not resolve, an archive without the
//! files its manifest names, or a signature that no longer covers the bytes. All of those are decidable from the files
//! already on disk, so this command reads them the way an install would and says what it found.
//!
//! # What it does not decide
//!
//! Whether a bucket is public, whether a CDN is configured, whether the key is one a device trusts. Those belong to the
//! host and to the installing device.

use std::path::{Path, PathBuf};

use crate::run::Outcome;

/// Checks the files an index names.
///
/// # Errors
///
/// A sentence when the index is unreadable, a tarball is missing, an archive is malformed, or a signature does not cover
/// the bytes. Each names the version and the file, because an author fixing three versions at once reads the list.
pub fn publish_plugin(args: &crate::args::PublishArgs) -> Outcome {
    match validate(args) {
        Ok(lines) => Outcome::Reported { lines, code: 0, failure: false },
        Err(lines) => Outcome::Reported { lines, code: 1, failure: true },
    }
}

/// The check itself, as a list of lines.
fn validate(args: &crate::args::PublishArgs) -> Result<Vec<String>, Vec<String>> {
    let text = std::fs::read_to_string(&args.index)
        .map_err(|error| vec![format!("{}: {error}", args.index.display())])?;
    let index = synra_registry::parse_static_index(&text)
        .map_err(|error| vec![format!("{}: {error}", args.index.display())])?;
    let directory = args.index.parent().unwrap_or_else(|| Path::new("."));

    let mut lines = vec![format!(
        "{} lists {} version(s)",
        args.index.display(),
        index.document.versions.len()
    )];
    let mut failures = Vec::new();

    for (version, entry) in &index.document.versions {
        match check_version(version, entry, directory, args.base.as_deref()) {
            Ok(line) => lines.push(line),
            Err(line) => failures.push(line),
        }
    }

    if args.verify {
        match verify_remote(args, &index) {
            Ok(remote) => lines.extend(remote),
            Err(remote) => failures.extend(remote),
        }
    }

    if failures.is_empty() {
        Ok(lines)
    }
    else {
        // The successful versions stay in the output: an author who fixed one of three should not have to re-run to see
        // that the other two are still wrong.
        lines.extend(failures);
        Err(lines)
    }
}

/// Reads the bucket back and compares it with the local files.
///
/// The remote document is parsed with the same parser the installing side uses, and the tarballs are compared by digest
/// rather than by size: a bucket that serves a different file of the same size is exactly the failure a size check misses.
fn verify_remote(
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
        if digest(&remote_bytes) == digest(&local_bytes) {
            lines.push(format!("  remote {version}  digest matches"));
        }
        else {
            failures.push(format!(
                "  {version}  the bucket serves different bytes than {}",
                local.display()
            ));
        }
    }

    if failures.is_empty() { Ok(lines) } else { Err(failures) }
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

/// A tarball reference from the remote index, resolved against that index's URL.
fn resolve_remote(index_url: &str, tarball: &str) -> Result<String, String> {
    if tarball.starts_with("https://") || tarball.starts_with("http://") {
        return Ok(tarball.to_owned());
    }
    if tarball.is_empty() || tarball.split('/').any(|segment| segment == "..") {
        return Err(format!("{tarball}: the index names a path outside its own directory"));
    }
    if let Some(absolute) = tarball.strip_prefix('/') {
        let origin = index_url
            .split_once("://")
            .map(|(scheme, rest)| {
                let authority = rest.split('/').next().unwrap_or_default();
                format!("{scheme}://{authority}")
            })
            .ok_or_else(|| "the index URL is not absolute".to_owned())?;
        return Ok(format!("{origin}/{absolute}"));
    }
    let directory = index_url
        .rsplit_once('/')
        .map(|(directory, _)| directory)
        .ok_or_else(|| "the index URL is not absolute".to_owned())?;
    Ok(format!("{directory}/{tarball}"))
}

/// A content digest, so two files are compared by what they are rather than by how large they are.
fn digest(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Checks one version's tarball, returning the line to print or the failure.
fn check_version(
    version: &str,
    entry: &synra_registry::Version,
    directory: &Path,
    base: Option<&str>,
) -> Result<String, String> {
    let local = local_tarball(directory, base, &entry.dist.tarball)
        .map_err(|reason| format!("  {version}  {reason}"))?;
    let bytes = std::fs::read(&local).map_err(|error| format!("  {version}  {}: {error}", local.display()))?;

    let extracted = extract_for_check(&bytes)
        .map_err(|reason| format!("  {version}  {}: {reason}", local.display()))?;
    let signature = extracted.dir.join("signature.json");
    let signed = if signature.is_file() {
        let document = std::fs::read_to_string(&signature)
            .map_err(|error| format!("  {version}  signature.json: {error}"))?;
        let trust = synra_plugin_api::publisher::PublisherTrustStore::new();
        let verified = crate::sign::verify(&document, &extracted.dir, &trust)
            .map_err(|error| format!("  {version}  the signature does not cover this tarball: {error}"));
        if let Err(line) = verified {
            cleanup(&extracted);
            return Err(line);
        }
        true
    }
    else {
        false
    };

    // The manifest is read from the source directory, not the archive: it is what the author just packed, and the archive
    // check only has to agree that its files are there.
    let manifest = synra_plugin_api::Manifest::from_json(&entry_text(entry)?)
        .map_err(|error| format!("  {version}  the index's inline manifest: {error}"))?;
    let missing: Vec<String> = artifact_names_local(&manifest)
        .into_iter()
        .filter(|name| !extracted.dir.join(name).is_file())
        .collect();
    if !missing.is_empty() {
        let names = missing.join(", ");
        cleanup(&extracted);
        return Err(format!("  {version}  the tarball does not contain {names}"));
    }

    let size = bytes.len();
    cleanup(&extracted);
    Ok(format!(
        "  {version}  {}  {size} bytes  {}",
        local.display(),
        if signed { "signed" } else { "unsigned" }
    ))
}

/// The index's inline manifest, as text, or a refusal naming the version.
fn entry_text(entry: &synra_registry::Version) -> Result<String, String> {
    let manifest = entry
        .synra
        .as_ref()
        .ok_or_else(|| "the index carries no inline manifest, so the tarball cannot be checked".to_owned())?;
    serde_json::to_string(manifest).map_err(|error| error.to_string())
}

/// Where a tarball reference lives on disk.
fn local_tarball(directory: &Path, base: Option<&str>, tarball: &str) -> Result<PathBuf, String> {
    if tarball.starts_with("https://") || tarball.starts_with("http://") {
        let base = base.ok_or_else(|| {
            format!("{tarball}: it is absolute; pass --base with the public URL to find the local file")
        })?;
        let rest = tarball
            .strip_prefix(base)
            .ok_or_else(|| format!("{tarball}: it is not under --base {base}"))?;
        return Ok(directory.join(rest.trim_start_matches('/')));
    }
    if tarball.is_empty() || tarball.split('/').any(|segment| segment == "..") {
        return Err(format!("{tarball}: the index names a path outside its own directory"));
    }
    Ok(directory.join(tarball))
}

/// The file names a manifest says the archive contains.
fn artifact_names_local(manifest: &synra_plugin_api::Manifest) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(runtime) = &manifest.runtime.headless {
        names.push(runtime.artifact.clone());
    }
    if let Some(runtime) = &manifest.runtime.ui {
        names.push(runtime.artifact.clone());
    }
    names
}

/// A tarball unpacked under a fresh temporary directory.
struct Extracted {
    /// Where it was unpacked.
    dir: PathBuf,
    /// The files written, so cleanup can remove exactly them.
    files: Vec<PathBuf>,
}

/// Unpacks a tarball into a fresh directory for checking.
fn extract_for_check(bytes: &[u8]) -> Result<Extracted, String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("synra-publish-{}-{stamp}", std::process::id()));
    let files = synra_registry::extract_tgz(
        bytes,
        &dir,
        Some("package"),
        synra_registry::Limits::default(),
    )
    .map_err(|error| error.to_string())?;
    Ok(Extracted { dir, files })
}

/// Removes what [`extract_for_check`] wrote, deepest first, without a recursive delete.
fn cleanup(extracted: &Extracted) {
    for file in &extracted.files {
        let _ = std::fs::remove_file(file);
    }
    let mut directories: Vec<PathBuf> = extracted
        .files
        .iter()
        .filter_map(|file| file.parent().map(Path::to_path_buf))
        .collect();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    directories.dedup();
    for directory in directories {
        if directory.starts_with(&extracted.dir) {
            let _ = std::fs::remove_dir(&directory);
        }
    }
    let _ = std::fs::remove_dir(&extracted.dir);
}

#[cfg(test)]
mod tests {
    use super::{local_tarball, publish_plugin, validate};

    fn manifest(version: &str) -> String {
        serde_json::json!({
            "id": "@acme/hello",
            "version": version,
            "title": "Hello",
            "publisher": { "id": "acme" },
            "sdk": { "min": "1.0.0" },
            "wit": synra_plugin_host::host_world(),
            "capabilities": [{ "cap": "log:*" }],
            "runtime": { "headless": { "artifact": "plugin.wasm", "stateful": false } }
        })
        .to_string()
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("synra-publish-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a directory");
        path
    }

    /// Packs the fixture the way an author would, and returns the index path.
    fn packed(root: &std::path::Path, version: &str) -> std::path::PathBuf {
        std::fs::write(root.join("manifest.json"), manifest(version)).expect("a manifest");
        std::fs::write(root.join("plugin.wasm"), b"\0asm\x01\0\0\0").expect("an artifact");
        let key = crate::sign::SigningKeyFile::generate().expect("a key");
        let content = crate::sign::SignedContent::read(root).expect("what a signature covers");
        std::fs::write(
            root.join("signature.json"),
            key.sign(&content, "2026-01-01T00:00:00Z"),
        )
        .expect("a signature");
        let outcome = crate::pack::pack_plugin(&crate::args::PackArgs {
            dir: root.to_path_buf(),
            out: None,
            index: Some(String::new()),
            registry: None,
            dry_run: false,
        })
        .expect("it packs");
        let _ = crate::execute::execute(&outcome, false);
        root.join("dist").join("@acme").join("hello.json")
    }

    #[test]
    fn a_packed_index_passes_the_check() {
        // ★ The property is that `publish` reads the files the way an install would: index → tarball → unpack → signature.
        let root = scratch("ok");
        let index = packed(&root, "1.0.0");

        let outcome = publish_plugin(&crate::args::PublishArgs { index, base: None, verify: false });

        let crate::run::Outcome::Reported { lines, code, .. } = outcome else {
            panic!("expected a report");
        };
        assert_eq!(code, 0, "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("signed")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_tarball_is_named() {
        let root = scratch("missing");
        let index = packed(&root, "1.0.0");
        std::fs::remove_file(root.join("dist").join("@acme").join("@acme-hello-1.0.0.tgz"))
            .expect("the tarball is gone");

        let outcome = publish_plugin(&crate::args::PublishArgs { index, base: None, verify: false });
        let crate::run::Outcome::Reported { lines, failure, .. } = outcome else {
            panic!("expected a report");
        };
        assert!(failure);
        assert!(lines.iter().any(|line| line.contains("1.0.0.tgz")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_signature_that_no_longer_covers_the_tarball_is_refused() {
        let root = scratch("tampered");
        let index = packed(&root, "1.0.0");
        let tarball = root.join("dist").join("@acme").join("@acme-hello-1.0.0.tgz");
        // The manifest gains a permission after it was signed: the archive is well formed, the signature is genuine, and
        // it no longer covers what shipped.
        let mut changed: serde_json::Value =
            serde_json::from_str(&manifest("1.0.0")).expect("a manifest document");
        changed["capabilities"] = serde_json::json!([{ "cap": "log:*" }, { "cap": "device:send:*" }]);
        std::fs::write(root.join("manifest.json"), changed.to_string()).expect("the changed manifest");
        crate::pack::write_archive(
            &tarball,
            &root.join("manifest.json"),
            &["plugin.wasm".to_owned()],
            Some(&root.join("signature.json")),
        )
        .expect("the changed archive");

        let outcome = publish_plugin(&crate::args::PublishArgs { index, base: None, verify: false });
        let crate::run::Outcome::Reported { lines, failure, .. } = outcome else {
            panic!("expected a report");
        };
        assert!(failure);
        assert!(
            lines.iter().any(|line| line.contains("signature")),
            "{lines:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_reads_the_bucket_back() {
        // ★ The question is not "did the upload succeed" but "does the bucket serve what was packed": the remote index is
        // parsed by the installing side's parser and the tarballs are compared by digest.
        use std::io::{BufRead, BufReader, Write as _};

        let root = scratch("verify");
        let index_path = packed(&root, "1.0.0");
        let index_bytes = std::fs::read(&index_path).expect("the index");
        let tarball_bytes = std::fs::read(root.join("dist").join("@acme").join("@acme-hello-1.0.0.tgz"))
            .expect("the tarball");
        let base = serve(index_bytes, tarball_bytes);

        let outcome = publish_plugin(&crate::args::PublishArgs {
            index: index_path,
            base: Some(base),
            verify: true,
        });
        let crate::run::Outcome::Reported { lines, code, .. } = outcome else {
            panic!("expected a report");
        };
        assert_eq!(code, 0, "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("digest matches")), "{lines:?}");
        let _ = std::fs::remove_dir_all(&root);

        fn serve(index: Vec<u8>, tarball: Vec<u8>) -> String {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a port");
            let base = format!("http://{}", listener.local_addr().expect("an address"));
            std::thread::spawn(move || {
                for _ in 0..2 {
                    let Ok((mut stream, _)) = listener.accept() else { return };
                    let mut reader = BufReader::new(stream.try_clone().expect("a clone"));
                    let mut line = String::new();
                    let _ = reader.read_line(&mut line);
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                            break;
                        }
                    }
                    let body = if line.contains(".json") { index.clone() } else { tarball.clone() };
                    let head = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body);
                }
            });
            base
        }
    }

    #[test]
    fn verify_refuses_a_bucket_that_serves_different_bytes() {
        use std::io::{BufRead, BufReader, Write as _};

        let root = scratch("verify-tampered");
        let index_path = packed(&root, "1.0.0");
        let index_bytes = std::fs::read(&index_path).expect("the index");
        let mut tarball_bytes = std::fs::read(root.join("dist").join("@acme").join("@acme-hello-1.0.0.tgz"))
            .expect("the tarball");
        if let Some(byte) = tarball_bytes.last_mut() {
            *byte ^= 0xFF;
        }

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a port");
        let base = format!("http://{}", listener.local_addr().expect("an address"));
        std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else { return };
                let mut reader = BufReader::new(stream.try_clone().expect("a clone"));
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                loop {
                    let mut header = String::new();
                    if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" {
                        break;
                    }
                }
                let body = if line.contains(".json") { index_bytes.clone() } else { tarball_bytes.clone() };
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });

        let outcome = publish_plugin(&crate::args::PublishArgs {
            index: index_path,
            base: Some(base),
            verify: true,
        });
        let crate::run::Outcome::Reported { lines, failure, .. } = outcome else {
            panic!("expected a report");
        };
        assert!(failure);
        assert!(
            lines.iter().any(|line| line.contains("different bytes")),
            "{lines:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_absolute_tarball_needs_the_base_to_be_found_locally() {
        let root = scratch("base");
        assert!(validate(&crate::args::PublishArgs {
            index: root.join("missing.json"),
            base: None,
            verify: false,
        })
        .is_err());
        assert_eq!(
            local_tarball(&root, Some("https://bucket.example/plugins"), "https://bucket.example/plugins/x.tgz"),
            Ok(root.join("x.tgz"))
        );
        assert!(local_tarball(&root, None, "https://bucket.example/x.tgz").is_err());
        assert!(local_tarball(&root, None, "../x.tgz").is_err());
    }
}
