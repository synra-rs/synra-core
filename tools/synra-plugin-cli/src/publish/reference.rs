//! Resolves the same index entry against its local directory or remote URL.

use std::path::{Path, PathBuf};

/// A tarball reference from the remote index, resolved against that index's URL.
pub(super) fn resolve_remote(index_url: &str, tarball: &str) -> Result<String, String> {
    if is_http_reference(tarball) {
        return Ok(tarball.to_owned());
    }
    check_relative_reference(tarball)?;
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

/// Where a tarball reference lives on disk.
pub(crate) fn local_tarball(directory: &Path, base: Option<&str>, tarball: &str) -> Result<PathBuf, String> {
    if is_http_reference(tarball) {
        let base = base.ok_or_else(|| {
            format!("{tarball}: it is absolute; pass --base with the public URL to find the local file")
        })?;
        let rest = tarball
            .strip_prefix(base)
            .ok_or_else(|| format!("{tarball}: it is not under --base {base}"))?;
        return Ok(directory.join(rest.trim_start_matches('/')));
    }
    check_relative_reference(tarball)?;
    Ok(directory.join(tarball))
}

fn is_http_reference(tarball: &str) -> bool {
    tarball.starts_with("https://") || tarball.starts_with("http://")
}

fn check_relative_reference(tarball: &str) -> Result<(), String> {
    if tarball.is_empty() || tarball.split('/').any(|segment| segment == "..") {
        return Err(format!("{tarball}: the index names a path outside its own directory"));
    }
    Ok(())
}
