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

use std::path::Path;

use crate::run::Outcome;

mod local;
mod reference;
mod remote;

pub(crate) use reference::local_tarball;

use local::check_version;
use remote::verify_remote;

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

#[cfg(test)]
mod tests;
