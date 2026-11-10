//! Deterministic tarball writing for the package described by the CLI.

use std::path::Path;

/// Writes the archive an [`Outcome::Archive`](crate::run::Outcome::Archive) describes.
///
/// # Errors
///
/// A sentence naming the file that could not be written or read.
pub fn write_archive(
    target: &Path,
    manifest: &Path,
    artifacts: &[String],
    signature: Option<&Path>,
) -> Result<(), String> {
    if let Some(parent) = target.parent()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return Err(format!("{}: {error}", parent.display()));
    }
    let file = std::fs::File::create(target).map_err(|error| format!("{}: {error}", target.display()))?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);

    append(&mut builder, manifest, "manifest.json")?;
    for name in artifacts {
        let source = manifest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(name);
        append(&mut builder, &source, name)?;
    }
    if let Some(signature) = signature {
        append(&mut builder, signature, "signature.json")?;
    }

    let encoder = builder.into_inner().map_err(|error| error.to_string())?;
    encoder.finish().map_err(|error| error.to_string())?;
    Ok(())
}

/// Appends one file under `package/`, with fixed metadata so two packs of unchanged files match byte for byte.
fn append(builder: &mut tar::Builder<flate2::write::GzEncoder<std::fs::File>>, source: &Path, name: &str) -> Result<(), String> {
    let mut file = std::fs::File::open(source).map_err(|error| format!("{}: {error}", source.display()))?;
    let size = file
        .metadata()
        .map_err(|error| format!("{}: {error}", source.display()))?
        .len();
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append_data(&mut header, format!("package/{name}"), &mut file)
        .map_err(|error| format!("{}: {error}", source.display()))?;
    Ok(())
}
