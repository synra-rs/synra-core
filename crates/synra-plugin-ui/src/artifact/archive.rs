//! Read actual ZIP metadata and bytes through the same policy used for expansion.

use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::Path;

use super::{
    ArchiveLimits, ArtifactError, Entry, EntryKind, Expansion, UiArtifact, UiArtifactIndex,
    UnpackError, plan,
};

mod directory;

pub(super) struct Archive<R: Read + Seek> {
    zip: zip::ZipArchive<R>,
    pub(super) expansion: Expansion,
}

impl Archive<std::io::Cursor<Vec<u8>>> {
    pub(super) fn open(
        path: &Path,
        limits: ArchiveLimits,
        encoded_limit: u64,
    ) -> Result<Self, UnpackError> {
        if !std::fs::symlink_metadata(path)?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "archive must be a regular file",
            )
            .into());
        }
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "opened archive is not a regular file",
            )
            .into());
        }
        let size = file.metadata()?.len();
        if size > encoded_limit {
            return Err(ArtifactError::TooLarge {
                found: size,
                limit: encoded_limit,
            }
            .into());
        }
        // Preflight and the foreign decoder must inspect identical bytes. File metadata
        // and a shared file descriptor do not prevent a writer from replacing ZIP64 counts.
        let mut bytes = Vec::new();
        file.take(encoded_limit.saturating_add(1))
            .read_to_end(&mut bytes)?;
        let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        Self::new(std::io::Cursor::new(bytes), observed, limits, encoded_limit)
    }
}

impl<R: Read + Seek> Archive<R> {
    fn new(
        mut file: R,
        size: u64,
        limits: ArchiveLimits,
        encoded_limit: u64,
    ) -> Result<Self, UnpackError> {
        let limit = encoded_limit;
        if size > limit {
            return Err(ArtifactError::TooLarge { found: size, limit }.into());
        }
        let count = directory::check(&mut file, size, limits)?;
        let mut zip = zip::ZipArchive::new(file)?;
        // The ZIP reader indexes by decoded name and silently collapses duplicates.
        if zip.len() != count {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "duplicate ZIP entry names",
            )
            .into());
        }
        if zip.len() > limits.max_entries {
            return Err(ArtifactError::TooManyFiles {
                found: zip.len(),
                limit: limits.max_entries,
            }
            .into());
        }
        let mut entries = Vec::with_capacity(zip.len());
        for index in 0..zip.len() {
            let file = zip.by_index(index)?;
            entries.push(Entry {
                path: file.name().to_owned(),
                kind: kind(file.unix_mode(), file.is_dir()),
                size: file.size(),
                compressed: Some(file.compressed_size()),
            });
        }
        let expansion = plan(&entries, limits)?;
        Ok(Self { zip, expansion })
    }

    pub(super) fn copy(&mut self, index: usize, sink: &mut impl Write) -> Result<(), UnpackError> {
        let expected =
            self.expansion.entries.get(index).ok_or_else(|| {
                std::io::Error::other("ZIP entry is absent from its validated plan")
            })?;
        let file = self.zip.by_index(index)?;
        let size = std::io::copy(&mut file.take(expected.size.saturating_add(1)), sink)?;
        if size != expected.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{} expanded to {size} bytes, expected {}",
                    expected.path, expected.size
                ),
            )
            .into());
        }
        Ok(())
    }
}

fn kind(mode: Option<u32>, directory: bool) -> EntryKind {
    match mode.unwrap_or(0) & 0o170_000 {
        0 | 0o040_000 if directory => EntryKind::Directory,
        0 | 0o100_000 if !directory => EntryKind::File,
        0o120_000 => EntryKind::Symlink,
        _ => EntryKind::Other,
    }
}

/// Validate a UI ZIP's paths, kinds, sizes, compression, entry document and actual data/CRC.
/// No files are extracted and no scripts are executed.
///
/// # Errors
/// Returns the same archive or artifact refusal as native expansion.
pub fn inspect_ui(
    archive: &Path,
    entry: &str,
    limits: ArchiveLimits,
) -> Result<UiArtifact, UnpackError> {
    inspect(
        Archive::open(archive, limits, super::MAX_ARCHIVE_BYTES)?,
        entry,
    )
}

/// Validate an already bounded UI ZIP snapshot without writing temporary files.
///
/// # Errors
/// Reports the same archive and artifact refusals as file inspection and expansion.
pub fn inspect_ui_bytes(
    bytes: &[u8],
    entry: &str,
    limits: ArchiveLimits,
) -> Result<UiArtifact, UnpackError> {
    let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    inspect(
        Archive::new(
            std::io::Cursor::new(bytes),
            size,
            limits,
            super::MAX_ARCHIVE_BYTES,
        )?,
        entry,
    )
}

fn inspect<R: Read + Seek>(
    mut archive: Archive<R>,
    entry: &str,
) -> Result<UiArtifact, UnpackError> {
    let files = archive
        .expansion
        .files()
        .into_iter()
        .map(|file| (file.path.clone(), file.size))
        .collect();
    let artifact = UiArtifact::build(UiArtifactIndex {
        entry: entry.to_owned(),
        default_page: None,
        files,
    })?;
    for index in 0..archive.expansion.len() {
        if archive
            .expansion
            .entries
            .get(index)
            .is_some_and(|entry| entry.kind == EntryKind::File)
        {
            archive.copy(index, &mut std::io::sink())?;
        }
    }
    Ok(artifact)
}

#[cfg(test)]
mod tests;
