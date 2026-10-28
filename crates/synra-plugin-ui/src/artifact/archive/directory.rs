//! Bound central-directory allocation before the ZIP reader builds its name index.
//!
//! UI artifacts are single-disk ZIPs without executable prefixes or trailing records.
//! ZIP64 metadata is accepted, even though artifact budgets never require it.

use std::io::{Read, Seek, SeekFrom};

use super::{ArchiveLimits, ArtifactError, UnpackError};

fn invalid() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid UI ZIP central directory",
    )
}

fn value(bytes: &[u8], offset: usize, length: usize) -> Result<u64, std::io::Error> {
    let field = bytes.get(offset..offset + length).ok_or_else(invalid)?;
    Ok(field.iter().enumerate().fold(0, |value, (index, byte)| {
        value | (u64::from(*byte) << (index * 8))
    }))
}

pub(super) fn check(
    file: &mut (impl Read + Seek),
    length: u64,
    limits: ArchiveLimits,
) -> Result<usize, UnpackError> {
    let tail_size = usize::try_from(length.min(65_557)).map_err(|_| invalid())?;
    let mut tail = vec![0; tail_size];
    file.seek(SeekFrom::Start(length.saturating_sub(65_557)))?;
    file.read_exact(&mut tail)?;
    let end = tail
        .windows(22)
        .enumerate()
        .rev()
        .find_map(|(at, part)| {
            (part.starts_with(b"PK\x05\x06")
                && value(part, 20, 2).ok()? + u64::try_from(at + 22).ok()?
                    == u64::try_from(tail_size).ok()?)
            .then_some(at)
        })
        .ok_or_else(invalid)?;
    let footer = tail.get(end..).ok_or_else(invalid)?;
    if value(footer, 4, 2)? != 0
        || value(footer, 6, 2)? != 0
        || value(footer, 8, 2)? != value(footer, 10, 2)?
    {
        return Err(invalid().into());
    }
    let footer_at = length - u64::try_from(tail_size - end).map_err(|_| invalid())?;
    let mut count = value(footer, 10, 2)?;
    let mut size = value(footer, 12, 4)?;
    let mut offset = value(footer, 16, 4)?;
    let mut directory_end = footer_at;
    // The reader recognizes a ZIP64 locator even when legacy fields fit.
    // Inspect it too, so hidden ZIP64 counts cannot bypass the allocation budget.
    let has_zip64 = if let Some(at) = footer_at.checked_sub(20) {
        let mut signature = [0; 4];
        file.seek(SeekFrom::Start(at))?;
        file.read_exact(&mut signature)?;
        signature == *b"PK\x06\x07"
    } else {
        false
    };
    if has_zip64 || count == 65_535 || size == u64::from(u32::MAX) || offset == u64::from(u32::MAX)
    {
        let extended = zip64(file, footer_at)?;
        (count, size, offset, directory_end) = extended;
    }
    if count > u64::try_from(limits.max_entries).unwrap_or(u64::MAX) {
        return Err(ArtifactError::TooManyFiles {
            found: usize::try_from(count).unwrap_or(usize::MAX),
            limit: limits.max_entries,
        }
        .into());
    }
    if offset.checked_add(size) != Some(directory_end) {
        return Err(invalid().into());
    }
    if count > 0 {
        let mut signature = [0; 4];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut signature)?;
        if signature != *b"PK\x03\x04" {
            return Err(invalid().into());
        }
    }
    scan(file, count, offset, directory_end)?;
    usize::try_from(count).map_err(|_| invalid().into())
}

fn zip64(
    file: &mut (impl Read + Seek),
    footer: u64,
) -> Result<(u64, u64, u64, u64), std::io::Error> {
    let locator_at = footer.checked_sub(20).ok_or_else(invalid)?;
    file.seek(SeekFrom::Start(locator_at))?;
    let mut locator = [0; 20];
    file.read_exact(&mut locator)?;
    if !locator.starts_with(b"PK\x06\x07")
        || value(&locator, 4, 4)? != 0
        || value(&locator, 16, 4)? != 1
    {
        return Err(invalid());
    }
    let at = value(&locator, 8, 8)?;
    file.seek(SeekFrom::Start(at))?;
    let mut record = [0; 56];
    file.read_exact(&mut record)?;
    let size = value(&record, 4, 8)?;
    if !record.starts_with(b"PK\x06\x06")
        || size < 44
        || at.checked_add(12).and_then(|at| at.checked_add(size)) != Some(locator_at)
        || value(&record, 16, 4)? != 0
        || value(&record, 20, 4)? != 0
        || value(&record, 24, 8)? != value(&record, 32, 8)?
    {
        return Err(invalid());
    }
    Ok((
        value(&record, 32, 8)?,
        value(&record, 40, 8)?,
        value(&record, 48, 8)?,
        at,
    ))
}

fn scan(
    file: &mut (impl Read + Seek),
    count: u64,
    mut at: u64,
    end: u64,
) -> Result<(), std::io::Error> {
    for _ in 0..count {
        if at.checked_add(46).is_none_or(|next| next > end) {
            return Err(invalid());
        }
        file.seek(SeekFrom::Start(at))?;
        let mut header = [0; 46];
        file.read_exact(&mut header)?;
        if !header.starts_with(b"PK\x01\x02") {
            return Err(invalid());
        }
        let variable = value(&header, 28, 2)? + value(&header, 30, 2)? + value(&header, 32, 2)?;
        at = at
            .checked_add(46 + variable)
            .filter(|next| *next <= end)
            .ok_or_else(invalid)?;
    }
    if at != end {
        return Err(invalid());
    }
    Ok(())
}
