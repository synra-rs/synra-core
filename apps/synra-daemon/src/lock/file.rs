//! Reads and writes the daemon claim, reporting disk failures before startup can claim the directory.

use std::path::Path;

use super::{Claim, LockError, LockFile, decide};

/// What was on disk, as far as this build can tell.
///
/// # The two failures are different from "nothing there"
///
/// A missing file is a free directory. A file that exists and cannot be interpreted is *not* — it might be a live
/// owner's, and treating it as absent is how a second daemon starts over a running one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimFile {
    /// Nothing owns the directory.
    Absent,
    /// A claim was read.
    Found(Box<LockFile>),
}

impl ClaimFile {
    /// Reads the claim file.
    ///
    /// # Errors
    ///
    /// [`LockError::Unreadable`] when the file exists and cannot be read as a claim, and
    /// [`LockError::FromTheFuture`] when it was written by a newer build. Both are refusals rather than "absent".
    pub fn read(path: &Path) -> Result<Self, LockError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            // A missing file is the ordinary first start. Every other read error — permission, a directory where a
            // file should be, a device that does not answer — might be a live owner's claim and is refused.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Self::Absent),
            Err(error) => {
                return Err(LockError::Unreadable {
                    path: path.display().to_string(),
                    reason: error.to_string(),
                });
            }
        };

        // An empty file is what a process killed *between* creating and writing leaves behind. It is not a claim, and
        // it is also not another instance — so it is absent rather than unreadable, because refusing would leave a
        // daemon unable to start after exactly the crash this module exists to recover from.
        if text.trim().is_empty() {
            return Ok(Self::Absent);
        }

        match serde_json::from_str::<LockFile>(&text) {
            Ok(file) => Ok(Self::Found(Box::new(file))),
            Err(error) => Err(LockError::Unreadable {
                path: path.display().to_string(),
                reason: format!("the claim file is not one this build understands: {error}"),
            }),
        }
    }

    /// The lock value, for [`decide`].
    #[must_use]
    pub fn as_lock(&self) -> Option<&LockFile> {
        match self {
            Self::Absent => None,
            Self::Found(file) => Some(file),
        }
    }

    /// Decides the claim from what was on disk.
    ///
    /// # Errors
    ///
    /// [`LockError`] when the file was written by a newer build.
    pub fn decide(&self, now_ms: u64, path: &Path) -> Result<Claim, LockError> {
        decide(self.as_lock(), now_ms, &path.display().to_string())
    }
}

/// Writes the claim for this process.
///
/// # Why writing is separate from deciding
///
/// Deciding is a pure function of what was on disk, which is the part worth testing. Writing is the part that makes
/// the decision *mean* something — and this function exists because a daemon that decided it owned the directory and
/// never wrote the file reported "claimed the data directory" while leaving no claim behind, so a second instance
/// decided the same thing. The exclusive claim was decorative.
///
/// # Errors
///
/// [`LockError::Unreadable`] when the directory cannot be made or the file cannot be written. A daemon that cannot
/// write its claim must not start: it would be running while believing it holds a claim it does not.
pub fn write_claim(path: &Path, pid: u32, now_ms: u64) -> Result<LockFile, LockError> {
    let refuse =
        |reason: String| LockError::Unreadable { path: path.display().to_string(), reason };

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| refuse(format!("the data directory could not be made: {error}")))?;
    }

    let lock = LockFile::claim(pid, env!("CARGO_PKG_VERSION"), now_ms);
    write_claim_file(path, &lock, "the claim could not be written")?;
    Ok(lock)
}

/// Rewrites the claim's heartbeat, leaving its identity alone.
///
/// # Errors
///
/// [`LockError::Unreadable`] when the file cannot be rewritten.
///
/// # Why the identity is preserved
///
/// The claimed-at reading and the pid *are* the claim's identity: a user reading the file wants to know when the
/// session started and which process it is. Overwriting them on every beat would make `claimed_at_ms` mean "the last
/// beat", which is the one thing a reader is trying to tell apart from the heartbeat.
pub fn refresh_claim(path: &Path, lock: &LockFile, now_ms: u64) -> Result<LockFile, LockError> {
    let mut refreshed = lock.clone();
    refreshed.owner.heartbeat_ms = now_ms;
    write_claim_file(path, &refreshed, "the heartbeat could not be written")?;
    Ok(refreshed)
}

/// Removes the claim.
///
/// # Errors
///
/// [`LockError::Unreadable`] when the file exists and cannot be removed. A missing file is **not** an error: the claim
/// being gone is the outcome the caller wanted, and a shutdown that failed because it had already cleaned up would be
/// a shutdown that reported a problem where there is none.
pub fn remove_claim(path: &Path) -> Result<(), LockError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LockError::Unreadable {
            path: path.display().to_string(),
            reason: format!("the claim could not be removed: {error}"),
        }),
    }
}

/// The claim file's contents for an owner, as text.
///
/// # Errors
///
/// [`LockError::Unreadable`] when it cannot be serialised, which is a bug in the shape rather than a runtime
/// condition — and reported rather than unwrapped because a daemon that panicked while writing its lock would leave
/// the file it was mid-write on.
pub fn encode_claim(lock: &LockFile, path: &Path) -> Result<String, LockError> {
    serde_json::to_string_pretty(lock).map_err(|error| LockError::Unreadable {
        path: path.display().to_string(),
        reason: format!("the claim could not be written: {error}"),
    })
}

pub(crate) fn write_claim_file(path: &Path, lock: &LockFile, failure: &str) -> Result<(), LockError> {
    std::fs::write(path, encode_claim(lock, path)?).map_err(|error| LockError::Unreadable {
        path: path.display().to_string(),
        reason: format!("{failure}: {error}"),
    })
}

#[cfg(test)]
mod tests;
