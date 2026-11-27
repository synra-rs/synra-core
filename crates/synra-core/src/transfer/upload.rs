//! Admission and state transitions for a staged upload. Callers own serialization and the file.

/// Limits for staged uploads and the workers that take them over.
#[derive(Debug, Clone, Copy)]
pub struct UploadPolicy {
    /// Maximum declared size of one file, in bytes.
    pub file_bytes: u64,
    /// Maximum decoded size of one append, in bytes.
    pub chunk_bytes: usize,
    /// Concurrent reservations for a single page session.
    pub per_session: usize,
    /// Concurrent reservations for a plugin across its pages.
    pub per_plugin: usize,
    /// Concurrent reservations across the host.
    pub slots: usize,
    /// Maximum total declared bytes across all live reservations.
    pub spool_bytes: u64,
    /// Idle time before an upload in the receiving phase expires, in milliseconds.
    pub idle_ms: u64,
}

impl Default for UploadPolicy {
    fn default() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            file_bytes: 64 * MIB,
            chunk_bytes: 1024 * 1024,
            per_session: 2,
            per_plugin: 4,
            slots: 32,
            spool_bytes: 256 * MIB,
            idle_ms: 2 * 60 * 1000,
        }
    }
}

/// Existing reservations at the point of admission.
#[derive(Debug, Clone, Copy, Default)]
pub struct UploadUsage {
    /// Number held by this session.
    pub session: usize,
    /// Number held by this plugin.
    pub plugin: usize,
    /// Number held by the host.
    pub slots: usize,
    /// Bytes held by the host.
    pub bytes: u64,
}

/// Stable reason an upload operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UploadError {
    /// The declared file or appended chunk is empty.
    #[error("an upload write must contain bytes")]
    Empty,
    /// One upload or append exceeds the policy limit.
    #[error("the size exceeds {limit} bytes")]
    Size {
        /// The applicable limit.
        limit: u64,
    },
    /// No reservation is available at this usage.
    #[error("upload capacity is exhausted")]
    Capacity,
    /// The offset does not follow the committed bytes.
    #[error("the next upload offset is {expected}")]
    Offset {
        /// The next offset the host accepts.
        expected: u64,
    },
    /// The staged file is incomplete or its size differs from the committed size.
    #[error("the upload must contain exactly {expected} committed bytes")]
    Incomplete {
        /// The declared file length.
        expected: u64,
    },
    /// The session no longer accepts writes.
    #[error("the upload is closed")]
    Closed,
}

impl UploadPolicy {
    /// Verifies a reservation under the caller's admission lock.
    ///
    /// # Errors
    /// Refuses an invalid file size or exhausted capacity.
    pub fn admit(self, usage: UploadUsage, bytes: u64) -> Result<(), UploadError> {
        if bytes == 0 {
            return Err(UploadError::Empty);
        }
        if bytes > self.file_bytes {
            return Err(UploadError::Size {
                limit: self.file_bytes,
            });
        }
        if usage.session >= self.per_session
            || usage.plugin >= self.per_plugin
            || usage.slots >= self.slots
            || bytes > self.spool_bytes.saturating_sub(usage.bytes)
        {
            return Err(UploadError::Capacity);
        }
        Ok(())
    }
}

/// Why an upload ended before a worker accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadEnd {
    /// An operation could not complete reliably.
    Failed,
    /// The owner gave up or lost authority.
    Aborted,
    /// The upload remained idle past the policy budget.
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Receiving,
    HandingOff,
    Transferred,
    Closed(UploadEnd),
}

/// Byte accounting for one upload. The caller applies an append under the same lock as its write.
#[derive(Debug)]
pub struct UploadProgress {
    total: u64,
    committed: u64,
    last_activity_ms: u64,
    phase: Phase,
}

impl UploadProgress {
    /// Starts an admitted upload with no committed bytes.
    #[must_use]
    pub const fn new(total: u64, now_ms: u64) -> Self {
        Self {
            total,
            committed: 0,
            last_activity_ms: now_ms,
            phase: Phase::Receiving,
        }
    }

    /// Declared object size.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// The first offset not committed to disk.
    #[must_use]
    pub const fn committed(&self) -> u64 {
        self.committed
    }

    /// Validates a proposed append and returns the next committed offset.
    ///
    /// # Errors
    /// Refuses a closed session, noncontiguous offset or invalid size.
    pub fn append_end(
        &self,
        policy: UploadPolicy,
        offset: u64,
        bytes: usize,
    ) -> Result<u64, UploadError> {
        if self.phase != Phase::Receiving {
            return Err(UploadError::Closed);
        }
        if offset != self.committed {
            return Err(UploadError::Offset {
                expected: self.committed,
            });
        }
        if bytes == 0 {
            return Err(UploadError::Empty);
        }
        if bytes > policy.chunk_bytes {
            return Err(UploadError::Size {
                limit: policy.chunk_bytes as u64,
            });
        }
        if bytes as u64 > self.total - self.committed {
            return Err(UploadError::Size {
                limit: self.total - self.committed,
            });
        }
        Ok(self.committed + bytes as u64)
    }

    /// Applies the checked offset after the corresponding write has succeeded.
    pub fn commit_append(&mut self, end: u64, now_ms: u64) {
        if self.phase == Phase::Receiving && self.committed < end && end <= self.total {
            self.committed = end;
            self.last_activity_ms = self.last_activity_ms.max(now_ms);
        }
    }

    /// Moves a fully written upload into handoff.
    ///
    /// # Errors
    /// Refuses an incomplete, inconsistent, or already closed upload.
    pub fn begin_handoff(&mut self, actual_bytes: u64) -> Result<(), UploadError> {
        if self.phase != Phase::Receiving {
            return Err(UploadError::Closed);
        }
        if self.committed != self.total || actual_bytes != self.total {
            return Err(UploadError::Incomplete {
                expected: self.total,
            });
        }
        self.phase = Phase::HandingOff;
        Ok(())
    }

    /// Records that the worker accepted the staged file.
    pub fn transferred(&mut self) {
        if self.phase == Phase::HandingOff {
            self.phase = Phase::Transferred;
        }
    }

    /// Closes the upload once. Returns whether the caller should release its resources.
    pub fn close(&mut self, end: UploadEnd) -> bool {
        if !matches!(self.phase, Phase::Receiving | Phase::HandingOff) {
            return false;
        }
        self.phase = Phase::Closed(end);
        true
    }

    /// Checks the idle budget of an upload that can still accept chunks.
    #[must_use]
    pub fn expired(&self, policy: UploadPolicy, now_ms: u64) -> bool {
        self.phase == Phase::Receiving
            && now_ms.saturating_sub(self.last_activity_ms) >= policy.idle_ms
    }
}

#[cfg(test)]
mod tests {
    use super::{UploadEnd, UploadError, UploadPolicy, UploadProgress, UploadUsage};

    #[test]
    fn admission_counts_disk_reservations_before_writes() {
        let policy = UploadPolicy {
            spool_bytes: 10,
            per_session: 1,
            ..UploadPolicy::default()
        };
        assert!(policy.admit(UploadUsage::default(), 8).is_ok());
        assert_eq!(
            policy.admit(
                UploadUsage {
                    bytes: 8,
                    ..UploadUsage::default()
                },
                3
            ),
            Err(UploadError::Capacity)
        );
        assert_eq!(
            policy.admit(
                UploadUsage {
                    session: 1,
                    ..UploadUsage::default()
                },
                1
            ),
            Err(UploadError::Capacity)
        );
    }

    #[test]
    fn only_committed_bytes_can_be_handed_off_once() {
        let policy = UploadPolicy::default();
        let mut upload = UploadProgress::new(4, 10);
        let end = upload.append_end(policy, 0, 4).unwrap();
        assert_eq!(
            upload.begin_handoff(4),
            Err(UploadError::Incomplete { expected: 4 })
        );
        upload.commit_append(end, 11);
        assert_eq!(
            upload.append_end(policy, 0, 4),
            Err(UploadError::Offset { expected: 4 })
        );
        assert_eq!(
            upload.begin_handoff(3),
            Err(UploadError::Incomplete { expected: 4 })
        );
        assert!(upload.begin_handoff(4).is_ok());
        upload.transferred();
        assert!(!upload.close(UploadEnd::Aborted));
        assert_eq!(upload.begin_handoff(4), Err(UploadError::Closed));
    }
}
