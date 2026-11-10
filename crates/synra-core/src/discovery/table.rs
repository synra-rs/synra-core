use std::collections::BTreeMap;
use std::time::Duration;

use synra_protocol::ids::DeviceId;

use super::CANDIDATE_TTL;
use super::model::Candidate;

/// Everything the kernel has heard about.
///
/// # Why a `BTreeMap` and not a `HashMap`
///
/// Because a report and a test both want the same order twice, and the interface renders a list. The protocol's routing
/// table uses a seeded hash because it is indexed by an untrusted name on a hot path; this is indexed by an identifier
/// the kernel already holds and is read once per render.
#[derive(Debug, Clone)]
pub struct DiscoveryTable {
    pub(super) candidates: BTreeMap<DeviceId, Candidate>,
    pub(super) local: DeviceId,
    pub(super) ttl: Duration,
}

impl DiscoveryTable {
    /// A table that ignores announcements from `local`.
    #[must_use]
    pub const fn new(local: DeviceId) -> Self {
        Self {
            candidates: BTreeMap::new(),
            local,
            ttl: CANDIDATE_TTL,
        }
    }

    /// A table with a chosen lifetime, for a test that does not want to wait one out.
    #[must_use]
    pub const fn with_ttl(local: DeviceId, ttl: Duration) -> Self {
        Self {
            candidates: BTreeMap::new(),
            local,
            ttl,
        }
    }

    /// This device's identifier, which announcements from it are ignored against.
    #[must_use]
    pub const fn local(&self) -> DeviceId {
        self.local
    }

    /// How many devices are known, expired ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Whether nothing is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// A device, whether or not it is still current.
    #[must_use]
    pub fn get(&self, device_id: DeviceId) -> Option<&Candidate> {
        self.candidates.get(&device_id)
    }

    /// Every device, in identifier order.
    pub fn iter(&self) -> impl Iterator<Item = &Candidate> {
        self.candidates.values()
    }

    /// Every device that is still current, in identifier order.
    pub fn current(&self, now_ms: i64) -> impl Iterator<Item = &Candidate> {
        let ttl = self.ttl;
        self.candidates
            .values()
            .filter(move |candidate| candidate.is_current(now_ms, ttl))
    }

    /// Every device the interface may show, in identifier order.
    ///
    /// The intersection of current and displayable, which is the list a screen renders and therefore the list worth
    /// having a name for.
    pub fn displayable(&self, now_ms: i64) -> impl Iterator<Item = &Candidate> {
        let ttl = self.ttl;
        self.candidates.values().filter(move |candidate| {
            candidate.is_current(now_ms, ttl) && candidate.is_displayable()
        })
    }
}
