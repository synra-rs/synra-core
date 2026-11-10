use std::net::SocketAddr;
use std::time::Duration;

use synra_protocol::discovery::{DeviceAnnouncement, TrustLevel};
use synra_protocol::ids::DeviceId;

use super::UNUSABLE_NAME;
use super::model::{Absorbed, Candidate};
use super::table::DiscoveryTable;
use super::util::usable_name;

impl DiscoveryTable {
    /// Records an announcement.
    ///
    /// # Why the trust level only rises
    ///
    /// An announcement is unauthenticated. A peer that announced itself is not evidence that a paired device stopped
    /// being paired, so the level is raised for a device that has just been heard from and never lowered here. A
    /// pairing is forgotten by the code that owns pairings, with a reason a user can see.
    pub fn absorb(
        &mut self,
        announcement: &DeviceAnnouncement,
        from: SocketAddr,
        now_ms: i64,
    ) -> Absorbed {
        if announcement.device_id == self.local {
            return Absorbed::SelfAnnouncement;
        }

        let address = SocketAddr::new(from.ip(), announcement.port);
        let name = usable_name(&announcement.display_name);
        if synra_observe::wire::is_installed() {
            synra_observe::wire::note("lan", format!("heard {address}"));
        }

        let existing = self.candidates.get(&announcement.device_id);
        let Some(existing) = existing else {
            self.candidates.insert(
                announcement.device_id,
                Candidate {
                    device_id: announcement.device_id,
                    display_name: name,
                    platform: announcement.platform,
                    app_version: announcement.app_version.clone(),
                    claimed_features: announcement.features.clone(),
                    address,
                    trust: TrustLevel::Announced,
                    last_seen_ms: now_ms,
                },
            );
            return Absorbed::New {
                device_id: announcement.device_id,
            };
        };

        // Nothing changed, which is the ordinary case: a device announces on an interval and most announcements say the
        // same thing. Reported rather than silently swallowed, because a caller that counts *changes* needs to know the
        // difference between "heard from again" and "said something new" — and the first is what keeps a candidate
        // alive.
        let moved = existing.address != address;
        let same = existing.display_name == name
            && existing.platform == announcement.platform
            && existing.app_version == announcement.app_version
            && existing.claimed_features == announcement.features
            && !moved;

        // ★ The trust level is preserved, not reset to `Announced`. An announcement cannot demote a pairing, and a table
        // that reset the level would make a paired device fall back to "found on this network" every time it broadcast.
        let trust = existing.trust;
        self.candidates.insert(
            announcement.device_id,
            Candidate {
                device_id: announcement.device_id,
                display_name: name,
                platform: announcement.platform,
                app_version: announcement.app_version.clone(),
                claimed_features: announcement.features.clone(),
                address,
                trust,
                last_seen_ms: now_ms,
            },
        );

        if same {
            Absorbed::Unchanged {
                device_id: announcement.device_id,
            }
        } else {
            Absorbed::Updated {
                device_id: announcement.device_id,
                moved,
            }
        }
    }

    /// Records that a device completed a handshake with this one.
    ///
    /// # Why this takes the address too
    ///
    /// Because a handshake that completed over a connection proves the address the connection was made to works, which
    /// is better evidence than anything a datagram claimed. A device reached at a different address from the one it
    /// announced is one whose announcement is stale, and recording the address it was actually reachable at is what
    /// makes the next connection attempt succeed.
    ///
    /// Returns whether the device was known. A handshake with an unknown device is not a failure: a direct connection
    /// may be attempted without discovery, and refusing it would make discovery mandatory for a device that is already
    /// known by address.
    pub fn handshaked(
        &mut self,
        device_id: DeviceId,
        address: SocketAddr,
        name: Option<&str>,
        now_ms: i64,
    ) -> bool {
        let Some(existing) = self.candidates.get_mut(&device_id) else {
            // A device reached without discovery becomes a candidate at the handshaked level: the connection is evidence,
            // and it is better evidence than a datagram.
            self.candidates.insert(
                device_id,
                Candidate {
                    device_id,
                    display_name: name.map_or_else(|| UNUSABLE_NAME.to_owned(), usable_name),
                    platform: None,
                    app_version: None,
                    claimed_features: Vec::new(),
                    address,
                    trust: TrustLevel::Handshaked,
                    last_seen_ms: now_ms,
                },
            );
            return false;
        };

        existing.address = address;
        existing.trust = existing.trust.max(TrustLevel::Handshaked);
        existing.last_seen_ms = now_ms;
        if let Some(name) = name {
            existing.display_name = usable_name(name);
        }
        true
    }

    /// Records that the user paired with a device.
    ///
    /// # Why this can create a candidate
    ///
    /// Because a pairing can be made without discovery — two devices given each other's addresses. A table that
    /// required an announcement first would make a paired device invisible until it happened to broadcast.
    pub fn paired(
        &mut self,
        device_id: DeviceId,
        address: SocketAddr,
        name: Option<&str>,
        now_ms: i64,
    ) {
        match self.candidates.get_mut(&device_id) {
            Some(existing) => {
                existing.trust = TrustLevel::Paired;
                existing.address = address;
                existing.last_seen_ms = now_ms;
                if let Some(name) = name {
                    existing.display_name = usable_name(name);
                }
            }
            None => {
                self.candidates.insert(
                    device_id,
                    Candidate {
                        device_id,
                        display_name: name.map_or_else(|| UNUSABLE_NAME.to_owned(), usable_name),
                        platform: None,
                        app_version: None,
                        claimed_features: Vec::new(),
                        address,
                        trust: TrustLevel::Paired,
                        last_seen_ms: now_ms,
                    },
                );
            }
        }
    }

    /// Records that a device said goodbye.
    ///
    /// # Why the candidate is kept rather than removed
    ///
    /// Because "it left" and "it was never here" are different, and the user asked to see a list of devices — a device
    /// that said goodbye is one the interface should show as offline until its entry ages out, not one that vanishes. A
    /// paired device is kept indefinitely, because a pairing outlives a departure.
    ///
    /// Returns whether the device was known.
    pub fn went_offline(&mut self, device_id: DeviceId, now_ms: i64) -> Absorbed {
        match self.candidates.get_mut(&device_id) {
            // The last-seen time is moved *back* rather than left alone, so the entry ages out at the same rate as one
            // that was never seen — a goodbye is the beginning of the end of the entry, not a refresh of it.
            Some(existing) => {
                existing.last_seen_ms =
                    now_ms.saturating_sub(i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX));
                Absorbed::Offline { device_id }
            }
            None => Absorbed::Unchanged { device_id },
        }
    }

    /// Drops the candidates that have stopped being current.
    ///
    /// # Why this reports what it dropped
    ///
    /// Because the interface has to be told: a device that disappears from a list without an event is one a screen keeps
    /// showing. The names are returned rather than only a count so the caller can say which without looking them up
    /// again, which it cannot do — they are gone.
    pub fn expire(&mut self, now_ms: i64) -> Vec<Candidate> {
        let ttl = self.ttl;
        let expired: Vec<DeviceId> = self
            .candidates
            .values()
            .filter(|candidate| !candidate.is_current(now_ms, ttl))
            .map(|candidate| candidate.device_id)
            .collect();

        expired
            .into_iter()
            .filter_map(|id| self.candidates.remove(&id))
            .collect()
    }

    /// Forgets a device entirely, for an unpairing or a block.
    ///
    /// Returns whether it was known. Unlike [`DiscoveryTable::expire`], this is not about time: the user decided, and a
    /// device that is blocked must not be shown again because it broadcast once more.
    pub fn forget(&mut self, device_id: DeviceId) -> Option<Candidate> {
        self.candidates.remove(&device_id)
    }

    /// How long a candidate stays after its last announcement.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }
}
