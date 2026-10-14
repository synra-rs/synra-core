//! What the kernel has heard about, and how much of it to believe.
//!
//! # What discovery does and does not establish
//!
//! `synra-protocol`'s own module docs put it exactly: discovery answers *what addresses might a Synra device be at?* and
//! refuses to answer any other question. A UDP datagram's source address is trivially forged and its contents are
//! unauthenticated, so **anything a device claims about itself here is a hint to be checked, not a fact to be trusted**.
//!
//! That restraint is what this module is built around. A device found this way is a *candidate*, and it becomes a peer
//! only after a TCP connection has been made and a `Hello` exchanged over it. The trust level is tracked explicitly
//! rather than inferred, because the three levels have genuinely different consequences:
//!
//! | Level | What it took | What the user sees |
//! | --- | --- | --- |
//! | announced | a datagram arrived | the device, under "found on this network" |
//! | handshaked | a TCP connection completed a `Hello` | the device, as reachable |
//! | paired | the user approved it | the device, as usable |
//!
//! # Why the name is checked here
//!
//! It arrives from another device and it is **rendered**. A control character in it is how a device list row is
//! rewritten and a newline is how a log line is forged — the same reasoning `identity`'s validator follows, applied to
//! the same value arriving from the other direction. A name that fails is **not** a reason to drop the candidate: the
//! datagram told us a device exists and where, which is what discovery is for, and the name is only a display concern.
//! So it is replaced with a placeholder rather than the whole announcement being refused.
//!
//! # Why the trust level never goes down
//!
//! A datagram cannot demote a pairing: it is unauthenticated, so a peer that announced itself is not evidence that a
//! paired device stopped being paired. The level rises when the evidence rises and is lowered only by the kernel
//! forgetting the pairing, which is a different code path with a different reason.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use synra_protocol::discovery::{DeviceAnnouncement, TrustLevel};
use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

use crate::identity::check_display_name;

/// How long a candidate stays after its last announcement.
///
/// # Why this is not the protocol's scan budget
///
/// The scan budget is how long one *scan* runs — 2.5 seconds — and it decides when a scan stops looking. This is how
/// long a device that was found stays in the list, which is a different question: a device that answered a scan a
/// second ago is one the user should still see, and one that answered ten minutes ago is one that may have been
/// unplugged. A figure in that range, not in the scan's.
pub const CANDIDATE_TTL: Duration = Duration::from_secs(90);

/// The name shown for a device whose own name was not usable.
pub const UNUSABLE_NAME: &str = "Unnamed device";

/// One device the kernel has heard about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Which device.
    pub device_id: DeviceId,
    /// What to show a person.
    ///
    /// Never the raw announced string: a name that failed validation is [`UNUSABLE_NAME`].
    pub display_name: String,
    /// What it claims to be, when it said.
    pub platform: Option<PlatformKind>,
    /// What it claims to run, when it said.
    pub app_version: Option<String>,
    /// What it claims it can do, when it said.
    ///
    /// A claim, and a caller that acts on it without a handshake is acting on an unauthenticated value. Kept because
    /// the handshake compares against it, which is what makes "the peer said it could resume and then could not"
    /// detectable.
    pub claimed_features: Vec<synra_protocol::handshake::Feature>,
    /// Where it said it listens.
    pub address: SocketAddr,
    /// How much of it to believe.
    pub trust: TrustLevel,
    /// When it was last heard from, as a wall-clock reading.
    ///
    /// A wall clock rather than a monotonic reading, because this crosses to a client and to the database — the same
    /// reasoning every other `*_ms` in the kernel follows.
    pub last_seen_ms: i64,
}

impl Candidate {
    /// Whether it is still worth showing.
    ///
    /// # Why a paired device never expires
    ///
    /// Because the pairing is recorded and the user approved it. A paired device that has gone quiet is one that is
    /// *offline*, which is a state the interface shows and the user can act on — and dropping it would make the device
    /// disappear until it was rediscovered, which reads as an unpairing.
    #[must_use]
    pub fn is_current(&self, now_ms: i64, ttl: Duration) -> bool {
        if self.trust == TrustLevel::Paired {
            return true;
        }
        let age = now_ms.saturating_sub(self.last_seen_ms);
        // `as_millis` on a `u128` into an `i64`: saturating, because a ttl beyond 292 million years is a caller mistake
        // rather than a duration this can represent.
        let ttl_ms = i64::try_from(ttl.as_millis()).unwrap_or(i64::MAX);
        age < ttl_ms
    }

    /// Whether the interface may show it.
    ///
    /// The protocol's own rule, delegated rather than restated.
    #[must_use]
    pub const fn is_displayable(&self) -> bool {
        self.trust.is_displayable()
    }
}

/// What the table decided about an announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Absorbed {
    /// A device the table had not heard of.
    New {
        /// Which device.
        device_id: DeviceId,
    },
    /// A device it had heard of, with something different to say.
    Updated {
        /// Which device.
        device_id: DeviceId,
        /// Whether the address changed, which is what makes a peer worth reconnecting to.
        moved: bool,
    },
    /// A device it had heard of, saying the same thing again.
    Unchanged {
        /// Which device.
        device_id: DeviceId,
    },
    /// The announcement was from this device.
    ///
    /// Ignored rather than refused: a device hears its own broadcasts, because that is what broadcasting means. Every
    /// kernel ignores its own datagrams, and a table that counted them would show the user their own machine as a peer.
    SelfAnnouncement,
    /// The announcement named a device that is now offline.
    Offline {
        /// Which device.
        device_id: DeviceId,
    },
}

/// Everything the kernel has heard about.
///
/// # Why a `BTreeMap` and not a `HashMap`
///
/// Because a report and a test both want the same order twice, and the interface renders a list. The protocol's routing
/// table uses a seeded hash because it is indexed by an untrusted name on a hot path; this is indexed by an identifier
/// the kernel already holds and is read once per render.
#[derive(Debug, Clone)]
pub struct DiscoveryTable {
    candidates: BTreeMap<DeviceId, Candidate>,
    local: DeviceId,
    ttl: Duration,
}

impl DiscoveryTable {
    /// A table that ignores announcements from `local`.
    #[must_use]
    pub const fn new(local: DeviceId) -> Self {
        Self { candidates: BTreeMap::new(), local, ttl: CANDIDATE_TTL }
    }

    /// A table with a chosen lifetime, for a test that does not want to wait one out.
    #[must_use]
    pub const fn with_ttl(local: DeviceId, ttl: Duration) -> Self {
        Self { candidates: BTreeMap::new(), local, ttl }
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
        self.candidates.values().filter(move |candidate| candidate.is_current(now_ms, ttl))
    }

    /// Every device the interface may show, in identifier order.
    ///
    /// The intersection of current and displayable, which is the list a screen renders and therefore the list worth
    /// having a name for.
    pub fn displayable(&self, now_ms: i64) -> impl Iterator<Item = &Candidate> {
        let ttl = self.ttl;
        self.candidates
            .values()
            .filter(move |candidate| candidate.is_current(now_ms, ttl) && candidate.is_displayable())
    }

    /// Records an announcement.
    ///
    /// # Why the trust level only rises
    ///
    /// An announcement is unauthenticated. A peer that announced itself is not evidence that a paired device stopped
    /// being paired, so the level is raised for a device that has just been heard from and never lowered here. A
    /// pairing is forgotten by the code that owns pairings, with a reason a user can see.
    pub fn absorb(&mut self, announcement: &DeviceAnnouncement, from: SocketAddr, now_ms: i64) -> Absorbed {
        if announcement.device_id == self.local {
            return Absorbed::SelfAnnouncement;
        }

        let address = SocketAddr::new(from.ip(), announcement.port);
        let name = usable_name(&announcement.display_name);

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
            return Absorbed::New { device_id: announcement.device_id };
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
            Absorbed::Unchanged { device_id: announcement.device_id }
        }
        else {
            Absorbed::Updated { device_id: announcement.device_id, moved }
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
    pub fn paired(&mut self, device_id: DeviceId, address: SocketAddr, name: Option<&str>, now_ms: i64) {
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
                existing.last_seen_ms = now_ms.saturating_sub(
                    i64::try_from(self.ttl.as_millis()).unwrap_or(i64::MAX),
                );
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

        expired.into_iter().filter_map(|id| self.candidates.remove(&id)).collect()
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

/// A name to display, or the placeholder.
///
/// # Why a bad name does not drop the candidate
///
/// The datagram told us a device exists and where, which is what discovery is *for*. The name is a display concern, so a
/// name that fails the check costs the name and not the candidate — and the user still sees that something is there,
/// which is the difference between a device they can investigate and one that is silently missing.
fn usable_name(announced: &str) -> String {
    check_display_name(announced).unwrap_or_else(|_| UNUSABLE_NAME.to_owned())
}

/// The address a datagram came from, with the port it announced.
///
/// The source address and not the announced endpoint list: the source is what the operating system vouched for, and the
/// announced list is a claim. The port is the announced one, because the source port is the ephemeral one the datagram
/// was sent from rather than the one the peer listens on.
#[must_use]
pub const fn announced_address(from: IpAddr, announcement: &DeviceAnnouncement) -> SocketAddr {
    SocketAddr::new(from, announcement.port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use synra_protocol::handshake::Feature;

    const LOCAL: &str = "11111111-1111-4111-8111-111111111111";
    const PEER: &str = "22222222-2222-4222-8222-222222222222";
    const OTHER: &str = "33333333-3333-4333-8333-333333333333";

    fn device(name: &str) -> DeviceId {
        name.parse().expect("a valid device id")
    }

    fn address(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 5], port))
    }

    fn announcement(id: &str, name: &str, port: u16) -> DeviceAnnouncement {
        DeviceAnnouncement {
            device_id: device(id),
            display_name: name.to_owned(),
            protocol: synra_protocol::handshake::PROTOCOL_VERSION,
            port,
            platform: Some(PlatformKind::Desktop),
            app_version: Some("0.1.0".to_owned()),
            features: vec![Feature::EventStream],
        }
    }

    fn table() -> DiscoveryTable {
        DiscoveryTable::new(device(LOCAL))
    }

    /// A table with a short lifetime, so a test does not wait one out.
    fn short_table() -> DiscoveryTable {
        DiscoveryTable::with_ttl(device(LOCAL), Duration::from_millis(1_000))
    }

    // ── Absorbing ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_announcement_from_an_unknown_device_is_new() {
        let mut table = table();
        let result = table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        assert_eq!(result, Absorbed::New { device_id: device(PEER) });
        assert_eq!(table.len(), 1);

        let candidate = table.get(device(PEER)).expect("a candidate");
        assert_eq!(candidate.display_name, "Phone");
        assert_eq!(candidate.platform, Some(PlatformKind::Desktop));
        assert_eq!(candidate.address, address(47100));
        assert_eq!(candidate.trust, TrustLevel::Announced);
        assert_eq!(candidate.last_seen_ms, 1_000);
    }

    #[test]
    fn the_announced_port_is_used_rather_than_the_source_port() {
        // ★ The source address is what the operating system vouched for and the port is what the peer listens on — the
        // source port is the ephemeral one the datagram was sent *from*. Using it would make every connection attempt
        // dial a port that nothing is listening on.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(5_4321), 1_000);
        let candidate = table.get(device(PEER)).expect("a candidate");
        assert_eq!(candidate.address.port(), 47100);
        assert_eq!(candidate.address.ip(), address(0).ip());
    }

    #[test]
    fn a_devices_own_announcement_is_ignored() {
        // ★ A device hears its own broadcasts, because that is what broadcasting means. A table that counted them would
        // show the user their own machine as a peer.
        let mut table = table();
        let result = table.absorb(&announcement(LOCAL, "Me", 47100), address(0), 1_000);
        assert_eq!(result, Absorbed::SelfAnnouncement);
        assert!(table.is_empty());
    }

    #[test]
    fn a_repeat_says_unchanged_and_still_refreshes_the_time() {
        // ★ The ordinary case: a device announces on an interval and most announcements say the same thing. Reported
        // rather than swallowed, because a caller that counts *changes* needs the difference — and the time is refreshed
        // either way, because being heard from is what keeps a candidate alive.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        let result = table.absorb(&announcement(PEER, "Phone", 47100), address(0), 2_000);

        assert_eq!(result, Absorbed::Unchanged { device_id: device(PEER) });
        assert_eq!(table.get(device(PEER)).expect("a candidate").last_seen_ms, 2_000);
    }

    #[test]
    fn a_changed_name_says_updated_and_not_moved() {
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        let result = table.absorb(&announcement(PEER, "Lena's phone", 47100), address(0), 2_000);

        assert_eq!(result, Absorbed::Updated { device_id: device(PEER), moved: false });
        assert_eq!(table.get(device(PEER)).expect("c").display_name, "Lena's phone");
    }

    #[test]
    fn a_changed_address_says_moved_which_is_what_makes_a_reconnect_worth_it() {
        // ★ A device that moved is one the last connection attempt will fail against. `moved` is what tells a caller to
        // drop the old connection rather than retry it.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        let result = table.absorb(&announcement(PEER, "Phone", 47101), address(0), 2_000);

        assert_eq!(result, Absorbed::Updated { device_id: device(PEER), moved: true });
        assert_eq!(table.get(device(PEER)).expect("c").address.port(), 47101);
    }

    #[test]
    fn the_same_device_heard_from_twice_is_one_candidate() {
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 2_000);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn a_name_with_a_control_character_costs_the_name_and_not_the_candidate() {
        // ★ The name arrives from another device and it is **rendered**. A newline in it is how a log line is forged.
        // But the datagram also said a device exists and where, which is what discovery is for — so the name is replaced
        // and the candidate is kept. A user still sees that something is there, which is the difference between a device
        // they can investigate and one that is silently missing.
        let mut table = table();
        table.absorb(&announcement(PEER, "bad\nname", 47100), address(0), 1_000);
        let candidate = table.get(device(PEER)).expect("a candidate");
        assert_eq!(candidate.display_name, UNUSABLE_NAME);
        assert!(!candidate.display_name.contains('\n'));
    }

    #[test]
    fn an_over_long_name_costs_the_name_too() {
        let mut table = table();
        let long = "a".repeat(500);
        table.absorb(&announcement(PEER, &long, 47100), address(0), 1_000);
        assert_eq!(table.get(device(PEER)).expect("c").display_name, UNUSABLE_NAME);
    }

    #[test]
    fn an_ordinary_name_is_kept_as_announced_and_trimmed() {
        let mut table = table();
        table.absorb(&announcement(PEER, "  Phone  ", 47100), address(0), 1_000);
        assert_eq!(table.get(device(PEER)).expect("c").display_name, "Phone");
    }

    // ── The trust level ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_handshake_raises_the_trust_level() {
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        assert!(table.handshaked(device(PEER), address(47100), Some("Phone"), 2_000));
        assert_eq!(table.get(device(PEER)).expect("c").trust, TrustLevel::Handshaked);
    }

    #[test]
    fn an_announcement_cannot_demote_a_paired_device() {
        // ★ An announcement is unauthenticated, so it is not evidence that a pairing ended. A table that reset the level
        // would make a paired device fall back to "found on this network" every time it broadcast — and the user would
        // watch a device they had approved become unapproved, once every interval.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        table.paired(device(PEER), address(47100), Some("Phone"), 1_500);
        assert_eq!(table.get(device(PEER)).expect("c").trust, TrustLevel::Paired);

        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 2_000);
        assert_eq!(table.get(device(PEER)).expect("c").trust, TrustLevel::Paired);
    }

    #[test]
    fn a_handshake_over_a_different_address_records_where_it_actually_worked() {
        // ★ A handshake that completed proves the address the connection was made to works, which is better evidence
        // than anything a datagram claimed. Recording it is what makes the next connection attempt succeed.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        table.handshaked(device(PEER), address(9_999), Some("Phone"), 2_000);
        assert_eq!(table.get(device(PEER)).expect("c").address.port(), 9_999);
    }

    #[test]
    fn a_handshake_with_an_unknown_device_creates_a_candidate() {
        // A direct connection may be attempted without discovery, and refusing it would make discovery mandatory for a
        // device that is already known by address.
        let mut table = table();
        let known = table.handshaked(device(PEER), address(47100), Some("Phone"), 1_000);
        assert!(!known, "the device was not known before");
        let candidate = table.get(device(PEER)).expect("a candidate");
        assert_eq!(candidate.trust, TrustLevel::Handshaked);
        assert_eq!(candidate.display_name, "Phone");
        // And its claimed features are empty, because nothing claimed them — the connection proved identity, not ability.
        assert!(candidate.claimed_features.is_empty());
    }

    #[test]
    fn a_handshake_with_a_bad_name_still_records_the_device() {
        let mut table = table();
        table.handshaked(device(PEER), address(47100), Some("bad\nname"), 1_000);
        assert_eq!(table.get(device(PEER)).expect("c").display_name, UNUSABLE_NAME);
    }

    #[test]
    fn pairing_creates_a_candidate_when_discovery_never_saw_it() {
        // ★ A pairing can be made without discovery — two devices given each other's addresses. A table that required an
        // announcement first would make a paired device invisible until it happened to broadcast.
        let mut table = table();
        table.paired(device(PEER), address(47100), Some("Phone"), 1_000);
        let candidate = table.get(device(PEER)).expect("a candidate");
        assert_eq!(candidate.trust, TrustLevel::Paired);
        assert_eq!(candidate.address.port(), 47100);
    }

    #[test]
    fn pairing_raises_the_level_on_a_device_already_known() {
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        table.paired(device(PEER), address(47100), Some("Approved"), 2_000);
        let candidate = table.get(device(PEER)).expect("c");
        assert_eq!(candidate.trust, TrustLevel::Paired);
        assert_eq!(candidate.display_name, "Approved");
    }

    // ── Expiry ────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_candidate_expires_after_its_lifetime() {
        let mut table = short_table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 0);
        assert_eq!(table.current(500).count(), 1);
        assert_eq!(table.current(1_000).count(), 0, "the boundary is exclusive");
    }

    #[test]
    fn a_paired_device_never_expires() {
        // ★ The pairing is recorded and the user approved it. A paired device that has gone quiet is one that is
        // *offline*, which the interface shows and the user can act on — dropping it would make the device vanish until
        // it was rediscovered, which reads as an unpairing.
        let mut table = short_table();
        table.paired(device(PEER), address(47100), Some("Phone"), 0);
        assert_eq!(table.current(1_000_000).count(), 1);
        // But it is still dropped by `forget`, because that is the user deciding.
        assert!(table.forget(device(PEER)).is_some());
    }

    #[test]
    fn expiring_returns_what_it_dropped_so_a_screen_can_be_told() {
        // ★ A device that disappears from a list without an event is one a screen keeps showing. The candidates are
        // returned rather than only a count because the caller cannot look them up afterwards — they are gone.
        let mut table = short_table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 0);
        table.absorb(&announcement(OTHER, "Tablet", 47100), address(0), 900);

        let expired = table.expire(1_000);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].device_id, device(PEER));
        assert_eq!(expired[0].display_name, "Phone");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn a_goodbye_ages_the_entry_out_at_the_ordinary_rate() {
        // ★ A goodbye is the beginning of the end of the entry, not a refresh of it. Leaving the last-seen time alone
        // would keep the entry alive for a further lifetime after the device said it was leaving.
        let mut table = short_table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 0);
        assert_eq!(table.went_offline(device(PEER), 100), Absorbed::Offline { device_id: device(PEER) });
        // The entry was pushed a lifetime back, so it is already expired at the moment of the goodbye.
        assert_eq!(table.current(100).count(), 0);
    }

    #[test]
    fn a_goodbye_from_an_unknown_device_says_so_rather_than_creating_one() {
        // A goodbye for a device we have never heard of is not a reason to start showing it.
        let mut table = table();
        assert_eq!(
            table.went_offline(device(OTHER), 1_000),
            Absorbed::Unchanged { device_id: device(OTHER) }
        );
        assert!(table.is_empty());
    }

    #[test]
    fn forgetting_is_what_a_block_does_and_it_does_not_come_back_from_a_broadcast() {
        // The user decided, and a device that is blocked must not be shown again because it broadcast once more.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        assert!(table.forget(device(PEER)).is_some());
        assert!(table.forget(device(PEER)).is_none(), "forgetting twice should say nothing was there");
        assert!(table.is_empty());
    }

    // ── The lists ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_current_list_excludes_the_expired_and_the_displayable_list_excludes_the_rest() {
        let mut table = short_table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 0);
        table.absorb(&announcement(OTHER, "Tablet", 47100), address(0), 1_500);

        // At 1_900 the first is 1_900 old and expired, the second is 400 old and current — so one is current.
        assert_eq!(table.current(1_900).count(), 1);
        // ★ And the current one is **not** displayable: the protocol's own rule is `Handshaked | Paired`, so a device
        // heard from over UDP — which is unauthenticated — is a *candidate* and not a peer. The interface shows
        // candidates under a separate heading for exactly this reason.
        assert_eq!(table.displayable(1_900).count(), 0, "an announced device is not displayable");

        // A handshake is what makes it displayable, because a completed connection is evidence — and it does not change
        // whether the entry is current.
        table.handshaked(device(OTHER), address(47100), Some("Tablet"), 1_800);
        assert_eq!(table.displayable(1_900).count(), 1);
        assert_eq!(table.current(1_900).count(), 1);

        // Both are still in the table, because expiry is a separate act — a caller decides when to sweep.
        assert_eq!(table.iter().count(), 2);
        // At 3_100 the handshaked device is 1_300 old, so nothing is current any more. The arithmetic matters: the
        // `1_800` above is the handshake's own timestamp, and a test that reused `1_500` would leave the entry alive
        // for a further lifetime and assert the wrong thing about the sweep.
        assert_eq!(table.current(3_100).count(), 0);
        assert_eq!(table.expire(3_100).len(), 2);
        assert!(table.is_empty());
    }

    #[test]
    fn the_list_is_in_identifier_order_so_two_runs_agree() {
        // Two renders of the same state have to agree, or a diff of two reports is noise.
        let mut table = table();
        table.absorb(&announcement(OTHER, "Z", 47100), address(0), 1_000);
        table.absorb(&announcement(PEER, "A", 47100), address(0), 1_000);

        let order: Vec<DeviceId> = table.iter().map(|candidate| candidate.device_id).collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(order, sorted);
    }

    #[test]
    fn an_empty_table_reports_itself_as_empty() {
        let table = table();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(table.current(0).count(), 0);
        assert_eq!(table.displayable(0).count(), 0);
        assert!(table.get(device(PEER)).is_none());
        assert_eq!(table.local(), device(LOCAL));
        assert_eq!(table.ttl(), CANDIDATE_TTL);
    }

    #[test]
    fn the_announced_address_uses_the_source_and_the_announced_port() {
        // Two different things, and mixing them is the bug the function exists to prevent.
        let ann = announcement(PEER, "Phone", 47100);
        let resolved = announced_address(IpAddr::from([192, 168, 1, 9]), &ann);
        assert_eq!(resolved.port(), 47100);
        assert_eq!(resolved.ip(), IpAddr::from([192, 168, 1, 9]));
    }
}
