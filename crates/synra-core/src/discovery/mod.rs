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

mod model;
mod mutation;
mod table;
mod util;

pub use model::{Absorbed, Candidate};
pub use table::DiscoveryTable;
pub use util::announced_address;

use std::time::Duration;

/// How long an unpaired candidate stays current after its last announcement.
pub const CANDIDATE_TTL: Duration = Duration::from_secs(90);
/// The display name used when an announcement contains an unusable name.
pub const UNUSABLE_NAME: &str = "Unnamed device";

#[cfg(test)]
use std::net::{IpAddr, SocketAddr};
#[cfg(test)]
use synra_protocol::discovery::{DeviceAnnouncement, TrustLevel};
#[cfg(test)]
use synra_protocol::ids::DeviceId;
#[cfg(test)]
use synra_protocol::session::PlatformKind;
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
        assert_eq!(
            result,
            Absorbed::New {
                device_id: device(PEER)
            }
        );
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

        assert_eq!(
            result,
            Absorbed::Unchanged {
                device_id: device(PEER)
            }
        );
        assert_eq!(
            table.get(device(PEER)).expect("a candidate").last_seen_ms,
            2_000
        );
    }

    #[test]
    fn a_changed_name_says_updated_and_not_moved() {
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        let result = table.absorb(
            &announcement(PEER, "Lena's phone", 47100),
            address(0),
            2_000,
        );

        assert_eq!(
            result,
            Absorbed::Updated {
                device_id: device(PEER),
                moved: false
            }
        );
        assert_eq!(
            table.get(device(PEER)).expect("c").display_name,
            "Lena's phone"
        );
    }

    #[test]
    fn a_changed_address_says_moved_which_is_what_makes_a_reconnect_worth_it() {
        // ★ A device that moved is one the last connection attempt will fail against. `moved` is what tells a caller to
        // drop the old connection rather than retry it.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        let result = table.absorb(&announcement(PEER, "Phone", 47101), address(0), 2_000);

        assert_eq!(
            result,
            Absorbed::Updated {
                device_id: device(PEER),
                moved: true
            }
        );
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
        assert_eq!(
            table.get(device(PEER)).expect("c").display_name,
            UNUSABLE_NAME
        );
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
        assert_eq!(
            table.get(device(PEER)).expect("c").trust,
            TrustLevel::Handshaked
        );
    }

    #[test]
    fn an_announcement_cannot_demote_a_paired_device() {
        // ★ An announcement is unauthenticated, so it is not evidence that a pairing ended. A table that reset the level
        // would make a paired device fall back to "found on this network" every time it broadcast — and the user would
        // watch a device they had approved become unapproved, once every interval.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        table.paired(device(PEER), address(47100), Some("Phone"), 1_500);
        assert_eq!(
            table.get(device(PEER)).expect("c").trust,
            TrustLevel::Paired
        );

        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 2_000);
        assert_eq!(
            table.get(device(PEER)).expect("c").trust,
            TrustLevel::Paired
        );
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
        assert_eq!(
            table.get(device(PEER)).expect("c").display_name,
            UNUSABLE_NAME
        );
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
        assert_eq!(
            table.went_offline(device(PEER), 100),
            Absorbed::Offline {
                device_id: device(PEER)
            }
        );
        // The entry was pushed a lifetime back, so it is already expired at the moment of the goodbye.
        assert_eq!(table.current(100).count(), 0);
    }

    #[test]
    fn a_goodbye_from_an_unknown_device_says_so_rather_than_creating_one() {
        // A goodbye for a device we have never heard of is not a reason to start showing it.
        let mut table = table();
        assert_eq!(
            table.went_offline(device(OTHER), 1_000),
            Absorbed::Unchanged {
                device_id: device(OTHER)
            }
        );
        assert!(table.is_empty());
    }

    #[test]
    fn forgetting_is_what_a_block_does_and_it_does_not_come_back_from_a_broadcast() {
        // The user decided, and a device that is blocked must not be shown again because it broadcast once more.
        let mut table = table();
        table.absorb(&announcement(PEER, "Phone", 47100), address(0), 1_000);
        assert!(table.forget(device(PEER)).is_some());
        assert!(
            table.forget(device(PEER)).is_none(),
            "forgetting twice should say nothing was there"
        );
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
        assert_eq!(
            table.displayable(1_900).count(),
            0,
            "an announced device is not displayable"
        );

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
