use synra_protocol::discovery::TrustLevel;
use synra_protocol::session::PlatformKind;
use super::super::{Absorbed, UNUSABLE_NAME};
use super::{LOCAL, PEER, address, announcement, device, table};

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
