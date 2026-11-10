use super::*;

#[test]
fn domain_names_round_trip() {
    for domain in Domain::ALL {
        assert_eq!(Domain::parse(domain.as_str()), Ok(*domain));
        assert_eq!(domain.to_string(), domain.as_str());
    }
    assert!(Domain::parse("Network").is_err(), "names are lowercase");
    assert!(Domain::parse("telepathy").is_err());
    assert!(Domain::parse("").is_err());
}

#[test]
fn domain_list_is_unique_and_fits_a_mask() {
    let mut seen = std::collections::HashSet::new();
    for domain in Domain::ALL {
        assert!(seen.insert(domain.as_str()), "duplicate name {domain}");
        assert!(!domain.bit().eq(&0), "{domain} occupies no bit");
    }
    // A mask has 32 bits, and one domain per bit. A list long enough to overflow it would make
    // `bit()` silently alias two domains.
    assert!(Domain::ALL.len() <= 32, "too many domains for a u32 mask");
}

#[test]
fn each_domain_gets_its_own_bit() {
    let mut bits = std::collections::HashSet::new();
    for domain in Domain::ALL {
        assert!(bits.insert(domain.bit()), "{domain} shares a bit with another domain");
    }
    // Every bit is a distinct power of two.
    for domain in Domain::ALL {
        assert!(domain.bit().is_power_of_two(), "{domain}");
    }
}

#[test]
fn a_domain_id_is_stable_and_reversible() {
    for domain in Domain::ALL {
        let id = DomainId::of(*domain);
        assert_eq!(id.domain(), Ok(*domain));
        assert_eq!(DomainId::from(*domain), id);
    }

    // Distinct ids.
    let mut ids = std::collections::HashSet::new();
    for domain in Domain::ALL {
        assert!(ids.insert(DomainId::of(*domain).get()), "duplicate id for {domain}");
    }

    // A stored value from a newer version is refused, rather than mapped to a domain we happen
    // to have. A grant for a domain we do not understand must not become one we do.
    let unknown = DomainId::of(Domain::Ui);
    assert!(unknown.domain().is_ok());
    assert!(DomainId::of(Domain::Log).get() != unknown.get());
}

#[test]
fn an_empty_mask_has_nothing() {
    let mask = DomainMask::empty();
    assert!(mask.is_empty());
    assert_eq!(mask.count(), 0);
    for domain in Domain::ALL {
        assert!(!mask.has(*domain));
    }
    assert_eq!(mask.iter().count(), 0);
    assert_eq!(mask.to_string(), "(none)");
}

#[test]
fn a_mask_reports_exactly_what_was_added() {
    let mask = DomainMask::empty()
        .with(Domain::Network)
        .with(Domain::Fs)
        .with(Domain::Network);

    assert!(mask.has(Domain::Network));
    assert!(mask.has(Domain::Fs));
    assert!(!mask.has(Domain::Ui));
    // Adding twice is idempotent: a set, not a count.
    assert_eq!(mask.count(), 2);
    assert_eq!(mask.iter().collect::<Vec<_>>(), vec![Domain::Network, Domain::Fs]);
}

#[test]
fn a_full_mask_has_every_domain() {
    let mask = DomainMask::all();
    assert_eq!(mask.count(), Domain::ALL.len() as u32);
    for domain in Domain::ALL {
        assert!(mask.has(*domain));
    }
    assert!(!mask.is_empty());
}

#[test]
fn removing_a_domain_clears_only_its_bit() {
    let mask = DomainMask::all().without(Domain::Network);
    assert!(!mask.has(Domain::Network));
    for domain in Domain::ALL.iter().filter(|d| **d != Domain::Network) {
        assert!(mask.has(*domain), "{domain} should still be present");
    }
    assert_eq!(mask.count(), Domain::ALL.len() as u32 - 1);
}

#[test]
fn a_mask_displays_readably() {
    let mask = DomainMask::empty().with(Domain::Log).with(Domain::Network);
    assert_eq!(mask.to_string(), "log, network");
}

#[test]
fn a_domain_id_displays_its_name() {
    assert_eq!(DomainId::of(Domain::Network).to_string(), "network");
}
