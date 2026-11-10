use super::super::{Feature, negotiate};

#[test]
fn negotiation_intersects_the_two_lists() {
    let ours = [Feature::EventStream, Feature::ClipboardSync, Feature::LanDiscovery];
    let theirs = [Feature::EventStream, Feature::LanDiscovery, Feature::TransferResume];
    let agreed = negotiate(&ours, &theirs, &[]);

    assert!(agreed.is_usable());
    assert!(agreed.supports(Feature::EventStream));
    assert!(agreed.supports(Feature::LanDiscovery));
    assert!(!agreed.supports(Feature::ClipboardSync), "the peer does not offer it");
    assert!(!agreed.supports(Feature::TransferResume), "we do not offer it");
}

#[test]
fn a_missing_required_feature_makes_the_link_unusable() {
    let agreed = negotiate(&[Feature::EventStream], &[Feature::TransferResume], &[Feature::EventStream]);

    assert!(!agreed.is_usable());
    assert_eq!(agreed.missing_required, vec![Feature::EventStream]);
    // And it is not in `common`, so a caller that forgot to check `is_usable` still cannot
    // accidentally use it.
    assert!(!agreed.supports(Feature::EventStream));
}

#[test]
fn duplicates_in_either_list_are_harmless() {
    let agreed = negotiate(
        &[Feature::EventStream, Feature::EventStream],
        &[Feature::EventStream, Feature::EventStream],
        &[],
    );
    assert_eq!(agreed.common, vec![Feature::EventStream]);
}

#[test]
fn negotiation_does_not_depend_on_list_order() {
    // The list is stored on the link and compared when a second connection is considered, so an
    // order that depended on which side dialled would make identical links look different.
    let a = negotiate(
        &[Feature::EventStream, Feature::LanDiscovery],
        &[Feature::LanDiscovery, Feature::EventStream],
        &[],
    );
    let b = negotiate(
        &[Feature::LanDiscovery, Feature::EventStream],
        &[Feature::EventStream, Feature::LanDiscovery],
        &[],
    );
    assert_eq!(a.common, b.common);
    assert_eq!(
        a.common,
        vec![Feature::EventStream, Feature::LanDiscovery],
        "sorted by wire name: event-stream before lan-discovery"
    );
}

#[test]
fn an_empty_intersection_is_not_an_error_by_itself() {
    // Two devices with nothing in common can still exchange messages; they just cannot use any
    // optional capability. Only a *required* feature makes the link unusable.
    let agreed = negotiate(&[Feature::EventStream], &[Feature::ClipboardSync], &[]);
    assert!(agreed.is_usable());
    assert!(agreed.common.is_empty());
}

#[test]
fn feature_list_is_exhaustive() {
    // A variant added without a wire name, or two sharing one, makes the format ambiguous. This
    // is the guard for a `#[non_exhaustive]` enum, where the compiler cannot help.
    let mut seen = std::collections::HashSet::new();
    for feature in Feature::ALL {
        assert!(seen.insert(feature.as_str()), "duplicate wire name for {feature:?}");
        assert_eq!(Feature::from_str_opt(feature.as_str()), Some(*feature));
        assert_eq!(feature.to_string(), feature.as_str());

        let json = serde_json::to_string(feature).expect("serialises");
        assert_eq!(json, format!("\"{}\"", feature.as_str()));
        let back: Feature = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, *feature);
    }
    assert_eq!(Feature::from_str_opt("teleportation"), None);
    assert_eq!(Feature::ALL.len(), seen.len());
}
