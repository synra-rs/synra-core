use rstest::rstest;
use super::super::version::{check_version, compare_versions};

#[rstest]
#[case("1.0.0")]
#[case("0.0.0")]
#[case("10.20.30")]
#[case("1.0.0-rc.1")]
#[case("1.0.0-alpha")]
#[case("1.0.0+build.1")]
#[case("1.0.0-rc.1+build.2")]
fn legal_versions_are_accepted(#[case] version: &str) {
    assert_eq!(check_version(version), Ok(()), "{version}");
}

#[rstest]
#[case("1.0")]
#[case("1")]
#[case("1.0.0.0")]
#[case("v1.0.0")]
#[case("01.0.0")]
#[case("1.0.0-")]
#[case("1.0.0+")]
#[case("1.0.0-rc..1")]
#[case("")]
#[case("one.two.three")]
fn illegal_versions_are_refused(#[case] version: &str) {
    assert!(
        check_version(version).is_err(),
        "{version} should not parse"
    );
}

#[test]
fn versions_compare_by_their_parts() {
    use core::cmp::Ordering;
    assert_eq!(
        compare_versions("1.0.0", "1.0.0").expect("ok"),
        Ordering::Equal
    );
    assert_eq!(
        compare_versions("1.0.1", "1.0.0").expect("ok"),
        Ordering::Greater
    );
    assert_eq!(
        compare_versions("1.0.0", "1.1.0").expect("ok"),
        Ordering::Less
    );
    assert_eq!(
        compare_versions("2.0.0", "1.99.99").expect("ok"),
        Ordering::Greater
    );
}

#[test]
fn a_prerelease_sorts_below_its_release() {
    // Getting this backwards would let a release candidate satisfy a minimum that the release was written
    // for, so a plugin would be installed and then fail on a function that is not in the RC.
    use core::cmp::Ordering;
    assert_eq!(
        compare_versions("1.0.0-rc.1", "1.0.0").expect("ok"),
        Ordering::Less
    );
    assert_eq!(
        compare_versions("1.0.0", "1.0.0-rc.1").expect("ok"),
        Ordering::Greater
    );
    assert_eq!(
        compare_versions("1.0.0-rc.1", "1.0.0-rc.2").expect("ok"),
        Ordering::Less
    );
    // Numeric identifiers compare numerically, not as strings: `rc.10` is above `rc.9`.
    assert_eq!(
        compare_versions("1.0.0-rc.10", "1.0.0-rc.9").expect("ok"),
        Ordering::Greater
    );
    // Fewer identifiers is lower.
    assert_eq!(
        compare_versions("1.0.0-rc", "1.0.0-rc.1").expect("ok"),
        Ordering::Less
    );
    // A numeric identifier is below an alphanumeric one.
    assert_eq!(
        compare_versions("1.0.0-1", "1.0.0-alpha").expect("ok"),
        Ordering::Less
    );
}

#[test]
fn comparing_an_illegal_version_is_an_error_not_an_ordering() {
    assert!(compare_versions("1.0", "1.0.0").is_err());
    assert!(compare_versions("1.0.0", "nonsense").is_err());
}
