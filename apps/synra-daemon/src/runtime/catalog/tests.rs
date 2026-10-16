//! The one piece of this module that is arithmetic rather than I/O.

use super::host_of;

#[test]
fn a_mirror_yields_its_host_for_the_guard() {
    assert_eq!(host_of("https://registry.npmjs.org"), Some("registry.npmjs.org".to_owned()));
    assert_eq!(host_of("https://example.test:8443/x"), Some("example.test".to_owned()));
    assert_eq!(host_of("http://user@example.test/x"), Some("example.test".to_owned()));
}

#[test]
fn a_url_the_guard_cannot_read_yields_no_host() {
    // ★ The security-relevant half. A mirror whose host cannot be read must yield **nothing**, so it is simply absent from
    // the guard's allow-list: the guard is an allow-list, and an unparsed entry that became a host would be a wildcard.
    for url in ["not a url", "registry.npmjs.org", "https://", "https:///path", ""] {
        assert_eq!(host_of(url), None, "{url}");
    }
}
