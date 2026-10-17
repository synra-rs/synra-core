//! Reading a peer's answer into the kernel's view of it.
//!
//! # Why the mapping is tested on its own
//!
//! Because it is where the wire and the kernel can disagree. The plan that follows it — `decide` — is already covered by its own
//! tests; what was untested is the step between a `PluginList` and the `RemoteState` values it is compared with, and a missing
//! `digest` there would turn "different bytes" into "already synchronised".

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use synra_core::plugin_sync::RemoteState;
use synra_protocol::ids::PluginId;
use synra_protocol::session::PluginSummary;

fn summary(version: Option<&str>, digest: Option<&str>, active: bool) -> PluginSummary {
    PluginSummary {
        plugin_id: PluginId::parse("@acme/hello").expect("an id"),
        version: version.map(str::to_owned),
        digest: digest.map(str::to_owned),
        active,
    }
}

#[test]
fn every_field_of_the_answer_reaches_the_kernel() {
    let state = RemoteState::from_summary(&summary(Some("1.2.3"), Some("sha256-abc"), true));

    assert_eq!(state.plugin_id.as_str(), "@acme/hello");
    assert_eq!(state.version.as_deref(), Some("1.2.3"));
    assert_eq!(state.digest.as_deref(), Some("sha256-abc"));
    assert!(state.active);
}

#[test]
fn an_answer_without_a_digest_stays_without_one() {
    // ★ The failure this guards: a mapping that filled the digest with the version, or with an empty string, would make two
    // devices with different bytes look like the same artifact — and the plan would skip a transfer that was needed.
    let state = RemoteState::from_summary(&summary(Some("1.2.3"), None, false));

    assert_eq!(state.digest, None, "no digest is not the same as an empty one");
    assert_eq!(state.version.as_deref(), Some("1.2.3"), "the version is still known");
}

#[test]
fn a_plugin_nobody_has_maps_to_an_absent_state() {
    let state = RemoteState::from_summary(&summary(None, None, false));

    assert_eq!(state.version, None);
    assert_eq!(state.digest, None);
    assert!(!state.active);
    assert_eq!(state, RemoteState::absent(state.plugin_id.clone()), "the same as the kernel's own guess");
}
