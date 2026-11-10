use synra_plugin_api::publisher::PublisherTrustStore;
use super::super::{Candidate, HostFacts, Stage, Step, Verdict, verify};
use super::{Fixture, manifest_json};

#[test]
fn a_plugin_needing_something_this_host_cannot_do_warns_rather_than_failing() {
    // ★ A warning, because the package is valid: its notification button will not work on this machine and will work
    // on another. Refusing it would make a plugin uninstallable on the device that cannot do one of the things it
    // offers.
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["platform:simulate-keys"]);
    let facts = HostFacts { actions: Vec::new(), ..HostFacts::desktop() };
    let candidate = Candidate { host: facts, ..fixture.candidate(None, false) };

    let report = verify(&candidate, &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable(), "a warning is not a refusal");
    // The warnings are read off the steps rather than through a temporary vector, which would be dropped while the
    // reference into it is still held.
    let warnings: Vec<&Step> = report.steps.iter().filter(|step| step.verdict == Verdict::Warn).collect();
    assert_eq!(warnings.len(), 1);
    let warning = warnings.first().expect("a warning");
    assert_eq!(warning.stage, Stage::PlatformApplicability);
    assert!(warning.detail.contains("simulate-keys"), "{}", warning.detail);
    assert!(report.describe().contains("warning"), "{}", report.describe());
}

#[test]
fn a_headless_host_warns_about_the_platform_actions_it_has_none_of() {
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["platform:open-url"]);
    let candidate = Candidate { host: HostFacts::headless(), ..fixture.candidate(None, false) };

    let report = verify(&candidate, &PublisherTrustStore::new()).expect("a report");
    assert_eq!(report.warnings().len(), 1);
    assert!(report.warnings().first().expect("a warning").detail.contains("platform:open-url"));
}

#[test]
fn a_plugin_whose_capabilities_the_host_has_does_not_warn() {
    let mut fixture = Fixture::new();
    fixture.manifest = manifest_json(&["platform:open-url"]);
    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.warnings().is_empty());
    assert!(report.describe().contains("all 11"), "{}", report.describe());
}
