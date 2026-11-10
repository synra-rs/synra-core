use super::{Consent, InstallSource, Move, PluginSlot, Resolved, Verified};

mod installation;
mod failures;
mod persistence;
mod running;

const NOW: i64 = 1_000;

fn registry_source() -> InstallSource {
    InstallSource::Registry { package: "@acme/hello".to_owned(), version: "^1".to_owned() }
}

fn resolved() -> Resolved {
    Resolved {
        version: "1.2.3".to_owned(),
        artifacts: vec!["plugin.wasm".to_owned()],
        manifest_digest: "aaa".to_owned(),
        development_only: false,
    }
}

fn verified() -> Verified {
    Verified {
        version: "1.2.3".to_owned(),
        artifact_digest: "bbb".to_owned(),
        manifest_digest: "aaa".to_owned(),
        requested: vec!["platform:open-url".to_owned()],
        trust: Some("signed by a publisher this device has seen".to_owned()),
    }
}

fn consented() -> Consent {
    Consent { granted: vec!["platform:open-url".to_owned()], denied: Vec::new() }
}

/// Drives a slot to `Installed`, through every stage, the way a caller does.
fn installed() -> PluginSlot {
    let mut slot = PluginSlot::available();
    let _ = slot.apply(Move::Install { source: registry_source() }, NOW).expect("install");
    let _ = slot.apply(Move::Resolved { resolved: resolved() }, NOW).expect("resolved");
    let _ = slot.apply(Move::Fetched { artifact_digest: "bbb".to_owned() }, NOW).expect("fetched");
    let _ = slot.apply(Move::Verified { verified: verified() }, NOW).expect("verified");
    let _ = slot.apply(Move::Consented { consent: consented() }, NOW).expect("consented");
    let _ = slot.apply(Move::Installed, NOW).expect("installed");
    slot
}
