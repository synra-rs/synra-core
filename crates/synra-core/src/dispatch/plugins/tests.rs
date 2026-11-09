use std::sync::Arc;

use synra_capability::CapabilitySet;
use synra_plugin_host::quota::Quota;
use synra_protocol::ids::PluginId;

use super::{Authority, PluginSetError};

fn id(name: &str) -> PluginId {
    PluginId::try_from(name.to_owned()).expect("a plugin id")
}

fn authority(grants: CapabilitySet) -> Authority {
    Authority::new(
        grants,
        Quota::default(),
        Arc::new(parking_lot::Mutex::new(Vec::new())),
    )
}

#[test]
fn a_session_carries_the_plugins_own_authority() {
    // ★ The test the whole change exists for, and it needs no engine.
    //
    // Every instance used to be created with `session: None`, and `linker::run` refuses **every** host call when
    // there is no session — so the capability gate, the mechanism the entire capability model rests on, never ran.
    // Nothing failed; a plugin simply could not reach a host function, and the only signal was `HOST_FAILED`, which
    // says "no session" rather than "you are not allowed".
    //
    // What is asserted is the session's own contents, because the session is what the linker reads. A test that
    // called through the set could not tell a missing session from a denied capability: both refuse, with different
    // codes, and only one of them means the gate ran.
    let mut grants = CapabilitySet::new();
    grants.insert_str("log:*").expect("a capability");

    let session = authority(grants).session_for(&id("@synra/aaa"), &super::super::tests::host());

    assert_eq!(session.plugin, id("@synra/aaa"));
    assert!(
        session
            .grants
            .contains(&synra_capability::Capability::parse("log:info").expect("a capability")),
        "the session must carry the plugin's grants, not an empty set"
    );
}

#[test]
fn two_instances_of_one_plugin_share_their_rate_and_their_record() {
    // ★ Why the budget and the audit belong to the plugin rather than to the instance.
    //
    // A budget cloned per instance would multiply the rate by the instance limit — a plugin allowed ten calls a
    // minute with four instances would get forty, which is not what its quota says. And a record of the instance's
    // own would die with the store, which is the same as having no audit at all. Asserted with pointer equality,
    // because "the same allowance" is exactly what a copy is not.
    let authority = authority(CapabilitySet::new());
    let host = super::super::tests::host();

    let first = authority.session_for(&id("@synra/bbb"), &host);
    let second = authority.session_for(&id("@synra/bbb"), &host);

    assert!(
        Arc::ptr_eq(&first.budget, &second.budget),
        "two instances, two rates"
    );
    assert!(
        Arc::ptr_eq(&first.audit, &second.audit),
        "two instances, two records"
    );
}

#[test]
fn every_plugin_failure_names_a_code_the_interface_branches_on() {
    // ★ The mapping used to be `Internal` for all of them, which told a user to file a bug whether the plugin was
    // missing, throttled, or had trapped.
    use synra_protocol::ErrorCode;

    let id = PluginId::parse("@acme/hello").expect("a plugin id");
    assert_eq!(
        PluginSetError::NotLoaded { id: id.clone() }.code(),
        ErrorCode::PluginNotInstalled
    );
    assert_eq!(
        PluginSetError::AtInstanceLimit { id: id.clone() }.code(),
        ErrorCode::RateLimited
    );
    assert_eq!(
        PluginSetError::UndeclaredImport {
            id: id.clone(),
            import: "host.call".to_owned()
        }
        .code(),
        ErrorCode::CapabilityDenied
    );
    assert_eq!(
        PluginSetError::Faulted {
            id,
            reason: "too many traps".to_owned()
        }
        .code(),
        ErrorCode::PluginTrapped
    );
}
