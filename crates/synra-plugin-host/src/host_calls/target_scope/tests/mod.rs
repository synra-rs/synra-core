use super::*;
use crate::{
    HostCalls,
    quota::{Budget, Quota},
    test_host::Stub,
};
use synra_observe::audit::AuditOutcome;

const DEVICE: &str = "00000000-0000-4000-8000-000000000001";
const OTHER: &str = "00000000-0000-4000-8000-000000000002";

fn grants(texts: &[&str]) -> CapabilitySet {
    CapabilitySet::parse_all(texts.iter().copied()).expect("grants")
}

fn check_call(grant: &str, import: &str, args: serde_json::Value, expected: Option<&str>) {
    let host = Stub::default();
    let held = grants(&[grant]);
    let budget = Budget::new(Quota::default());
    let mut audit = Vec::new();
    let mut calls = HostCalls::new(
        &host,
        PluginId::parse("@acme/chat").expect("plugin"),
        &held,
        &budget,
        &mut audit,
    );
    let result = calls.call(&format!("synra:plugin/host#{import}"), &args.to_string());
    match expected {
        None => assert!(result.is_ok(), "{grant} {args}: {result:?}"),
        Some(code) => assert_eq!(result.expect_err("refused").code, code, "{grant} {args}"),
    }
    assert_eq!(host.called().len(), usize::from(expected.is_none()));
    let outcome = if expected == Some(CallError::CAPABILITY_DENIED) {
        AuditOutcome::Denied
    } else if expected.is_some() {
        AuditOutcome::Failed
    } else {
        AuditOutcome::Allowed
    };
    assert_eq!(audit.len(), 1);
    assert_eq!(audit.first().expect("audit").outcome, outcome);
}

mod scoped_grants;
mod declarations;
mod precedence;
