use synra_capability::Domain;

use super::*;

#[test]
fn a_record_has_no_place_to_put_a_payload() {
    // The property that makes the record safe to keep and safe to export. Asserted as a compile-time
    // fact by construction: the struct's fields are all there is, and none of them can hold content.
    let record = entry(1_000, &plugin("@synra-plugin/chat"), "network:fetch:api.github.com", AuditOutcome::Allowed);

    assert_eq!(record.at_ms, 1_000);
    assert_eq!(record.domain(), Domain::Network);
    assert_eq!(record.destination(), Some("api.github.com"));
    // The rendering is a destination, not a body.
    let rendered = record.render();
    assert!(rendered.contains("api.github.com"), "{rendered}");
    assert!(!rendered.contains("payload"), "{rendered}");
}

#[test]
fn outcomes_report_whether_they_were_refusals() {
    assert!(AuditOutcome::Allowed.was_allowed());
    assert!(AuditOutcome::Failed.was_allowed());
    assert!(!AuditOutcome::Denied.was_allowed());

    // A refusal by the capability system, as distinct from an operation that failed.
    assert!(AuditOutcome::Denied.is_refusal());
    assert!(AuditOutcome::QuotaExceeded.is_refusal());
    assert!(AuditOutcome::RateLimited.is_refusal());
    assert!(!AuditOutcome::Allowed.is_refusal());
    assert!(!AuditOutcome::Failed.is_refusal(), "the call was permitted and then failed");
}

#[test]
fn outcome_markers_match_the_documented_icons() {
    // The settings screen shows these, and the design document names them.
    assert_eq!(AuditOutcome::Allowed.marker(), "ok");
    assert_eq!(AuditOutcome::Failed.marker(), "warn");
    assert_eq!(AuditOutcome::Denied.marker(), "blocked");
    assert_eq!(AuditOutcome::QuotaExceeded.marker(), "blocked");
}

#[test]
fn outcomes_round_trip_through_json_with_their_names() {
    for outcome in [
        AuditOutcome::Allowed,
        AuditOutcome::Denied,
        AuditOutcome::QuotaExceeded,
        AuditOutcome::RateLimited,
        AuditOutcome::Failed,
    ] {
        let json = serde_json::to_string(&outcome).expect("serialises");
        assert_eq!(json, format!("\"{}\"", outcome.as_str()));
        let back: AuditOutcome = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, outcome);
    }
}

#[test]
fn every_name_the_table_stores_parses_back_to_its_outcome() {
    // ★ The table's `outcome` column is written with `as_str`, so this is the reader's half of that one spelling
    // table. Asserting through the same loop is what keeps a new variant from being stored but not parsed.
    for outcome in [
        AuditOutcome::Allowed,
        AuditOutcome::Denied,
        AuditOutcome::QuotaExceeded,
        AuditOutcome::RateLimited,
        AuditOutcome::Failed,
    ] {
        assert_eq!(AuditOutcome::from_stable_name(outcome.as_str()), Some(outcome));
    }

    // An unknown name is not "allowed": a row written by a newer build is reported by name rather than guessed at.
    assert_eq!(AuditOutcome::from_stable_name("something-new"), None);
}

#[test]
fn a_record_round_trips_through_json_with_camel_case_fields() {
    let record = entry(1_700_000_000_000, &plugin("@synra-plugin/chat"), "device:send:@pc", AuditOutcome::Allowed);
    let json = serde_json::to_string(&record).expect("serialises");

    assert!(json.contains("\"atMs\""), "{json}");
    assert!(!json.contains("at_ms"), "{json}");

    let back: AuditEntry = serde_json::from_str(&json).expect("deserialises");
    assert_eq!(back, record);
}

#[test]
fn a_record_without_a_destination_renders_without_one() {
    let record = AuditEntry::new(
        1_000,
        plugin("@synra-plugin/chat"),
        capability("device:list"),
        AuditOutcome::Allowed,
        None,
    );
    assert_eq!(record.destination(), None);
    assert!(!record.render().contains("->"), "{}", record.render());
}

#[test]
fn a_rendered_record_is_a_destination_not_a_body() {
    // The whole justification for keeping these longer than a log. A rendering that could contain content
    // would put the audit trail in the same category as the log, with the same retention problem.
    let chat = plugin("@synra-plugin/chat");
    let record = entry(1_000, &chat, "network:fetch:api.github.com:POST", AuditOutcome::Allowed);
    let rendered = record.render();

    assert!(rendered.contains("network"), "{rendered}");
    assert!(rendered.contains("api.github.com"), "{rendered}");
    assert!(rendered.contains("ok"), "{rendered}");
    assert!(rendered.contains("5ms"), "{rendered}");
}
