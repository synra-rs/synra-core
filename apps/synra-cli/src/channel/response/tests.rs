use synra_control::Response;
use synra_protocol::error::ErrorCode;

use super::{Shape, outcome_of, render_device, render_plugin};

#[test]
fn a_json_shape_prints_the_value_pretty() {
    let response = Response::ok(serde_json::json!({"devices": []}));
    match outcome_of(&response, Shape::Json) {
        crate::session::CommandOutcome::Json { body, ok } => {
            assert!(ok, "a success should not be a failure");
            assert!(body.contains('\n'), "not pretty-printed: {body}");
            assert!(body.contains("devices"), "{body}");
        }
        other => panic!("expected JSON, got {other:?}"),
    }
}

#[test]
fn a_prose_shape_summarises_a_status() {
    let response = Response::ok(serde_json::json!({
        "state": "running",
        "version": "0.1.0",
        "dataDir": "/tmp/synra",
        "transportPort": 47100,
        "uptimeMs": 5_000,
        "notImplemented": ["session"],
    }));
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            let text = lines.join("\n");
            assert!(text.contains("running"), "{text}");
            assert!(text.contains("0.1.0"), "{text}");
            assert!(text.contains("5s"), "{text}");
            // ★ The missing layer is printed: `status` is what a user runs to find out what is going on, and a
            // summary that hid it would leave them wondering why the next command refuses.
            assert!(text.contains("session"), "{text}");
        }
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn a_prose_shape_says_when_there_are_no_devices_rather_than_printing_nothing() {
    // A command that printed nothing would look like a command that failed.
    let response = Response::ok(serde_json::json!({"devices": []}));
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            assert_eq!(lines, vec!["no devices".to_owned()]);
        }
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn a_removal_report_names_the_files_the_system_would_not_let_go() {
    // ★ The row is gone and the removal cannot fail on a locked file, so this sentence is the only place the user
    // learns that something is still on disk. A count alone would send them looking; the paths are the answer.
    let response = Response::ok(serde_json::json!({
        "pluginId": "@acme/hello",
        "bytesFreed": 1536,
        "dataKept": true,
        "leftovers": ["/tmp/synra/plugins/@acme/hello"]
    }));
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            assert_eq!(
                lines,
                vec![
                    "removed @acme/hello; 1536 bytes freed; its data was kept; could not remove \
                     /tmp/synra/plugins/@acme/hello"
                ]
            );
        }
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn a_log_answer_says_when_lines_were_dropped_or_not_written() {
    // ★ The difference between "the kernel is quiet" and "the kernel could not write": both produce a short file, and
    // only this sentence tells them apart.
    let response = Response::ok(serde_json::json!({
        "lines": [],
        "dropped": 3,
        "writeErrors": 1,
        "lastWriteError": "no space left on device"
    }));
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            assert_eq!(lines.len(), 1, "{lines:?}");
            assert!(lines[0].contains("dropped 3"), "{lines:?}");
            assert!(lines[0].contains("could not write 1"), "{lines:?}");
            assert!(lines[0].contains("no space left on device"), "{lines:?}");
        }
        other => panic!("expected lines, got {other:?}"),
    }

    let quiet = Response::ok(serde_json::json!({
        "lines": [],
        "dropped": 0,
        "writeErrors": 0
    }));
    match outcome_of(&quiet, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            assert!(lines.is_empty(), "a healthy log adds nothing: {lines:?}");
        }
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn a_prose_shape_says_when_there_are_no_plugins() {
    let response = Response::ok(serde_json::json!({"plugins": [], "loaded": false}));
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            assert!(lines[0].contains("no plugins"), "{lines:?}");
        }
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn a_removal_report_reads_as_a_sentence_about_the_data() {
    // ★ The field name `dataKept` is not what a user is asking about; the sentence says which of the two acts happened.
    let response = Response::ok(serde_json::json!({
        "pluginId": "@acme/hello",
        "bytesFreed": 1536,
        "dataKept": false
    }));
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            assert_eq!(
                lines,
                vec!["removed @acme/hello; 1536 bytes freed; its data was deleted"]
            );
        }
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn a_device_row_says_both_what_it_is_and_whether_it_is_reachable() {
    // ★ Two different questions, and a row that answered one would make a paired-but-offline device look usable.
    let row = render_device(&serde_json::json!({
        "deviceId": "dev_a", "displayName": "Laptop", "online": false, "paired": true
    }));
    assert!(row.contains("dev_a"), "{row}");
    assert!(row.contains("Laptop"), "{row}");
    assert!(row.contains("paired, offline"), "{row}");

    let row = render_device(&serde_json::json!({
        "deviceId": "dev_b", "online": true, "paired": false
    }));
    assert!(row.contains("not paired"), "{row}");
}

#[test]
fn a_plugin_row_reports_a_problem_instead_of_hiding_it() {
    // A directory in the plugins directory that is not a plugin is something the user should see.
    let row = render_plugin(&serde_json::json!({
        "id": "@acme/hello", "version": "1.2.3", "title": "Hello"
    }));
    assert!(row.contains("@acme/hello"), "{row}");
    assert!(row.contains("1.2.3"), "{row}");

    let broken = render_plugin(&serde_json::json!({
        "id": "broken", "problem": "there is no manifest.json in this directory"
    }));
    assert!(broken.contains("manifest"), "{broken}");
}

#[test]
fn a_prose_shape_falls_back_to_json_for_a_shape_it_does_not_know() {
    // ★ A client older than the kernel must print the answer rather than nothing. The fallback is ugly and complete,
    // and complete is what a user filing a bug report needs.
    let response = Response::ok(serde_json::json!({"somethingNew": {"a": 1}}));
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            assert!(lines.join("").contains("somethingNew"), "{lines:?}");
        }
        other => panic!("expected lines, got {other:?}"),
    }
}

#[test]
fn a_refusal_is_a_failure_with_its_code_and_a_non_zero_exit() {
    // ★ A refusal is the kernel *answering*: a result, with a code a script reads. Collapsing it with a transport
    // error would make "the device is offline" indistinguishable from "no kernel is running".
    let response = Response::failed(
        ErrorCode::Unsupported.as_str(),
        "the session layer is not implemented yet",
        false,
    );
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Json { body, ok } => {
            assert!(!ok, "a refusal must not be a success");
            assert!(body.contains("unsupported"), "{body}");
            assert!(body.contains("session layer"), "{body}");
        }
        other => panic!("expected a JSON failure, got {other:?}"),
    }
    // The same shape whatever output was asked for, so a script does not have to tell prose from JSON.
    assert!(matches!(
        outcome_of(&response, Shape::Json),
        crate::session::CommandOutcome::Json { ok: false, .. }
    ));
}

#[test]
fn a_hello_response_is_readable_rather_than_json() {
    let response = Response::Hello {
        version: 1,
        kernel: "0.1.0".to_owned(),
    };
    match outcome_of(&response, Shape::Prose) {
        crate::session::CommandOutcome::Lines(lines) => {
            assert!(lines[0].contains("0.1.0"), "{lines:?}");
            assert!(lines[0].contains('1'), "{lines:?}");
        }
        other => panic!("expected lines, got {other:?}"),
    }
}
