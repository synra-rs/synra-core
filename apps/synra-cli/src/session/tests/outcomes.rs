use super::super::{CommandOutcome, dispatch, follow_in};
use super::cli;

#[test]
fn following_without_a_kernel_says_so_rather_than_waiting_for_lines() {
    // ★ `--follow` used to be refused as unimplemented. It is implemented now, and the failure that remains is the
    // ordinary one: no kernel answers. That must be said **before** the follower starts waiting on a file, or a user
    // with no daemon sees a silent command that looks like it is following a log.
    let directory =
        std::env::temp_dir().join(format!("synra-cli-follow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("a data directory");

    let mut out = Vec::new();
    let code = follow_in(
        &directory,
        &cli(&["synra", "logs", "--follow"]),
        &mut out,
        std::time::Duration::from_millis(5),
    );

    assert_eq!(code, 1, "an unreachable kernel is a failure");
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("no kernel is listening"),
        "the socket error should be named: {text}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_command_that_produced_output_succeeded() {
    // An empty device list is a successful answer to "which devices are there", and exiting non-zero for it would
    // make a script treat an ordinary situation as an error.
    assert_eq!(CommandOutcome::Lines(vec![]).exit_code(), 0);
    assert_eq!(CommandOutcome::Lines(vec!["a".to_owned()]).exit_code(), 0);
    assert_eq!(CommandOutcome::json("{}").exit_code(), 0);
    // And JSON carries no success of its own: a failing command that printed JSON returned zero before this, which
    // is the one signal a script reads.
    assert_eq!(CommandOutcome::json_failure("{}").exit_code(), 1);
    assert_eq!(CommandOutcome::Failed("no".to_owned()).exit_code(), 1);
}

#[test]
fn the_text_is_what_a_caller_prints() {
    assert_eq!(CommandOutcome::Lines(vec!["a".to_owned(), "b".to_owned()]).text(), "a\nb");
    assert_eq!(CommandOutcome::json("{}").text(), "{}");
    assert_eq!(CommandOutcome::json_failure("{}").text(), "{}");
    assert_eq!(CommandOutcome::Failed("bad".to_owned()).text(), "bad");
}

#[test]
fn a_failure_is_what_main_sends_to_the_error_stream() {
    assert!(CommandOutcome::Failed("no".to_owned()).is_failure());
    assert!(!CommandOutcome::json("{}").is_failure());
    assert!(CommandOutcome::json_failure("{}").is_failure());
    assert!(!CommandOutcome::Lines(vec![]).is_failure());
}

#[test]
fn a_command_needing_a_kernel_that_is_not_running_says_where_it_looked() {
    // ★ Every command but `doctor` and `db` opens the socket, so a kernel that is not running is a transport failure
    // — and the sentence names the **path**, which is what the user needs. A generic "no kernel is reachable" would
    // hide that the client looked somewhere specific, and the commonest cause is that it looked in the wrong place:
    // that is what `SYNRA_DATA_DIR` is for.
    let outcome = dispatch(&cli(&["synra", "status"]));
    match outcome {
        CommandOutcome::Json { body, ok } => {
            assert!(!ok, "a command with no kernel is a failure");
            let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
            assert_eq!(value["code"], "transport_not_open");
            let message = value["message"].as_str().expect("a message");
            assert!(message.contains("kernel.sock"), "{message}");
        }
        other => panic!("expected a JSON failure, got {other:?}"),
    }
}

#[test]
fn a_script_asking_for_json_gets_json_even_when_it_failed() {
    // So a caller does not have to tell prose from JSON to know it failed: the exit code is the primary signal and
    // this is the detail beside it.
    let outcome = dispatch(&cli(&["synra", "--output", "json", "status"]));
    match outcome {
        CommandOutcome::Json { body, ok } => {
            assert!(!ok, "a command with no kernel is a failure");
            let value: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
            assert_eq!(value["code"], "transport_not_open");
            assert!(
                value["message"].as_str().expect("a message").contains("kernel.sock"),
                "the message should name the path: {body}"
            );
        }
        other => panic!("expected JSON, got {other:?}"),
    }
}
