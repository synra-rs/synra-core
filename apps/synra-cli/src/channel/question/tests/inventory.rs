use synra_control::Request;

use crate::args::{Command, DbAction, DbArgs, OutputFormat};

use super::super::{Question, Shape, question_for};
use super::{devices_args, logs_args, send_args};

#[test]
fn every_request_the_cli_can_make_is_accounted_for() {
    // ★ The exhaustive half. A command added to the enum and not to the mapping is one that silently does nothing,
    // and the compiler cannot see it because the mapping has a `None` arm.
    let commands: Vec<(&str, Option<Question>)> = vec![
        ("status", question_for(&Command::Status, None, || None)),
        (
            "devices",
            question_for(&Command::Devices(devices_args(false)), None, || None),
        ),
        (
            "send",
            question_for(&Command::Send(send_args(Some("x"), None)), None, || None),
        ),
        (
            "logs",
            question_for(&Command::Logs(logs_args(1, None, false)), None, || None),
        ),
        (
            "share",
            question_for(
                &Command::Share(crate::args::ShareArgs {
                    text: "https://example.com".to_owned(),
                    mime: "text/uri-list".to_owned(),
                }),
                None,
                || None,
            ),
        ),
        (
            "intent",
            question_for(
                &Command::Intent(crate::args::IntentArgs {
                    action: crate::args::IntentAction::Show {
                        intent: "abc".to_owned(),
                    },
                }),
                None,
                || None,
            ),
        ),
        (
            "doctor",
            question_for(
                &Command::Doctor(crate::args::DoctorArgs {
                    failures_only: false,
                    bundle: None,
                }),
                None,
                || None,
            ),
        ),
        (
            "db",
            question_for(
                &Command::Db(DbArgs {
                    action: DbAction::Dump { table: None },
                }),
                None,
                || None,
            ),
        ),
    ];
    for (name, question) in commands {
        let expected = !matches!(name, "doctor" | "db");
        assert_eq!(question.is_some(), expected, "{name}");
    }
}

#[test]
fn each_answer_to_a_prompt_becomes_its_own_request() {
    // ★ The mapping, rather than the parsing. Three verbs that all reached `IntentSnapshot` would parse, print
    // something plausible, and never decide or cancel anything — and no argument test would notice.
    let ask = |action: crate::args::IntentAction| {
        question_for(
            &Command::Intent(crate::args::IntentArgs { action }),
            None,
            || None,
        )
        .map(|question| question.request)
    };

    assert!(matches!(
        ask(crate::args::IntentAction::Show {
            intent: "abc".to_owned()
        }),
        Some(Request::IntentSnapshot { .. })
    ));
    assert!(matches!(
        ask(crate::args::IntentAction::Decide {
            intent: "abc".to_owned(),
            plugin: None,
            target: None,
        }),
        Some(Request::IntentDecide { .. })
    ));
    assert!(matches!(
        ask(crate::args::IntentAction::Cancel {
            intent: "abc".to_owned()
        }),
        Some(Request::IntentCancel { .. })
    ));

    // And the two optional answers survive the trip. A `decide` that dropped them would be one where choosing between
    // several plugins, or answering "where", silently did the default instead.
    let Some(Request::IntentDecide {
        plugin_id, target, ..
    }) = ask(crate::args::IntentAction::Decide {
        intent: "abc".to_owned(),
        plugin: Some("@acme/opener".to_owned()),
        target: Some("0e5a1c34-0000-4000-8000-000000000001".to_owned()),
    })
    else {
        panic!("expected a decide request");
    };
    assert_eq!(plugin_id.as_deref(), Some("@acme/opener"));
    assert_eq!(
        target.as_deref(),
        Some("0e5a1c34-0000-4000-8000-000000000001")
    );
}

#[test]
fn the_two_commands_that_need_no_kernel_say_so() {
    // ★ `doctor` exists for the user whose kernel will not start, and `db` reads the database directly. Sending them
    // over the socket would make the first fail in exactly the case it exists for.
    assert!(
        question_for(
            &Command::Doctor(crate::args::DoctorArgs {
                failures_only: false,
                bundle: None
            }),
            None,
            || None,
        )
        .is_none()
    );
    assert!(
        question_for(
            &Command::Db(DbArgs {
                action: DbAction::Integrity
            }),
            None,
            || None
        )
        .is_none()
    );
}

#[test]
fn asking_for_json_asks_the_kernel_for_json_shaped_output() {
    // The shape is the request's, not the caller's alone: a command that asked for prose and printed JSON would be
    // one a script could not read.
    let prose = question_for(&Command::Devices(devices_args(false)), None, || None).expect("q");
    assert_eq!(prose.shape, Shape::Prose);
    let json = question_for(
        &Command::Devices(devices_args(false)),
        Some(OutputFormat::Json),
        || None,
    )
    .expect("q");
    assert_eq!(json.shape, Shape::Json);
}
