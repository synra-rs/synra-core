use synra_control::Request;

use crate::args::Command;

use super::super::question_for;
use super::{devices_args, logs_args, send_args};

#[test]
fn the_devices_flag_reaches_the_request() {
    // ★ A `--all` that did not arrive is a command whose flag is silently ignored, and the output looks plausible
    // either way — so the assertion is on the operand rather than on the shape of the question.
    let question =
        question_for(&Command::Devices(devices_args(true)), None, || None).expect("a question");
    assert_eq!(
        question.request,
        Request::Devices {
            include_unpaired: true,
            scan_ms: None
        }
    );

    let question = question_for(&Command::Devices(devices_args(false)), None, || None)
        .expect("a question");
    assert_eq!(
        question.request,
        Request::Devices {
            include_unpaired: false,
            scan_ms: None
        }
    );
}

#[test]
fn text_and_a_file_become_their_own_requests() {
    // The two are different requests rather than one with an optional payload, because the kernel does different
    // things with them: text may go inline and a file never does.
    let text = question_for(&Command::Send(send_args(Some("hi"), None)), None, || None)
        .expect("a question");
    assert_eq!(
        text.request,
        Request::SendText {
            to: "dev_a".to_owned(),
            text: "hi".to_owned()
        }
    );

    let file = question_for(
        &Command::Send(send_args(None, Some("/tmp/a"))),
        None,
        || None,
    )
    .expect("a question");
    assert_eq!(
        file.request,
        Request::SendFile {
            to: "dev_a".to_owned(),
            path: "/tmp/a".to_owned()
        }
    );
}

#[test]
fn a_send_with_neither_text_nor_a_file_asks_nothing() {
    // `clap` refuses this before it is reached, so a `None` here is a request nobody made rather than a refusal —
    // and the caller's next step is the same either way: print the usage.
    assert!(question_for(&Command::Send(send_args(None, None)), None, || None).is_none());
}

#[test]
fn the_log_line_count_reaches_the_request() {
    // Off by a default is the silent failure here: `--lines 5` arriving as the default would print the wrong amount
    // and look like an answer.
    let question = question_for(&Command::Logs(logs_args(25, None, false)), None, || None)
        .expect("a question");
    assert_eq!(
        question.request,
        Request::Logs {
            lines: 25,
            verbose: false,
            trace: None
        }
    );
}

#[test]
fn a_trace_filter_carries_the_id_and_asks_for_the_verbose_log() {
    // ★ This test used to assert only `verbose: true`, and its comment said "the filter is applied to what comes
    // back". Nothing applied it: the id was dropped in this very function, so `--trace` returned the whole log and
    // the user had no way to tell that their filter had been ignored.
    //
    // The id is carried now, and that is the half of the assertion that would have caught it.
    let question = question_for(
        &Command::Logs(logs_args(10, Some("trace-1"), false)),
        None,
        || None,
    )
    .expect("a question");
    match question.request {
        Request::Logs {
            lines,
            verbose,
            trace,
        } => {
            assert_eq!(lines, 10);
            // Widened, because a trace's lines are the debug ones.
            assert!(
                verbose,
                "a trace filter needs the verbose log to have anything to filter"
            );
            // ★ And carried. Without this the filter has nothing to match on and the daemon answers with
            // everything, which is what used to happen.
            assert_eq!(
                trace.as_deref(),
                Some("trace-1"),
                "the trace id was dropped on the way to the request"
            );
        }
        other => panic!("expected a logs request, got {other:?}"),
    }
}
