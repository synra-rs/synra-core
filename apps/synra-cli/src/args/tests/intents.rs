use super::super::{Command, IntentAction};
use super::parsed;

#[test]
fn share_asks_the_kernel_to_route_rather_than_to_send() {
    // ★ The two are opposites and the difference is the whole feature: `send` names a device and delivers to it,
    // `share` names nothing and asks every plugin which one can handle it. A `share` that quietly became a `send`
    // would look identical from the command line and do something else entirely.
    let Command::Share(args) = parsed(&["synra", "share", "https://example.com"]).command
    else {
        panic!("share is a command");
    };
    assert_eq!(args.text, "https://example.com");
    // The default is `text/plain`, which is what a bare argument is. A link is `text/uri-list`, and the caller says
    // so rather than the kernel guessing from the contents.
    assert_eq!(args.mime, "text/plain");

    let Command::Share(args) = parsed(&[
        "synra",
        "share",
        "--mime",
        "text/uri-list",
        "https://example.com",
    ])
    .command
    else {
        panic!("share is a command");
    };
    assert_eq!(args.mime, "text/uri-list");
}

#[test]
fn the_three_answers_to_a_prompt_each_parse() {
    // ★ `share` prints an identifier and these are the commands that spend it. Before them, routing could be
    // started from the command line and never finished there — the identifier was a value with no second command.
    let Command::Intent(args) = parsed(&[
        "synra",
        "intent",
        "show",
        "01a140ce-0000-7000-8000-000000000000",
    ])
    .command
    else {
        panic!("intent is a command");
    };
    assert!(matches!(args.action, IntentAction::Show { .. }));

    let Command::Intent(args) = parsed(&["synra", "intent", "decide", "abc"]).command else {
        panic!("intent is a command");
    };
    // Both optional: omitting them is the ordinary case — one plugin claimed the share and named where to run it.
    assert!(matches!(
        args.action,
        IntentAction::Decide {
            plugin: None,
            target: None,
            ..
        }
    ));

    // And naming them is how a user answers a share that left either open.
    let Command::Intent(args) = parsed(&[
        "synra",
        "intent",
        "decide",
        "abc",
        "--plugin",
        "@acme/opener",
        "--target",
        "0e5a1c34-0000-4000-8000-000000000001",
    ])
    .command
    else {
        panic!("intent is a command");
    };
    match args.action {
        IntentAction::Decide { plugin, target, .. } => {
            assert_eq!(plugin.as_deref(), Some("@acme/opener"));
            assert_eq!(
                target.as_deref(),
                Some("0e5a1c34-0000-4000-8000-000000000001")
            );
        }
        other => panic!("expected decide, got {other:?}"),
    }

    let Command::Intent(args) = parsed(&["synra", "intent", "cancel", "abc"]).command else {
        panic!("intent is a command");
    };
    assert!(matches!(args.action, IntentAction::Cancel { .. }));
}

// ── The main.rs bound ─────────────────────────────────────────────────────────────────────────
