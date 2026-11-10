use super::super::{Command, SendArgs, Payload, PayloadError};
use super::{parse, parsed};

#[test]
fn devices_defaults_to_paired_only_and_no_scan() {
    // A paired device is one the user has decided about, and a list mixing in everything heard on the network is
    // one where the interesting entries are hard to find.
    let cli = parsed(&["synra", "devices"]);
    let Command::Devices(args) = cli.command else {
        panic!("expected devices");
    };
    assert!(!args.all);
    assert!(!args.cached);
    assert_eq!(args.scan_ms, None);
}

#[test]
fn devices_accepts_a_scan_and_a_cache_read_but_not_both() {
    // Scanning and reading the cache are opposite requests. Accepting both would mean one of them silently losing.
    let Command::Devices(scan) = parsed(&["synra", "devices", "--scan-ms", "2500"]).command
    else {
        panic!("expected devices");
    };
    assert_eq!(scan.scan_ms, Some(2_500));

    let Command::Devices(cached) = parsed(&["synra", "devices", "--cached"]).command else {
        panic!("expected devices");
    };
    assert!(cached.cached);

    assert!(parse(&["synra", "devices", "--scan-ms", "2500", "--cached"]).is_err());
}

// ── Send ──────────────────────────────────────────────────────────────────────────────────────

#[test]
fn send_requires_a_target_and_a_payload() {
    // Both are required, and they are required in different places: the target by `clap`, because "which device"
    // is a flag a user plainly has to give, and the payload by `SendArgs::payload`, because "one of two flags"
    // with a sentence naming both is a better message than a usage line.
    assert!(
        parse(&["synra", "send", "--text", "hi"]).is_err(),
        "no target"
    );
    assert!(
        parse(&["synra", "send", "--to", "dev_a"]).is_ok(),
        "the parser accepts it, and `payload` is what refuses it"
    );
    let Command::Send(args) = parsed(&["synra", "send", "--to", "dev_a"]).command else {
        panic!("expected send");
    };
    assert_eq!(args.payload(), Err(PayloadError::NothingToSend));
}

#[test]
fn send_refuses_both_payloads_at_the_parser() {
    // Not "one of them wins": a user who typed both meant one thing, and guessing produces a message that goes
    // somewhere they did not intend.
    let error = parse(&[
        "synra", "send", "--to", "dev_a", "--text", "hi", "--file", "a.txt",
    ])
    .expect_err("should be refused");
    let text = error.to_string();
    assert!(text.contains("text"), "{text}");
    assert!(text.contains("file"), "{text}");
}

#[test]
fn send_carries_text() {
    let Command::Send(args) =
        parsed(&["synra", "send", "--to", "dev_a", "--text", "hi"]).command
    else {
        panic!("expected send");
    };
    assert_eq!(args.to, "dev_a");
    assert_eq!(args.payload(), Ok(Payload::Text("hi")));
}

#[test]
fn send_carries_a_file() {
    let Command::Send(args) =
        parsed(&["synra", "send", "--to", "dev_a", "--file", "a.txt"]).command
    else {
        panic!("expected send");
    };
    assert_eq!(args.payload(), Ok(Payload::File("a.txt")));
}

#[test]
fn a_payload_built_in_code_is_checked_too() {
    // `clap` cannot be reached by a caller building the arguments directly, and the two shapes it refuses are the
    // two that would otherwise be decided by whichever field a caller read first.
    let neither = SendArgs {
        to: "dev_a".to_owned(),
        text: None,
        file: None,
        context: None,
    };
    assert_eq!(neither.payload(), Err(PayloadError::NothingToSend));

    let both = SendArgs {
        to: "dev_a".to_owned(),
        text: Some("hi".to_owned()),
        file: Some("a.txt".to_owned()),
        context: None,
    };
    assert_eq!(both.payload(), Err(PayloadError::Both));
}

#[test]
fn send_accepts_a_context() {
    let Command::Send(args) = parsed(&[
        "synra",
        "send",
        "--to",
        "dev_a",
        "--text",
        "hi",
        "--context",
        "c1",
    ])
    .command
    else {
        panic!("expected send");
    };
    assert_eq!(args.context.as_deref(), Some("c1"));
}

#[test]
fn an_empty_payload_is_text_rather_than_nothing() {
    // `--text ""` is a user sending an empty message, which is a thing people do. Treating it as "no payload"
    // would refuse a valid invocation.
    let Command::Send(args) = parsed(&["synra", "send", "--to", "dev_a", "--text", ""]).command
    else {
        panic!("expected send");
    };
    assert_eq!(args.payload(), Ok(Payload::Text("")));
}

// ── Plugins ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn payload_errors_explain_themselves() {
    for error in [PayloadError::NothingToSend, PayloadError::Both] {
        let text = error.to_string();
        assert!(text.len() > 20, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
}
