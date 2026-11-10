use super::*;
use clap::CommandFactory as _;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(args)
}

fn parsed(args: &[&str]) -> Cli {
    parse(args).expect("parses")
}

#[test]
fn the_parser_is_internally_consistent() {
    // `clap`'s own check: two flags with one long name, a subcommand with an undocumented required argument, and
    // so on. A build failure rather than something an author finds.
    Cli::command().debug_assert();
}

#[test]
fn every_documented_command_exists() {
    // The design document's list, as an executable statement. `publish` and `dev` are documented and not
    // implemented — see the crate docs for why a version of them that only printed what it would do would be worse
    // than one that says it is not implemented.
    for args in [
        vec!["synra-plugin", "new", "@scope/plugin"],
        vec!["synra-plugin", "build"],
        vec!["synra-plugin", "verify"],
        vec!["synra-plugin", "sign", "--generate-key"],
        vec!["synra-plugin", "publish", "--index", "dist/@acme/hello.json"],
    ] {
        assert!(parse(&args).is_ok(), "{args:?} should parse");
    }
}

#[test]
fn a_command_this_build_does_not_have_is_refused() {
    // `dev` needs a running host, and a stub that printed "would run" would be worse than an absent one: it exits
    // zero. `clap`'s "unrecognized subcommand" is the honest answer.
    let error = parse(&["synra-plugin", "dev"]).expect_err("not implemented");
    assert!(error.to_string().contains("unrecognized"), "{error}");
}

// ── new ───────────────────────────────────────────────────────────────────────────────────────

#[test]
fn new_needs_a_plugin_id() {
    assert!(parse(&["synra-plugin", "new"]).is_err());
}

#[test]
fn new_defaults_to_the_headless_template_and_the_current_directory() {
    let Command::New(args) = parsed(&["synra-plugin", "new", "@scope/plugin"]).command else {
        panic!("expected new");
    };
    assert_eq!(args.template, TemplateKind::Headless);
    assert_eq!(args.dir, None);
    assert_eq!(args.version, "0.1.0");
    assert!(!args.dry_run);
}

#[test]
fn new_accepts_every_template_by_name() {
    for (word, kind) in [
        ("headless", TemplateKind::Headless),
        ("hybrid", TemplateKind::Hybrid),
    ] {
        let Command::New(args) =
            parsed(&["synra-plugin", "new", "@scope/plugin", "--template", word]).command
        else {
            panic!("expected new");
        };
        assert_eq!(args.template, kind, "{word}");
    }
}

#[test]
fn new_rejects_the_unsupported_ui_only_template() {
    assert!(
        Cli::try_parse_from(["synra-plugin", "new", "@scope/plugin", "--template", "ui"])
            .is_err()
    );
}

#[test]
fn an_unknown_template_is_refused() {
    // A typo that fell back to a default would scaffold the wrong shape, and the author would find out at `verify`
    // — or at install.
    assert!(parse(&["synra-plugin", "new", "@scope/p", "--template", "server"]).is_err());
}

#[test]
fn the_title_defaults_to_the_name_part_of_the_id() {
    // An author who typed `@scope/my-plugin` has already said what it is called, and being asked again is friction
    // at the moment they are least invested.
    let Command::New(args) = parsed(&["synra-plugin", "new", "@scope/my-plugin"]).command else {
        panic!("expected new");
    };
    assert_eq!(args.title(), "my-plugin");

    let Command::New(args) =
        parsed(&["synra-plugin", "new", "@scope/my-plugin", "--title", "My Plugin"]).command
    else {
        panic!("expected new");
    };
    assert_eq!(args.title(), "My Plugin");
}

#[test]
fn a_title_is_derived_even_from_an_id_with_no_scope() {
    // The id validator refuses this, and `title()` must not panic on the way to that refusal.
    let Command::New(args) = parsed(&["synra-plugin", "new", "plugin"]).command else {
        panic!("expected new");
    };
    assert_eq!(args.title(), "plugin");
}

#[test]
fn new_can_be_pointed_at_a_directory_and_a_dry_run() {
    let Command::New(args) =
        parsed(&["synra-plugin", "new", "@scope/p", "--dir", "/tmp/p", "--dry-run"]).command
    else {
        panic!("expected new");
    };
    assert_eq!(args.dir, Some(PathBuf::from("/tmp/p")));
    assert!(args.dry_run);
}

// ── verify ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn verify_defaults_to_the_current_directory_and_prose() {
    let Command::Verify(args) = parsed(&["synra-plugin", "verify"]).command else {
        panic!("expected verify");
    };
    assert_eq!(args.dir, PathBuf::from("."));
    assert!(!args.json);
    assert!(!args.brief);
}

#[test]
fn verify_can_be_pointed_and_asked_for_json() {
    let Command::Verify(args) =
        parsed(&["synra-plugin", "verify", "--dir", "/tmp/p", "--json"]).command
    else {
        panic!("expected verify");
    };
    assert_eq!(args.dir, PathBuf::from("/tmp/p"));
    assert!(args.json);
}
