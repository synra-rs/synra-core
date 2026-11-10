use crate::args::NewArgs;
use crate::run::new_plugin;
use crate::template::TemplateKind;
use super::super::{Executed, execute};
use super::Cleanup;

#[test]
fn a_scaffold_is_written_and_a_dry_run_is_not() {
    let dir = Cleanup::new("scaffold");
    let args = NewArgs {
        plugin_id: "@synra-plugin/example".to_owned(),
        version: "0.1.0".to_owned(),
        title: None,
        template: TemplateKind::Headless,
        dir: Some(dir.path().to_path_buf()),
        dry_run: false,
    };
    let outcome = new_plugin(&args).expect("builds");

    // The dry run first, so the assertion about what is on disk is about a run that wrote.
    assert_eq!(execute(&outcome, true), Executed::ok(Vec::new()));
    assert!(
        !dir.path().join("manifest.json").exists(),
        "a dry run wrote"
    );

    let executed = execute(&outcome, false);
    assert_eq!(executed.code, 0, "{executed:?}");
    assert!(dir.path().join("manifest.json").exists());
    assert!(dir.path().join("src/lib.rs").exists());
}

#[test]
fn a_scaffold_that_cannot_be_written_fails_with_the_path() {
    // The message an author needs, and the path is the half of it that tells them which file.
    let dir = Cleanup::new("unwritable");
    // A *file* where the directory should be, so creating the root fails on every platform.
    dir.write("blocked", b"");
    let outcome = new_plugin(&NewArgs {
        plugin_id: "@synra-plugin/example".to_owned(),
        version: "0.1.0".to_owned(),
        title: None,
        template: TemplateKind::Headless,
        dir: Some(dir.path().join("blocked").join("nested")),
        dry_run: false,
    })
    .expect("builds");

    let executed = execute(&outcome, false);
    assert_eq!(executed.code, 1);
    assert!(
        executed.lines[0].contains("blocked"),
        "{:?}",
        executed.lines
    );
}
