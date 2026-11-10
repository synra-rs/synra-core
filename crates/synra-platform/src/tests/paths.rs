use std::path::Path;
use super::super::actions::{Policies, EXECUTABLE_EXTENSIONS};
use super::super::error::{PathRefusal, PlatformError};
use super::super::guard::{check_path, PathUse};
use super::{absolute, absolute_text, sandbox_root, sibling_root};

#[test]
fn an_executable_extension_is_refused_for_opening() {
    // Opened with the default application, an executable runs.
    let policies = Policies::new();
    let root = sandbox_root();
    for extension in ["exe", "sh", "bat", "cmd", "ps1", "app", "dmg", "deb", "jar", "lnk"] {
        let path = absolute(&format!("thing.{extension}"));
        match check_path(&path, PathUse::Open, &policies, Some(root.as_path())) {
            Err(PlatformError::BadPath { reason, .. }) => {
                assert_eq!(reason, PathRefusal::Executable, "{extension}");
            }
            other => panic!(".{extension} should be refused, got {other:?}"),
        }
    }
}

#[test]
fn the_extension_check_ignores_case() {
    let policies = Policies::new();
    for extension in ["EXE", "Exe", "eXe"] {
        let path = absolute(&format!("thing.{extension}"));
        assert!(matches!(
            check_path(&path, PathUse::Open, &policies, None),
            Err(PlatformError::BadPath { reason: PathRefusal::Executable, .. })
        ));
    }
}

#[test]
fn a_path_with_no_extension_is_refused_for_opening() {
    // The check's purpose is to prove a file is not a program, and with no extension there is nothing to prove
    // it with. A file named `invoice` with no extension could be anything.
    let policies = Policies::new();
    match check_path(absolute("invoice").as_path(), PathUse::Open, &policies, None) {
        Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::UnknownKind),
        other => panic!("expected an unknown-kind refusal, got {other:?}"),
    }
}

#[test]
fn an_ordinary_document_may_be_opened() {
    let policies = Policies::new();
    for path in [absolute_text("report.pdf").as_str(), absolute_text("notes.txt").as_str(), absolute_text("image.png").as_str(), absolute_text("data.json").as_str()] {
        assert_eq!(
            check_path(Path::new(path), PathUse::Open, &policies, None),
            Ok(()),
            "{path}"
        );
    }
}

#[test]
fn revealing_may_show_an_executable() {
    // Revealing selects a file in the file manager and runs nothing, so the extension check does not apply —
    // and applying it would refuse a legitimate "show me where my download went".
    let policies = Policies::new();
    let root = sandbox_root();
    let path = sandbox_root().join("files/setup.exe");
    let path = path.as_path();
    assert_eq!(check_path(path, PathUse::Reveal, &policies, Some(root.as_path())), Ok(()));
}

#[test]
fn revealing_outside_the_sandbox_is_refused_by_default() {
    // Revealing an arbitrary path tells the plugin what exists on the disk, which is information it was not
    // given.
    let policies = Policies::new();
    match check_path(Path::new(absolute_text("passwd").as_str()), PathUse::Reveal, &policies, Some(sandbox_root().as_path())) {
        Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::OutsideSandbox),
        other => panic!("expected a sandbox refusal, got {other:?}"),
    }
}

#[test]
fn revealing_with_no_sandbox_is_refused_when_the_policy_restricts() {
    // A check that cannot be made is not a check that passed.
    let policies = Policies::new();
    assert!(matches!(
        check_path(absolute("x.txt").as_path(), PathUse::Reveal, &policies, None),
        Err(PlatformError::BadPath { reason: PathRefusal::OutsideSandbox, .. })
    ));
}

#[test]
fn the_sandbox_check_is_component_wise() {
    // `/sandbox` is a string prefix of `/sandbox-other`, so a string comparison would accept a sibling.
    let policies = Policies::new();
    let inside = sandbox_root().join("files/x.txt");
    let sibling = sibling_root().join("x.txt");

    assert!(
        check_path(inside.as_path(), PathUse::Reveal, &policies, Some(sandbox_root().as_path()))
            .is_ok()
    );
    assert!(
        check_path(sibling.as_path(), PathUse::Reveal, &policies, Some(sandbox_root().as_path()))
            .is_err()
    );
}

#[test]
fn revealing_outside_the_sandbox_can_be_allowed_by_policy() {
    let policies = Policies::new().with_reveal_outside_sandbox(true);
    assert_eq!(
        check_path(absolute("x.txt").as_path(), PathUse::Reveal, &policies, None),
        Ok(())
    );
}

#[test]
fn a_relative_path_is_refused() {
    // It would be checked against the working directory, which is whichever thread the host happened to be on,
    // so the same call would open different files at different times.
    let policies = Policies::new();
    for path in ["report.pdf", "./report.pdf", "a/b.txt"] {
        match check_path(Path::new(path), PathUse::Open, &policies, None) {
            Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::NotAbsolute, "{path}"),
            other => panic!("{path:?} should be refused, got {other:?}"),
        }
    }
}

#[test]
fn an_empty_path_is_refused() {
    let policies = Policies::new();
    assert!(matches!(
        check_path(Path::new(""), PathUse::Open, &policies, None),
        Err(PlatformError::BadPath { reason: PathRefusal::Empty, .. })
    ));
}

#[test]
fn every_path_refusal_explains_itself() {
    for reason in [
        PathRefusal::Empty,
        PathRefusal::NotAbsolute,
        PathRefusal::UnknownKind,
        PathRefusal::Executable,
        PathRefusal::OutsideSandbox,
        PathRefusal::ControlCharacter,
        PathRefusal::ReservedName,
        PathRefusal::AlternativeStream,
        PathRefusal::DeviceNamespace,
    ] {
        assert!(reason.explain().len() > 15, "{reason:?}");
    }
}

#[test]
fn a_windows_device_name_is_refused_however_it_is_written() {
    // ★ The kernel and the file system disagree about these names, and the disagreement is the whole problem: Windows
    // resolves `NUL` before it looks at the disk, so a sandbox that believed it had written `<root>/NUL` wrote nothing
    // — and one that believed it had read `<root>/CON` would be reading the console.
    let policies = Policies::new();
    for name in [
        // Plain, and in every case Windows accepts.
        "NUL", "nul", "Nul", "CON", "con", "AUX", "PRN",
        // ★ The one that surprises people: the device is resolved **before** the extension, so `CON.txt` is the console.
        "CON.txt", "nul.json", "aux.log",
        // And Windows strips a trailing dot or space from a name before resolving it, so these are the same device.
        "NUL.", "nul ", "CON..txt",
        // The numbered ports.
        "COM1", "com9", "LPT1", "lpt9",
    ] {
        match check_path(&absolute(name), PathUse::Reveal, &policies, None) {
            Err(PlatformError::BadPath { reason, .. }) => {
                assert_eq!(reason, PathRefusal::ReservedName, "{name}")
            }
            other => panic!("{name:?} should be refused, got {other:?}"),
        }
    }
}

#[test]
fn a_name_that_merely_starts_like_a_device_is_an_ordinary_file() {
    // The other half, and the reason the comparison is on the whole stem rather than a prefix: refusing `console.log`
    // or `nulify.txt` would be refusing ordinary files, and a rule that refuses ordinary work is one people route
    // around.
    let policies = Policies::new();
    for name in ["console.log", "nulify.txt", "com10.txt", "lpt0.txt", "my-con.txt", "conn.md"] {
        // `Open` rather than `Reveal`: a reveal without a sandbox root is refused for that reason instead, and the
        // first version of this test passed `Reveal` with no root — so it was asserting the wrong refusal.
        assert!(
            check_path(&absolute(name), PathUse::Open, &policies, None).is_ok(),
            "{name} is an ordinary file"
        );
    }
}

#[test]
fn an_alternate_data_stream_is_refused() {
    // `notes.txt:secret` is a second, hidden stream of `notes.txt` on NTFS and an ordinary file name everywhere else,
    // and the two readings differ — so it is refused rather than interpreted. It is also how an extension check is
    // walked past: the extension of `report.exe:harmless.txt` is `txt`.
    let policies = Policies::new();
    // ★ Not a bare `a:b`, which is a path this cannot test: `Path::join` sees `a:` as a **prefix** and replaces the
    // base with it, so the join produced the relative `a:b` and the refusal was `NotAbsolute` — a correct refusal for
    // the wrong reason, which is what the first version of this test asserted against.
    for name in ["notes.txt:secret", "report.exe:harmless.txt", "archive.zip:inner.txt"] {
        match check_path(&absolute(name), PathUse::Reveal, &policies, None) {
            Err(PlatformError::BadPath { reason, .. }) => {
                assert_eq!(reason, PathRefusal::AlternativeStream, "{name}")
            }
            other => panic!("{name:?} should be refused, got {other:?}"),
        }
    }
}

#[test]
fn the_windows_device_namespace_is_refused_rather_than_normalised() {
    // ★ Why the design's "normalise it" is not what this does.
    //
    // `\\?\` turns **off** the path cleaning Windows otherwise performs, so `\\?\C:\data\..\..\Windows` is a
    // literal name for a directory called `..` rather than a way back up the tree. The same text therefore does not
    // mean the same place, and a check that stripped the prefix would be comparing a name with a different one.
    let policies = Policies::new();
    let verbatim = if cfg!(windows) { r"\\?\C:\data\file.txt" } else { r"\\?\tmp\file.txt" };

    match check_path(Path::new(verbatim), PathUse::Reveal, &policies, None) {
        Err(PlatformError::BadPath { reason, .. }) => {
            assert_eq!(reason, PathRefusal::DeviceNamespace, "{verbatim}")
        }
        other => panic!("{verbatim:?} should be refused, got {other:?}"),
    }
}

#[test]
fn the_executable_list_covers_the_installation_formats() {
    // A list that missed one would be a list that lets that one through, and the failure is silent.
    for extension in ["exe", "msi", "dmg", "pkg", "deb", "rpm", "appimage", "apk"] {
        assert!(EXECUTABLE_EXTENSIONS.contains(&extension), "{extension} is not listed");
    }
    // And the entries are lowercase and without dots, which is what the comparison produces.
    for extension in EXECUTABLE_EXTENSIONS {
        assert_eq!(*extension, extension.to_ascii_lowercase(), "{extension}");
        assert!(!extension.starts_with('.'), "{extension}");
    }
}
