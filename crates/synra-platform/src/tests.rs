//! The platform guard's tests.

use core::time::Duration;
use std::path::Path;

use super::actions::*;
use super::error::{PathRefusal, PlatformError, UrlRefusal};
use super::guard::*;
use super::host::*;

// ★ No `use super::*;` here: the four globs above are what this file uses, and the fifth was left over from when these
// lines were inside a `mod tests { … }` whose wrapper the split removed. rustc 1.88 reports it; 1.98 had it cached.
use rstest::rstest;

    /// A directory that is absolute on the platform running the test.
    ///
    /// Not a literal `/tmp`: on Windows that is *drive-relative* — it names the root of whichever drive is current —
    /// so `Path::is_absolute` is false for it and every path test would exercise the wrong branch.
    fn absolute_base() -> &'static str {
        if cfg!(windows) { "C:\\tmp" } else { "/tmp" }
    }

    /// An absolute path under the base directory.
    fn absolute(name: &str) -> std::path::PathBuf {
        Path::new(absolute_base()).join(name)
    }

    /// A path literal that is absolute on this platform, for the cases that take a `&str`.
    fn absolute_text(name: &str) -> String {
        absolute(name).display().to_string()
    }

    /// A plugin's sandbox root, absolute on this platform.
    fn sandbox_root() -> std::path::PathBuf {
        absolute("sandbox")
    }

    /// A directory that shares a string prefix with [`sandbox_root`] but is not inside it.
    ///
    /// The case a string-prefix containment check gets wrong, kept as a named helper so every test that needs it
    /// uses the same shape.
    fn sibling_root() -> std::path::PathBuf {
        absolute("sandbox-other")
    }

    // ── Actions ───────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_action_has_its_own_capability() {
        // An authorisation that covered "the platform" would be one a user granted for a different reason. Each
        // action names exactly one effect, and none implies another.
        let actions = [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ];
        let mut capabilities = std::collections::HashSet::new();
        for action in actions {
            let capability = action.capability();
            assert!(capabilities.insert(capability), "{capability} is shared");
            assert!(capability.starts_with("platform:"), "{capability}");
        }
        // Reading and writing the clipboard are separate grants.
        assert_ne!(
            PlatformAction::ReadClipboard.capability(),
            PlatformAction::WriteClipboard.capability()
        );
        // And opening a file is not opening a URL: the first can run a program.
        assert_ne!(PlatformAction::OpenUrl.capability(), PlatformAction::OpenPath.capability());
    }

    #[test]
    fn only_simulating_keys_is_off_by_default() {
        // It is the one action that lets a plugin drive other applications, and the design document requires it to
        // be a separate, default-off authorisation.
        for action in [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ] {
            assert!(!action.is_off_by_default(), "{action}");
        }
        assert!(PlatformAction::SimulateKeys.is_off_by_default());
    }

    #[test]
    fn the_silent_actions_are_the_ones_needing_an_indicator() {
        // A browser window announces itself. Reading the clipboard and typing do not, which is why they need
        // something else.
        assert!(PlatformAction::SimulateKeys.needs_visible_indicator());
        assert!(PlatformAction::ReadClipboard.needs_visible_indicator());
        assert!(!PlatformAction::WriteClipboard.needs_visible_indicator());
        assert!(!PlatformAction::Notify.needs_visible_indicator());
        // And the visible ones do not need an extra indicator, because they are their own.
        assert!(PlatformAction::OpenUrl.is_user_visible());
        assert!(!PlatformAction::SimulateKeys.is_user_visible());
    }

    #[test]
    fn every_action_names_its_risk() {
        // The consent screen is where a user decides, so a variant without a sentence is one the interface cannot
        // render.
        for action in [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ] {
            let risk = action.risk();
            assert!(risk.len() > 20, "{action} -> {risk}");
        }
    }

    #[test]
    fn action_capabilities_parse_as_capabilities() {
        // The names have to be ones the capability DSL accepts, or a manifest cannot request them.
        for action in [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ] {
            // `synra-capability` is not a dependency here, so the check is the character set its grammar allows,
            // taken from the same constant: `[A-Za-z0-9._@/*-]` per segment, with a `:` between segments.
            let capability = action.capability();
            let (domain, rest) = capability.split_once(':').expect("has a domain");
            assert_eq!(domain, "platform");
            assert!(!rest.is_empty());
            for segment in rest.split(':') {
                assert!(!segment.is_empty(), "{capability}");
                assert!(
                    segment
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '/' | '*' | '-')),
                    "{capability}: segment {segment:?} has a character outside the grammar"
                );
            }
        }
    }

    #[test]
    fn an_action_displays_its_capability() {
        assert_eq!(PlatformAction::OpenUrl.to_string(), "platform:open-url");
    }

    // ── URLs ──────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_https_url_is_accepted_by_default() {
        let policies = Policies::new();
        for url in [
            "https://example.com",
            "https://example.com/path?q=1#frag",
            "https://api.github.com/repos/synra-rs/synra-core",
            "https://example.com:8443/x",
        ] {
            assert_eq!(check_url(url, &policies), Ok(()), "{url}");
        }
    }

    #[test]
    fn a_plain_http_url_is_refused_by_default() {
        // The consent prompt shows the user a hostname. Over HTTP that hostname can be rewritten before the
        // response, so the prompt is true about the destination and false about what will be displayed.
        let policies = Policies::new();
        match check_url("http://example.com", &policies) {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::Insecure),
            other => panic!("expected an insecure refusal, got {other:?}"),
        }
        // And the refusal explains why, in terms of what the user is deciding about.
        assert!(UrlRefusal::Insecure.explain().contains("changed in transit"));
    }

    #[test]
    fn http_can_be_allowed_by_policy() {
        let policies = Policies::new().with_insecure_urls(true);
        assert_eq!(check_url("http://example.com", &policies), Ok(()));
    }

    #[rstest]
    #[case("javascript:alert(1)")]
    #[case("data:text/html,<script>x</script>")]
    #[case("vbscript:x")]
    #[case("file:///etc/passwd")]
    #[case("ftp://example.com")]
    fn a_non_web_scheme_is_refused_by_default(#[case] url: &str) {
        // The list is closed rather than "anything that is not http": each of these is something a plugin could
        // put behind an "open this link" prompt, and a `file:` URL reaches a path without passing through the
        // executable check.
        let policies = Policies::new();
        match check_url(url, &policies) {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::LocalScheme, "{url}"),
            other => panic!("{url} should be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_local_scheme_can_be_allowed_by_policy() {
        let policies = Policies::new().with_local_schemes(true);
        assert_eq!(check_url("file:///tmp/x", &policies), Ok(()));
    }

    #[test]
    fn a_url_with_no_scheme_or_host_is_refused() {
        let policies = Policies::new();
        for (url, expected) in [
            ("example.com", UrlRefusal::NoScheme),
            ("https://", UrlRefusal::NoHost),
            ("https:///path", UrlRefusal::NoHost),
            ("https://?q=1", UrlRefusal::NoHost),
            ("", UrlRefusal::Empty),
        ] {
            match check_url(url, &policies) {
                Err(PlatformError::BadUrl { reason, .. }) => {
                    assert_eq!(reason, expected, "{url:?}");
                }
                other => panic!("{url:?} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_control_character_in_a_url_is_refused() {
        // A newline could forge a line in the consent prompt or split a log record, and the prompt is what the user
        // decides from.
        let policies = Policies::new();
        for url in [
            "https://example.com/\nhttps://evil.com",
            "https://example.com/\u{7}",
            "https://exa\u{0}mple.com",
        ] {
            match check_url(url, &policies) {
                Err(PlatformError::BadUrl { reason, .. }) => {
                    assert_eq!(reason, UrlRefusal::ControlCharacter, "{url:?}");
                }
                other => panic!("{url:?} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_over_long_url_is_refused() {
        let policies = Policies::new();
        let long = format!("https://example.com/{}", "x".repeat(MAX_URL_LEN));
        match check_url(&long, &policies) {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::TooLong),
            other => panic!("expected a length refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_scheme_check_is_case_insensitive() {
        // `HTTPS://example.com` is the same scheme, and a comparison that missed it would refuse a legitimate
        // address.
        let policies = Policies::new();
        assert_eq!(check_url("HTTPS://example.com", &policies), Ok(()));
        assert!(check_url("HTTP://example.com", &policies).is_err());
    }

    #[test]
    fn every_url_refusal_explains_itself() {
        for reason in [
            UrlRefusal::Empty,
            UrlRefusal::TooLong,
            UrlRefusal::NoScheme,
            UrlRefusal::LocalScheme,
            UrlRefusal::Insecure,
            UrlRefusal::NoHost,
            UrlRefusal::ControlCharacter,
        ] {
            assert!(reason.explain().len() > 15, "{reason:?}");
        }
    }

    #[test]
    fn the_url_length_helper_refuses_before_the_open() {
        // So a caller building a URL finds out where it made the mistake rather than at the point a browser is
        // asked to open something.
        assert!(check_url_length("https://example.com").is_ok());
        let long = "x".repeat(MAX_URL_LEN + 1);
        assert!(matches!(
            check_url_length(&long),
            Err(PlatformError::TooLong { field: "address", .. })
        ));
    }

    // ── Paths ─────────────────────────────────────────────────────────────────────────────────────

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
        let shares = [r"\\server\share\file.txt", r"\\.\PhysicalDrive0"];

        for path in [verbatim] {
            match check_path(Path::new(path), PathUse::Reveal, &policies, None) {
                Err(PlatformError::BadPath { reason, .. }) => {
                    assert_eq!(reason, PathRefusal::DeviceNamespace, "{path}")
                }
                other => panic!("{path:?} should be refused, got {other:?}"),
            }
        }
        let _ = shares;
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

    // ── Notification and chord limits ─────────────────────────────────────────────────────────────

    #[test]
    fn a_notification_within_its_limits_is_accepted() {
        assert_eq!(check_notification("Synra", "A file arrived"), Ok(()));
        assert_eq!(check_notification("", ""), Ok(()));
    }

    #[test]
    fn an_over_long_notification_is_refused_and_names_the_field() {
        let long = "x".repeat(MAX_NOTIFICATION_LEN + 1);
        match check_notification(&long, "body") {
            Err(PlatformError::TooLong { field, len, max }) => {
                assert_eq!(field, "notification title");
                assert_eq!(len, MAX_NOTIFICATION_LEN + 1);
                assert_eq!(max, MAX_NOTIFICATION_LEN);
            }
            other => panic!("expected a length refusal, got {other:?}"),
        }
        assert!(matches!(
            check_notification("title", &long),
            Err(PlatformError::TooLong { field: "notification body", .. })
        ));
    }

    #[test]
    fn a_notification_is_measured_in_characters() {
        // A CJK notification of the same character count is not "too long" in a unit a user cannot see.
        let cjk = "电".repeat(MAX_NOTIFICATION_LEN);
        assert_eq!(check_notification(&cjk, &cjk), Ok(()));
    }

    #[test]
    fn an_empty_key_chord_is_refused() {
        // Not "no keys": a call that does nothing, and a loop of them would still hold the rate limiter.
        assert!(matches!(
            check_key_chord("   "),
            Err(PlatformError::Unavailable(_))
        ));
        assert_eq!(check_key_chord("cmd+c"), Ok(()));
        assert!(matches!(
            check_key_chord(&"x".repeat(MAX_CHORD_LEN + 1)),
            Err(PlatformError::TooLong { field: "key chord", .. })
        ));
    }

    // ── Rate limiting ─────────────────────────────────────────────────────────────────────────────

    /// A limiter with a short interval so the arithmetic is easy to read.
    fn limiter() -> RateLimiter {
        RateLimiter::new(
            Policies::new()
                .with_key_chord_interval(Duration::from_millis(100))
                .with_notification_interval(Duration::from_millis(1_000))
                .with_notifications_per_hour(3),
        )
    }

    #[test]
    fn unrelated_actions_are_not_rate_limited() {
        // A rate limit on `open-url` would refuse a legitimate burst of links a user clicked.
        let limiter = limiter();
        for _ in 0..100 {
            assert_eq!(limiter.admit(PlatformAction::OpenUrl, 0), Ok(()));
            assert_eq!(limiter.admit(PlatformAction::ReadClipboard, 0), Ok(()));
        }
    }

    #[test]
    fn key_chords_are_spaced_out() {
        let limiter = limiter();
        assert_eq!(limiter.admit(PlatformAction::SimulateKeys, 0), Ok(()));

        match limiter.admit(PlatformAction::SimulateKeys, 50) {
            Err(PlatformError::RateLimited { action, remaining_ms }) => {
                assert_eq!(action, PlatformAction::SimulateKeys);
                assert_eq!(remaining_ms, 50, "the wait is the remainder, not the whole interval");
            }
            other => panic!("expected a rate limit, got {other:?}"),
        }
        // At the interval it is allowed again.
        assert_eq!(limiter.admit(PlatformAction::SimulateKeys, 100), Ok(()));
        assert_eq!(limiter.admit(PlatformAction::SimulateKeys, 200), Ok(()));
    }

    #[test]
    fn notifications_are_spaced_out() {
        let limiter = limiter();
        assert_eq!(limiter.admit(PlatformAction::Notify, 0), Ok(()));
        assert!(matches!(
            limiter.admit(PlatformAction::Notify, 500),
            Err(PlatformError::RateLimited { .. })
        ));
        assert_eq!(limiter.admit(PlatformAction::Notify, 1_000), Ok(()));
    }

    #[test]
    fn an_hourly_ceiling_applies_to_notifications() {
        // An application that notifies more often than this is one whose notifications get turned off entirely.
        let limiter = limiter();
        // Spaced far enough apart to clear the interval, but only three are allowed in the window.
        for index in 0..3u64 {
            assert_eq!(
                limiter.admit(PlatformAction::Notify, index * 1_000),
                Ok(()),
                "notification {index}"
            );
        }
        match limiter.admit(PlatformAction::Notify, 3_000) {
            Err(PlatformError::QuotaExceeded { action, used, limit }) => {
                assert_eq!(action, PlatformAction::Notify);
                assert_eq!(used, 3);
                assert_eq!(limit, 3);
            }
            other => panic!("expected a quota refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_notification_window_slides() {
        // A fixed window would let a plugin fire the whole ceiling at the end of one hour and again at the start
        // of the next.
        let limiter = limiter();
        for index in 0..3u64 {
            limiter.admit(PlatformAction::Notify, index * 1_000).expect("within the ceiling");
        }
        assert_eq!(limiter.notifications_in_window(3_000), 3);

        // An hour after the first, that one has left the window.
        let later = 3_600_000 + 1;
        assert_eq!(limiter.notifications_in_window(later), 2);
        // So a fourth is allowed at that point.
        assert!(limiter.admit(PlatformAction::Notify, later).is_ok());
    }

    #[test]
    fn forgetting_an_action_clears_its_history() {
        // A device resuming from suspend has a clock that did not advance, and the alternative to forgetting is a
        // plugin that cannot notify until the process restarts.
        let limiter = limiter();
        limiter.admit(PlatformAction::Notify, 0).expect("first");
        assert!(limiter.admit(PlatformAction::Notify, 0).is_err());

        limiter.forget(PlatformAction::Notify);
        assert_eq!(limiter.notifications_in_window(0), 0);
        assert!(limiter.admit(PlatformAction::Notify, 0).is_ok());
    }

    #[test]
    fn a_zero_interval_allows_every_call() {
        // A configuration that disables the limit must actually disable it, not turn it into a refusal.
        let limiter = RateLimiter::new(
            Policies::new()
                .with_key_chord_interval(Duration::ZERO)
                .with_notification_interval(Duration::ZERO)
                .with_notifications_per_hour(1_000),
        );
        for _ in 0..5 {
            assert_eq!(limiter.admit(PlatformAction::SimulateKeys, 0), Ok(()));
            assert_eq!(limiter.admit(PlatformAction::Notify, 0), Ok(()));
        }
    }

    // ── Policies ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_defaults_are_the_restrictive_ones() {
        // A host that wants to be permissive has to say so, which is the opposite of a configuration whose
        // defaults quietly allow whatever was added last.
        let policies = Policies::new();
        assert!(!policies.allows_insecure_urls());
        assert!(!policies.allows_simulate_keys());
        assert!(policies.restricts_reveal_to_sandbox());
        assert_eq!(policies.notifications_per_hour(), 20);
        assert!(policies.foreground_window() > Duration::ZERO);
        assert!(policies.key_chord_interval() > Duration::ZERO);
        assert!(policies.notification_interval() > Duration::ZERO);
    }

    #[test]
    fn a_policy_describes_what_a_grant_would_allow() {
        // Composed from the policy rather than written per action, so a policy change cannot leave the prompt
        // describing something the host no longer does.
        let strict = Policies::new();
        let open = Policies::new()
            .with_insecure_urls(true)
            .with_simulate_keys(true)
            .with_reveal_outside_sandbox(true);

        assert!(strict.describe(PlatformAction::OpenUrl).contains("https"));
        assert!(!open.describe(PlatformAction::OpenUrl).contains("https only"));

        assert!(strict.describe(PlatformAction::SimulateKeys).contains("turned off"));
        assert!(!open.describe(PlatformAction::SimulateKeys).contains("turned off"));

        assert!(strict.describe(PlatformAction::RevealPath).contains("own data directory"));
        assert!(!open.describe(PlatformAction::RevealPath).contains("own data directory"));

        // Every action has a description under both policies, so the screen has something to render.
        for action in [
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::SimulateKeys,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
            PlatformAction::Notify,
        ] {
            assert!(!strict.describe(action).is_empty(), "{action}");
            assert!(!open.describe(action).is_empty(), "{action}");
        }
    }

    #[test]
    fn the_builders_are_chainable() {
        let policies = Policies::new()
            .with_insecure_urls(true)
            .with_local_schemes(true)
            .with_simulate_keys(true)
            .with_foreground_requirement(false)
            .with_foreground_window(Duration::from_secs(5))
            .with_key_chord_interval(Duration::from_millis(10))
            .with_notification_interval(Duration::from_secs(1))
            .with_notifications_per_hour(5)
            .with_reveal_outside_sandbox(true);

        assert!(policies.allows_insecure_urls());
        assert!(policies.allows_simulate_keys());
        assert!(!policies.restricts_reveal_to_sandbox());
        assert_eq!(policies.foreground_window(), Duration::from_secs(5));
        assert_eq!(policies.key_chord_interval(), Duration::from_millis(10));
        assert_eq!(policies.notifications_per_hour(), 5);
    }

    // ── The headless host ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_headless_host_performs_nothing() {
        // Every action reports `Unsupported` rather than pretending to succeed, so a caller that forgot to provide
        // a real implementation finds out immediately.
        let host = HeadlessPlatform::new();
        assert_eq!(host.name(), "headless");
        assert!(matches!(host.open_url("https://example.com"), Err(PlatformError::Unsupported(_))));
        assert!(matches!(host.read_clipboard(), Err(PlatformError::Unsupported(_))));
        assert!(matches!(host.write_clipboard("x"), Err(PlatformError::Unsupported(_))));
        assert!(matches!(host.notify("t", "b"), Err(PlatformError::Unsupported(_))));
        // Key simulation is refused for a second reason before the host is consulted: it is off by default, and
        // that refusal is about the policy rather than about the host having no keyboard.
        assert!(matches!(
            host.simulate_keys("cmd+c"),
            Err(PlatformError::SimulateKeysNotGranted)
        ));
        // With the policy in place it reaches the host, which then refuses.
        let granted = HeadlessPlatform::with_policies(Policies::new().with_simulate_keys(true));
        assert!(matches!(
            granted.simulate_keys("cmd+c"),
            Err(PlatformError::Unsupported(_))
        ));
        assert!(host.supported_actions().is_empty());
    }

    #[test]
    fn a_headless_host_still_reports_a_bad_address() {
        // The order matters: a plugin that supplied `javascript:` should be told its address is refused, not that
        // this host has no browser. The first is a mistake the author can fix and the second is a fact about the
        // installation.
        let host = HeadlessPlatform::new();
        match host.open_url("javascript:alert(1)") {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::LocalScheme),
            other => panic!("expected a URL refusal, got {other:?}"),
        }
        match host.open_url("http://example.com") {
            Err(PlatformError::BadUrl { reason, .. }) => assert_eq!(reason, UrlRefusal::Insecure),
            other => panic!("expected an insecure refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_headless_host_uses_the_policies_it_was_given() {
        let host = HeadlessPlatform::with_policies(Policies::new().with_insecure_urls(true));
        assert!(host.policies().allows_insecure_urls());
        // Still unsupported, but the address check passed, so the error is about the host.
        assert!(matches!(host.open_url("http://example.com"), Err(PlatformError::Unsupported(_))));
    }

    #[test]
    fn the_headless_host_checks_paths_before_refusing() {
        let host = HeadlessPlatform::new();
        // A relative path is refused for being relative, not for the host being headless.
        match host.open_path(Path::new("report.pdf")) {
            Err(PlatformError::BadPath { reason, .. }) => assert_eq!(reason, PathRefusal::NotAbsolute),
            other => panic!("expected a path refusal, got {other:?}"),
        }
        // And an absolute document reaches the host, which then refuses. The path is bound rather than passed as a
        // temporary, because `as_path` borrows it.
        let document = absolute("report.pdf");
        match host.open_path(document.as_path()) {
            Err(PlatformError::Unsupported(_)) => {}
            other => panic!("expected the host to refuse {document:?}, got {other:?}"),
        }
    }

    #[test]
    fn platform_errors_explain_themselves() {
        let errors = vec![
            PlatformError::BadUrl { url: "u".to_owned(), reason: UrlRefusal::Insecure },
            PlatformError::BadPath { path: "p".to_owned(), reason: PathRefusal::Executable },
            PlatformError::SimulateKeysNotGranted,
            PlatformError::NoRecentInteraction { elapsed_ms: 5_000 },
            PlatformError::RateLimited { action: PlatformAction::Notify, remaining_ms: 10 },
            PlatformError::QuotaExceeded { action: PlatformAction::Notify, used: 3, limit: 3 },
            PlatformError::TooLong { field: "f", len: 1, max: 0 },
            PlatformError::Unavailable("do a thing"),
            PlatformError::Unsupported("do a thing"),
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 15, "{error:?} -> {text:?}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
