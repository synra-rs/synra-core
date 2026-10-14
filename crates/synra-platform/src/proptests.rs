//! The platform guard's property tests.

use core::time::Duration;
use std::path::Path;

use super::actions::*;
use super::guard::*;

use proptest::prelude::*;

    use super::*;
    

    /// The same platform-absolute fixture the unit tests use, so a path is absolute on the platform running the
    /// test rather than under the one the literal was written for.
    fn absolute(name: &str) -> std::path::PathBuf {
        let base = if cfg!(windows) { "C:\\tmp" } else { "/tmp" };
        Path::new(base).join(name)
    }

    /// A plugin's sandbox root.
    fn sandbox_root() -> std::path::PathBuf {
        absolute("sandbox")
    }

    proptest! {
        /// A URL that passes the check is one the host will actually open, so it is either https or a scheme the
        /// policy explicitly allowed. The property is what stops a refusal from being bypassed by an unusual
        /// spelling.
        #[test]
        fn an_accepted_url_has_an_allowed_scheme(
            scheme in "[a-zA-Z]{2,8}",
            host in "[a-z]{1,10}\\.[a-z]{2,4}",
            path in proptest::option::of("/[a-z/]{0,10}"),
        ) {
            let url = format!("{scheme}://{host}{}", path.unwrap_or_default());
            let strict = Policies::new();
            let permissive = Policies::new().with_insecure_urls(true).with_local_schemes(true);

            for policies in [&strict, &permissive] {
                if check_url(&url, policies).is_ok() {
                    let lowered = scheme.to_ascii_lowercase();
                    let acceptable = lowered == "https"
                        || (lowered == "http" && policies.allows_insecure_urls())
                        || policies.allows_insecure_urls() && policies.allows_local_schemes();
                    prop_assert!(acceptable, "{} was accepted with scheme {}", url, scheme);
                }
            }
        }

        /// Whatever the input, checking a URL is total. A URL a plugin supplies is untrusted text, and the check
        /// runs before anything else sees it.
        #[test]
        fn checking_a_url_is_total(url in ".{0,200}") {
            let policies = Policies::new();
            let _ = check_url(&url, &policies);
            let _ = check_url_length(&url);
        }

        /// A path is refused for opening whenever its extension is an executable one, however the extension is
        /// spelled. Case folding is where such a check usually fails.
        #[test]
        fn an_executable_extension_is_always_refused(
            stem in "[a-z]{1,8}",
            index in 0usize..EXECUTABLE_EXTENSIONS.len(),
            upper in any::<bool>(),
        ) {
            let extension = EXECUTABLE_EXTENSIONS[index];
            let extension = if upper { extension.to_ascii_uppercase() } else { extension.to_owned() };
            let path = absolute(&format!("{stem}.{extension}"));

            let result = check_path(&path, PathUse::Open, &Policies::new(), None);
            prop_assert!(
                matches!(result, Err(PlatformError::BadPath { reason: PathRefusal::Executable, .. })),
                "{:?} -> {:?}",
                path,
                result,
            );
        }

        /// Checking a path is total, whatever the text. Paths come from plugins and from messages.
        #[test]
        fn checking_a_path_is_total(text in ".{0,120}") {
            let policies = Policies::new();
            let path = Path::new(&text);
            let _ = check_path(path, PathUse::Open, &policies, None);
            let root = sandbox_root();
            let _ = check_path(path, PathUse::Reveal, &policies, Some(root.as_path()));
        }

        /// The rate limiter never admits two key chords closer together than the interval, whatever the times
        /// supplied. It is the property that bounds how fast a plugin can type into another application.
        #[test]
        fn key_chords_respect_their_interval(
            interval_ms in 1u64..500,
            times in proptest::collection::vec(0u64..2_000, 0..40),
        ) {
            let limiter = RateLimiter::new(
                Policies::new().with_key_chord_interval(Duration::from_millis(interval_ms)),
            );
            let mut last_admitted: Option<u64> = None;
            for at in times {
                if limiter.admit(PlatformAction::SimulateKeys, at).is_ok() {
                    if let Some(previous) = last_admitted {
                        // Time may go backwards if the caller supplies unsorted times, and the limiter treats that
                        // as no elapsed time.
                        prop_assert!(
                            at.saturating_sub(previous) >= interval_ms || at < previous,
                            "admitted {} after {} with a {}-ms interval",
                            at,
                            previous,
                            interval_ms,
                        );
                    }
                    last_admitted = Some(at);
                }
            }
        }
    }
