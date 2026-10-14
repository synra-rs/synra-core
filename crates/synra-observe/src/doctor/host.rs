//! The probes the host itself answers, and the tolerances they are judged against.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{HostFacts, ProbeResult};

/// The lowest WebView version considered usable.
///
/// A build of the interface that relies on a feature an old WebView lacks fails at runtime in a way the user
/// cannot diagnose. Naming the floor here lets the probe say so before they hit it.
pub const MIN_WEBVIEW_MAJOR: u32 = 105;

/// How far the system clock may be out before it is a problem, in seconds.
///
/// A device whose clock is wrong by more than this breaks heartbeat timing and makes every log line from
/// another device look like it came from the future or the past.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Whether the system clock is close enough to plausible.
///
/// Compares against a build-time floor rather than against a network time source, because a device with no
/// internet is exactly the device whose clock is wrong and exactly the one where a diagnosis is needed.
#[must_use]
pub fn probe_clock_sanity() -> ProbeResult {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);

    if now == 0 {
        return ProbeResult::fail(
            "clock_sanity",
            "the system clock reports the epoch",
            "set the date and time; every timeout and every log line depends on it",
        );
    }
    if now < 1_577_836_800 {
        // Before 2020. Not impossible, but on a device running this build it means the clock is wrong.
        return ProbeResult::warn(
            "clock_sanity",
            format!("the system clock reads {now}, which is before 2020"),
            "set the date and time; a clock this far out breaks connection timeouts",
        );
    }
    if now > 4_102_444_800 {
        // Past 2100.
        return ProbeResult::warn(
            "clock_sanity",
            format!("the system clock reads {now}, which is after 2100"),
            "set the date and time; a clock this far out breaks connection timeouts",
        );
    }
    ProbeResult::ok("clock_sanity", "the system clock is plausible")
}

/// Whether the WebView is new enough.
#[must_use]
pub fn probe_webview_version(host: &HostFacts) -> ProbeResult {
    let Some(version) = &host.webview_version else {
        return ProbeResult::unknown("webview_version", "the host did not report a WebView version");
    };

    let major = version
        .split(['.', '-', '+'])
        .next()
        .and_then(|part| part.parse::<u32>().ok());

    match major {
        Some(major) if major >= MIN_WEBVIEW_MAJOR => {
            ProbeResult::ok("webview_version", format!("WebView {version}"))
        }
        // The parsed major is used to build the message, so a reader sees both numbers rather than being told
        // the version is too old without being told how old.
        Some(major) => ProbeResult::fail(
            "webview_version",
            format!("WebView {version} (major {major}) is older than {MIN_WEBVIEW_MAJOR}"),
            "update the system WebView; the interface uses features it does not have",
        ),
        None => ProbeResult::unknown(
            "webview_version",
            format!("the WebView version {version:?} could not be read"),
        ),
    }
}

/// Whether the platform keychain works.
#[must_use]
pub fn probe_keyring_available(host: &HostFacts) -> ProbeResult {
    match host.keyring_available {
        Some(true) => ProbeResult::ok("keyring", "the platform keychain answered"),
        Some(false) => ProbeResult::fail(
            "keyring",
            "the platform keychain did not answer",
            "unlock your login keychain; without it, pairing secrets cannot be stored securely",
        ),
        None => ProbeResult::unknown("keyring", "the keychain was not tested"),
    }
}

/// Whether the Wasm runtime initialised.
#[must_use]
pub fn probe_wasm_backend(host: &HostFacts) -> ProbeResult {
    match host.wasm_backend_available {
        Some(true) => ProbeResult::ok("wasm_backend", "the Wasm runtime initialised"),
        Some(false) => ProbeResult::fail(
            "wasm_backend",
            "the Wasm runtime did not initialise",
            "plugins cannot run in this state; a reinstall of the application may be needed",
        ),
        None => ProbeResult::unknown("wasm_backend", "the Wasm runtime was not tested"),
    }
}

/// Checks the clock reading is within [`MAX_CLOCK_SKEW_SECS`] of `reference`.
///
/// Split out from [`probe_clock_sanity`] so the comparison can be tested without moving the system clock. The
/// probe cannot use it — it has no reference to compare against — but a caller that *does* have one, such as
/// a negotiation with a peer, can.
#[must_use]
pub const fn clock_skew_within_tolerance(local_secs: u64, reference_secs: u64) -> bool {
    local_secs.abs_diff(reference_secs) <= MAX_CLOCK_SKEW_SECS
}
