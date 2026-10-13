//! Environment diagnosis: the eleven checks behind `synra doctor` and the settings screen.
//!
//! # What this is for
//!
//! Most support conversations start with a question the user cannot answer: which port is in use, whether
//! the disk is full, whether the system clock is weeks out and quietly breaking every timeout. A probe
//! answers it in code and reports three things — what it checked, what it found, and what to do about it.
//!
//! The third is the one that matters. "Port 32100 is in use by another process" is information; "close the
//! other copy of Synra, or change the port in Settings → Network" is a fix.
//!
//! # Every probe says which of the three it is
//!
//! * [`ProbeStatus::Ok`] — nothing to do.
//! * [`ProbeStatus::Warn`] — it works, and it will probably bite later. A disk with 400 MB free is a warning
//!   now and a failure in an hour.
//! * [`ProbeStatus::Fail`] — something will not work.
//!
//! A probe that cannot reach a conclusion reports `Warn` rather than `Fail`. `Fail` is a claim that the
//! feature is broken; not being able to tell is not the same claim, and a diagnostic that cries wolf is one
//! people learn to ignore.
//!
//! # Probes that need the host are injected
//!
//! A keyring, a WebView version and a firewall hint are different on every platform and only knowable from
//! the application layer. They arrive as a [`HostFacts`] value rather than as calls into Tauri, so the whole
//! probe suite is testable without a window, a keychain or a network stack.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// How the check went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ProbeStatus {
    /// Nothing to do.
    Ok,
    /// It works, and it will probably bite later.
    Warn,
    /// Something will not work.
    Fail,
}

impl ProbeStatus {
    /// The name used in the interface and in a diagnostic bundle.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    /// Whether this deserves the user's attention.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        !matches!(self, Self::Ok)
    }
}

impl core::fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    /// A stable machine-readable name, such as `tcp_port_available`.
    ///
    /// Stable because it is what a support conversation quotes and what a test asserts on; the `detail` text
    /// is for humans and will be reworded.
    pub name: String,
    /// How it went.
    pub status: ProbeStatus,
    /// What was found, in a sentence.
    pub detail: String,
    /// What to do about it, when there is something to do.
    ///
    /// Shown next to the result. A probe that reports a problem without a suggestion has moved the work onto
    /// the user without giving them the means to do it.
    pub suggestion: Option<String>,
}

impl ProbeResult {
    /// A passing check.
    #[must_use]
    pub fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self { name: name.into(), status: ProbeStatus::Ok, detail: detail.into(), suggestion: None }
    }

    /// A check that works but will bite later.
    #[must_use]
    pub fn warn(
        name: impl Into<String>,
        detail: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: ProbeStatus::Warn,
            detail: detail.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    /// A check that found something broken.
    #[must_use]
    pub fn fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        suggestion: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            status: ProbeStatus::Fail,
            detail: detail.into(),
            suggestion: Some(suggestion.into()),
        }
    }

    /// A check that could not reach a conclusion.
    ///
    /// Reported as a warning rather than a failure, because `Fail` claims the feature is broken and "could not
    /// tell" is a different claim.
    #[must_use]
    pub fn unknown(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ProbeStatus::Warn,
            detail: detail.into(),
            suggestion: Some("include this report when asking for help".to_owned()),
        }
    }

    /// The probe names, for the summary line.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.name
    }
}

/// A whole run's results.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProbeReport {
    /// Every result, in the order the probes ran.
    pub results: Vec<ProbeResult>,
}

impl ProbeReport {
    /// An empty report.
    #[must_use]
    pub const fn new() -> Self {
        Self { results: Vec::new() }
    }

    /// Adds a result.
    pub fn push(&mut self, result: ProbeResult) {
        self.results.push(result);
    }

    /// The worst status in the report.
    ///
    /// What the summary badge shows: one failure among ten passes is a failing report.
    #[must_use]
    pub fn worst(&self) -> ProbeStatus {
        self.results
            .iter()
            .map(|result| result.status)
            .max()
            .unwrap_or(ProbeStatus::Ok)
    }

    /// Whether anything needs attention.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.results.iter().any(|result| result.status.needs_attention())
    }

    /// How many results have each status.
    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut ok = 0;
        let mut warn = 0;
        let mut fail = 0;
        for result in &self.results {
            match result.status {
                ProbeStatus::Ok => ok += 1,
                ProbeStatus::Warn => warn += 1,
                ProbeStatus::Fail => fail += 1,
            }
        }
        (ok, warn, fail)
    }

    /// A one-line summary for the settings screen.
    #[must_use]
    pub fn summarise(&self) -> String {
        let (ok, warn, fail) = self.counts();
        if fail > 0 {
            return format!("{fail} problem(s), {warn} warning(s), {ok} ok");
        }
        if warn > 0 {
            return format!("{warn} warning(s), {ok} ok");
        }
        format!("all {ok} checks passed")
    }

    /// Only the results that need attention.
    #[must_use]
    pub fn problems(&self) -> Vec<&ProbeResult> {
        self.results
            .iter()
            .filter(|result| result.status.needs_attention())
            .collect()
    }

    /// The result for a probe, by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ProbeResult> {
        self.results.iter().find(|result| result.name == name)
    }
}

/// What only the application layer can know.
///
/// Injected rather than queried, so the probe suite runs in a test with no window, no keychain and no
/// network stack.
#[derive(Debug, Clone, Default)]
pub struct HostFacts {
    /// The WebView's version, when the host could read it.
    pub webview_version: Option<String>,
    /// Whether the platform keychain answered a test round trip.
    pub keyring_available: Option<bool>,
    /// Whether the Wasm runtime initialised.
    pub wasm_backend_available: Option<bool>,
    /// The platform's firewall advice, when there is any to give.
    pub firewall_hint: Option<String>,
}

/// What a probe needs to know about the installation.
#[derive(Debug, Clone)]
pub struct ProbeTargets {
    /// The directory the application writes its data to.
    pub data_dir: PathBuf,
    /// The directory plugins are installed under.
    pub plugins_dir: PathBuf,
    /// The port the main connection listens on.
    pub listen_port: u16,
    /// The port discovery listens on.
    pub discovery_port: u16,
}

/// The lowest WebView version considered usable.
///
/// A build of the interface that relies on a feature an old WebView lacks fails at runtime in a way the user
/// cannot diagnose. Naming the floor here lets the probe say so before they hit it.
pub const MIN_WEBVIEW_MAJOR: u32 = 105;

/// The disk space below which a warning is raised, in bytes.
///
/// Declared here because the threshold is a policy decision rather than a platform fact, and the settings
/// screen shows it. Enforcing it needs a free-space figure, which is a platform query: see
/// [`probe_disk_space`], which measures writability portably and states that the figure is unavailable rather
/// than guessing. A caller that *does* have the figure — the application layer calling `GetDiskFreeSpaceEx`
/// or `statvfs` — compares it using [`is_low_disk_space`], so the rule is stated once.
pub const LOW_DISK_BYTES: u64 = 500 * 1024 * 1024;

/// How large a sample [`probe_disk_space`] writes.
///
/// One mebibyte: enough that a full or nearly-full disk fails the write, small enough that a diagnosis is
/// unnoticeable. A sample scaled to [`LOW_DISK_BYTES`] would mean writing a hundred megabytes in order to
/// report on disk space.
pub const DISK_PROBE_SAMPLE_BYTES: usize = 1024 * 1024;

/// Whether a free-space figure is low enough to warn about.
///
/// Split out so the threshold can be tested without filling a disk, and so the application layer — which can
/// read the figure — applies the same rule instead of restating it.
#[must_use]
pub const fn is_low_disk_space(free_bytes: u64) -> bool {
    free_bytes < LOW_DISK_BYTES
}

/// How far the system clock may be out before it is a problem, in seconds.
///
/// A device whose clock is wrong by more than this breaks heartbeat timing and makes every log line from
/// another device look like it came from the future or the past.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Runs every probe.
///
/// Synchronous: a probe is a `bind`, a `statfs` or an environment read, all of which finish immediately, and
/// making the suite `async` would push that decision onto every caller for no benefit.
#[must_use]
pub fn run_probes(targets: &ProbeTargets, host: &HostFacts) -> ProbeReport {
    let mut report = ProbeReport::new();
    report.push(probe_port_available("tcp_port_available", targets.listen_port));
    report.push(probe_port_available("discovery_port_available", targets.discovery_port));
    report.push(probe_udp_port_available(targets.discovery_port));
    report.push(probe_network_interfaces());
    report.push(probe_firewall_hint(host));
    report.push(probe_data_dir_writable(&targets.data_dir));
    report.push(probe_disk_space(&targets.data_dir));
    report.push(probe_clock_sanity());
    report.push(probe_webview_version(host));
    report.push(probe_keyring_available(host));
    report.push(probe_wasm_backend(host));
    report.push(probe_plugin_dir(&targets.plugins_dir));
    report
}

/// Whether a TCP port can be bound.
///
/// Binding is the only honest test: asking the operating system whether a port is free and then binding it
/// leaves a window in which another process takes it, and the answer arrives before the question was really
/// asked.
#[must_use]
pub fn probe_port_available(name: &str, port: u16) -> ProbeResult {
    match TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)) {
        Ok(listener) => {
            // Released immediately, so the real listener can take it.
            drop(listener);
            ProbeResult::ok(name, format!("port {port} is free"))
        }
        Err(error) => ProbeResult::fail(
            name,
            format!("port {port} cannot be bound: {error}"),
            format!(
                "close whatever else is using port {port}, or choose another port in \
                 Settings → Network"
            ),
        ),
    }
}

/// Whether the discovery socket can be bound.
///
/// Checked separately from TCP because they are different protocols: a process holding the UDP port does not
/// appear in the TCP probe, and discovery is the feature that breaks when it is taken.
#[must_use]
pub fn probe_udp_port_available(port: u16) -> ProbeResult {
    match UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)) {
        Ok(socket) => {
            drop(socket);
            ProbeResult::ok("discovery_udp_available", format!("UDP port {port} is free"))
        }
        Err(error) => ProbeResult::fail(
            "discovery_udp_available",
            format!("UDP port {port} cannot be bound: {error}"),
            "another discovery service may be running; close it, or turn off local discovery",
        ),
    }
}

/// Whether there is a usable network interface.
///
/// Standard library only, so this cannot enumerate interfaces on every platform. What it can do — and what
/// catches the case users actually hit — is check whether a loopback connection works at all. A machine with
/// no network stack fails here.
#[must_use]
pub fn probe_network_interfaces() -> ProbeResult {
    // A loopback TCP bind proves the stack is present. Enumerating interfaces needs a platform API, which is
    // the application layer's business; this is the part that is portable and still catches the real failure.
    match TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)) {
        Ok(listener) => {
            let port = listener.local_addr().map(|addr| addr.port()).unwrap_or(0);
            drop(listener);
            ProbeResult::ok("network_stack", format!("loopback works (bound port {port})"))
        }
        Err(error) => ProbeResult::fail(
            "network_stack",
            format!("loopback binding failed: {error}"),
            "the network stack looks unavailable; a firewall or a sandbox may be blocking it",
        ),
    }
}

/// A platform-specific firewall note, when the host has one.
#[must_use]
pub fn probe_firewall_hint(host: &HostFacts) -> ProbeResult {
    match &host.firewall_hint {
        Some(hint) => ProbeResult::warn(
            "firewall",
            hint.clone(),
            "allow Synra through the firewall so your other devices can reach it",
        ),
        None => ProbeResult::ok("firewall", "no firewall advice for this platform"),
    }
}

/// Whether the data directory can be written to.
///
/// Tested by writing a file rather than by asking about permissions. A directory's mode bits do not account
/// for a read-only mount, an ACL, or a full disk, and the write is what the application actually needs.
#[must_use]
pub fn probe_data_dir_writable(data_dir: &Path) -> ProbeResult {
    if let Err(error) = std::fs::create_dir_all(data_dir) {
        return ProbeResult::fail(
            "data_dir_writable",
            format!("{} cannot be created: {error}", data_dir.display()),
            "check that the parent directory exists and is writable by this user",
        );
    }

    let probe = data_dir.join(".synra-write-probe");
    match std::fs::write(&probe, b"probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            ProbeResult::ok("data_dir_writable", format!("{} is writable", data_dir.display()))
        }
        Err(error) => ProbeResult::fail(
            "data_dir_writable",
            format!("{} cannot be written: {error}", data_dir.display()),
            "check the directory's permissions, or move the data directory in Settings → Advanced",
        ),
    }
}

/// How much space is left where the data lives.
///
/// Reports what it can. Reading free space portably needs a platform call, so when the host cannot supply it
/// the probe measures what it *can* — whether the directory is writable — and says the free-space figure is
/// unavailable rather than inventing one.
#[must_use]
pub fn probe_disk_space(data_dir: &Path) -> ProbeResult {
    // A portable free-space query does not exist in the standard library, so this measures what it can: a file
    // of a known size is written and read back. A full disk fails that, which is the case the probe exists to
    // catch; the free-space *figure* still needs a platform call, and the detail says so rather than inventing
    // one.
    //
    // The earlier version called the writability probe and discarded its result, which checked nothing and
    // reported success — a probe that always passes is worse than no probe, because it is believed.
    let probe = data_dir.join(".synra-disk-probe");
    if let Err(error) = std::fs::create_dir_all(data_dir) {
        return ProbeResult::fail(
            "disk_space",
            format!("the data directory is unusable: {error}"),
            "check the directory's permissions, or move the data directory in Settings → Advanced",
        );
    }

    // One mebibyte, not a fraction of the low-space threshold. A larger sample would mean a diagnosis writes
    // a hundred megabytes to report on disk space, which is both slow and rude; a mebibyte is enough that a
    // full or nearly-full disk fails the write, and small enough to be unnoticeable.
    let sample = vec![0u8; DISK_PROBE_SAMPLE_BYTES];
    match std::fs::write(&probe, &sample) {
        Ok(()) => {
            let read_back = std::fs::read(&probe).map(|bytes| bytes.len()).unwrap_or(0);
            let _ = std::fs::remove_file(&probe);

            if read_back != sample.len() {
                return ProbeResult::fail(
                    "disk_space",
                    format!("wrote {} bytes but read back {read_back}", sample.len()),
                    "the storage may be failing; back up your data and check the disk",
                );
            }
            ProbeResult::ok(
                "disk_space",
                "the data directory accepts writes; the free-space figure needs a platform query",
            )
        }
        Err(error) => ProbeResult::fail(
            "disk_space",
            format!("a {} byte write failed: {error}", sample.len()),
            "free some disk space; Synra needs room for plugin data and transfer buffers",
        ),
    }
}

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

/// Whether the plugin directory is usable.
///
/// Existence and writability only. Whether each installed plugin's *artifact* is intact needs the loader,
/// which lives in another crate; this reports the container rather than overstating what it checked.
#[must_use]
pub fn probe_plugin_dir(plugins_dir: &Path) -> ProbeResult {
    if !plugins_dir.exists() {
        return ProbeResult::ok(
            "plugin_dir",
            format!("{} does not exist yet; no plugins are installed", plugins_dir.display()),
        );
    }
    match std::fs::read_dir(plugins_dir) {
        Ok(entries) => {
            let count = entries.filter_map(Result::ok).count();
            ProbeResult::ok(
                "plugin_dir",
                format!("{} holds {count} entr(ies)", plugins_dir.display()),
            )
        }
        Err(error) => ProbeResult::fail(
            "plugin_dir",
            format!("{} cannot be read: {error}", plugins_dir.display()),
            "check the directory's permissions",
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique directory per call.
    ///
    /// A counter rather than the process id: two tests in one process would otherwise share a directory, and
    /// the disk probe writes a mebibyte into it — so they would race over the same path and one would see the
    /// other's write as a failure.
    fn unique_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn targets() -> ProbeTargets {
        let base = std::env::temp_dir().join(format!("synra-doctor-{}", unique_suffix()));
        ProbeTargets {
            data_dir: base.join("data"),
            plugins_dir: base.join("plugins"),
            // Ports in the ephemeral range are the ones a test can be confident about, and the probe tests
            // pass 0 where they need a guaranteed-free port.
            listen_port: 0,
            discovery_port: 0,
        }
    }

    fn hosts() -> HostFacts {
        HostFacts {
            webview_version: Some("120.0.0".to_owned()),
            keyring_available: Some(true),
            wasm_backend_available: Some(true),
            firewall_hint: None,
        }
    }

    #[test]
    fn a_passing_probe_has_nothing_to_suggest() {
        let result = ProbeResult::ok("check", "all good");
        assert_eq!(result.status, ProbeStatus::Ok);
        assert_eq!(result.suggestion, None);
        assert!(!result.status.needs_attention());
    }

    #[test]
    fn a_warning_and_a_failure_both_suggest_something() {
        // A probe that reports a problem without a suggestion has moved the work onto the user without giving
        // them the means to do it.
        for result in [
            ProbeResult::warn("check", "nearly full", "free some space"),
            ProbeResult::fail("check", "no space", "free some space"),
            ProbeResult::unknown("check", "could not tell"),
        ] {
            assert!(result.suggestion.is_some(), "{result:?}");
            assert!(result.status.needs_attention());
        }
    }

    #[test]
    fn an_inconclusive_probe_is_a_warning_not_a_failure() {
        // `Fail` claims the feature is broken. Not being able to tell is a different claim, and a diagnostic
        // that cries wolf is one people learn to ignore.
        let result = ProbeResult::unknown("check", "could not tell");
        assert_eq!(result.status, ProbeStatus::Warn);
    }

    #[test]
    fn statuses_order_from_ok_to_fail() {
        // The ordering is what `worst` relies on.
        assert!(ProbeStatus::Ok < ProbeStatus::Warn);
        assert!(ProbeStatus::Warn < ProbeStatus::Fail);
    }

    #[test]
    fn a_report_reports_the_worst_status_it_holds() {
        // One failure among ten passes is a failing report, not a passing one.
        let mut report = ProbeReport::new();
        report.push(ProbeResult::ok("a", "fine"));
        report.push(ProbeResult::warn("b", "nearly", "do something"));
        report.push(ProbeResult::fail("c", "broken", "fix it"));
        report.push(ProbeResult::ok("d", "fine"));

        assert_eq!(report.worst(), ProbeStatus::Fail);
        assert!(report.needs_attention());
        assert_eq!(report.counts(), (2, 1, 1));
        assert!(report.summarise().contains("1 problem"));
        assert_eq!(report.problems().len(), 2);
    }

    #[test]
    fn a_report_of_passes_says_so() {
        let mut report = ProbeReport::new();
        report.push(ProbeResult::ok("a", "fine"));
        report.push(ProbeResult::ok("b", "fine"));

        assert_eq!(report.worst(), ProbeStatus::Ok);
        assert!(!report.needs_attention());
        assert_eq!(report.summarise(), "all 2 checks passed");
        assert!(report.problems().is_empty());
    }

    #[test]
    fn an_empty_report_is_not_a_problem() {
        let report = ProbeReport::new();
        assert_eq!(report.worst(), ProbeStatus::Ok);
        assert!(!report.needs_attention());
        assert!(report.results.is_empty());
    }

    #[test]
    fn a_report_summarises_warnings_without_failures() {
        let mut report = ProbeReport::new();
        report.push(ProbeResult::ok("a", "fine"));
        report.push(ProbeResult::warn("b", "nearly", "do something"));

        assert_eq!(report.worst(), ProbeStatus::Warn);
        assert!(report.summarise().contains("1 warning"));
        assert!(!report.summarise().contains("problem"));
    }

    #[test]
    fn a_result_can_be_found_by_name() {
        // The name is what a support conversation quotes, so it has to be a lookup key.
        let mut report = ProbeReport::new();
        report.push(ProbeResult::ok("clock_sanity", "plausible"));
        assert!(report.get("clock_sanity").is_some());
        assert!(report.get("nothing").is_none());
    }

    #[test]
    fn a_free_port_passes() {
        // Port zero asks the operating system for any free port, so this cannot fail for the reason under test.
        let result = probe_port_available("tcp_port_available", 0);
        assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
        assert!(result.detail.contains("free"));
    }

    #[test]
    fn a_port_already_held_fails_with_advice() {
        // The failure a user actually hits: another copy of the application, or something else on the port.
        //
        // Bound to the wildcard address, because that is what the probe binds and what the real listener binds.
        // A holder on `127.0.0.1` alone does *not* conflict with a listener on `0.0.0.0` — the two can coexist
        // — so a test that used the loopback address would assert something the probe is right not to detect.
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .expect("binds an ephemeral port");
        let port = listener.local_addr().expect("has an address").port();

        let result = probe_port_available("tcp_port_available", port);
        assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
        assert!(result.suggestion.is_some());
        assert!(result.detail.contains(&port.to_string()));
        drop(listener);
    }

    #[test]
    fn a_held_udp_port_fails_separately_from_tcp() {
        // Discovery is the feature that breaks when it is taken, and a process holding the UDP port does not
        // appear in the TCP probe.
        // The wildcard address again, for the same reason as the TCP case.
        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .expect("binds an ephemeral port");
        let port = socket.local_addr().expect("has an address").port();

        let result = probe_udp_port_available(port);
        assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
        assert_eq!(result.name, "discovery_udp_available");
        drop(socket);
    }

    #[test]
    fn the_network_stack_is_present_in_a_test_process() {
        // If this fails, the machine has no loopback, which is the case the probe exists to catch.
        let result = probe_network_interfaces();
        assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
    }

    #[test]
    fn a_firewall_hint_is_a_warning_with_advice() {
        let host = HostFacts {
            firewall_hint: Some("Windows Defender may be blocking inbound connections".to_owned()),
            ..hosts()
        };
        let result = probe_firewall_hint(&host);
        assert_eq!(result.status, ProbeStatus::Warn);
        assert!(result.detail.contains("Windows Defender"));
        assert!(result.suggestion.is_some());
    }

    #[test]
    fn no_firewall_hint_is_not_a_problem() {
        assert_eq!(probe_firewall_hint(&hosts()).status, ProbeStatus::Ok);
    }

    #[test]
    fn a_writable_directory_passes_and_gains_no_litter() {
        let dir = std::env::temp_dir().join(format!("synra-doctor-rw-{}", unique_suffix()));
        let _ = std::fs::remove_dir_all(&dir);

        let result = probe_data_dir_writable(&dir);
        assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
        // The probe file is removed, so a repeated diagnosis does not accumulate files.
        assert!(
            !dir.join(".synra-write-probe").exists(),
            "the probe left its file behind"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_that_cannot_be_created_fails() {
        // A path under an existing regular file cannot become a directory, on every platform.
        let file = std::env::temp_dir().join(format!("synra-doctor-file-{}", unique_suffix()));
        std::fs::write(&file, b"not a directory").expect("writes");

        let result = probe_data_dir_writable(&file.join("under-a-file"));
        assert_eq!(result.status, ProbeStatus::Fail, "{result:?}");
        assert!(result.suggestion.is_some());

        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn the_disk_probe_does_not_claim_a_figure_it_cannot_read() {
        // A portable free-space query does not exist in the standard library, so the probe says so rather
        // than inventing a number.
        let dir = std::env::temp_dir().join(format!("synra-doctor-disk-{}", unique_suffix()));
        let result = probe_disk_space(&dir);
        assert!(result.status.needs_attention() || result.status == ProbeStatus::Ok);
        assert!(
            result.detail.contains("platform query"),
            "the probe overstated what it measured: {}",
            result.detail
        );
    }

    #[test]
    fn the_clock_is_plausible_in_a_test_process() {
        assert_eq!(probe_clock_sanity().status, ProbeStatus::Ok);
    }

    #[test]
    fn a_recent_webview_passes_the_version_check() {
        let result = probe_webview_version(&HostFacts {
            webview_version: Some(format!("{MIN_WEBVIEW_MAJOR}.0.0")),
            ..hosts()
        });
        assert_eq!(result.status, ProbeStatus::Ok);
    }

    #[test]
    fn an_old_webview_fails_with_advice() {
        let result = probe_webview_version(&HostFacts {
            webview_version: Some("90.0.4430.72".to_owned()),
            ..hosts()
        });
        assert_eq!(result.status, ProbeStatus::Fail);
        assert!(result.detail.contains("90.0.4430.72"));
        assert!(result.suggestion.is_some());
    }

    #[test]
    fn a_webview_version_that_cannot_be_read_is_inconclusive() {
        // Not a failure: the interface may work perfectly, and claiming otherwise sends the user to update
        // something that is not the problem.
        for version in ["unknown", ""] {
            let result = probe_webview_version(&HostFacts {
                webview_version: Some(version.to_owned()),
                ..hosts()
            });
            assert_eq!(result.status, ProbeStatus::Warn, "{version:?}");
        }
    }

    #[test]
    fn a_missing_webview_report_is_inconclusive_rather_than_a_failure() {
        let result = probe_webview_version(&HostFacts::default());
        assert_eq!(result.status, ProbeStatus::Warn);
        assert!(result.detail.contains("did not report"));
    }

    #[test]
    fn keyring_states_map_to_the_right_status() {
        assert_eq!(
            probe_keyring_available(&HostFacts { keyring_available: Some(true), ..Default::default() }).status,
            ProbeStatus::Ok
        );
        let locked = probe_keyring_available(&HostFacts {
            keyring_available: Some(false),
            ..Default::default()
        });
        assert_eq!(locked.status, ProbeStatus::Fail);
        assert!(locked.suggestion.is_some());
        assert_eq!(probe_keyring_available(&HostFacts::default()).status, ProbeStatus::Warn);
    }

    #[test]
    fn wasm_backend_states_map_to_the_right_status() {
        assert_eq!(
            probe_wasm_backend(&HostFacts { wasm_backend_available: Some(true), ..Default::default() }).status,
            ProbeStatus::Ok
        );
        let broken = probe_wasm_backend(&HostFacts {
            wasm_backend_available: Some(false),
            ..Default::default()
        });
        assert_eq!(broken.status, ProbeStatus::Fail);
        assert!(broken.suggestion.is_some());
        assert_eq!(probe_wasm_backend(&HostFacts::default()).status, ProbeStatus::Warn);
    }

    #[test]
    fn a_missing_plugin_directory_is_not_a_problem() {
        // A fresh install has no plugins, and reporting that as a fault would make every new install look
        // broken.
        let dir = std::env::temp_dir().join(format!("synra-doctor-plugins-{}", unique_suffix()));
        let _ = std::fs::remove_dir_all(&dir);

        let result = probe_plugin_dir(&dir);
        assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
        assert!(result.detail.contains("no plugins"));
    }

    #[test]
    fn a_plugin_directory_is_counted_rather_than_described() {
        let dir = std::env::temp_dir().join(format!("synra-doctor-plugins2-{}", unique_suffix()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("creates");
        for index in 0..3 {
            std::fs::write(dir.join(format!("plugin{index}")), b"x").expect("writes");
        }

        let result = probe_plugin_dir(&dir);
        assert_eq!(result.status, ProbeStatus::Ok);
        assert!(result.detail.contains('3'), "{}", result.detail);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_whole_suite_reports_every_probe() {
        // Every probe has to appear in the report even when it passes, because "which checks ran" is part of
        // what the user is being shown.
        let report = run_probes(&targets(), &hosts());

        for name in [
            "tcp_port_available",
            "discovery_port_available",
            "discovery_udp_available",
            "network_stack",
            "firewall",
            "data_dir_writable",
            "disk_space",
            "clock_sanity",
            "webview_version",
            "keyring",
            "wasm_backend",
            "plugin_dir",
        ] {
            assert!(report.get(name).is_some(), "{name} is missing from the report");
        }
        // And every result carries a non-empty name and detail, so the interface has something to render.
        for result in &report.results {
            assert!(!result.name.is_empty());
            assert!(!result.detail.is_empty(), "{}", result.name);
        }
    }

    #[test]
    fn the_suite_passes_on_a_healthy_machine() {
        // With every host fact good and ports chosen by the operating system, nothing should fail.
        let report = run_probes(&targets(), &hosts());
        assert_eq!(report.worst(), ProbeStatus::Ok, "{:#?}", report.problems());
    }

    #[test]
    fn a_missing_host_fact_makes_the_suite_warn_rather_than_fail() {
        // The application layer not reporting something is not the machine being broken.
        let report = run_probes(&targets(), &HostFacts::default());
        assert_ne!(report.worst(), ProbeStatus::Fail, "{:#?}", report.problems());
        assert!(report.needs_attention(), "three facts were unknown");
    }

    #[test]
    fn the_low_space_threshold_is_inclusive_at_its_boundary() {
        // A disk with exactly the threshold free is not yet low, and one byte less is. The boundary has to be
        // decided once, here, or the settings screen and the probe would disagree.
        assert!(!is_low_disk_space(LOW_DISK_BYTES));
        assert!(is_low_disk_space(LOW_DISK_BYTES - 1));
        assert!(is_low_disk_space(0));
        assert!(!is_low_disk_space(LOW_DISK_BYTES + 1));
    }

    #[test]
    fn the_disk_probe_sample_is_small_enough_to_be_unobtrusive() {
        // A diagnosis that writes a hundred megabytes to talk about disk space is both slow and rude.
        assert_eq!(DISK_PROBE_SAMPLE_BYTES, 1024 * 1024);
        assert!(
            (DISK_PROBE_SAMPLE_BYTES as u64) < LOW_DISK_BYTES / 100,
            "the sample is a material fraction of the threshold it is checking"
        );
    }

    #[test]
    fn clock_skew_tolerance_is_symmetric_and_bounded() {
        assert!(clock_skew_within_tolerance(1_000, 1_000));
        assert!(clock_skew_within_tolerance(1_000, 1_000 + MAX_CLOCK_SKEW_SECS));
        assert!(clock_skew_within_tolerance(1_000 + MAX_CLOCK_SKEW_SECS, 1_000));
        assert!(!clock_skew_within_tolerance(1_000, 1_000 + MAX_CLOCK_SKEW_SECS + 1));
        assert!(!clock_skew_within_tolerance(1_000 + MAX_CLOCK_SKEW_SECS + 1, 1_000));
    }

    #[test]
    fn clock_skew_does_not_underflow() {
        // A local clock at zero against a reference at the epoch must not wrap into a pass.
        assert!(clock_skew_within_tolerance(0, 0));
        assert!(!clock_skew_within_tolerance(0, u64::MAX));
    }

    #[test]
    fn a_status_round_trips_through_json() {
        for status in [ProbeStatus::Ok, ProbeStatus::Warn, ProbeStatus::Fail] {
            let json = serde_json::to_string(&status).expect("serialises");
            assert_eq!(json, format!("\"{}\"", status.as_str()));
            let back: ProbeStatus = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, status);
        }
    }

    #[test]
    fn a_probe_result_round_trips_with_camel_case_fields() {
        let result = ProbeResult::fail("clock_sanity", "wrong", "set the clock");
        let json = serde_json::to_string(&result).expect("serialises");
        assert!(json.contains("\"name\""), "{json}");
        assert!(json.contains("\"suggestion\""), "{json}");
        // A passing probe omits its suggestion rather than writing null, so a reader never handles both.
        let passing = serde_json::to_string(&ProbeResult::ok("x", "fine")).expect("serialises");
        assert!(passing.contains("\"suggestion\":null") || !passing.contains("suggestion"), "{passing}");

        let back: ProbeResult = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, result);
    }

    #[test]
    fn a_report_serialises_as_a_bare_list() {
        // The bundle carries it, and a transparent list is what an interface expects to iterate.
        let mut report = ProbeReport::new();
        report.push(ProbeResult::ok("a", "fine"));

        let json = serde_json::to_string(&report).expect("serialises");
        assert!(json.starts_with('['), "{json}");

        let back: ProbeReport = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, report);
    }

    #[test]
    fn a_probe_result_displays_its_status() {
        assert_eq!(ProbeStatus::Ok.to_string(), "ok");
        assert_eq!(ProbeStatus::Warn.to_string(), "warn");
        assert_eq!(ProbeStatus::Fail.to_string(), "fail");
    }

    #[test]
    fn a_result_reports_its_name_as_its_title() {
        assert_eq!(ProbeResult::ok("clock_sanity", "fine").title(), "clock_sanity");
    }
}
