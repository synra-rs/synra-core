//! The diagnostic bundle: what a user sends when they ask for help.
//!
//! # The consent screen is the design
//!
//! Everything here exists to make one screen honest. That screen lists what will be included and what will
//! not, marks the sensitive parts as optional and off by default, and names the file it will write. A bundle
//! assembled without that screen is a bundle assembled from somebody's private data without them knowing,
//! which is the failure mode this module is built to avoid.
//!
//! So the flow is three steps, and the types enforce the order:
//!
//! 1. [`DiagnosticBundle::plan`] produces a [`BundlePlan`] — what *would* be included.
//! 2. The user edits the plan: [`BundlePlan::toggle_optional`].
//! 3. [`BundlePlan::render`] produces the JSON, and the caller writes it and reports the path, size and digest.
//!
//! There is deliberately no `export_everything()`.
//!
//! # Two lists, because "not included" is the interesting one
//!
//! A prompt that only says what it collects leaves the user to wonder about the rest, and wondering is what
//! stops people from sending the file that would have got their problem fixed. So [`BundlePlan::excludes`]
//! names the things that are never included — clipboard contents, message bodies, file contents, keys, plugin
//! secure storage — in the same list the inclusions are in.
//!
//! # The digest is for the user, not for us
//!
//! Every export reports the SHA-256 of what it wrote. Nothing in this application verifies it; it exists so a
//! person who posts a bundle in an issue can check that what they uploaded is what they reviewed.
//!
//! # Retained logs are redacted before they enter the bundle
//!
//! [`crate::logging::redact_line`] runs over every log line as it is collected. The lines on disk were already
//! treated on their way there, and this is the second pass — because the bundle is the artifact that leaves
//! the machine, and "already redacted once" is not a reason to trust a file that has been sitting in a
//! directory for two weeks.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit::AuditEntry;
use crate::doctor::ProbeResult;
use crate::logging::{DEFAULT_REDACTED_FIELDS, redact_line};
use crate::metrics::MetricsSnapshot;

/// How many log lines a bundle carries by default.
///
/// A tail plus every error, rather than the whole file: the interesting part of a log is what happened just
/// before the problem, and a bundle containing two weeks of `INFO` lines is one nobody reads.
pub const DEFAULT_LOG_TAIL_LINES: usize = 2_000;

/// The longest a single log line may be in a bundle.
pub const MAX_LOG_LINE_BYTES: usize = 4_096;

/// What can be included, and what is always excluded.
///
/// The distinction is a field rather than a convention: a caller assembles a plan and the plan is what is
/// shown, so an inclusion nobody intended cannot reach the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum BundleSection {
    /// Operating system, architecture, application and kernel versions.
    Environment,
    /// The application's configuration, with secret fields removed.
    Config,
    /// Which devices are paired and whether the links are up.
    Devices,
    /// Which plugins are installed and their state.
    Plugins,
    /// Counters and histograms.
    Metrics,
    /// The tail of the log, plus every error.
    Logs,
    /// Recent crash reports.
    Crashes,
    /// The environment probe results.
    Probes,
    /// What plugins have been doing, including refusals.
    ///
    /// Optional, and off by default. It is the one section that describes the user's own activity rather than
    /// the software's state.
    AuditTrail,
    /// Debug-level log lines.
    ///
    /// Optional, and off by default. Debug lines carry device names and file paths, which are the user's
    /// information even though they are not secrets.
    DebugLogs,
}

impl BundleSection {
    /// Every section, in the order the prompt lists them.
    pub const ALL: &'static [Self] = &[
        Self::Environment,
        Self::Config,
        Self::Devices,
        Self::Plugins,
        Self::Metrics,
        Self::Logs,
        Self::Crashes,
        Self::Probes,
        Self::AuditTrail,
        Self::DebugLogs,
    ];

    /// The name used in the prompt and in the bundle's manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Config => "config",
            Self::Devices => "devices",
            Self::Plugins => "plugins",
            Self::Metrics => "metrics",
            Self::Logs => "logs",
            Self::Crashes => "crashes",
            Self::Probes => "probes",
            Self::AuditTrail => "audit-trail",
            Self::DebugLogs => "debug-logs",
        }
    }

    /// Whether this section is off unless the user turns it on.
    ///
    /// Two sections, and both are about the user rather than the software: what they did, and the detail
    /// lines that name their devices and files. Everything else is state the application would report about
    /// itself anyway.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(self, Self::AuditTrail | Self::DebugLogs)
    }

    /// Whether this section is in the bundle by default.
    #[must_use]
    pub const fn is_default(self) -> bool {
        !self.is_optional()
    }

    /// A phrase for the consent prompt.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Environment => "version and platform information",
            Self::Config => "your settings, with anything secret removed",
            Self::Devices => "which devices are paired, and whether they are reachable",
            Self::Plugins => "which plugins are installed and whether they are running",
            Self::Metrics => "performance counters",
            Self::Logs => "recent errors and the last part of the log",
            Self::Crashes => "reports from any recent crash",
            Self::Probes => "the environment check results",
            Self::AuditTrail => "which capabilities plugins used, including refusals",
            Self::DebugLogs => "detailed debug lines, which may name your devices and files",
        }
    }
}

/// What is never included, whatever the user asks for.
///
/// A constant rather than a computation, because it is a promise. The prompt renders it verbatim, and a test
/// asserts the promise holds for a bundle built with every optional section enabled.
pub const NEVER_INCLUDED: &[&str] = &[
    "clipboard contents",
    "the body of any message",
    "the contents of any file",
    "passwords, tokens or pairing secrets",
    "anything a plugin stored in secure storage",
];

/// Where a bundle's sections came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvSummary {
    /// The application's version.
    pub app_version: String,
    /// The kernel's version, so a protocol mismatch is visible without asking.
    pub kernel_version: String,
    /// The operating system, as the platform reported it.
    pub os: String,
    /// The architecture.
    pub arch: String,
    /// The WebView's version, when it was readable.
    pub webview_version: Option<String>,
}

/// A log line in a bundle, already redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleLogLine {
    /// The line's own text, with secrets removed.
    pub text: String,
    /// Whether the tail was cut because the line was too long.
    pub truncated: bool,
}

/// The log slice a bundle carries.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogSlice {
    /// The last lines of the log, oldest first.
    pub tail: Vec<BundleLogLine>,
    /// Every error-level line found, even outside the tail.
    pub errors: Vec<BundleLogLine>,
    /// How many lines were read.
    pub lines_read: usize,
    /// How many lines were left out.
    pub lines_omitted: usize,
}

/// Whether a device is reachable, as the bundle records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    /// The device's id, as text.
    pub device_id: String,
    /// Whether it is paired.
    pub paired: bool,
    /// Whether a link is up right now.
    pub online: bool,
}

/// A plugin's state, as the bundle records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRecord {
    /// The plugin's id.
    pub plugin_id: String,
    /// Its version.
    pub version: String,
    /// Whether it is currently loaded.
    pub active: bool,
    /// Whether any of its capabilities were refused.
    ///
    /// A boolean rather than the records themselves: this section is not optional, so it must not carry the
    /// audit trail's detail. The count is what a maintainer needs to know to ask for the trail.
    pub had_refusals: bool,
}

/// Everything a bundle can hold.
///
/// One optional field per section, so a section that was not selected is `None` rather than an empty list. The
/// difference matters: an empty list of plugins reads as "no plugins installed", and `None` reads as "not
/// collected", which is what a reader needs in order to know whether the absence is information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticBundle {
    /// When the bundle was assembled, in milliseconds since the epoch.
    pub generated_at_ms: i64,
    /// Which sections are present, for a reader that wants the list before the contents.
    pub sections: Vec<String>,
    /// What is never included, carried in the file itself.
    ///
    /// The consent screen shows this list, and so does the bundle: a maintainer reading the file should see the
    /// same promise the user agreed to, rather than having to trust that the screen said it.
    pub excluded: Vec<String>,
    /// The environment summary.
    pub environment: Option<EnvSummary>,
    /// The configuration, already redacted.
    pub config: Option<serde_json::Value>,
    /// Paired devices and their state.
    pub devices: Option<Vec<DeviceRecord>>,
    /// Installed plugins and their state.
    pub plugins: Option<Vec<PluginRecord>>,
    /// Counter and histogram values.
    pub metrics: Option<MetricsSnapshot>,
    /// The log slice.
    pub logs: Option<LogSlice>,
    /// Recent crash reports.
    pub crashes: Option<Vec<crate::crash::CrashReport>>,
    /// Environment probe results.
    pub probes: Option<Vec<ProbeResult>>,
    /// The audit trail.
    pub audit_trail: Option<Vec<AuditEntry>>,
}

impl DiagnosticBundle {
    /// An empty bundle.
    #[must_use]
    pub fn empty(generated_at_ms: i64) -> Self {
        Self {
            generated_at_ms,
            sections: Vec::new(),
            excluded: NEVER_INCLUDED.iter().map(|item| (*item).to_owned()).collect(),
            environment: None,
            config: None,
            devices: None,
            plugins: None,
            metrics: None,
            logs: None,
            crashes: None,
            probes: None,
            audit_trail: None,
        }
    }

    /// Whether a section is present.
    #[must_use]
    pub fn contains(&self, section: BundleSection) -> bool {
        self.sections.iter().any(|name| name == section.as_str())
    }

    /// How many sections are present.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.sections.len()
    }

    /// Whether the bundle holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }

    /// The bundle as pretty JSON.
    ///
    /// Pretty rather than compact because a person reads this file — that is the whole point of a bundle
    /// somebody chose to export — and a reader who opens it should not be looking at one line of eight thousand
    /// characters.
    ///
    /// # Errors
    ///
    /// A serialisation error, which would mean a type in the bundle is not serialisable.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// The SHA-256 of the rendered JSON.
    ///
    /// Reported to the user after an export so they can check that what they uploaded is what they reviewed.
    /// Nothing in the application verifies it.
    ///
    /// # Errors
    ///
    /// As [`Self::to_json`].
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        Ok(sha256_hex(self.to_json()?.as_bytes()))
    }
}

/// The sources a bundle is assembled from.
///
/// Borrowed rather than owned, because a bundle is a view over state that already exists and cloning a log
/// slice to plan an export the user may cancel is work for nothing.
#[derive(Debug, Clone, Default)]
pub struct BundleSources {
    /// The environment summary.
    pub environment: Option<EnvSummary>,
    /// The configuration, already redacted by the caller.
    pub config: Option<serde_json::Value>,
    /// Paired devices.
    pub devices: Option<Vec<DeviceRecord>>,
    /// Installed plugins.
    pub plugins: Option<Vec<PluginRecord>>,
    /// Metrics.
    pub metrics: Option<Box<MetricsSnapshot>>,
    /// The log's lines, oldest first. Redaction happens during assembly.
    pub log_lines: Option<Vec<String>>,
    /// Crash reports.
    pub crashes: Option<Vec<crate::crash::CrashReport>>,
    /// Probe results.
    pub probes: Option<Vec<ProbeResult>>,
    /// Audit records.
    pub audit: Option<Vec<AuditEntry>>,
}

/// A plan the user has reviewed.
#[derive(Debug, Clone)]
pub struct BundlePlan {
    sections: Vec<BundleSection>,
    sources: BundleSources,
    generated_at_ms: i64,
    log_tail_lines: usize,
    destination: PathBuf,
}

impl BundlePlan {
    /// Assembles a plan from the available sources.
    ///
    /// Every section with a source is available; the optional ones start off. Nothing is rendered until
    /// [`Self::render`], so a cancelled export costs nothing.
    #[must_use]
    pub fn plan(sources: BundleSources, generated_at_ms: i64, destination: PathBuf) -> Self {
        let sections = BundleSection::ALL
            .iter()
            .copied()
            .filter(|section| section.is_default() && available(*section, &sources))
            .collect();

        Self {
            sections,
            sources,
            generated_at_ms,
            log_tail_lines: DEFAULT_LOG_TAIL_LINES,
            destination,
        }
    }

    /// Where the bundle would be written.
    ///
    /// Shown on the consent screen, so the user knows where to look for it. A path revealed only after the
    /// export is a path the user has to hunt for.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Changes the destination.
    pub fn set_destination(&mut self, destination: PathBuf) {
        self.destination = destination;
    }

    /// Caps how many log lines the bundle carries.
    pub const fn set_log_tail_lines(&mut self, lines: usize) {
        self.log_tail_lines = lines;
    }

    /// The sections currently selected.
    #[must_use]
    pub fn sections(&self) -> &[BundleSection] {
        &self.sections
    }

    /// Whether a section is selected.
    #[must_use]
    pub fn includes(&self, section: BundleSection) -> bool {
        self.sections.contains(&section)
    }

    /// Whether a section could be included at all.
    #[must_use]
    pub const fn is_available(&self, section: BundleSection) -> bool {
        available(section, &self.sources)
    }

    /// Turns an optional section on or off.
    ///
    /// Returns whether the request took effect. A caller cannot switch on a section that is not optional — the
    /// two sensitive ones are the only choices here, and a required section is not a choice the user makes.
    pub fn toggle_optional(&mut self, section: BundleSection, on: bool) -> bool {
        if !section.is_optional() {
            return false;
        }
        if on {
            if self.sections.contains(&section) {
                return true;
            }
            self.sections.push(section);
            // Kept in the documented order, so the bundle's `sections` list reads the same however it was
            // edited and two exports of the same state compare equal.
            self.sections.sort_by_key(|section| {
                BundleSection::ALL.iter().position(|known| known == section).unwrap_or(usize::MAX)
            });
            true
        }
        else {
            self.sections.retain(|existing| *existing != section);
            true
        }
    }

    /// The optional sections the user has switched on.
    #[must_use]
    pub fn enabled_optional(&self) -> Vec<BundleSection> {
        self.sections.iter().copied().filter(|s| s.is_optional()).collect()
    }

    /// What the consent screen shows as included.
    #[must_use]
    pub fn inclusions(&self) -> Vec<(&'static str, &'static str)> {
        self.sections
            .iter()
            .map(|section| (section.describe(), section.as_str()))
            .collect()
    }

    /// What the consent screen shows as never included.
    #[must_use]
    pub const fn excludes(&self) -> &'static [&'static str] {
        NEVER_INCLUDED
    }

    /// A sentence naming the size and the digest, for after the export.
    ///
    /// # Errors
    ///
    /// A serialisation error.
    pub fn receipt(&self, rendered: &str) -> Result<String, serde_json::Error> {
        let digest = sha256_hex(rendered.as_bytes());
        Ok(format!(
            "{} bytes written to {} (sha256 {digest})",
            rendered.len(),
            self.destination.display()
        ))
    }

    /// Assembles the bundle and renders it.
    ///
    /// # Errors
    ///
    /// A serialisation error.
    pub fn render(&self) -> Result<String, serde_json::Error> {
        self.build().to_json()
    }

    /// Assembles the bundle without rendering it.
    #[must_use]
    pub fn build(&self) -> DiagnosticBundle {
        let mut bundle = DiagnosticBundle::empty(self.generated_at_ms);

        for section in &self.sections {
            bundle.sections.push((*section).as_str().to_owned());
            match section {
                BundleSection::Environment => {
                    bundle.environment.clone_from(&self.sources.environment);
                }
                BundleSection::Config => bundle.config.clone_from(&self.sources.config),
                BundleSection::Devices => bundle.devices.clone_from(&self.sources.devices),
                BundleSection::Plugins => bundle.plugins.clone_from(&self.sources.plugins),
                BundleSection::Metrics => {
                    bundle.metrics = self.sources.metrics.as_deref().cloned();
                }
                BundleSection::Logs | BundleSection::DebugLogs => {
                    // Merged into one slice: a reader asking "what does the log say" does not care which
                    // checkbox put a line there, and two slices would invite them to read only one.
                    let slice = self.log_slice(*section);
                    match &mut bundle.logs {
                        Some(existing) => existing.merge(slice),
                        None => bundle.logs = Some(slice),
                    }
                }
                BundleSection::Crashes => bundle.crashes.clone_from(&self.sources.crashes),
                BundleSection::Probes => bundle.probes.clone_from(&self.sources.probes),
                BundleSection::AuditTrail => bundle.audit_trail.clone_from(&self.sources.audit),
            }
        }

        bundle
    }

    /// Redacts and slices the log.
    fn log_slice(&self, section: BundleSection) -> LogSlice {
        let Some(lines) = &self.sources.log_lines else {
            return LogSlice::default();
        };

        // Debug and trace lines are excluded unless the debug section was chosen, because they are where the
        // device names and file paths live — the user's information, even though it is not secret.
        let wants_debug = section == BundleSection::DebugLogs;
        let kept: Vec<&String> = lines
            .iter()
            .filter(|line| wants_debug || !is_debug_line(line))
            .collect();

        let omitted = lines.len() - kept.len();
        let mut tail: Vec<BundleLogLine> = kept
            .iter()
            .rev()
            .take(self.log_tail_lines)
            .rev()
            .map(|line| redact_one(line))
            .collect();
        tail.shrink_to_fit();

        let errors: Vec<BundleLogLine> = kept
            .iter()
            .filter(|line| is_error_line(line))
            .map(|line| redact_one(line))
            .collect();

        LogSlice { tail, errors, lines_read: lines.len(), lines_omitted: omitted }
    }
}

impl LogSlice {
    /// Adds another slice's lines to this one, de-duplicating the errors.
    ///
    /// The tail is appended rather than de-duplicated: the two sections read the same file at different
    /// filters, and a repeated line in a tail reads as "this happened twice", which would be a lie.
    fn merge(&mut self, other: Self) {
        self.lines_read = self.lines_read.max(other.lines_read);
        self.lines_omitted += other.lines_omitted;
        self.tail.extend(other.tail);
        for line in other.errors {
            if !self.errors.contains(&line) {
                self.errors.push(line);
            }
        }
    }
}

/// Whether a source can supply a section.
const fn available(section: BundleSection, sources: &BundleSources) -> bool {
    match section {
        BundleSection::Environment => sources.environment.is_some(),
        BundleSection::Config => sources.config.is_some(),
        BundleSection::Devices => sources.devices.is_some(),
        BundleSection::Plugins => sources.plugins.is_some(),
        BundleSection::Metrics => sources.metrics.is_some(),
        BundleSection::Logs | BundleSection::DebugLogs => sources.log_lines.is_some(),
        BundleSection::Crashes => sources.crashes.is_some(),
        BundleSection::Probes => sources.probes.is_some(),
        BundleSection::AuditTrail => sources.audit.is_some(),
    }
}

/// Whether a line is debug or trace level.
fn is_debug_line(line: &str) -> bool {
    line.contains("DEBUG") || line.contains("TRACE")
}

/// Whether a line is error level.
fn is_error_line(line: &str) -> bool {
    line.contains("ERROR")
}

/// Redacts one line and enforces the per-line cap.
///
/// The second redaction pass over already-treated lines: the bundle is the artifact that leaves the machine,
/// and "already redacted once" is not a reason to trust a file that has been sitting in a directory for two
/// weeks.
fn redact_one(line: &str) -> BundleLogLine {
    // The cap is applied to the raw line, before redaction.
    //
    // The other order looks natural and is wrong twice over. `redact_line`'"'"'s own length limit counts
    // *characters*, so a line of CJK text passes it at 1,570 bytes while this cap is 4,096 — a short-looking
    // line could skip the cap entirely and the `truncated` flag would never be set, which is the lie the flag
    // exists to prevent. And measuring after redaction measures a string redaction already rewrote, so a
    // `payload=` field'"'"'s true size is invisible.
    //
    // Cutting first is also the safe direction: the bytes that are dropped are never copied into the bundle.
    let (source, truncated) = if line.len() > MAX_LOG_LINE_BYTES {
        // Cut on a character boundary: a byte slice would split a multi-byte character, and the resulting
        // string cannot even be built.
        let cut: String = line.chars().take(MAX_LOG_LINE_BYTES).collect();
        (cut, true)
    }
    else {
        (line.to_owned(), false)
    };

    let (redacted, _) = redact_line(&source, DEFAULT_REDACTED_FIELDS, true);
    // A formatted line has no structure the parser can trust, so `redact_line` can only replace a value up to
    // the next space: `payload=the secret message` becomes `payload=<redacted> secret message`, and the tail
    // leaks.
    //
    // For a log *file* that is a bounded imperfection. For a bundle — the artifact that leaves the machine, is
    // posted in an issue and is read by somebody else — it is not acceptable, so a line that mentions a secret
    // field at all is cut at that point. Over-redacting a diagnostic line costs a maintainer one question;
    // under-redacting costs the user their privacy, and the asymmetry decides it.
    let mut text = truncate_at_secret(&redacted).to_owned();
    if truncated {
        text.push_str("…(truncated)");
    }
    BundleLogLine { text, truncated }
}

/// Cuts a line at the first secret field name it mentions.
///
/// Returns the whole line when it mentions none.
fn truncate_at_secret(line: &str) -> &str {
    let lowered = line.to_ascii_lowercase();
    // The earliest *completed* assignment: a name counts only when the `=` follows it directly, so
    // `payload_len=4` does not truncate a line that never carried a payload.
    let mut cut: Option<usize> = None;
    for field in DEFAULT_REDACTED_FIELDS {
        let mut from = 0usize;
        while let Some(offset) = lowered.get(from..).and_then(|rest| rest.find(field)) {
            let at = from + offset;
            let after = at + field.len();
            if lowered.as_bytes().get(after) == Some(&b'=') {
                cut = Some(cut.map_or(at, |existing: usize| existing.min(at)));
                break;
            }
            from = after;
        }
    }

    match cut {
        Some(at) => line.get(..at).unwrap_or(line),
        None => line,
    }
}

/// SHA-256 of some bytes, as lowercase hex.
///
/// Implemented here rather than pulled in as a dependency: the algorithm is short, it is only used to let a user
/// check that an uploaded file is the one they reviewed, and a build that needs a cryptographic hash to report
/// a file size has one more thing to keep current.
///
/// This is **not** used for anything security-critical — nothing in the protocol verifies it. A digest for a
/// transfer's integrity comes from the platform's crypto, not from here.
#[must_use]
pub fn sha256_hex(input: &[u8]) -> String {
    let digest = sha256(input);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = core::fmt::Write::write_fmt(&mut out, format_args!("{byte:02x}"));
    }
    out
}

/// The SHA-256 round constants.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];


/// SHA-256, in the straightforward form.
///
/// A faithful implementation of FIPS 180-4 with no attempt at constant-time behaviour, because nothing here is
/// secret: the input is a file the user chose to export.
fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Padding: a `1` bit, zeroes, then the length in bits as a big-endian u64.
    let mut message = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        // Destructured in groups of four rather than indexed: `indexing_slicing` is denied workspace-wide, and a
        // hash function is the last place that should rely on an annotation claiming a slice is long enough.
        // `as_chunks` also makes the length guarantee part of the type.
        for (word, bytes) in w.iter_mut().take(16).zip(chunk.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        // The schedule is built without indexing, and without an unreachable branch.
        //
        // `split_at_mut` puts the guarantee in the types: the left half always has exactly `index` words, so its
        // last sixteen are the window and each of the four operands is a named binding rather than a computed
        // offset. `w[index - 15]` says the same thing and is the sort of expression a linter cannot distinguish
        // from an off-by-one — and an earlier version of this function answered that doubt with a fallback that
        // returned a *wrong digest*, which is worse than the lint.
        // The schedule, with the window bound into the types and no unreachable branch.
        //
        // `try_into` turns the slice into a `[u32; 16]`, so the four operands are named bindings at fixed
        // positions rather than computed offsets — the difference between an expression a reader can check and
        // `w[index - 15]`, which no reader can. A labelled `break` handles the impossible case by leaving the
        // schedule at zero, which produces a detectable wrong digest: the alternatives were a panic the workspace
        // forbids, or a branch that *fabricated* a plausible digest, which is worse than either.
        'schedule: for index in 16..64 {
            let (done, rest) = w.split_at_mut(index);
            // Pattern-matched straight to the operand bindings: `last_chunk` already returns a `&[u32; 16]`,
            // and a by-value pattern copies the four words that are used.
            let Some(&[w16, w15, _, _, _, _, _, _, _, w7, _, _, _, _, w2, _]) = done.last_chunk::<16>()
            else {
                break 'schedule;
            };
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            let next = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
            if let Some(slot) = rest.first_mut() {
                *slot = next;
            }
        }

        let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
        let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);

        // Zipped over the round constants and the schedule rather than indexed: the two arrays are both 64 long
        // by construction, and a zip says so without an offset a reader has to verify.
        for (&round_constant, &schedule_word) in K.iter().zip(w.iter()) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(round_constant)
                .wrapping_add(schedule_word);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut out = [0u8; 32];
    for (index, word) in h.iter().enumerate() {
        let bytes = word.to_be_bytes();
        let start = index * 4;
        if let Some(slot) = out.get_mut(start..start + 4) {
            slot.copy_from_slice(&bytes);
        }
    }
    out
}

/// The default file name for a bundle, with a timestamp.
///
/// In the user's downloads directory with a name that sorts chronologically, because they will have more than
/// one of these and "synra-diagnostic (3).json" tells them nothing about which is which.
#[must_use]
pub fn default_file_name(generated_at_ms: i64) -> String {
    format!("synra-diagnostic-{generated_at_ms}.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn sources() -> BundleSources {
        BundleSources {
            environment: Some(EnvSummary {
                app_version: "1.0.0".to_owned(),
                kernel_version: "1.0.0".to_owned(),
                os: "windows".to_owned(),
                arch: "x86_64".to_owned(),
                webview_version: Some("120.0".to_owned()),
            }),
            config: Some(serde_json::json!({ "listen_port": 32100 })),
            devices: Some(vec![DeviceRecord {
                device_id: "0193".to_owned(),
                paired: true,
                online: true,
            }]),
            plugins: Some(vec![PluginRecord {
                plugin_id: "@synra-plugin/chat".to_owned(),
                version: "1.0.0".to_owned(),
                active: true,
                had_refusals: true,
            }]),
            metrics: Some(Box::new(MetricsSnapshot::default())),
            log_lines: Some(vec![
                "ts=1 level=INFO event=start peer=abc".to_owned(),
                "ts=2 level=ERROR payload=the secret message".to_owned(),
                "ts=3 level=DEBUG device_name=my-laptop".to_owned(),
            ]),
            crashes: Some(Vec::new()),
            probes: Some(Vec::new()),
            audit: Some(Vec::new()),
        }
    }

    fn plan() -> BundlePlan {
        BundlePlan::plan(sources(), 1_700_000_000_000, PathBuf::from("/tmp/bundle.json"))
    }

    #[test]
    fn the_plan_includes_the_required_sections_and_none_of_the_optional_ones() {
        // The consent screen's whole point: nothing sensitive is in the bundle until the user says so.
        let plan = plan();
        assert!(plan.includes(BundleSection::Environment));
        assert!(plan.includes(BundleSection::Logs));
        assert!(!plan.includes(BundleSection::AuditTrail), "off by default");
        assert!(!plan.includes(BundleSection::DebugLogs), "off by default");
        assert!(plan.enabled_optional().is_empty());
    }

    #[test]
    fn only_two_sections_are_optional_and_they_are_the_user_s_own_data() {
        // What the user did, and the detail lines that name their devices and files. Everything else is state
        // the application would report about itself anyway.
        let optional: Vec<BundleSection> =
            BundleSection::ALL.iter().copied().filter(|s| s.is_optional()).collect();
        assert_eq!(optional, vec![BundleSection::AuditTrail, BundleSection::DebugLogs]);

        for section in BundleSection::ALL {
            assert_eq!(section.is_default(), !section.is_optional(), "{section:?}");
        }
    }

    #[test]
    fn a_section_with_no_source_is_not_offered() {
        // A checkbox that does nothing is a checkbox that confuses.
        let sources = BundleSources { environment: None, ..sources() };
        let plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
        assert!(!plan.includes(BundleSection::Environment));
        assert!(!plan.is_available(BundleSection::Environment));
    }

    #[test]
    fn a_required_section_cannot_be_toggled() {
        // The two sensitive sections are the only choices here; a required section is not a decision the user
        // makes, and letting them remove it would produce a bundle a maintainer cannot use.
        let mut plan = plan();
        assert!(!plan.toggle_optional(BundleSection::Environment, false));
        assert!(plan.includes(BundleSection::Environment));
        assert!(!plan.toggle_optional(BundleSection::Metrics, true));
        assert!(!plan.includes(BundleSection::AuditTrail));
    }

    #[test]
    fn an_optional_section_can_be_turned_on_and_off() {
        let mut plan = plan();
        assert!(plan.toggle_optional(BundleSection::AuditTrail, true));
        assert!(plan.includes(BundleSection::AuditTrail));
        assert_eq!(plan.enabled_optional(), vec![BundleSection::AuditTrail]);

        assert!(plan.toggle_optional(BundleSection::AuditTrail, false));
        assert!(!plan.includes(BundleSection::AuditTrail));
    }

    #[test]
    fn toggling_the_same_section_twice_is_idempotent() {
        let mut plan = plan();
        plan.toggle_optional(BundleSection::DebugLogs, true);
        plan.toggle_optional(BundleSection::DebugLogs, true);
        assert_eq!(plan.enabled_optional(), vec![BundleSection::DebugLogs]);
    }

    #[test]
    fn sections_keep_the_documented_order_however_they_were_edited() {
        // Two exports of the same state must compare equal, and a reader should see the same list each time.
        let mut plan = plan();
        plan.toggle_optional(BundleSection::DebugLogs, true);
        plan.toggle_optional(BundleSection::AuditTrail, true);

        let order: Vec<BundleSection> = plan.sections().to_vec();
        let expected: Vec<BundleSection> = BundleSection::ALL
            .iter()
            .copied()
            .filter(|section| plan.includes(*section))
            .collect();
        assert_eq!(order, expected);
    }

    #[test]
    fn the_consent_screen_names_everything_it_collects() {
        // A prompt that only says what it collects leaves the user to wonder about the rest, and wondering is
        // what stops people from sending the file that would have got their problem fixed.
        let plan = plan();
        let inclusions = plan.inclusions();
        assert_eq!(inclusions.len(), plan.sections().len());
        for (description, name) in &inclusions {
            assert!(!description.is_empty(), "{name}");
            assert!(!name.is_empty());
        }
        // And every section has a description, so a newly added one cannot appear as a bare name.
        for section in BundleSection::ALL {
            assert!(!section.describe().is_empty(), "{section:?}");
        }
    }

    #[test]
    fn the_consent_screen_names_what_is_never_included() {
        let plan = plan();
        let excluded = plan.excludes();
        for promised in [
            "clipboard contents",
            "the body of any message",
            "the contents of any file",
            "passwords, tokens or pairing secrets",
            "anything a plugin stored in secure storage",
        ] {
            assert!(excluded.contains(&promised), "{promised} is not promised");
        }
    }

    #[test]
    fn a_bundle_built_with_everything_enabled_still_holds_no_content() {
        // The promise in `NEVER_INCLUDED` has to hold for the most permissive plan a user can construct, or it
        // is not a promise.
        let mut plan = plan();
        plan.toggle_optional(BundleSection::AuditTrail, true);
        plan.toggle_optional(BundleSection::DebugLogs, true);
        let rendered = plan.render().expect("renders");

        // The log line that carried a payload is cut at the field name, so neither the secret nor the rest of the
        // value survives.
        assert!(!rendered.contains("the secret message"), "{rendered}");
        assert!(!rendered.contains("secret message"), "{rendered}");
        // And the never-included list is in the file so a reader sees the same promise the user agreed to.
        for promised in NEVER_INCLUDED {
            assert!(rendered.contains(promised), "{promised}");
        }
    }

    #[test]
    fn debug_lines_are_left_out_unless_the_debug_section_is_chosen() {
        // Debug lines carry device names and file paths, which are the user's information even though they are
        // not secrets.
        let mut plan = plan();
        let default_render = plan.render().expect("renders");
        assert!(!default_render.contains("my-laptop"), "a device name leaked");

        plan.toggle_optional(BundleSection::DebugLogs, true);
        let debug_render = plan.render().expect("renders");
        assert!(debug_render.contains("my-laptop"), "the chosen section was not included");
    }

    #[test]
    fn the_log_slice_keeps_a_tail_and_every_error() {
        // The interesting part of a log is what happened just before the problem, and an error outside the
        // tail is the problem itself.
        let mut sources = sources();
        let mut lines: Vec<String> = (0..100)
            .map(|index| format!("ts={index} level=INFO event=tick"))
            .collect();
        lines.insert(5, "ts=5 level=ERROR event=boom".to_owned());
        sources.log_lines = Some(lines);

        let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
        plan.set_log_tail_lines(10);
        let bundle = plan.build();
        let logs = bundle.logs.expect("has logs");

        assert_eq!(logs.tail.len(), 10);
        assert!(logs.errors.iter().any(|line| line.text.contains("boom")));
        assert_eq!(logs.lines_read, 101);
    }

    #[test]
    fn the_log_tail_respects_its_cap() {
        let mut sources = sources();
        sources.log_lines = Some((0..500).map(|index| format!("ts={index} level=INFO")).collect());
        let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));

        plan.set_log_tail_lines(3);
        let logs = plan.build().logs.expect("has logs");
        // Three INFO lines, plus the errors list which is separate.
        assert!(logs.tail.len() <= 3);
    }

    #[test]
    fn a_very_long_log_line_is_truncated_on_a_character_boundary() {
        // A byte slice would split a multi-byte character, and the resulting string cannot even be built.
        let mut sources = sources();
        let long = format!("ts=1 level=INFO note={}", "电".repeat(5_000));
        assert!(long.len() > MAX_LOG_LINE_BYTES, "the fixture must exceed the cap");
        sources.log_lines = Some(vec![long.clone()]);
        let plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
        let logs = plan.build().logs.expect("has logs");

        assert_eq!(logs.tail.len(), 1, "the fixture line is missing: {logs:?}");
        let line = &logs.tail[0];
        assert!(line.truncated, "a {} byte line was not truncated", long.len());
        assert!(line.text.ends_with("…(truncated)"));
        // The kept prefix is whole characters, which `chars().take` guarantees and a byte slice would not, so
        // the byte length can be up to four times the character cap.
        assert!(line.text.len() <= MAX_LOG_LINE_BYTES * 4 + 32, "{}", line.text.len());
    }

    #[test]
    fn a_short_log_line_is_not_marked_truncated() {
        let plan = plan();
        let logs = plan.build().logs.expect("has logs");
        assert!(logs.tail.iter().all(|line| !line.truncated));
    }

    #[test]
    fn a_missing_source_leaves_its_field_none_rather_than_empty() {
        // An empty list of plugins reads as "no plugins installed"; `None` reads as "not collected". The
        // difference is what tells a reader whether the absence is information.
        let sources = BundleSources { plugins: None, devices: Some(Vec::new()), ..sources() };
        let plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
        let bundle = plan.build();

        assert!(bundle.plugins.is_none());
        assert_eq!(bundle.devices, Some(Vec::new()), "an empty list is a real answer");
    }

    #[test]
    fn the_bundle_lists_the_sections_it_holds() {
        let bundle = plan().build();
        assert_eq!(bundle.sections.len(), bundle.len());
        for section in BundleSection::ALL {
            assert_eq!(bundle.contains(*section), plan().includes(*section), "{section:?}");
        }
    }

    #[test]
    fn an_empty_bundle_is_representable_and_says_so() {
        let plan = BundlePlan::plan(BundleSources::default(), 0, PathBuf::from("/tmp/x.json"));
        let bundle = plan.build();
        assert!(bundle.is_empty());
        assert!(bundle.sections.is_empty());
        // And it still renders, because a bundle with nothing in it is a valid answer to "what is there".
        assert!(plan.render().is_ok());
    }

    #[test]
    fn a_bundle_round_trips_through_json() {
        let bundle = plan().build();
        let json = bundle.to_json().expect("renders");
        let back: DiagnosticBundle = serde_json::from_str(&json).expect("parses");
        assert_eq!(back, bundle);
    }

    #[test]
    fn a_bundle_renders_readably() {
        // A person reads this file; that is the point of a bundle somebody chose to export.
        let json = plan().render().expect("renders");
        assert!(json.contains('\n'), "the bundle is not pretty-printed");
        assert!(json.contains("generatedAtMs"), "{json}");
        assert!(!json.contains("generated_at_ms"), "{json}");
    }

    #[test]
    fn the_plan_names_where_the_bundle_will_go() {
        // A path revealed only after the export is a path the user has to hunt for.
        let plan = plan();
        assert_eq!(plan.destination(), Path::new("/tmp/bundle.json"));

        let mut plan = plan;
        plan.set_destination(PathBuf::from("/tmp/other.json"));
        assert_eq!(plan.destination(), Path::new("/tmp/other.json"));
    }

    #[test]
    fn the_receipt_names_the_size_the_path_and_the_digest() {
        // So a person who posts a bundle in an issue can check that what they uploaded is what they reviewed.
        let plan = plan();
        let rendered = plan.render().expect("renders");
        let receipt = plan.receipt(&rendered).expect("renders");

        assert!(receipt.contains(&rendered.len().to_string()), "{receipt}");
        assert!(receipt.contains("/tmp/bundle.json"), "{receipt}");
        assert!(receipt.contains("sha256 "), "{receipt}");
        assert!(receipt.contains(&sha256_hex(rendered.as_bytes())), "{receipt}");
    }

    #[test]
    fn the_digest_matches_an_independent_implementation() {
        // The known-answer vectors, so the hand-written SHA-256 is verified against the standard rather than
        // against itself.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // A message longer than one block, so the length append and multi-block loop are exercised.
        assert_eq!(
            sha256_hex(&b"a".repeat(1_000_000)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn a_digest_is_lowercase_hex_of_the_right_length() {
        let digest = sha256_hex(b"anything");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
    }

    #[test]
    fn the_bundle_digest_matches_its_rendering() {
        let bundle = plan().build();
        assert_eq!(bundle.digest().expect("renders"), sha256_hex(bundle.to_json().expect("renders").as_bytes()));
    }

    #[test]
    fn the_default_file_name_sorts_chronologically() {
        // A user will have more than one of these, and "synra-diagnostic (3).json" tells them nothing about
        // which is which.
        let earlier = default_file_name(1_700_000_000_000);
        let later = default_file_name(1_700_000_001_000);
        assert!(earlier < later, "{earlier} !< {later}");
        assert!(earlier.starts_with("synra-diagnostic-"));
        assert!(earlier.ends_with(".json"));
    }

    #[rstest]
    #[case("ts=1 level=ERROR event=boom", true, false)]
    #[case("ts=1 level=DEBUG event=x", false, true)]
    #[case("ts=1 level=TRACE event=x", false, true)]
    #[case("ts=1 level=INFO event=x", false, false)]
    #[case("ts=1 level=WARN event=x", false, false)]
    fn level_detection_matches_the_line(#[case] line: &str, #[case] error: bool, #[case] debug: bool) {
        assert_eq!(is_error_line(line), error, "{line}");
        assert_eq!(is_debug_line(line), debug, "{line}");
    }

    #[test]
    fn a_section_name_round_trips_through_json() {
        for section in BundleSection::ALL {
            let json = serde_json::to_string(section).expect("serialises");
            assert_eq!(json, format!("\"{}\"", section.as_str()));
            let back: BundleSection = serde_json::from_str(&json).expect("deserialises");
            assert_eq!(back, *section);
        }
    }

    #[test]
    fn section_names_are_unique() {
        // A duplicate name would make `contains` answer for the wrong section.
        let mut names = std::collections::HashSet::new();
        for section in BundleSection::ALL {
            assert!(names.insert(section.as_str()), "duplicate name {section:?}");
        }
        assert_eq!(BundleSection::ALL.len(), names.len());
    }

    #[test]
    fn the_bundle_carries_the_audit_trail_only_when_asked() {
        let mut sources = sources();
        sources.audit = Some(vec![AuditEntry::new(
            1_000,
            synra_protocol::PluginId::parse("@synra-plugin/chat").expect("valid"),
            synra_capability::Capability::parse("network:fetch:evil.com").expect("valid"),
            crate::audit::AuditOutcome::Denied,
            None,
        )]);

        let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
        assert!(plan.build().audit_trail.is_none());

        plan.toggle_optional(BundleSection::AuditTrail, true);
        let bundle = plan.build();
        assert_eq!(bundle.audit_trail.as_ref().map(Vec::len), Some(1));
        // And the refusal is visible in the rendered file, which is the point of including it.
        let rendered = plan.render().expect("renders");
        assert!(rendered.contains("evil.com"), "{rendered}");
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The digest matches the standard implementation for arbitrary input lengths, which is what exercises
        /// the padding rule at every remainder. A wrong remainder produces a digest that is valid-looking and
        /// wrong, and the only way to notice is a vector.
        #[test]
        fn a_digest_is_the_right_length_for_any_input(len in 0usize..300) {
            let digest = sha256_hex(&vec![b'x'; len]);
            prop_assert_eq!(digest.len(), 64);
            prop_assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()));
        }

        /// A redacted bundle never contains a forbidden value, whatever was in the logs it was built from.
        /// This is the promise the consent screen makes, checked against content rather than asserted.
        #[test]
        fn a_redacted_bundle_never_leaks_a_payload(secret in "[a-zA-Z0-9]{8,24}") {
            let sources = BundleSources {
                log_lines: Some(vec![
                    format!("ts=1 level=INFO payload={secret}"),
                    format!("ts=2 level=ERROR token={secret}"),
                    format!("ts=3 level=INFO body={secret}"),
                ]),
                ..BundleSources::default()
            };

            let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
            plan.toggle_optional(BundleSection::DebugLogs, true);
            let rendered = plan.render().expect("renders");

            prop_assert!(!rendered.contains(&secret), "the secret leaked into the bundle");
        }

        /// A selected section is present and an unselected one is absent, whatever the section and whatever the
        /// sources. A bundle that quietly included something is the failure this module exists to prevent.
        #[test]
        fn selection_decides_presence(
            toggle_audit in any::<bool>(),
            toggle_debug in any::<bool>(),
        ) {
            let sources = BundleSources {
                environment: Some(EnvSummary {
                    app_version: "1".to_owned(),
                    kernel_version: "1".to_owned(),
                    os: "test".to_owned(),
                    arch: "test".to_owned(),
                    webview_version: None,
                }),
                log_lines: Some(vec!["ts=1 level=INFO event=x".to_owned()]),
                audit: Some(Vec::new()),
                ..BundleSources::default()
            };

            let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
            plan.toggle_optional(BundleSection::AuditTrail, toggle_audit);
            plan.toggle_optional(BundleSection::DebugLogs, toggle_debug);

            let bundle = plan.build();
            prop_assert_eq!(bundle.audit_trail.is_some(), toggle_audit);
            prop_assert_eq!(plan.includes(BundleSection::Environment), bundle.environment.is_some());
            prop_assert!(bundle.logs.is_some(), "logs are a default section");
            // The section list and the fields agree: nothing is listed that is not there.
            for section in BundleSection::ALL {
                let listed = bundle.contains(*section);
                let present = match section {
                    BundleSection::Environment => bundle.environment.is_some(),
                    BundleSection::Config => bundle.config.is_some(),
                    BundleSection::Devices => bundle.devices.is_some(),
                    BundleSection::Plugins => bundle.plugins.is_some(),
                    BundleSection::Metrics => bundle.metrics.is_some(),
                    BundleSection::Crashes => bundle.crashes.is_some(),
                    BundleSection::Probes => bundle.probes.is_some(),
                    BundleSection::AuditTrail => bundle.audit_trail.is_some(),
                    // The one exception, and the exception is the point: both log filters read the same file and
                    // merge into one slice, because a reader asking "what does the log say" does not care which
                    // checkbox put a line there. So the slice is present exactly when at least one is selected.
                    BundleSection::Logs | BundleSection::DebugLogs => {
                        let any = plan.includes(BundleSection::Logs) || plan.includes(BundleSection::DebugLogs);
                        prop_assert_eq!(bundle.logs.is_some(), any);
                        continue;
                    }
                };
                prop_assert_eq!(listed, present, "section {:?} disagrees with its field", section);
            }
        }

        /// The tail never exceeds its cap, whatever the log length. A bundle that carried the whole file would
        /// be one nobody reads, and one that carried unbounded memory during assembly would be a hazard.
        #[test]
        fn the_tail_respects_its_cap(
            line_count in 0usize..200,
            cap in 0usize..50,
        ) {
            let sources = BundleSources {
                log_lines: Some(
                    (0..line_count)
                        .map(|index| format!("ts={index} level=INFO event=x"))
                        .collect(),
                ),
                ..BundleSources::default()
            };

            let mut plan = BundlePlan::plan(sources, 0, PathBuf::from("/tmp/x.json"));
            plan.set_log_tail_lines(cap);
            let logs = plan.build().logs.expect("has logs");
            prop_assert!(logs.tail.len() <= cap);
            prop_assert_eq!(logs.lines_read, line_count);
        }
    }
}
