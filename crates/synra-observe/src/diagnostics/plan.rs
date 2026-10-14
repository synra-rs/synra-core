//! Assembling a bundle, and the two redaction passes over a log line.
//!
//! # Why redaction happens twice
//!
//! Because the bundle is the artifact that leaves the machine. A line that was already redacted on its way into the log
//! is not thereby trustworthy: it may have sat in a directory for two weeks, and a second pass costs nothing next to
//! shipping a secret to a maintainer.

use std::path::{Path, PathBuf};

use crate::logging::{DEFAULT_REDACTED_FIELDS, redact_line};
use crate::metrics::MetricsSnapshot;

use super::digest::sha256_hex;
use crate::audit::AuditEntry;
use crate::doctor::ProbeResult;

use super::records::{
    BundleLogLine, DeviceRecord, DiagnosticBundle, EnvSummary, LogSlice, PluginRecord,
};
use super::sections::{BundleSection, DEFAULT_LOG_TAIL_LINES, MAX_LOG_LINE_BYTES, NEVER_INCLUDED};

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
pub fn is_debug_line(line: &str) -> bool {
    line.contains("DEBUG") || line.contains("TRACE")
}

/// Whether a line is error level.
pub fn is_error_line(line: &str) -> bool {
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
