//! Assembling a bundle, and the two redaction passes over a log line.
//!
//! # Why redaction happens twice
//!
//! Because the bundle is the artifact that leaves the machine. A line that was already redacted on its way into the log
//! is not thereby trustworthy: it may have sat in a directory for two weeks, and a second pass costs nothing next to
//! shipping a secret to a maintainer.

use std::path::{Path, PathBuf};

use crate::metrics::MetricsSnapshot;

use super::digest::sha256_hex;
use crate::audit::AuditEntry;
use crate::doctor::ProbeResult;

use super::records::{DeviceRecord, DiagnosticBundle, EnvSummary, LogSlice, PluginRecord};
use super::sections::{BundleSection, DEFAULT_LOG_TAIL_LINES, NEVER_INCLUDED};

mod log;

use log::slice as log_slice;

pub use log::{is_debug_line, is_error_line};

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
                BundleSection::ALL
                    .iter()
                    .position(|known| known == section)
                    .unwrap_or(usize::MAX)
            });
            true
        } else {
            self.sections.retain(|existing| *existing != section);
            true
        }
    }

    /// The optional sections the user has switched on.
    #[must_use]
    pub fn enabled_optional(&self) -> Vec<BundleSection> {
        self.sections
            .iter()
            .copied()
            .filter(|s| s.is_optional())
            .collect()
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

        log_slice(lines, section, self.log_tail_lines)
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


