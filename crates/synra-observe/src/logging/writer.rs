//! The redacting writer, the field list, and the line redactor.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use parking_lot::Mutex;

use crate::redact::{REDACTED, Redactor};
use std::sync::atomic::AtomicBool;
use super::stats::LogStats;

/// A writer that applies the redaction policy to each line before it reaches its destination.
///
/// See the module docs for why the policy is applied here rather than in a layer.
pub struct RedactingWriter<W> {
    pub(super) inner: Mutex<W>,
    stats: Arc<LogStats>,
    enabled: AtomicBool,
    /// Field names whose `name=value` shapes are always replaced, lowercased.
    fields: Vec<&'static str>,
    /// Whether to also strip a URL's query from anything that looks like one.
    strip_urls: bool,
}

impl<W: Write> RedactingWriter<W> {
    /// Wraps a writer with the default policy.
    pub fn new(inner: W) -> Self {
        Self::with_stats(inner, Arc::new(LogStats::default()))
    }

    /// Wraps a writer with counters a caller already holds.
    ///
    /// # Why the caller would hold them
    ///
    /// Because the destination may be a queue in front of the file, and the queue is the thing that knows when a line was
    /// dropped. One set of counters has to cover both halves, or the status report would say a line was written when it
    /// was discarded on the way.
    pub fn with_stats(inner: W, stats: Arc<LogStats>) -> Self {
        Self {
            inner: Mutex::new(inner),
            stats,
            enabled: AtomicBool::new(true),
            fields: DEFAULT_REDACTED_FIELDS.to_vec(),
            strip_urls: true,
        }
    }

    /// The counters for what this writer has seen.
    #[must_use]
    pub fn stats(&self) -> Arc<LogStats> {
        Arc::clone(&self.stats)
    }

    /// Turns redaction off, for a test that needs to see the raw text.
    ///
    /// Not exposed as a configuration option: a setting that turns off secret redaction is a setting
    /// somebody will turn off.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Replaces the list of redacted field names.
    pub fn set_fields(&mut self, fields: Vec<&'static str>) {
        self.fields = fields;
    }

    /// Redacts one line.
    ///
    /// Exposed so the policy can be tested and reused — the diagnostic bundle applies the same treatment
    /// to log excerpts it collects.
    pub fn redact_line(&self, line: &str) -> (String, usize) {
        if !self.enabled.load(Ordering::Relaxed) {
            return (line.to_owned(), 0);
        }
        redact_line(line, &self.fields, self.strip_urls)
    }
}

impl<W: Write> RedactingWriter<W> {
    /// Redacts a received buffer, without touching the destination.
    ///
    /// `None` means the bytes were not UTF-8 and must be passed through unexamined.
    fn prepare(&self, buf: &[u8]) -> Option<String> {
        let text = core::str::from_utf8(buf).ok()?;
        let (redacted, count) = self.redact_line(text);
        if count > 0 {
            self.stats.redactions.fetch_add(count as u64, Ordering::Relaxed);
        }
        Some(redacted)
    }

    /// Writes a redacted line and accounts for it.
    ///
    /// `consumed` is the length of the *received* buffer, which is what the [`Write`] contract asks to be
    /// returned. Reporting the redacted length instead would tell the caller that fewer bytes were taken
    /// than were, and it would then re-send the tail.
    fn write_redacted(&mut self, redacted: &str, consumed: usize) -> io::Result<usize> {
        // The write is bound to a local before the `?`. Clippy's `significant_drop_in_scrutinee` treats
        // the guard inside `guard.write_all(..)?` as a temporary in a scrutinee, dropped at the end of the
        // `?` rather than after the branch — and it is right: the lock would be released before the
        // statistics are updated, so a concurrent writer could interleave.
        let written = {
            let mut guard = self.inner.lock();
            guard.write_all(redacted.as_bytes())
        };
        written?;

        self.stats.bytes.fetch_add(redacted.len() as u64, Ordering::Relaxed);
        if redacted.ends_with('\n') {
            self.stats.lines.fetch_add(1, Ordering::Relaxed);
        }
        Ok(consumed)
    }

    /// Writes bytes that were not UTF-8, unexamined.
    fn write_raw(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = {
            let mut guard = self.inner.lock();
            guard.write(buf)
        };
        let written = written?;
        self.stats.bytes.fetch_add(written as u64, Ordering::Relaxed);
        Ok(written)
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // A `tracing` writer receives one already-formatted event per call, but the contract is a byte
        // stream, so the redaction has to tolerate being handed a fragment.
        let redacted = self.prepare(buf);
        // Both arms are plain calls, so the destination lock is never a temporary inside a scrutinee.
        match redacted {
            Some(redacted) => self.write_redacted(&redacted, buf.len()),
            // Not UTF-8: passed through rather than failing the write, because a log line with a
            // replacement character is better than a dropped one and an error here would take down
            // whatever was being logged.
            None => self.write_raw(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.lock().flush()
    }
}

impl<W> core::fmt::Debug for RedactingWriter<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RedactingWriter")
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .field("fields", &self.fields.len())
            .finish_non_exhaustive()
    }
}

/// Field names redacted in already-formatted text.
///
/// A subset of [`crate::redact::Redactor`]'s list, because a formatted line only exposes the names a
/// caller chose to write. The rest are caught before formatting, where the name is known.
pub const DEFAULT_REDACTED_FIELDS: &[&str] = &[
    "payload",
    "body",
    "content",
    "clipboard",
    "text",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "credential",
    "authorization",
    "cookie",
    "private_key",
    "session_key",
    "bearer",
    "jwt",
    "secure_value",
];

/// Replaces the values of known fields in a formatted line, and strips URL queries.
///
/// Returns the line and how many substitutions were made.
///
/// # What it can and cannot see
///
/// A formatted line looks like `event=transport.send peer=abc url=https://x/y?t=1`. This finds each
/// `name=` and, when the name is on the list, replaces everything up to the next space. A value that
/// contains a space — a `Debug`-rendered struct, a quoted string — is only partly replaced, which is why
/// the primary defence is redacting typed fields before they are formatted. This function's job is to be
/// the net under that.
#[must_use]
pub fn redact_line(line: &str, fields: &[&str], strip_urls: bool) -> (String, usize) {
    let mut out = String::with_capacity(line.len());
    let mut count = 0usize;
    let bytes = line.as_bytes();
    let mut index = 0usize;

    while index < bytes.len() {
        // Find the next `name=` at a word boundary.
        let Some(relative) = line.get(index..).and_then(|rest| rest.find('=')) else {
            out.push_str(line.get(index..).unwrap_or_default());
            break;
        };
        let eq = index + relative;

        // The name runs back to the previous space.
        let name_start = line
            .get(..eq)
            .and_then(|head| head.rfind(' '))
            .map_or(0, |space| space + 1);
        let name = line.get(name_start..eq).unwrap_or_default();

        // The value runs to the next space.
        let value_start = eq + 1;
        let value_end = line
            .get(value_start..)
            .and_then(|rest| rest.find(' '))
            .map_or(bytes.len(), |offset| value_start + offset);
        let value = line.get(value_start..value_end).unwrap_or_default();

        let lowered = name.to_ascii_lowercase();
        let is_secret = fields.iter().any(|field| lowered.contains(field));

        out.push_str(line.get(index..eq + 1).unwrap_or_default());
        if is_secret {
            out.push_str(REDACTED);
            count += 1;
        }
        else if strip_urls {
            let redactor = Redactor::new();
            let redacted = redactor.value("url", value);
            if redacted.decision.withheld_something() {
                if !matches!(redacted.decision, crate::redact::Redaction::Truncated { .. }) {
                    count += 1;
                }
                out.push_str(&redacted.text);
            }
            else {
                out.push_str(value);
            }
        }
        else {
            out.push_str(value);
        }

        index = value_end;
    }

    (out, count)
}
