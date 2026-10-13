//! Logging: levels, a redacting writer, and the runtime verbosity switch.
//!
//! # Levels, and what each one is for
//!
//! The split is by *who reads it*, because that is what decides whether it belongs on disk:
//!
//! | Level | Audience | On disk |
//! |---|---|---|
//! | `ERROR` | the user, in a bug report | 14 days |
//! | `WARN` | a maintainer, after something recovered | 14 days |
//! | `INFO` | anyone reconstructing what the app did | 14 days |
//! | `DEBUG` | a developer, or a diagnostic session | only while enabled |
//! | `TRACE` | a developer chasing a frame | only while enabled |
//!
//! `INFO` is the default. A user can raise it to `DEBUG` for thirty minutes from the settings screen,
//! which is the single most useful support affordance the application has — and it expires on its own, so
//! nobody has to remember to turn it back down.
//!
//! # Redaction happens in the writer, not in the layer
//!
//! A `tracing` layer sees fields as typed values and can replace them, but it then has to re-implement
//! formatting to emit anything. A writer sees only the bytes that are about to reach the file, which is
//! the last moment before they become permanent. Putting [`RedactingWriter`] there means **nothing**
//! bypasses it: not a layer added later, not a third-party crate logging through the same subscriber.
//!
//! The cost is that redaction works on already-formatted text, so it matches on `field=value` shapes
//! rather than on field names. That is why the writer is the second line and not the first:
//! [`crate::redact::Redactor`] is applied to known fields as they are logged, and the writer catches
//! whatever a caller wrote by hand.

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::redact::{REDACTED, Redactor};

/// How verbose logging is.
///
/// A copy of the levels the log format supports, kept separate from the `tracing` types so that the
/// interface layer can persist and restore a level without depending on `tracing`'s API shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[non_exhaustive]
pub enum LogLevel {
    /// Everything, including per-frame detail.
    Trace,
    /// Flow detail. Only while a diagnostic session is open.
    Debug,
    /// The default: what the application did.
    #[default]
    Info,
    /// Something recovered from.
    Warn,
    /// Something the user noticed.
    Error,
    /// Logging off.
    Off,
}

impl LogLevel {
    /// The name used in configuration.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Off => "off",
        }
    }

    /// Parses a level name, case-insensitively.
    ///
    /// # Errors
    ///
    /// The unrecognised name, so a typo in a config file can be reported with the string that caused it.
    pub fn parse(name: &str) -> Result<Self, UnknownLevel> {
        let lowered = name.trim().to_ascii_lowercase();
        match lowered.as_str() {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" | "warning" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            "off" | "none" => Ok(Self::Off),
            _ => Err(UnknownLevel { name: name.to_owned() }),
        }
    }

    /// Whether this level is written to disk by default.
    ///
    /// `DEBUG` and `TRACE` are not, because they are only ever wanted for a bounded window: keeping them
    /// would fill a disk with frame-level detail nobody reads, and keeping them *forever* is how a log
    /// directory reaches a gigabyte.
    #[must_use]
    pub const fn is_persisted(self) -> bool {
        matches!(self, Self::Info | Self::Warn | Self::Error)
    }

    /// Whether a message at `message` level is recorded when the threshold is `self`.
    #[must_use]
    pub const fn admits(self, message: Self) -> bool {
        if matches!(self, Self::Off) {
            return false;
        }
        // Ordering is declaration order: Trace < Debug < Info < Warn < Error, so a lower threshold
        // admits more.
        (message as u8) >= (self as u8)
    }
}

impl core::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A level name that is not one of the known ones.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{name:?} is not a log level")]
pub struct UnknownLevel {
    /// The name that was offered.
    pub name: String,
}

/// How long a temporary verbosity increase lasts.
///
/// Thirty minutes, because that is long enough to reproduce a problem and short enough that a forgotten
/// switch does not leave a device writing debug logs for a month.
pub const VERBOSE_WINDOW: core::time::Duration = core::time::Duration::from_secs(30 * 60);

/// The runtime verbosity, with an expiring override.
///
/// Two levels: the configured one, and a temporary one that a user turns on from the diagnostics screen.
/// The override needs no timer to expire — [`Self::effective`] checks the deadline, so a device that was
/// suspended through the whole window comes back with normal logging rather than a stale override.
#[derive(Debug)]
pub struct Verbosity {
    /// What the configuration says.
    configured: LogLevel,
    /// The temporary level, if one is active.
    override_level: Mutex<Option<(LogLevel, std::time::Instant)>>,
    /// Injected clock reading, so a test can move time without sleeping.
    now: Clock,
}

/// A clock reading, wrapped so it can be `Debug`.
///
/// A closure has no useful representation, and the alternative — hand-writing `Debug` for [`Verbosity`]
/// — means every field added later has to be added there too, which is how a field ends up missing from
/// the output.
#[derive(Clone)]
struct Clock(Arc<dyn Fn() -> std::time::Instant + Send + Sync>);

impl Clock {
    /// Reads the clock.
    fn now(&self) -> std::time::Instant {
        (self.0)()
    }
}

impl core::fmt::Debug for Clock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<clock>")
    }
}

impl Verbosity {
    /// Builds a verbosity with the given configured level.
    #[must_use]
    pub fn new(configured: LogLevel) -> Self {
        Self {
            configured,
            override_level: Mutex::new(None),
            now: Clock(Arc::new(std::time::Instant::now)),
        }
    }

    /// Builds a verbosity whose clock is supplied, for tests.
    #[must_use]
    pub fn with_clock(
        configured: LogLevel,
        now: impl Fn() -> std::time::Instant + Send + Sync + 'static,
    ) -> Self {
        Self { configured, override_level: Mutex::new(None), now: Clock(Arc::new(now)) }
    }

    /// The configured level.
    #[must_use]
    pub const fn configured(&self) -> LogLevel {
        self.configured
    }

    /// The level in force right now.
    #[must_use]
    pub fn effective(&self) -> LogLevel {
        let now = self.now.now();
        let guard = self.override_level.lock();
        match *guard {
            Some((level, until)) if now < until => level,
            // Expired. The entry is left in place rather than cleared here, because `effective` is called
            // on every log line and taking a write lock on the hot path is what a read-mostly structure
            // is meant to avoid.
            Some(_) => self.configured,
            None => self.configured,
        }
    }

    /// Raises verbosity to `level` for [`VERBOSE_WINDOW`].
    pub fn raise_for_a_while(&self, level: LogLevel) {
        let until = self.now.now() + VERBOSE_WINDOW;
        *self.override_level.lock() = Some((level, until));
    }

    /// Raises verbosity until `until`.
    ///
    /// For a caller that already has a deadline — the settings screen showing a countdown, for instance.
    pub fn raise_until(&self, level: LogLevel, until: std::time::Instant) {
        *self.override_level.lock() = Some((level, until));
    }

    /// Ends a temporary increase immediately.
    pub fn reset(&self) {
        *self.override_level.lock() = None;
    }

    /// Whether a temporary increase is active.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        let now = self.now.now();
        self.override_level
            .lock()
            .is_some_and(|(_, until)| now < until)
    }

    /// How long the temporary increase has left.
    #[must_use]
    pub fn remaining(&self) -> Option<core::time::Duration> {
        let now = self.now.now();
        self.override_level.lock().as_ref().and_then(|(_, until)| {
            until.checked_duration_since(now)
        })
    }
}

/// Counts what the writer has seen, so the diagnostics screen can report it.
#[derive(Debug, Default)]
pub struct LogStats {
    lines: AtomicU64,
    bytes: AtomicU64,
    redactions: AtomicU64,
}

impl LogStats {
    /// How many lines have been written.
    #[must_use]
    pub fn lines(&self) -> u64 {
        self.lines.load(Ordering::Relaxed)
    }

    /// How many bytes have been written.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// How many values have been withheld.
    ///
    /// Reported because it is the one number that says whether the redaction policy is doing anything: a
    /// count of zero across a long session means either nothing sensitive was logged or the policy is not
    /// being applied, and both are worth knowing.
    #[must_use]
    pub fn redactions(&self) -> u64 {
        self.redactions.load(Ordering::Relaxed)
    }
}

/// A writer that applies the redaction policy to each line before it reaches its destination.
///
/// See the module docs for why the policy is applied here rather than in a layer.
pub struct RedactingWriter<W> {
    inner: Mutex<W>,
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
        Self {
            inner: Mutex::new(inner),
            stats: Arc::new(LogStats::default()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Redaction;
    use rstest::rstest;
    use std::sync::atomic::AtomicI64;

    /// The test the design document asks for by name: pass a payload to the log path and assert the
    /// original text is absent from the output.
    #[test]
    fn a_payload_never_reaches_the_output() {
        let secret = "the secret message";

        // As a formatted `tracing` line, which is what the writer sees.
        let line = format!("event=transport.recv payload={secret} peer=abc\n");
        let (redacted, count) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);

        assert!(!redacted.contains(secret), "{redacted}");
        assert!(redacted.contains(REDACTED), "{redacted}");
        assert_eq!(count, 1);
        // And the rest of the line survives, because the diagnosis is the point of logging at all.
        assert!(redacted.contains("peer=abc"), "{redacted}");
    }

    #[rstest]
    #[case("payload", r#"{"body":"x"}"#)]
    #[case("body", "the secret message")]
    #[case("content", "file contents")]
    #[case("clipboard", "copied text")]
    #[case("token", "ghp_abc123")]
    #[case("access_token", "ya29.abc")]
    #[case("api_key", "sk-live-abc")]
    #[case("secret", "hunter2")]
    #[case("password", "hunter2")]
    #[case("credential", "user:pass")]
    #[case("cookie", "session=abc")]
    #[case("private_key", "-----BEGIN")]
    #[case("session_key", "0123456789")]
    fn a_secret_field_is_redacted_in_a_formatted_line(#[case] field: &str, #[case] value: &str) {
        let line = format!("ts=1 level=INFO {field}={value} done=true\n");
        let (redacted, count) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);

        assert!(!redacted.contains(value), "{field}: {redacted}");
        assert!(redacted.contains(REDACTED), "{field}: {redacted}");
        assert_eq!(count, 1, "{field}");
    }

    #[test]
    fn a_url_query_is_stripped_from_a_formatted_line() {
        let line = "event=http.request url=https://api.github.com/repos?token=ghp_abc status=200\n";
        let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);

        assert!(!redacted.contains("ghp_abc"), "{redacted}");
        assert!(redacted.contains("https://api.github.com/repos"), "{redacted}");
        assert!(redacted.contains("status=200"), "{redacted}");
        assert_eq!(count, 1);
    }

    #[test]
    fn ordinary_fields_are_left_exactly_as_written() {
        let line = "event=transport.send peer=abc elapsed_ms=12 ok=true\n";
        let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);
        assert_eq!(redacted, line, "an untouched line must not be reflowed");
        assert_eq!(count, 0);
    }

    #[test]
    fn several_secrets_on_one_line_are_all_replaced() {
        let line = "payload=abc token=def peer=ok secret=ghi\n";
        let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);

        assert_eq!(count, 3);
        for leaked in ["abc", "def", "ghi"] {
            assert!(!redacted.contains(leaked), "{leaked} survived: {redacted}");
        }
        assert!(redacted.contains("peer=ok"), "{redacted}");
    }

    #[test]
    fn a_line_with_no_equals_sign_survives_intact() {
        // A panic message, a stack frame, a blank line: none of them have the shape this looks for, and
        // mangling them would lose the diagnostic.
        for line in ["thread 'main' panicked at src/lib.rs:1", "", "---- ---- ----", "  at foo"] {
            let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);
            assert_eq!(redacted, line, "{line:?}");
            assert_eq!(count, 0, "{line:?}");
        }
    }

    #[test]
    fn a_field_at_the_start_of_a_line_is_found() {
        // The name search runs back to a space, and there is none at the start of the line.
        let (redacted, count) = redact_line("token=abc rest=1", DEFAULT_REDACTED_FIELDS, true);
        assert!(redacted.starts_with(&format!("token={REDACTED}")), "{redacted}");
        assert_eq!(count, 1);
    }

    #[test]
    fn the_writer_applies_the_policy_and_counts_it() {
        let mut writer = RedactingWriter::new(Vec::new());
        let stats = writer.stats();

        let secret = "the secret message";
        let line = format!("payload={secret} peer=abc\n");
        writer.write_all(line.as_bytes()).expect("writes");
        writer.flush().expect("flushes");

        assert_eq!(stats.lines(), 1);
        assert_eq!(stats.redactions(), 1);
        assert!(stats.bytes() > 0);

        let output = String::from_utf8(writer.inner.lock().clone()).expect("utf8");
        assert!(!output.contains(secret), "{output}");
        assert!(output.contains("peer=abc"), "{output}");
    }

    #[test]
    fn the_writer_can_be_turned_off_for_a_test_that_needs_raw_text() {
        let mut writer = RedactingWriter::new(Vec::new());
        writer.set_enabled(false);
        writer.write_all(b"token=abc\n").expect("writes");

        let output = String::from_utf8(writer.inner.lock().clone()).expect("utf8");
        assert!(output.contains("token=abc"), "{output}");
        // And a disabled writer must not claim to have withheld anything.
        assert_eq!(writer.stats().redactions(), 0);
    }

    #[test]
    fn the_writer_passes_non_utf8_through_rather_than_failing() {
        // A dropped log line is worse than a garbled one, and an error here would propagate into whatever
        // was being logged.
        let mut writer = RedactingWriter::new(Vec::new());
        let bytes = [0xFFu8, 0xFE, b'\n'];
        writer.write_all(&bytes).expect("writes");
        writer.flush().expect("flushes");

        let output = writer.inner.lock().clone();
        assert_eq!(output, bytes);
    }

    #[test]
    fn the_writer_reports_how_much_it_wrote() {
        // The `Write` contract: a short count makes the caller retry or, worse, silently drop the rest.
        let mut writer = RedactingWriter::new(Vec::new());
        let line = b"peer=abc\n";
        assert_eq!(writer.write(line).expect("writes"), line.len());
    }

    #[test]
    fn a_writer_displays_without_exposing_its_target() {
        let writer = RedactingWriter::new(Vec::new());
        let debug = format!("{writer:?}");
        assert!(debug.contains("RedactingWriter"), "{debug}");
    }

    #[test]
    fn levels_order_from_most_to_least_verbose() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn a_threshold_admits_its_own_level_and_worse() {
        assert!(LogLevel::Info.admits(LogLevel::Info));
        assert!(LogLevel::Info.admits(LogLevel::Warn));
        assert!(LogLevel::Info.admits(LogLevel::Error));
        assert!(!LogLevel::Info.admits(LogLevel::Debug));
        assert!(!LogLevel::Info.admits(LogLevel::Trace));

        // Off admits nothing, including an error.
        for level in [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
        ] {
            assert!(!LogLevel::Off.admits(level), "{level}");
        }
    }

    #[test]
    fn only_the_persisted_levels_reach_disk() {
        // Debug and trace are for a bounded diagnostic window; keeping them forever is how a log
        // directory reaches a gigabyte.
        assert!(!LogLevel::Trace.is_persisted());
        assert!(!LogLevel::Debug.is_persisted());
        assert!(LogLevel::Info.is_persisted());
        assert!(LogLevel::Warn.is_persisted());
        assert!(LogLevel::Error.is_persisted());
    }

    #[test]
    fn level_names_round_trip() {
        for level in [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warn,
            LogLevel::Error,
            LogLevel::Off,
        ] {
            assert_eq!(LogLevel::parse(level.as_str()), Ok(level));
            assert_eq!(level.to_string(), level.as_str());
        }
        // Case and whitespace are tolerated, because these come from a config file a person edited.
        assert_eq!(LogLevel::parse("  INFO "), Ok(LogLevel::Info));
        assert_eq!(LogLevel::parse("WARNING"), Ok(LogLevel::Warn));
        assert!(LogLevel::parse("loud").is_err());
    }

    #[test]
    fn the_default_level_is_info() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn an_unknown_level_names_itself_in_the_error() {
        match LogLevel::parse("loud") {
            Err(error) => assert_eq!(error.name, "loud"),
            Ok(level) => panic!("expected an error, got {level}"),
        }
    }

    #[test]
    fn a_temporary_increase_expires_on_its_own() {
        // The clock is injected, so this asserts the deadline rather than sleeping for thirty minutes.
        let base = std::time::Instant::now();
        let offset = Arc::new(AtomicI64::new(0));
        let offset_for_clock = Arc::clone(&offset);

        let verbosity = Verbosity::with_clock(LogLevel::Info, move || {
            let seconds = offset_for_clock.load(Ordering::Relaxed);
            if seconds >= 0 {
                base + core::time::Duration::from_secs(seconds as u64)
            }
            else {
                base - core::time::Duration::from_secs(seconds.unsigned_abs())
            }
        });

        assert_eq!(verbosity.effective(), LogLevel::Info);
        assert!(!verbosity.is_raised());

        verbosity.raise_for_a_while(LogLevel::Debug);
        assert_eq!(verbosity.effective(), LogLevel::Debug);
        assert!(verbosity.is_raised());
        assert_eq!(verbosity.remaining(), Some(VERBOSE_WINDOW));

        // Just inside the window.
        offset.store(i64::try_from(VERBOSE_WINDOW.as_secs()).expect("small") - 1, Ordering::Relaxed);
        assert_eq!(verbosity.effective(), LogLevel::Debug);

        // Past it.
        offset.store(i64::try_from(VERBOSE_WINDOW.as_secs()).expect("small") + 1, Ordering::Relaxed);
        assert_eq!(verbosity.effective(), LogLevel::Info, "the override must lapse");
        assert!(!verbosity.is_raised());
        assert_eq!(verbosity.remaining(), None);
    }

    #[test]
    fn a_temporary_increase_can_be_ended_immediately() {
        let verbosity = Verbosity::new(LogLevel::Info);
        verbosity.raise_for_a_while(LogLevel::Trace);
        assert_eq!(verbosity.effective(), LogLevel::Trace);

        verbosity.reset();
        assert_eq!(verbosity.effective(), LogLevel::Info);
    }

    #[test]
    fn a_temporary_increase_can_be_given_an_explicit_deadline() {
        // The settings screen shows a countdown, so it already knows the deadline.
        let verbosity = Verbosity::new(LogLevel::Warn);
        let until = std::time::Instant::now() + core::time::Duration::from_secs(60);
        verbosity.raise_until(LogLevel::Debug, until);

        assert_eq!(verbosity.effective(), LogLevel::Debug);
        assert_eq!(verbosity.configured(), LogLevel::Warn);
        // The remaining time is asserted as a range rather than a value: reading the clock between the
        // caller's `Instant::now()` and this assertion makes an exact comparison flaky by nanoseconds.
        let remaining = verbosity.remaining().expect("a deadline is set");
        assert!(
            remaining <= core::time::Duration::from_secs(60)
                && remaining > core::time::Duration::from_secs(59),
            "{remaining:?}",
        );
    }

    #[test]
    fn raising_again_replaces_the_previous_deadline() {
        let verbosity = Verbosity::new(LogLevel::Info);
        verbosity.raise_for_a_while(LogLevel::Debug);
        verbosity.raise_for_a_while(LogLevel::Trace);
        assert_eq!(verbosity.effective(), LogLevel::Trace, "the latest request wins");
    }

    #[test]
    fn url_stripping_can_be_disabled_independently_of_field_redaction() {
        let line = "url=https://x/y?t=1 token=abc\n";
        let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, false);
        // The secret is still gone; only the URL treatment changed.
        assert!(!redacted.contains("abc"), "{redacted}");
        assert!(redacted.contains("https://x/y?t=1"), "{redacted}");
        assert_eq!(count, 1);
    }

    #[test]
    fn a_caller_can_supply_its_own_field_list() {
        let line = "session=abc peer=ok\n";
        let (redacted, count) = redact_line(line, &["session"], true);
        assert!(redacted.contains(REDACTED), "{redacted}");
        assert_eq!(count, 1);

        let (untouched, count) = redact_line(line, &["nothing"], true);
        assert!(untouched.contains("session=abc"), "{untouched}");
        assert_eq!(count, 0);
    }

    #[test]
    fn a_truncated_url_is_counted_and_a_truncated_value_is_not() {
        // Truncation is not withholding a secret, so counting it would make the redaction number
        // misleading — it would report that secrets were caught when none were.
        let long = format!("{}?q=1", "https://example.com/".repeat(60));
        let line = format!("url={long} note=ok\n");
        let (redacted, count) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);

        // The URL's query was removed, which *is* a redaction.
        assert_eq!(count, 1, "{redacted}");
        assert!(redacted.contains("len="), "the value was also truncated: {redacted}");
        assert!(redacted.contains("note=ok"), "{redacted}");

        // A long value that is not a URL is truncated without being counted. The value is a repeated
        // word rather than a repeated letter, so "the original is absent" is a real assertion: a single
        // repeated character also occurs inside `level=INFO`.
        let plain = "abcdefghij".repeat(200);
        let (redacted, count) = redact_line(&format!("note={plain}\n"), DEFAULT_REDACTED_FIELDS, true);
        assert_eq!(count, 0, "{redacted}");
        assert!(redacted.contains("len=2001"), "{redacted}");
        assert!(!redacted.contains(&plain), "the value was not truncated");
    }

    #[test]
    fn the_writer_reports_a_shorter_redaction_than_it_consumed() {
        // The `Write` contract wants the count of bytes *consumed*, not written: returning the shorter
        // figure makes the caller re-send the tail of the redacted value.
        let mut writer = RedactingWriter::new(Vec::new());
        let line = b"token=a\n";
        assert_eq!(writer.write(line).expect("writes"), line.len());
    }

    #[test]
    fn redaction_is_reported_through_the_stats() {
        let mut writer = RedactingWriter::new(Vec::new());
        let stats = writer.stats();
        writer.write_all(b"token=a token=b\n").expect("writes");

        assert_eq!(stats.redactions(), 2, "both fields");
        // And a second writer has its own counters.
        let other = RedactingWriter::new(Vec::new());
        assert_eq!(other.stats().redactions(), 0);
    }

    #[test]
    fn a_field_name_is_matched_case_insensitively_in_a_formatted_line() {
        let line = "TOKEN=abc Peer=ok\n";
        let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);
        assert!(!redacted.contains("abc"), "{redacted}");
        assert_eq!(count, 1);
    }

    #[test]
    fn a_url_decision_is_not_reported_as_truncation() {
        // The distinction matters to a consumer that renders the reason: "query removed" and "too long"
        // send a reader looking in different places.
        let redactor = Redactor::new();
        assert!(matches!(
            redactor.value("url", "https://x/y?a=1").decision,
            Redaction::UrlStripped { .. }
        ));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// A field whose name is on the list never contributes its value to the output. This is the
        /// property the whole module exists for, and it has to hold for arbitrary values because the
        /// value is whatever a developer happened to log.
        #[test]
        fn a_named_secret_field_never_reaches_the_output(
            // No spaces: a formatted value runs to the next space, so a value containing one cannot be
            // delimited from what follows it. That limitation is asserted separately, below.
            value in "[!-~]{1,80}",
            field in prop::sample::select(DEFAULT_REDACTED_FIELDS.to_vec()),
        ) {
            let line = format!("ts=1 level=INFO {field}={value} done=true\n");
            let (redacted, _) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);

            // What follows the field name must be the marker, not the value.
            //
            // Asserting "the output does not contain the value" would be wrong in both directions: a
            // one-character value occurs inside `level`, and a value of `<` occurs inside the marker
            // itself. Only the position right after the field name says whether the value was withheld.
            let expected = format!("{field}={REDACTED}");
            prop_assert!(
                redacted.contains(&expected),
                "expected {expected:?} in {}",
                redacted,
            );
            // Skipped when the value happens to be a prefix of the marker itself — a value of `<` is
            // "followed by its value" in the letter of the check and not in its meaning.
            if !REDACTED.starts_with(value.as_str()) {
                prop_assert!(
                    !redacted.contains(&format!("{field}={value}")),
                    "{} still immediately follows its field name: {}",
                    value,
                    redacted,
                );
            }
        }

        /// A value containing a space is only partly replaced, and that is a documented limitation rather
        /// than a silent one.
        ///
        /// A formatted line has no structure the writer can trust: `payload=a b` is indistinguishable from
        /// two fields. The primary defence is redacting typed fields before they are formatted, where the
        /// name is known and the value is still whole; this asserts what the backstop does so the gap is on
        /// the record.
        #[test]
        fn a_value_with_a_space_is_only_partly_replaced(_unused in Just(())) {
            let line = "payload=secret start end peer=ok\n";
            let (redacted, count) = redact_line(line, DEFAULT_REDACTED_FIELDS, true);
            prop_assert_eq!(count, 1);
            // The first token is gone; the remainder of the value is not.
            prop_assert!(!redacted.contains("secret"), "{}", redacted);
            prop_assert!(redacted.contains("start end"), "{}", redacted);
        }

        /// Redacting a line never loses the fields around it. A policy that ate the rest of the line
        /// would make the log useless, which is the failure mode that pushes people to turn redaction off.
        #[test]
        fn ordinary_fields_survive_redaction(
            // No spaces, for the same reason as above: a space inside the value would end it early and
            // the assertion would be about the delimiter rather than about redaction.
            value in "[!-~]{1,40}",
            peer in "[a-z0-9]{1,16}",
        ) {
            let line = format!("payload={value} peer={peer} elapsed_ms=5\n");
            let (redacted, _) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);
            prop_assert!(redacted.contains(&format!("peer={peer}")), "{}", redacted);
            prop_assert!(redacted.contains("elapsed_ms=5"), "{}", redacted);
        }

        /// Arbitrary text either survives unchanged or is modified, and the function never panics. Log
        /// lines come from everywhere, including a panic message and a third-party crate.
        #[test]
        fn redacting_a_line_is_total(line in ".{0,300}") {
            let _ = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);
        }

        /// A line with no field of interest comes back byte for byte. Reflowing it would corrupt a stack
        /// trace or a hex dump, which are the lines a reader most needs intact.
        #[test]
        fn a_line_without_secrets_is_not_reflowed(parts in proptest::collection::vec("[a-z]{1,8}", 1..6)) {
            let line = parts.join(" ");
            let (redacted, count) = redact_line(&line, DEFAULT_REDACTED_FIELDS, true);
            prop_assert_eq!(redacted, line);
            prop_assert_eq!(count, 0);
        }
    }
}
