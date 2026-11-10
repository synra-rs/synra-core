//! Log selection, merging and redaction for diagnostic bundles.

use crate::logging::{DEFAULT_REDACTED_FIELDS, redact_line};

use super::{BundleLogLine, BundleSection, LogSlice, MAX_LOG_LINE_BYTES};

impl LogSlice {
    /// Adds another slice's lines to this one, de-duplicating the errors.
    ///
    /// The tail is appended rather than de-duplicated: the two sections read the same file at different
    /// filters, and a repeated line in a tail reads as "this happened twice", which would be a lie.
    pub(super) fn merge(&mut self, other: Self) {
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

pub(super) fn slice(lines: &[String], section: BundleSection, log_tail_lines: usize) -> LogSlice {
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
        .take(log_tail_lines)
        .rev()
        .map(|line| redact_one(line))
        .collect();
    tail.shrink_to_fit();

    let errors: Vec<BundleLogLine> = kept
        .iter()
        .filter(|line| is_error_line(line))
        .map(|line| redact_one(line))
        .collect();

    LogSlice {
        tail,
        errors,
        lines_read: lines.len(),
        lines_omitted: omitted,
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
    } else {
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


