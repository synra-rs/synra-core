//! Panic hook installation and panic payload extraction.

use std::time::{SystemTime, UNIX_EPOCH};

use super::{CrashReport, CrashStore};

/// Installs the panic hook that writes a [`CrashReport`].
///
/// # ★ Why this exists, and what its absence meant
///
/// Every part of the crash pipeline was here — the report type, the store, the repeat count per location, the safe-mode
/// verdict, and a plugin-loading path that consults it — and **nothing ever wrote a report**. `set_hook` and `take_hook`
/// appeared nowhere in the workspace. So the chain was complete and dry: safe mode could not trigger, because the file
/// it counts was never created, and a user whose plugin crashed the host on activation would get the crash and nothing
/// else, every time.
///
/// # Why it chains rather than replaces
///
/// The previous hook is what prints `thread 'main' panicked at ...` and the backtrace. Replacing it would mean a build
/// with the crash hook installed panicked **silently** in a terminal, which is a worse failure than the one this is
/// meant to record. The report is written first and the previous hook runs afterwards, so a write that fails still
/// leaves the ordinary message.
///
/// # Why the version is a parameter
///
/// A report records which build crashed, and this crate does not know: `synra-observe` has its own version, and the
/// thing that crashed is the daemon or the application. Taking it from the caller is the only way to record the right
/// one — and it is not a `&'static str`, because the daemon reports the version it was built with rather than one
/// compiled into the observe layer.
///
/// # Errors
///
/// None. Everything that can fail inside the hook fails quietly: it runs while the process is unwinding, and a second
/// panic inside a panic hook aborts instead of unwinding — which would lose the report and the message together.
pub fn install_panic_hook(store: CrashStore, version: impl Into<String>) {
    let previous = std::panic::take_hook();
    let version = version.into();

    std::panic::set_hook(Box::new(move |info| {
        // ★ Built here rather than in a helper that returns a `Result`: there is no failure path worth propagating, and
        // a signature that could fail would invite a caller to handle it inside the hook.
        let report = report_from_panic(info, &version);
        // The result is dropped deliberately. The store's own documentation says the caller is a panic hook and is
        // expected to ignore it; a report that cannot be written must not become a second panic.
        let _ = store.write(&report);

        // The ordinary message still appears, after the report is safely on disk.
        previous(info);
    }));
}

/// Turns a panic into the report that gets written.
///
/// Split out from the hook so the extraction can be tested without installing a process-wide hook — a global hook is
/// shared by every test in a binary, and a test that installed one would change how the other tests in the same binary
/// report their own failures.
#[must_use]
fn report_from_panic(
    info: &std::panic::PanicHookInfo<'_>,
    version: &str,
) -> CrashReport {
    // `file:line:column`, which is the key the repeat count is kept on. A panic with no location cannot contribute to
    // safe mode — the store's own comment explains why: an unknown location is not evidence that the same bug happened
    // again.
    let location = info
        .location()
        .map(|at| format!("{}:{}:{}", at.file(), at.line(), at.column()));

    // `panic!("literal")` arrives as `&str` and `panic!("{formatted}")` as `String`; anything else is a payload the
    // caller chose, and saying so is better than a `Debug` rendering that could itself panic.
    let payload = info.payload();
    let message = if let Some(text) = payload.downcast_ref::<&str>() {
        Some((*text).to_owned())
    } else {
        payload.downcast_ref::<String>().cloned()
    };

    CrashReport::new(
        now_ms(),
        version,
        location,
        message,
        std::thread::current().name().map(str::to_owned),
        // ★ Only captured when the process was asked to capture one. `Backtrace::capture` returns a `Disabled` value
        // otherwise, and a `Disabled` backtrace stringifies to a sentence saying so — which is worth recording, because
        // a reader looking for frames should be told they were not collected rather than shown an empty section.
        Some(std::backtrace::Backtrace::capture().to_string()),
        None,
    )
}

/// The current time in milliseconds since the epoch.
///
/// A helper rather than a `SystemTime` so the report's field is a plain number: a report has to be readable
/// by a human in a text editor, and a serialised `SystemTime` is a struct of seconds and nanoseconds.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

/// Extracts the message from a panic payload.
///
/// `Box<dyn Any>` because that is what the hook offers: a `panic!` with a format string produces a
/// `String`, and `panic_any` can produce anything. Only the two shapes that carry readable text are
/// handled; anything else yields `None` rather than a `Debug` rendering that would be a pointer.
#[must_use]
pub fn panic_message(payload: &(dyn core::any::Any + Send)) -> Option<String> {
    if let Some(text) = payload.downcast_ref::<&'static str>() {
        return Some((*text).to_owned());
    }
    payload.downcast_ref::<String>().cloned()
}


