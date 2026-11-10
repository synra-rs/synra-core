use super::CrashReport;

mod reports;
mod safe_mode;
mod store;

fn report(at_ms: i64, location: Option<&str>) -> CrashReport {
    CrashReport::new(
        at_ms,
        "1.0.0",
        location.map(str::to_owned),
        Some("index out of bounds".to_owned()),
        Some("main".to_owned()),
        None,
        None,
    )
}

/// A per-test suffix, so two tests running at once do not share a temporary directory.
///
/// A counter rather than a random value: a test failure has to be reproducible, and a directory named
/// after a counter is one a developer can go and look at.
pub(super) fn test_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
