use synra_capability::Capability;
use synra_observe::audit::AuditOutcome;

use crate::host_surface;

use super::{AuditEntry, HostCalls};
use super::helpers::clock_ms;

impl HostCalls<'_> {
/// Adds one to a counter, when there is anywhere to add it to.
    ///
    /// # Why the labels are sorted here rather than by the caller
    ///
    /// Because `SeriesKey::new` sorts them, and a label list built in a different order at a different call site would be the
    /// same series either way — so this takes them as they read best at the call site and lets the key do the canonicalising.
    ///
    /// # Why a missing recorder is not an error
    ///
    /// Because a host that keeps no numbers is a host, not a broken one, and a call that failed because a *metric* could not be
    /// written would be a call refused for a reason the plugin cannot see or act on.
    /// Records one observation, on the same terms as [`count_metric`].
    ///
    /// ★ **Why the call duration is a histogram and not a counter.** `elapsed_ms` was already in this file's hand — it goes
    /// into the audit entry — and a counter cannot answer the question it is for: "how slow is this plugin" is a question
    /// about a distribution, and no number of audit rows can be averaged by a person reading them.
    ///
    /// Nothing in production called `histogram_observe` before this; only the recorder's own tests did. A histogram that no
    /// caller uses is a shape rather than a measurement, and the difference is one call at the place the number already is.
    pub(super) fn observe_metric(
        metrics: Option<&synra_observe::metrics::RingRecorder>,
        name: &str,
        labels: &[(&str, &str)],
        value: f64,
    ) {
        let Some(recorder) = metrics else {
            return;
        };
        let key = synra_observe::metrics::SeriesKey::new(
            name,
            labels
                .iter()
                .map(|(label, text)| ((*label).to_owned(), (*text).to_owned())),
        );
        recorder.histogram_observe(&key, value);
    }

    pub(super) fn count_metric(
        metrics: Option<&synra_observe::metrics::RingRecorder>,
        name: &str,
        labels: &[(&str, &str)],
        value: u64,
    ) {
        let Some(recorder) = metrics else {
            return;
        };
        let key = synra_observe::metrics::SeriesKey::new(
            name,
            labels
                .iter()
                .map(|(label, text)| ((*label).to_owned(), (*text).to_owned())),
        );
        recorder.counter_add(&key, value);
    }

    /// Adds to a counter on the session's recorder, when there is one.
    pub(super) fn count(&self, name: &str, labels: &[(&str, &str)], value: u64) {
        Self::count_metric(self.metrics, name, labels, value);
    }

    /// Records one observation on the session's recorder, when there is one.
    pub(super) fn observe(&self, name: &str, labels: &[(&str, &str)], value: f64) {
        Self::observe_metric(self.metrics, name, labels, value);
    }

    /// Writes one audit record.
    pub(super) fn record(&mut self, import_name: &str, outcome: AuditOutcome, elapsed_ms: Option<u64>) {
        // ★ Recorded before anything can return: a call that is refused still took as long as it took, and a
        // distribution built only from the calls that succeeded would answer "how slow is this plugin" with the times
        // of the calls that were allowed to run.
        if let Some(elapsed) = elapsed_ms {
            self.observe("host_call_ms", &[("import", import_name)], elapsed as f64);
        }
        // ★ A capability that cannot be parsed is recorded as `log:*`... no: it is *not* recorded under a capability
        // the plugin does not hold. The gate table is generated from the contract and every string in it is a
        // capability, so a parse failure here means the table and the capability crate disagree — which is a build
        // failure rather than a runtime one, and the record is skipped rather than invented.
        let Some(capability) = host_surface::gate(import_name).and_then(|gate| gate.capability())
        else {
            return;
        };
        let Ok(parsed) = Capability::parse(capability) else {
            return;
        };
        self.audit.push(AuditEntry::new(
            clock_ms() as i64,
            self.plugin.clone(),
            parsed,
            outcome,
            elapsed_ms,
        ));
    }
}
