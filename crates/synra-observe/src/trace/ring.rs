use parking_lot::RwLock;

use synra_protocol::TraceId;

use super::span::Span;

/// A bounded ring of recent spans, for the diagnostics screen.
///
/// Bounded because the log file is the durable record; this exists so the interface can show the last few
/// traces without reading the file back. An unbounded buffer would be a second copy of the log, in memory.
#[derive(Debug)]
pub struct TraceRing {
    spans: RwLock<Vec<Span>>,
    capacity: usize,
    /// How many spans were dropped because the ring was full.
    dropped: RwLock<u64>,
}

impl TraceRing {
    /// A ring holding the most recent `capacity` spans.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            spans: RwLock::new(Vec::with_capacity(capacity.min(1024))),
            capacity,
            dropped: RwLock::new(0),
        }
    }

    /// Records a span, dropping the oldest if the ring is full.
    pub fn record(&self, span: Span) {
        if self.capacity == 0 {
            *self.dropped.write() += 1;
            return;
        }
        let mut spans = self.spans.write();
        if spans.len() >= self.capacity {
            spans.remove(0);
            *self.dropped.write() += 1;
        }
        spans.push(span);
    }

    /// The steps of one trace, in the order they started.
    ///
    /// Ordered by start time rather than by span id: a fan-out gives three children of one parent, and the
    /// useful order is when they ran.
    #[must_use]
    pub fn steps_for(&self, trace_id: TraceId) -> Vec<Span> {
        let mut steps: Vec<Span> = self
            .spans
            .read()
            .iter()
            .filter(|span| span.context.trace_id == trace_id)
            .cloned()
            .collect();
        steps.sort_by_key(|span| (span.started_at_ms, span.context.span_id));
        steps
    }

    /// The distinct traces present, most recent first.
    #[must_use]
    pub fn recent_traces(&self, limit: usize) -> Vec<TraceId> {
        // Checked before the loop rather than inside it: a limit of zero must return nothing, and a check
        // at the end of the loop body admits the first entry regardless.
        if limit == 0 {
            return Vec::new();
        }

        // The scan happens inside a helper, so the read guard is created and released in a function body
        // with no expression around it. Clippy's `significant_drop_in_scrutinee` fires on a guard inside a
        // block whose value outlives it — the same hazard one level up, and a real one: the lock would be
        // released after the result was built rather than at the end of the scan.
        let mut traces = self.ordered_traces();
        traces.truncate(limit);
        traces
    }

    /// Every trace in the ring, most recently started first.
    fn ordered_traces(&self) -> Vec<TraceId> {
        let mut ordered: Vec<TraceId> = Vec::new();
        // The scan is written so the read guard's first use is the `for`, not a statement of its own: clippy
        // reads a guard introduced by one statement and consumed by the next as a lock released earlier than
        // the code suggests. Here the guard is created by the iterator expression itself, so its lifetime is
        // the loop's and nothing else.
        for span in self.spans.read().iter().rev() {
            if !ordered.contains(&span.context.trace_id) {
                ordered.push(span.context.trace_id);
            }
        }
        ordered
    }

    /// How many spans are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.spans.read().len()
    }

    /// Whether the ring is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.read().is_empty()
    }

    /// How many spans were dropped to make room.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        *self.dropped.read()
    }

    /// Empties the ring.
    pub fn clear(&self) {
        self.spans.write().clear();
    }
}
