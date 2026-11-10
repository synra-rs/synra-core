use synra_protocol::event::EventName;
use synra_protocol::envelope::Envelope;
use synra_protocol::{DeviceId, RequestId, TraceId};

use super::*;

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-late-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn envelope() -> Envelope {
    Envelope {
        request_id: RequestId::new(),
        event: EventName::parse(synra_protocol::event::events::INTENT_RESULT).expect("an event name"),
        target: DeviceId::new(),
        from: DeviceId::new(),
        reply_to: None,
        trace_id: TraceId::new(),
        payload: None,
        sent_at_ms: 0,
        ttl_ms: None,
    }
}

#[test]
fn an_answer_is_stored_and_read_back() {
    let scratch = Scratch::new("round-trip");
    let queue = LateQueue::in_data_dir(&scratch.0);
    let before = envelope();
    queue.push(&before, 1_000).expect("queued");

    let due = queue.due(1_000);
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].attempts, 0);
    assert_eq!(due[0].envelope.request_id, before.request_id);
}

#[test]
fn the_queue_is_bounded_by_dropping_the_oldest() {
    let scratch = Scratch::new("bounded");
    let queue = LateQueue::in_data_dir(&scratch.0);
    for index in 0..MAX_ENTRIES {
        queue.push(&envelope(), i64::try_from(index).expect("small") + 1).expect("queued");
    }
    assert_eq!(queue.len(), MAX_ENTRIES);
    queue.push(&envelope(), 10_000).expect("queued");
    assert_eq!(queue.len(), MAX_ENTRIES, "the queue grew past its bound");
    let due = queue.due(10_000);
    assert!(
        !due.iter().any(|pending| pending.queued_ms == 1),
        "the oldest entry should have been the one removed"
    );
}

#[test]
fn a_delivered_answer_is_removed() {
    let scratch = Scratch::new("delivered");
    let queue = LateQueue::in_data_dir(&scratch.0);
    queue.push(&envelope(), 1_000).expect("queued");

    let summary = queue.retry_with(1_000, |_| Ok(()));
    assert_eq!(summary, RetrySummary { delivered: 1, failed: 0, dropped: 0 });
    assert!(queue.due(1_000).is_empty());
}

#[test]
fn a_failed_answer_is_retried_and_then_dropped_at_the_bound() {
    let scratch = Scratch::new("attempts");
    let queue = LateQueue::in_data_dir(&scratch.0);
    queue.push(&envelope(), 1_000).expect("queued");

    // Every attempt fails; each pass increments the counter until the bound removes the entry.
    for _ in 0..MAX_ATTEMPTS - 1 {
        let summary = queue.retry_with(1_000, |_| Err("gone".to_owned()));
        assert_eq!(summary, RetrySummary { delivered: 0, failed: 1, dropped: 0 });
    }
    let summary = queue.retry_with(1_000, |_| Err("gone".to_owned()));
    assert_eq!(summary, RetrySummary { delivered: 0, failed: 0, dropped: 1 });
    assert!(queue.due(1_000).is_empty(), "an entry over the bound must be gone");
}

#[test]
fn an_answer_older_than_a_day_is_dropped_without_a_dial() {
    let scratch = Scratch::new("stale");
    let queue = LateQueue::in_data_dir(&scratch.0);
    queue.push(&envelope(), 1_000).expect("queued");

    let due = queue.due(1_000 + MAX_AGE_MS + 1);
    assert!(due.is_empty(), "a stale answer must not be dialled");
}

#[test]
fn a_file_that_is_not_an_answer_is_removed_rather_than_retried() {
    let scratch = Scratch::new("corrupt");
    let queue = LateQueue::in_data_dir(&scratch.0);
    std::fs::create_dir_all(queue.directory()).expect("the queue directory");
    std::fs::write(queue.directory().join("late-broken.json"), b"not json").expect("a bad file");

    assert!(queue.due(1_000).is_empty());
    assert!(
        !queue.directory().join("late-broken.json").exists(),
        "a file that can never become an answer was left behind"
    );
}
