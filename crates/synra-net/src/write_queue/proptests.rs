use proptest::prelude::*;

use super::{CloseReason, WriteQueue};

proptest! {
    /// The queue never holds more than its capacity. It is the bound that stops a peer which stops reading from
    /// turning the application into a buffer.
    #[test]
    fn the_queue_never_exceeds_its_capacity(
        capacity in 1usize..32,
        pushes in proptest::collection::vec(any::<u32>(), 0..200),
    ) {
        let mut queue = WriteQueue::with_capacity(capacity);
        for value in pushes {
            let _ = queue.push(value);
            prop_assert!(queue.len() <= capacity, "held {} of {}", queue.len(), capacity);
        }
    }

    /// Whatever the sequence, frames come out in the order they went in. A reordering would mean a receiver
    /// assembling a file from chunks that no longer correspond to the sender's view of it.
    #[test]
    fn frames_keep_their_order(pushes in proptest::collection::vec(any::<u32>(), 0..16)) {
        let mut queue = WriteQueue::with_capacity(16);
        let mut accepted = Vec::new();
        for value in pushes {
            if queue.push(value).is_ok() {
                accepted.push(value);
            }
            else {
                // The overflow discarded everything, so the expectation is only the frames since.
                accepted.clear();
                break;
            }
        }
        if !queue.is_closed() {
            prop_assert_eq!(queue.drain(), accepted);
        }
    }

    /// Once a queue is closed it stays closed until it is reopened, whatever is pushed at it. A closed link that
    /// silently accepted frames would let the caller believe messages were sent.
    #[test]
    fn a_closed_queue_stays_closed(
        reason_index in 0usize..6,
        pushes in proptest::collection::vec(any::<u32>(), 1..20),
    ) {
        let reasons = [
            CloseReason::Overflow,
            CloseReason::Goodbye,
            CloseReason::Refused,
            CloseReason::Silent,
            CloseReason::Requested,
            CloseReason::WriteFailed,
        ];
        let mut queue = WriteQueue::with_capacity(8);
        queue.close(reasons[reason_index]);

        for value in pushes {
            prop_assert!(queue.push(value).is_err());
            prop_assert!(queue.is_closed());
            prop_assert!(queue.is_empty());
        }

        queue.reopen();
        prop_assert!(!queue.is_closed());
        prop_assert!(queue.push(1).is_ok());
    }
}
