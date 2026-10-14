//! What a test expects, and the check that compares it with the record.

use synra_protocol::frame::FrameKind;

use super::harness::KernelPair;
use super::record::{ExpectationError, Side};
use super::helpers::frame_event;

/// What a test expects to see.
///
/// A value rather than a closure at the call site, so a failure message can name what was expected. A closure's
/// failure says "the predicate was false", and a reader then has to find the closure to learn what it meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// Which side it comes from.
    pub from: Side,
    /// What kind of frame.
    pub kind: FrameKind,
    /// The event name in the envelope, for an envelope frame.
    pub event: Option<String>,
}

impl Expectation {
    /// An envelope carrying an event.
    #[must_use]
    pub fn event(from: Side, event: &str) -> Self {
        Self { from, kind: FrameKind::Envelope, event: Some(event.to_owned()) }
    }

    /// A frame of a kind.
    #[must_use]
    pub const fn frame(from: Side, kind: FrameKind) -> Self {
        Self { from, kind, event: None }
    }
}

/// Asserts that an expectation holds, for a test that would rather see every failure at once.
///
/// # Why a list rather than an early return
///
/// A handshake test has several expectations, and a version that returned on the first failure would need one run per
/// unmet expectation. Collecting them means one run tells a reader everything that is wrong, which is the difference
/// between two iterations and six.
///
/// # Errors
///
/// [`ExpectationError`] naming the first that did not hold.
pub fn check<K>(pair: &KernelPair<K>, expectations: &[Expectation]) -> Result<(), ExpectationError> {
    for expectation in expectations {
        let found = pair.record(expectation.from).find(|frame| {
            frame.kind == expectation.kind
                && expectation.event.as_deref().is_none_or(|wanted| frame_event(frame).as_deref() == Some(wanted))
        });
        match found {
            Some(_) => {}
            None => {
                // A frame of the right kind with a different event is worth saying, because it is the usual cause:
                // the handshake happened and carried something else.
                if let Some(event) = &expectation.event
                    && let Some(frame) = pair
                        .record(expectation.from)
                        .find(|frame| frame.kind == expectation.kind)
                {
                    return Err(ExpectationError::WrongEvent {
                        from: expectation.from.as_str(),
                        kind: "envelope",
                        found: frame_event(&frame).unwrap_or_else(|| "<unreadable>".to_owned()),
                        expected: event.clone(),
                    });
                }
                return Err(ExpectationError::NeverArrived {
                    from: expectation.from.as_str(),
                    expected: expectation
                        .event
                        .clone()
                        .unwrap_or_else(|| format!("{:?}", expectation.kind)),
                });
            }
        }
    }
    Ok(())
}
