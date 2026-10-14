//! Two kernels wired to each other in memory, and what a test expects of them.
//!
//! # Why this is a directory and not a file
//!
//! Because it holds three separable things: what a test *expects* and how to say it, the pair of kernels itself, and
//! the two small helpers that read a frame or wrap a kernel with its clock. In one file the expectation vocabulary
//! was a hundred lines above the pair that answers it.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `record` | one recorded event, and what a side means |
//! | `expectation` | what a test expects, and the check that compares it with the record |
//! | `harness` | two kernels wired to each other, and the helpers that read them |

mod record;
mod harness;
mod expectation;
mod helpers;

#[cfg(test)]
mod tests;

pub use expectation::{Expectation, check};
pub use helpers::{PairedKernel, frame_event};
pub use harness::KernelPair;
pub use record::{ExpectationError, RECORD_CAPACITY, Side};
