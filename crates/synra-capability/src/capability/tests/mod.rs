//! The capability tests.

use rstest::rstest;

use crate::domain::Domain;

use super::{Capability, CapabilityError, MAX_LEN, MAX_SEGMENTS, Segment};

mod syntax;
mod matching;
mod representation;
