//! The logging module's tests.

use super::*;
use crate::redact::Redaction;
use rstest::rstest;
use std::sync::atomic::AtomicI64;

use std::sync::Arc;
use crate::redact::REDACTED;

use std::sync::atomic::Ordering;
use crate::redact::Redactor;

mod redaction;
mod writer;
mod levels;
mod temporary;
