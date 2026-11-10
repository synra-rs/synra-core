//! Plugin lifecycle transitions and stop history.

use super::{Lifecycle, Transition};

fn granted() -> Lifecycle {
    let mut lifecycle = Lifecycle::installed("1.0.0");
    lifecycle
        .apply(Transition::Validate { manifest_digest: "d1".to_owned() })
        .expect("validates");
    lifecycle.apply(Transition::Grant { partially_denied: false }).expect("grants");
    lifecycle
}

/// A lifecycle taken to `Active`.
fn active() -> Lifecycle {
    let mut lifecycle = granted();
    lifecycle.apply(Transition::Activate).expect("activates");
    lifecycle
}

mod installation;
mod running;
mod updates;
mod state;
mod stops;
