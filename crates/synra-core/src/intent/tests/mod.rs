//! The board's sequence, driven from both sides.
//!
//! Every test here names the side it is driving. The transfer bug this repository wrote a note about was a suite that
//! answered only the sender's question while the daemon asked a different one, and a state machine is exactly the kind
//! of code that attracts the same mistake: a test that raises an intent and asserts its own state proves the board
//! agrees with itself.
//!
//! So each test drives the board the way a caller does — raise, offer, settle, choose, confirm, conclude — and asserts
//! what a *person* or a *device* would observe.

use std::time::Duration;

use synra_protocol::ids::{DeviceId, PluginId};
use synra_protocol::inbound::ShareItem;

use super::board::Board;
use super::types::{IntentCandidate, IntentSource, PlannedAction};

mod board_state;
mod choice_and_target;
mod conclusion;
mod offering;
mod persistence;
mod raising;
mod recovery;
mod settling;

/// Ten past the epoch, so a deadline is a number a reader can check by hand.
const NOW: i64 = 1_000;

fn plugin(name: &str) -> PluginId {
    PluginId::parse(name).expect("a valid plugin id")
}

fn share() -> IntentSource {
    IntentSource::Share {
        item: ShareItem {
            from: DeviceId::new(),
            mime: "text/plain".to_owned(),
            text: Some("https://example.test/a".to_owned()),
            transfers: Vec::new(),
            context_id: None,
        },
        source_app: Some("Browser".to_owned()),
    }
}

fn candidate(name: &str, action: &str, target: Option<DeviceId>) -> IntentCandidate {
    IntentCandidate {
        plugin_id: plugin(name),
        plugin_version: "1.0.0".to_owned(),
        planned: PlannedAction {
            plugin_id: plugin(name),
            action: action.to_owned(),
            args: serde_json::json!({ "url": "https://example.test/a" }),
        },
        required_caps: vec!["platform:open-url".to_owned()],
        suggested_target: target,
        title: "Open this link".to_owned(),
        detail: None,
    }
}

/// A board whose matching window is one millisecond, so `settle` is a call rather than a wait.
fn board() -> Board {
    Board::with_window(Duration::from_millis(1))
}

/// The moment matching is over.
fn after_window() -> i64 {
    NOW + 2
}
