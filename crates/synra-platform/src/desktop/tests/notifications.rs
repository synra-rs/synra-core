use std::time::Duration;

use crate::host::Platform;
use crate::{PlatformError, Policies};

use super::super::{CommandPlatform, Desktop};
use super::over_recorder;

#[test]
fn notifications_are_rate_limited_by_the_hour() {
    // A notification has no permission to check — it is user-visible, so the risk is being annoying rather than being
    // dangerous. The limit is what it has instead.
    let (recorder, platform) = over_recorder(Desktop::Linux);
    let policies = Policies::new().with_notifications_per_hour(2).with_notification_interval(Duration::ZERO);
    let platform = platform.with_policies(policies);

    platform.notify("one", "b").expect("first");
    platform.notify("two", "b").expect("second");
    // Either refusal is correct — the hourly count or the interval — and which one fires first is the limiter's
    // business rather than this test's.
    match platform.notify("three", "b") {
        Err(PlatformError::RateLimited { .. } | PlatformError::QuotaExceeded { .. }) => {}
        other => panic!("expected a limit, got {other:?}"),
    }
    assert_eq!(recorder.count(), 2, "the refused notification reached the runner");
}

#[test]
fn how_many_notifications_are_left_is_a_question_the_interface_asks() {
    let (_, platform) = over_recorder(Desktop::Linux);
    let policies = Policies::new().with_notifications_per_hour(5).with_notification_interval(Duration::ZERO);
    let platform = platform.with_policies(policies);
    let now = CommandPlatform::now_ms();
    assert_eq!(platform.notifications_remaining(now), 5, "nothing has been sent yet");

    platform.notify("one", "b").expect("first");
    assert_eq!(platform.notifications_remaining(CommandPlatform::now_ms()), 4);
}
