//! 配对的那张桌子：一次只摆一份请求，人来决定它的下场。
//!
//! # 为什么是一个状态机，而不是几个布尔
//!
//! 配对的每一步都依赖上一步：只有**发起过**才谈得上取消，只有**收到过**才谈得上接受，
//! 而「接受」之后那份请求必须立刻消失——否则同一个人可以点两次「接受」，第二次落在已经写完的记录上，
//! 或者更糟，落在另一个人的请求上。
//!
//! 把这些写成 `Option` 与 `bool` 的组合，读的人要先在脑子里跑一遍三态表才能确认某个分支不可达；
//! 写成枚举之后，不可达的那一格**不存在**。
//!
//! # 它不认识数据库，也不认识 socket
//!
//! 这一层只回答「这个人点了之后，该发生什么」。写 `paired_devices` 与发帧都是调用方的事，
//! 因此这里每一条规矩都能在没有链路的测试里被验证，而不是只能在两台机器前试。
use std::time::Duration;

mod desk;
mod model;
mod service;

pub use model::{Ask, Desk, Offer, Outcome, Phase, Refused};
pub use service::{Decision, Service};

/// A pairing request expires when nobody answers it.
pub const PAIR_REQUEST_TTL: Duration = Duration::from_secs(120);

#[cfg(test)]
use std::time::Instant;
#[cfg(test)]
use synra_protocol::ids::DeviceId;
#[cfg(test)]
use synra_protocol::pairing::PairCode;
#[cfg(test)]
use synra_protocol::session::PlatformKind;

#[cfg(test)]
mod tests {
    use super::*;

    fn a_peer() -> DeviceId {
        DeviceId::new()
    }

    fn desk() -> Desk {
        Desk::new()
    }

    #[test]
    fn a_new_desk_is_idle() {
        assert_eq!(desk().phase(), Phase::Idle);
    }

    #[test]
    fn beginning_shows_a_code_and_waits() {
        let mut desk = desk();
        let peer = a_peer();
        let offer = desk
            .begin(peer, "Pixel", PlatformKind::Android, false, Instant::now())
            .expect("an empty desk accepts a request");
        assert_eq!(desk.phase(), Phase::Waiting);
        assert_eq!(offer.code, desk.offer().expect("an offer").code);
        assert_eq!(offer.peer, peer);
    }

    #[test]
    fn a_second_request_is_refused_while_one_is_on_the_table() {
        let mut desk = desk();
        let now = Instant::now();
        desk.begin(a_peer(), "Pixel", PlatformKind::Android, false, now)
            .expect("first");
        assert_eq!(
            desk.begin(a_peer(), "Laptop", PlatformKind::Desktop, false, now),
            Err(Refused::Busy)
        );
    }

    #[test]
    fn an_asking_peer_gets_a_desk_only_when_it_is_empty() {
        let mut desk = desk();
        let now = Instant::now();
        desk.begin(a_peer(), "Pixel", PlatformKind::Android, false, now)
            .expect("first");
        assert_eq!(
            desk.receive(
                PairCode::new(123_456).expect("in range"),
                a_peer(),
                "Laptop",
                PlatformKind::Desktop,
                false,
                now
            ),
            Err(Refused::Busy)
        );
    }

    #[test]
    fn accepting_answers_with_the_peer_and_clears_the_desk() {
        let mut desk = desk();
        let peer = a_peer();
        let now = Instant::now();
        desk.receive(
            PairCode::new(42).expect("in range"),
            peer,
            "Laptop",
            PlatformKind::Desktop,
            false,
            now,
        )
        .expect("an empty desk");
        assert_eq!(desk.accept(), Ok(Outcome::Accepted { peer }));
        assert_eq!(desk.accept(), Err(Refused::NothingToAnswer));
    }

    #[test]
    fn refusing_answers_without_recording_anything() {
        let mut desk = desk();
        let peer = a_peer();
        desk.receive(
            PairCode::new(42).expect("in range"),
            peer,
            "Laptop",
            PlatformKind::Desktop,
            false,
            Instant::now(),
        )
        .expect("an empty desk");
        assert_eq!(desk.refuse(), Ok(Outcome::Declined { peer }));
        assert_eq!(desk.accept(), Err(Refused::NothingToAnswer));
    }

    #[test]
    fn only_the_initiator_can_cancel() {
        let mut desk = desk();
        let now = Instant::now();
        let peer = a_peer();
        assert_eq!(desk.cancel(), Err(Refused::NothingToAnswer));
        desk.receive(
            PairCode::new(1).expect("in range"),
            peer,
            "Laptop",
            PlatformKind::Desktop,
            false,
            now,
        )
        .expect("an empty desk");
        // The peer asked us, so we can refuse but not "cancel": cancelling is the initiator's move,
        // and pretending otherwise would send the other side a message it is not waiting for.
        assert_eq!(desk.cancel(), Err(Refused::NothingToAnswer));
        assert_eq!(desk.refuse(), Ok(Outcome::Declined { peer }));
    }

    #[test]
    fn cancelling_after_beginning_answers_the_peer() {
        let mut desk = desk();
        let peer = a_peer();
        desk.begin(peer, "Pixel", PlatformKind::Android, false, Instant::now())
            .expect("an empty desk");
        assert_eq!(desk.cancel(), Ok(Outcome::Cancelled { peer }));
        assert_eq!(desk.phase(), Phase::Done);
    }

    #[test]
    fn an_acceptance_completes_the_waiting_request() {
        let mut desk = desk();
        let peer = a_peer();
        desk.begin(peer, "Pixel", PlatformKind::Android, false, Instant::now())
            .expect("an empty desk");
        assert_eq!(desk.answered(true), Ok(Outcome::Completed { peer }));
    }

    #[test]
    fn a_request_expires_after_its_ttl() {
        let mut desk = desk();
        let now = Instant::now();
        desk.begin(a_peer(), "Pixel", PlatformKind::Android, false, now)
            .expect("an empty desk");
        assert!(!desk.expire(now + Duration::from_secs(1)));
        assert!(desk.expire(now + PAIR_REQUEST_TTL));
        assert_eq!(desk.phase(), Phase::Idle);
    }

    #[test]
    fn an_already_paired_peer_is_refused_before_a_code_is_wasted() {
        let mut desk = desk();
        let now = Instant::now();
        assert_eq!(
            desk.begin(a_peer(), "Pixel", PlatformKind::Android, true, now),
            Err(Refused::AlreadyPaired)
        );
        assert_eq!(
            desk.receive(
                PairCode::new(1).expect("in range"),
                a_peer(),
                "Pixel",
                PlatformKind::Android,
                true,
                now
            ),
            Err(Refused::AlreadyPaired)
        );
        assert_eq!(desk.phase(), Phase::Idle);
    }
}

#[cfg(test)]
mod service_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_waiting_connection_is_woken_by_the_answer() {
        let service = Service::new();
        service
            .receive(
                PairCode::new(7).expect("in range"),
                DeviceId::new(),
                "Laptop",
                PlatformKind::Desktop,
                false,
            )
            .expect("an empty desk");

        let answerer = std::sync::Arc::clone(&service);
        let waiter = std::thread::spawn(move || answerer.wait_for_decision(Duration::from_secs(5)));

        std::thread::sleep(Duration::from_millis(20));
        assert!(service.accept().is_ok());

        assert_eq!(waiter.join().expect("the waiter"), Decision::Accepted);
    }

    #[test]
    fn a_refusal_wakes_the_waiter_with_a_refusal() {
        let service = Service::new();
        service
            .receive(
                PairCode::new(8).expect("in range"),
                DeviceId::new(),
                "Laptop",
                PlatformKind::Desktop,
                false,
            )
            .expect("an empty desk");

        let answerer = std::sync::Arc::clone(&service);
        let waiter = std::thread::spawn(move || answerer.wait_for_decision(Duration::from_secs(5)));

        std::thread::sleep(Duration::from_millis(20));
        assert!(service.refuse().is_ok());

        assert_eq!(waiter.join().expect("the waiter"), Decision::Refused);
    }

    #[test]
    fn nobody_answering_ends_in_a_timeout_rather_than_a_guess() {
        let service = Service::new();
        service
            .receive(
                PairCode::new(9).expect("in range"),
                DeviceId::new(),
                "Laptop",
                PlatformKind::Desktop,
                false,
            )
            .expect("an empty desk");

        assert_eq!(
            service.wait_for_decision(Duration::from_millis(50)),
            Decision::TimedOut
        );
    }
}

#[cfg(test)]
mod dial_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_initiator_wakes_with_its_own_cancellation() {
        let service = Service::new();
        let peer = DeviceId::new();
        service
            .begin(peer, "Pixel", PlatformKind::Android, false)
            .expect("an empty desk");

        let waiter_service = std::sync::Arc::clone(&service);
        let waiter =
            std::thread::spawn(move || waiter_service.wait_for_decision(Duration::from_secs(5)));

        std::thread::sleep(Duration::from_millis(20));
        assert!(service.cancel().is_ok());

        assert_eq!(waiter.join().expect("the waiter"), Decision::Cancelled);
    }

    #[test]
    fn the_initiator_wakes_when_the_peer_accepts() {
        let service = Service::new();
        let peer = DeviceId::new();
        service
            .begin(peer, "Pixel", PlatformKind::Android, false)
            .expect("an empty desk");

        let waiter_service = std::sync::Arc::clone(&service);
        let waiter =
            std::thread::spawn(move || waiter_service.wait_for_decision(Duration::from_secs(5)));

        std::thread::sleep(Duration::from_millis(20));
        assert!(service.answered(true).is_ok());

        assert_eq!(waiter.join().expect("the waiter"), Decision::Accepted);
    }

    #[test]
    fn the_initiator_wakes_when_the_peer_refuses() {
        let service = Service::new();
        let peer = DeviceId::new();
        service
            .begin(peer, "Pixel", PlatformKind::Android, false)
            .expect("an empty desk");

        let waiter_service = std::sync::Arc::clone(&service);
        let waiter =
            std::thread::spawn(move || waiter_service.wait_for_decision(Duration::from_secs(5)));

        std::thread::sleep(Duration::from_millis(20));
        assert!(service.answered(false).is_ok());

        assert_eq!(waiter.join().expect("the waiter"), Decision::Refused);
    }
}

#[cfg(test)]
mod sink_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn a_change_calls_the_sink_the_shell_installed() {
        let service = Service::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        service.set_sink(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));

        service
            .receive(
                PairCode::new(11).expect("in range"),
                DeviceId::new(),
                "Laptop",
                PlatformKind::Desktop,
                false,
            )
            .expect("an empty desk");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        assert!(service.accept().is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
