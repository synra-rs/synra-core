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

use std::time::{Duration, Instant};

use synra_protocol::ids::DeviceId;
use synra_protocol::pairing::{PairCode, PairRequest};
use synra_protocol::session::PlatformKind;

/// 一份请求在没有答复时会失效。
///
/// ★ 两分钟：足够一个人走到另一台设备前，短到不会在一天之后还挂着一个「正在配对」的窗口。
pub const PAIR_REQUEST_TTL: Duration = Duration::from_secs(120);

/// 当前摆在桌上的东西。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 什么都没发生。
    Idle,
    /// 本机发起了配对，正在等对方答复。码显示在本机。
    Waiting,
    /// 对端发起了配对，正在等本机的人决定。码显示在对方。
    Asked,
    /// 已有一方接受，记录已经交给调用方去写。
    Done,
}

/// 发起方看到的东西：码，以及这条请求什么时候失效。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// 要显示给本机用户的码。
    pub code: PairCode,
    /// 对端。
    pub peer: DeviceId,
    /// 对端自称的名称。
    pub peer_name: String,
    /// 对端平台。
    pub peer_platform: PlatformKind,
}

/// 接收方看到的东西：谁在问，以及要跟对方屏幕比对的码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// 对方屏幕上的码，本机要显示给用户。
    pub code: PairCode,
    /// 发起方。
    pub peer: DeviceId,
    /// 发起方自称的名称。
    pub peer_name: String,
    /// 发起方平台。
    pub peer_platform: PlatformKind,
}

/// 一个人做了一件事之后，调用方该做什么。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 本机接受了对方的请求：给对端回 `PAIR_RESPONSE{accepted:true}`，然后**两侧各写一行**。
    Accepted {
        /// 对方。
        peer: DeviceId,
    },
    /// 本机拒绝了对方的请求：回 `PAIR_RESPONSE{accepted:false}`，不写任何记录。
    Declined {
        /// 对方。
        peer: DeviceId,
    },
    /// 本机撤回了自己的请求：给对端回 `PAIR_CANCEL`。
    Cancelled {
        /// 对方。
        peer: DeviceId,
    },
    /// 对端接受了本机的请求：写记录，不回复。
    Completed {
        /// 对方。
        peer: DeviceId,
    },
}

/// 为什么有人点了却什么也没发生。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// 桌上没有对应的东西（已经答复过、已经撤回、或从未发起）。
    NothingToAnswer,
    /// 已经有一份请求在桌上：同一时刻只能谈一件事。
    Busy,
    /// 对方已经被本机记录过。
    AlreadyPaired,
}

/// 一张桌子。
#[derive(Debug)]
pub struct Desk {
    state: State,
}

#[derive(Debug)]
enum State {
    Idle,
    Waiting {
        offer: Offer,
        expires_at: Instant,
    },
    Asked {
        ask: Ask,
        expires_at: Instant,
    },
    Done { accepted: bool },
}

impl Default for Desk {
    fn default() -> Self {
        Self::new()
    }
}

impl Desk {
    /// 一张空桌。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Idle,
        }
    }

    /// 当前状态。界面用它决定画什么。
    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self.state {
            State::Idle => Phase::Idle,
            State::Waiting { .. } => Phase::Waiting,
            State::Asked { .. } => Phase::Asked,
            State::Done { .. } => Phase::Done,
        }
    }

    /// 本机发起的请求，若正等着答复。
    #[must_use]
    pub const fn offer(&self) -> Option<&Offer> {
        match &self.state {
            State::Waiting { offer, .. } => Some(offer),
            _ => None,
        }
    }

    /// 对端发起的请求，若正等着本机的人决定。
    #[must_use]
    pub const fn ask(&self) -> Option<&Ask> {
        match &self.state {
            State::Asked { ask, .. } => Some(ask),
            _ => None,
        }
    }

    /// 已完成的这次配对是否被接受；还没完成时为 `None`。
    #[must_use]
    pub const fn accepted(&self) -> Option<bool> {
        match self.state {
            State::Done { accepted } => Some(accepted),
            _ => None,
        }
    }

    /// 本机发起一次配对。
    ///
    /// # Errors
    ///
    /// [`Refused::Busy`]：桌上已经有一份请求。**覆盖它会让另一个人正在看的码静默失效。**
    /// [`Refused::AlreadyPaired`]：`known` 说对方已在记录里，再配一次没有意义。
    pub fn begin(
        &mut self,
        peer: DeviceId,
        peer_name: impl Into<String>,
        peer_platform: PlatformKind,
        already_paired: bool,
        now: Instant,
    ) -> Result<PairRequest, Refused> {
        if !matches!(self.state, State::Idle | State::Done { .. }) {
            return Err(Refused::Busy);
        }
        if already_paired {
            return Err(Refused::AlreadyPaired);
        }
        let offer = Offer {
            code: PairCode::generate(),
            peer,
            peer_name: peer_name.into(),
            peer_platform,
        };
        let request = PairRequest::new(
            offer.code,
            offer.peer,
            offer.peer_name.clone(),
            offer.peer_platform,
        );
        self.state = State::Waiting {
            offer,
            expires_at: now + PAIR_REQUEST_TTL,
        };
        Ok(request)
    }

    /// 收到对端的请求。
    ///
    /// # Errors
    ///
    /// 与 [`Self::begin`] 同：本机正忙，或对方已经在记录里。
    pub fn receive(
        &mut self,
        code: PairCode,
        peer: DeviceId,
        peer_name: impl Into<String>,
        peer_platform: PlatformKind,
        already_paired: bool,
        now: Instant,
    ) -> Result<Ask, Refused> {
        if !matches!(self.state, State::Idle | State::Done { .. }) {
            return Err(Refused::Busy);
        }
        if already_paired {
            return Err(Refused::AlreadyPaired);
        }
        let ask = Ask {
            code,
            peer,
            peer_name: peer_name.into(),
            peer_platform,
        };
        self.state = State::Asked {
            ask: ask.clone(),
            expires_at: now + PAIR_REQUEST_TTL,
        };
        Ok(ask)
    }

    /// 本机的人接受了对方。
    ///
    /// # Errors
    ///
    /// [`Refused::NothingToAnswer`]：桌上没有等着答复的请求。
    pub fn accept(&mut self) -> Result<Outcome, Refused> {
        match std::mem::replace(&mut self.state, State::Done { accepted: true }) {
            State::Asked { ask, .. } => Ok(Outcome::Accepted { peer: ask.peer }),
            previous => {
                self.state = previous;
                Err(Refused::NothingToAnswer)
            }
        }
    }

    /// 本机的人拒绝了对方。
    ///
    /// # Errors
    ///
    /// 同 [`Self::accept`]。
    pub fn refuse(&mut self) -> Result<Outcome, Refused> {
        match std::mem::replace(&mut self.state, State::Done { accepted: false }) {
            State::Asked { ask, .. } => Ok(Outcome::Declined { peer: ask.peer }),
            previous => {
                self.state = previous;
                Err(Refused::NothingToAnswer)
            }
        }
    }

    /// 本机撤回了自己的请求。
    ///
    /// # Errors
    ///
    /// [`Refused::NothingToAnswer`]：本机没有正在等待的请求（对端发起的那份不能由本机「取消」，
    /// 那是拒绝）。
    pub fn cancel(&mut self) -> Result<Outcome, Refused> {
        match std::mem::replace(&mut self.state, State::Done { accepted: true }) {
            State::Waiting { offer, .. } => Ok(Outcome::Cancelled { peer: offer.peer }),
            previous => {
                self.state = previous;
                Err(Refused::NothingToAnswer)
            }
        }
    }

    /// 对端答复了本机的请求。
    ///
    /// # Errors
    ///
    /// [`Refused::NothingToAnswer`]：本机没有正在等待的请求。
    pub fn answered(&mut self, accepted: bool) -> Result<Outcome, Refused> {
        let done = State::Done { accepted };
        match std::mem::replace(&mut self.state, done) {
            State::Waiting { offer, .. } if accepted => Ok(Outcome::Completed { peer: offer.peer }),
            State::Waiting { offer, .. } => Ok(Outcome::Declined { peer: offer.peer }),
            previous => {
                self.state = previous;
                Err(Refused::NothingToAnswer)
            }
        }
    }

    /// 到点之后把过期的请求清掉。
    ///
    /// 返回 `true` 表示桌上那份已经作废，调用方应该把界面收回去（对方的码也随之失效）。
    pub fn expire(&mut self, now: Instant) -> bool {
        let expired = match &self.state {
            State::Waiting { expires_at, .. } | State::Asked { expires_at, .. } => now >= *expires_at,
            State::Idle | State::Done { .. } => false,
        };
        if expired {
            self.state = State::Idle;
        }
        expired
    }

    /// 回到空桌，用于「忘记」之后或用户关掉面板。
    pub fn reset(&mut self) {
        self.state = State::Idle;
    }
}

/// 把一张桌子变成两个线程之间的约定。
///
/// # 为什么需要它，而不是让调用方自己加锁
///
/// 配对的两个人不在同一个线程里：接收方的人点「接受」发生在外壳的命令线程上，
/// 而等这个答复的是那条连接的线程。中间需要一个**带超时的等待**——不是轮询，
/// 也不是让连接线程去读界面状态。
///
/// `Condvar` 在这里是合适的原语：一个讲「状态变了」，一个讲「等到什么时候」，
/// 而这两件事正好就是配对需要表达的全部。
pub struct Service {
    desk: std::sync::Mutex<Desk>,
    decided: std::sync::Condvar,
    /// 每次状态变化加一，等待方用它判断「这次醒来是因为我关心的事，还是因为超时」。
    revision: std::sync::atomic::AtomicU64,
}

/// 一次等待的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// 人接受了。
    Accepted,
    /// 人拒绝了。
    Refused,
    /// 到点也没有人回答。
    TimedOut,
}

impl Service {
    /// 一张空桌，可以被多个线程共享。
    #[must_use]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            desk: std::sync::Mutex::new(Desk::new()),
            decided: std::sync::Condvar::new(),
            revision: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn desk(&self) -> std::sync::MutexGuard<'_, Desk> {
        // A poisoned desk is still a desk: the panic that poisoned it did not leave a half-written code behind, and
        // refusing every later pairing because an unrelated thread panicked would be the worse failure.
        self.desk.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn bump(&self) {
        self.revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.decided.notify_all();
    }

    /// 当前状态，供界面渲染。
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.desk().phase()
    }

    /// 本机发起的请求，若正等着答复。
    #[must_use]
    pub fn offer(&self) -> Option<Offer> {
        self.desk().offer().cloned()
    }

    /// 对端发起的请求，若正等着本机的人决定。
    #[must_use]
    pub fn ask(&self) -> Option<Ask> {
        self.desk().ask().cloned()
    }

    /// 已完成的这次配对是否被接受；还没完成时为 `None`。
    #[must_use]
    pub fn accepted(&self) -> Option<bool> {
        self.desk().accepted()
    }

    /// 本机发起一次配对。
    ///
    /// # Errors
    ///
    /// 桌上已经有一份请求，或对方已在记录里。
    pub fn begin(
        &self,
        peer: DeviceId,
        peer_name: impl Into<String>,
        peer_platform: PlatformKind,
        already_paired: bool,
    ) -> Result<PairRequest, Refused> {
        let answer = self
            .desk()
            .begin(peer, peer_name, peer_platform, already_paired, Instant::now());
        if answer.is_ok() {
            self.bump();
        }
        answer
    }

    /// 收到对端的请求，并把人要看到的码交回给调用方去通知界面。
    ///
    /// # Errors
    ///
    /// 桌上已经有一份请求，或对方已在记录里。
    pub fn receive(
        &self,
        code: PairCode,
        peer: DeviceId,
        peer_name: impl Into<String>,
        peer_platform: PlatformKind,
        already_paired: bool,
    ) -> Result<Ask, Refused> {
        let answer = self.desk().receive(
            code,
            peer,
            peer_name,
            peer_platform,
            already_paired,
            Instant::now(),
        );
        if answer.is_ok() {
            self.bump();
        }
        answer
    }

    /// 本机的人接受了对方。
    ///
    /// # Errors
    ///
    /// 桌上没有等着答复的请求。
    pub fn accept(&self) -> Result<Outcome, Refused> {
        let answer = self.desk().accept();
        if answer.is_ok() {
            self.bump();
        }
        answer
    }

    /// 本机的人拒绝了对方。
    ///
    /// # Errors
    ///
    /// 桌上没有等着答复的请求。
    pub fn refuse(&self) -> Result<Outcome, Refused> {
        let answer = self.desk().refuse();
        if answer.is_ok() {
            self.bump();
        }
        answer
    }

    /// 本机撤回了自己的请求。
    ///
    /// # Errors
    ///
    /// 本机没有正在等待的请求。
    pub fn cancel(&self) -> Result<Outcome, Refused> {
        let answer = self.desk().cancel();
        if answer.is_ok() {
            self.bump();
        }
        answer
    }

    /// 对端答复了本机的请求。
    ///
    /// # Errors
    ///
    /// 本机没有正在等待的请求。
    pub fn answered(&self, accepted: bool) -> Result<Outcome, Refused> {
        let answer = self.desk().answered(accepted);
        if answer.is_ok() {
            self.bump();
        }
        answer
    }

    /// 等一个人回答桌上那份请求，最多等到 `timeout`。
    ///
    /// 连接线程用它代替轮询：它不是「每隔一会儿看一眼界面」，而是「界面变了就叫醒我」。
    #[must_use]
    pub fn wait_for_decision(&self, timeout: Duration) -> Decision {
        let deadline = Instant::now() + timeout;
        let mut desk = self.desk();
        loop {
            match desk.phase() {
                Phase::Asked => {}
                // Somebody already answered (or reset the desk) while we were not looking.
                _ => return self.decision_of(&desk),
            }
            let now = Instant::now();
            if now >= deadline || desk.expire(now) {
                return Decision::TimedOut;
            }
            let wait = deadline.saturating_duration_since(now);
            let (next, _) = self
                .decided
                .wait_timeout(desk, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            desk = next;
        }
    }

    /// 读完状态之后把它换算成等待方的答案。
    fn decision_of(&self, desk: &Desk) -> Decision {
        // `Asked` 只有在「还没人回答」时才成立；能走到这里的都不是 `Asked`。
        match desk.accepted() {
            Some(true) => Decision::Accepted,
            Some(false) => Decision::Refused,
            None => Decision::TimedOut,
        }
    }

    /// 回到空桌。`forget` 之后或用户关掉面板时用。
    pub fn reset(&self) {
        self.desk().reset();
        self.bump();
    }
}

impl Default for Service {
    fn default() -> Self {
        Self {
            desk: std::sync::Mutex::new(Desk::new()),
            decided: std::sync::Condvar::new(),
            revision: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

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
        let request = desk
            .begin(peer, "Pixel", PlatformKind::Android, false, Instant::now())
            .expect("an empty desk accepts a request");
        assert_eq!(desk.phase(), Phase::Waiting);
        assert_eq!(request.code().expect("six digits"), desk.offer().expect("an offer").code);
        assert_eq!(request.from, peer);
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
            desk.receive(PairCode::new(1).expect("in range"), a_peer(), "Pixel", PlatformKind::Android, true, now),
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
