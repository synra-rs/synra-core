use std::time::{Duration, Instant};

use synra_protocol::ids::DeviceId;
use synra_protocol::pairing::PairCode;
use synra_protocol::session::PlatformKind;

use super::model::{Ask, Desk, Offer, Outcome, Phase, Refused};

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
    /// 状态变了之后叫一声。装它的是外壳：窗口不该靠轮询才知道有人在等它回答。
    sink: std::sync::Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
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
    /// 本机在对方答复前撤回了。
    Cancelled,
}

impl Service {
    /// 一张空桌，可以被多个线程共享。
    #[must_use]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            desk: std::sync::Mutex::new(Desk::new()),
            decided: std::sync::Condvar::new(),
            revision: std::sync::atomic::AtomicU64::new(0),
            sink: std::sync::Mutex::new(None),
        })
    }

    fn desk(&self) -> std::sync::MutexGuard<'_, Desk> {
        // A poisoned desk is still a desk: the panic that poisoned it did not leave a half-written code behind, and
        // refusing every later pairing because an unrelated thread panicked would be the worse failure.
        self.desk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn bump(&self) {
        self.revision
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.decided.notify_all();
        let sink = self
            .sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(sink) = sink {
            sink();
        }
    }

    /// 装上「配对变了」的通知者。装两次就替换，不叠加。
    pub fn set_sink(&self, sink: std::sync::Arc<dyn Fn() + Send + Sync>) {
        *self
            .sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sink);
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

    /// 这次配对是不是本机自己撤回的。
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.desk().cancelled()
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
    ) -> Result<Offer, Refused> {
        let answer = self.desk().begin(
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

    /// Withdraws the incoming request when its sender cancels or disconnects.
    ///
    /// # Errors
    /// There is no incoming request waiting for a decision.
    pub fn withdrawn(&self) -> Result<Outcome, Refused> {
        let answer = self.desk().withdrawn();
        if answer.is_ok() {
            self.bump();
        }
        answer
    }

    /// Announces completion again after the durable pairing record has been written.
    /// The initial decision wakes the socket worker; this notification lets readers refresh the stored device list.
    pub fn recorded(&self) {
        self.bump();
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
                Phase::Asked | Phase::Waiting => {}
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
    const fn decision_of(&self, desk: &Desk) -> Decision {
        // `Asked` 只有在「还没人回答」时才成立；能走到这里的都不是 `Asked`。
        match (desk.accepted(), desk.cancelled()) {
            (Some(true), _) => Decision::Accepted,
            (_, true) => Decision::Cancelled,
            (Some(false), false) => Decision::Refused,
            (None, false) => Decision::TimedOut,
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
            sink: std::sync::Mutex::new(None),
        }
    }
}
