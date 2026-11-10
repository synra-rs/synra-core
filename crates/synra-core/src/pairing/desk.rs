use std::time::Instant;

use super::PAIR_REQUEST_TTL;
use super::model::{Ask, Desk, Offer, Outcome, Phase, Refused, State};
use synra_protocol::ids::DeviceId;
use synra_protocol::pairing::PairCode;
use synra_protocol::session::PlatformKind;

impl Default for Desk {
    fn default() -> Self {
        Self::new()
    }
}

impl Desk {
    /// 一张空桌。
    #[must_use]
    pub const fn new() -> Self {
        Self { state: State::Idle }
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
            State::Done { accepted, .. } => Some(accepted),
            _ => None,
        }
    }

    /// 这次配对是不是本机自己撤回的。
    #[must_use]
    pub const fn cancelled(&self) -> bool {
        match self.state {
            State::Done { cancelled, .. } => cancelled,
            _ => false,
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
    ) -> Result<Offer, Refused> {
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
        self.state = State::Waiting {
            offer: offer.clone(),
            expires_at: now + PAIR_REQUEST_TTL,
        };
        // ★ 返回「桌上摆了什么」，不造信封：发起方的身份在这一层拿不到，
        // 硬拼只会把「谁发的」写成「发给谁」。
        Ok(offer)
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
        match std::mem::replace(
            &mut self.state,
            State::Done {
                accepted: true,
                cancelled: false,
            },
        ) {
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
        match std::mem::replace(
            &mut self.state,
            State::Done {
                accepted: false,
                cancelled: false,
            },
        ) {
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
        match std::mem::replace(
            &mut self.state,
            State::Done {
                accepted: false,
                cancelled: true,
            },
        ) {
            State::Waiting { offer, .. } => Ok(Outcome::Cancelled { peer: offer.peer }),
            previous => {
                self.state = previous;
                Err(Refused::NothingToAnswer)
            }
        }
    }

    /// The requester withdrew an incoming offer before it was answered.
    ///
    /// # Errors
    /// There is no incoming offer waiting for a decision.
    pub fn withdrawn(&mut self) -> Result<Outcome, Refused> {
        match std::mem::replace(
            &mut self.state,
            State::Done {
                accepted: false,
                cancelled: true,
            },
        ) {
            State::Asked { ask, .. } => Ok(Outcome::Cancelled { peer: ask.peer }),
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
        let done = State::Done {
            accepted,
            cancelled: false,
        };
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
            State::Waiting { expires_at, .. } | State::Asked { expires_at, .. } => {
                now >= *expires_at
            }
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
