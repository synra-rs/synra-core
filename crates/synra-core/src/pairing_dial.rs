//! 发起侧：拨过去，把码给对方看，等一个答复。
//!
//! # 为什么这不像接收侧那样「挂着等」
//!
//! 接收侧等的是**本机的人**，桌子变了就能醒；发起侧等的是**对面的人**，答复从 socket 来。
//! 所以这里是一个读取循环：每读到一条消息就看它是不是答复，每读不到就回头看桌子是不是已经被本机取消。
//!
//! # 超时不在这里数
//!
//! 两分钟的上限在 [`crate::pairing::PAIR_REQUEST_TTL`]，由桌子的 `expire` 管；这条连接自己的读超时
//! 只是让它有机会**回头看桌子**，不是配对的截止时间。两件事混成一个计时器，会让「读超时」看起来像
//! 「配对超时」，而它们该给用户看的话完全不同。

use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::path::Path;

use parking_lot::Mutex;
use synra_protocol::ids::{DeviceId, TraceId};
use synra_protocol::pairing::{PairRequest, PairResponse, PAIR_CANCEL, PAIR_RESPONSE};
use synra_protocol::session::PlatformKind;

use crate::host::Host;

/// 这条配对连接最后怎么了。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finished {
    /// 对面接受了。
    Paired,
    /// 对面拒绝了。
    Refused,
    /// 本机在对方答复前撤回了。
    Cancelled,
    /// 两分钟过去，谁也没给答复。
    TimedOut,
}

/// 发起配对失败在哪一步。
#[derive(Debug)]
pub enum DialError {
    /// 连不过去。
    Dial(String),
    /// 连上了，但请求发不出去。
    Send(String),
    /// 读不到答复，而本机也没有取消。
    Read(String),
}

/// 拨过去，等一个答复，必要时写记录。
///
/// # Errors
///
/// [`DialError::Dial`] 握手失败；[`DialError::Send`] 请求发不出去；
/// [`DialError::Read`] 连接断了而本机并没有取消。
pub fn dial(
    host: &std::sync::Arc<Mutex<Host>>,
    address: SocketAddr,
    peer: DeviceId,
    peer_name: &str,
    peer_platform: PlatformKind,
    request: &PairRequest,
    data_dir: &Path,
) -> Result<Finished, DialError> {
    // ★ `request` 里是发起方（本机）的身份，`peer` 是要连的那台。
    // 两者不能互换：互换会让本机把自己写进记录，也会把答复的方向写反。
    let (local, desk) = {
        let host = host.lock();
        (host.local_peer().clone(), host.pairing())
    };
    let now_ms = synra_store::sqlite::now_ms();
    // ★ 握手不持锁：`dial` 会在锁内做完整个 Hello 交换，而 `devices` 读列表时等的就是这把锁。
    // 分段调用让那次交换发生在锁外，只有"记下这条链路"这一步回到锁内。
    let now = u64::try_from(now_ms).unwrap_or(0);
    let (parts, flags) = host.lock().dialling_parts();
    let dialled = crate::host::dial_peer(&parts, flags, address, peer, now).map_err(|error| {
        // ★ 拨号失败也要收桌：否则这份没人等的请求会让下一次配对永远得到 Busy。
        desk.reset();
        DialError::Dial(error.to_string())
    })?;
    let mut link = host.lock().adopt(dialled, now).map_err(|error| {
        desk.reset();
        DialError::Dial(error.to_string())
    })?;

    let envelope = crate::messaging::pair_request(
        local.device_id,
        peer,
        request,
        TraceId::new(),
        now_ms,
    )
    .map_err(|error| {
        desk.reset();
        DialError::Send(error.to_string())
    })?;
    link.send(&envelope).map_err(|error| {
        desk.reset();
        DialError::Send(error.to_string())
    })?;

    let finished = wait_for_answer(&desk, &mut link).inspect_err(|_| {
        desk.reset();
    })?;
    if finished == Finished::Cancelled {
        // 撤回要告诉对面：否则那台设备的弹窗会一直摆到两分钟到期。
        if let Ok(cancel) = crate::messaging::pair_cancel(
            local.device_id,
            peer,
            TraceId::new(),
            synra_store::sqlite::now_ms(),
        ) {
            let _ = link.send(&cancel);
        }
    }
    if finished == Finished::Paired {
        let _ = crate::pairing_record::record_paired(
            data_dir,
            peer,
            peer_name,
            peer_platform,
            Some(address.to_string()),
            now_ms,
        );
    }
    Ok(finished)
}

/// 读到答复、读到撤回，或读到本机已经取消。
fn wait_for_answer(
    desk: &crate::pairing::Service,
    link: &mut crate::link::PeerLink,
) -> Result<Finished, DialError> {
    // ★ 200 毫秒的读超时不是配对的截止时间，而是让这条循环有机会回头看一眼桌子：
    // 本机的撤回发生在外壳的命令线程上，而这里可能正卡在 socket 上。
    link.set_read_timeout(Some(Duration::from_millis(200)));
    let deadline = Instant::now() + crate::pairing::PAIR_REQUEST_TTL;
    loop {
        // ★ 先看桌子：本机的取消发生在外壳的命令线程上，而这条循环可能正卡在 socket 上。
        match desk.phase() {
            crate::pairing::Phase::Done => return Ok(settled(desk)),
            crate::pairing::Phase::Idle => return Ok(Finished::TimedOut),
            _ => {}
        }
        if Instant::now() >= deadline {
            desk.reset();
            return Ok(Finished::TimedOut);
        }
        match link.receive() {
            Ok(answer) if answer.event.as_str() == PAIR_RESPONSE => {
                let accepted = answer
                    .payload
                    .as_ref()
                    .and_then(|raw| serde_json::from_str::<PairResponse>(raw.get()).ok())
                    .is_some_and(|response| response.accepted);
                let _ = desk.answered(accepted);
                return Ok(settled(desk));
            }
            // 对面在我们答复前先撤了：码已经没用，桌子要按「撤回」收，而不是按「拒绝」——
            // `refuse` 只对接收方的 `Asked` 有效，在 `Waiting` 上会失败，桌子便一直挂着。
            Ok(answer) if answer.event.as_str() == PAIR_CANCEL => {
                let _ = desk.cancel();
                return Ok(Finished::Cancelled);
            }
            // 这条短连接上不该有别的消息；有也读掉，不当作答复。
            Ok(_) => {}
            Err(crate::link::LinkError::TimedOut) => {}
            Err(error) => {
                if desk.phase() == crate::pairing::Phase::Done {
                    return Ok(settled(desk));
                }
                return Err(DialError::Read(error.to_string()));
            }
        }
    }
}

/// 从桌上读出这次配对的下场。
fn settled(desk: &crate::pairing::Service) -> Finished {
    match (desk.accepted(), desk.cancelled()) {
        (Some(true), _) => Finished::Paired,
        (_, true) => Finished::Cancelled,
        (Some(false), false) => Finished::Refused,
        (None, false) => Finished::TimedOut,
    }
}

/// 把码读出来，供外壳展示。
///
/// # Errors
///
/// 桌上没有本机发起的请求。
pub fn code_of(desk: &crate::pairing::Service) -> Option<synra_protocol::pairing::PairCode> {
    desk.offer().map(|offer| offer.code)
}
