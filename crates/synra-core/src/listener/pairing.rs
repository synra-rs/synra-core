use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use synra_protocol::envelope::Envelope;
use crate::link::{LinkError, PeerLink};

/// 回应一次配对请求：把码摆到桌上，等一个人回答，然后回复对方。
///
/// # 为什么这里可以阻塞
///
/// 因为配对的全部内容就是「等一个人」：它不像插件列表那样有一个立刻可得的事实。每连接一个线程，
/// 所以停在这里不挡 accept 循环；而两分钟的上限保证它不会永远停下去。
pub(super) fn answer_pairing(
    link: &mut PeerLink,
    desk: &Arc<crate::pairing::Service>,
    envelope: &Envelope,
    data_dir: &Path,
    peer: &synra_protocol::ids::DeviceId,
) {
    let Some(raw) = envelope.payload.as_ref() else {
        eprintln!("synra-daemon: {peer} asked to pair without a payload");
        return;
    };
    let request: synra_protocol::pairing::PairRequest = match serde_json::from_str(raw.get()) {
        Ok(request) => request,
        Err(error) => {
            eprintln!("synra-daemon: {peer}'s pairing request could not be read: {error}");
            return;
        }
    };
    if request.from != *peer || envelope.from != *peer {
        send_pair_answer(link, peer, false);
        return;
    }
    let code = match request.code() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("synra-daemon: {peer} sent a code that is not one: {error}");
            send_pair_answer(link, peer, false);
            return;
        }
    };
    let already = synra_store::SynraDb::open(&data_dir.join(synra_store::DB_FILE_NAME))
        .ok()
        .and_then(|db| db.paired_devices().ok())
        .is_some_and(|rows| {
            rows.iter()
                .any(|row| row.device_id == request.from.to_string())
        });
    // ★ 已经配对过的设备直接拒绝，不弹窗：再配一次只会让两个人各看一遍同样的码。
    // ★ 但绝不自动确认。配对是两个人在两块屏幕上比对六个数字；一条没有弹窗的「接受」会让这段流程名存实亡。
    // 有人在问的时候，桌上已经有一份请求就不再接第二份：两个人同时看到两个码，谁也说不清该比哪一个。
    if let Err(refused) = desk.receive(
        code,
        request.from,
        request.display_name.clone(),
        request.platform,
        already,
    ) {
        eprintln!("synra-daemon: {peer} asked to pair, and the desk said {refused:?}");
        send_pair_answer(link, peer, false);
        return;
    }
    // ★ 等的是本机的人，但也要留意对面的撤回：50 毫秒的读超时让这条循环能在
    // 「读连接」和「等人」之间来回，而不是一直卡在其中一边。
    let deadline = std::time::Instant::now() + crate::pairing::PAIR_REQUEST_TTL;
    link.set_read_timeout(Some(Duration::from_millis(50)));
    let accepted = loop {
        match link.receive() {
            Ok(answer) if answer.event.as_str() == synra_protocol::pairing::PAIR_CANCEL => {
                let _ = desk.withdrawn();
                return;
            }
            Ok(_) | Err(LinkError::TimedOut) => {}
            Err(_) => {
                let _ = desk.withdrawn();
                return;
            }
        }
        match desk.wait_for_decision(Duration::from_millis(50)) {
            crate::pairing::Decision::TimedOut if std::time::Instant::now() < deadline => {}
            crate::pairing::Decision::Accepted => break true,
            _ => break false,
        }
    };
    // ★ 到点没人回答，桌子必须收回空：否则 `Asked` 会一直摆着，下一次配对永远得到 `Busy`。
    if desk.phase() == crate::pairing::Phase::Asked {
        let _ = desk.refuse();
    }
    // ★ 只有答复真的发出去了才写记录：发不出去意味着对方已经撤回，写下的会是一行单方面记录。
    if send_pair_answer(link, peer, accepted) && accepted {
        record_paired(data_dir, &request, synra_store::sqlite::now_ms());
        desk.recorded();
    }
}

/// 回一条答复。发不出去时只报告——对方等不到答复会自己超时，而这条连接还有别的用。
fn send_pair_answer(
    link: &mut PeerLink,
    peer: &synra_protocol::ids::DeviceId,
    accepted: bool,
) -> bool {
    let response = synra_protocol::pairing::PairResponse { accepted };
    // ★ 答复由**本机**发出，回到问的那台设备：`link.local()` 是本机，`peer` 是对端。
    // 把请求里的 `from` 当发送者会写出一条"发问者发给自己"的信封。
    match crate::messaging::pair_response(
        link.local(),
        *peer,
        response,
        synra_protocol::ids::TraceId::new(),
        synra_store::sqlite::now_ms(),
    ) {
        Ok(answer) => {
            if let Err(error) = link.send(&answer) {
                eprintln!("synra-daemon: the pairing answer could not be sent to {peer}: {error}");
            } else {
                return true;
            }
        }
        Err(error) => eprintln!("synra-daemon: the pairing answer could not be built: {error}"),
    }
    false
}

/// 接受之后写一行「认识这台设备了」。
///
/// 写的字段与拨号侧一致：`device_id`、名称、平台、能力位、地址、时间。**能力位是空的**——
/// 配对请求里没有 `Hello` 协商出来的交集，假装有会是比缺一行更糟的谎。
fn record_paired(data_dir: &Path, request: &synra_protocol::pairing::PairRequest, now_ms: i64) {
    let _ = crate::pairing_record::record_paired(
        data_dir,
        request.from,
        &request.display_name,
        request.platform,
        None,
        now_ms,
    );
}
