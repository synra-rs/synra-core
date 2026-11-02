//! 配对的三条消息在线上是什么样子。
//!
//! # 为什么是集成测试
//!
//! 因为「答复是对哪一条请求的答复」这件事只在信封层成立：`pairing` 那一层存的是码与状态，
//! 它刻意不认识 `replyTo`。把两侧放在一个测试里，才能确认发出去的那条答复真的挂回了那条请求——
//! 而不是靠两个单元测试各自证明自己那一半。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use synra_core::messaging::{pair_cancel, pair_request, pair_response};
use synra_protocol::ids::{DeviceId, TraceId};
use synra_protocol::pairing::{PairCode, PairRequest, PairResponse};
use synra_protocol::session::PlatformKind;

fn a_request(from: DeviceId) -> PairRequest {
    PairRequest::new(
        PairCode::new(123).expect("in range"),
        from,
        "Pixel",
        PlatformKind::Android,
    )
}

#[test]
fn the_answer_comes_back_from_the_device_that_was_asked() {
    let asker = DeviceId::new();
    let answerer = DeviceId::new();
    let request = pair_request(
        asker,
        answerer,
        &a_request(asker),
        TraceId::new(),
        1_000,
    )
    .expect("a request");
    let answer = pair_response(
        answerer,
        asker,
        PairResponse::accept(),
        TraceId::new(),
        1_100,
    )
    .expect("an answer");

    let sent = serde_json::to_value(&request).expect("the request");
    let answered = serde_json::to_value(&answer).expect("the answer");
    // ★ 答复不带 `replyTo`，这是刻意的：一条配对连接上只有一次问答，读到 `PAIR_RESPONSE` 就是这次答复。
    // 引一条请求进来会让「一次一码」的规矩看起来像「可以并发多码」，而那是这张桌子明确拒绝的。
    assert_eq!(answered["event"], "_synra.pair.response");
    assert_eq!(answered["from"], sent["target"], "答复来自被问的那台设备");
    assert_eq!(answered["target"], sent["from"], "并且回到发问的那台");
}

#[test]
fn the_code_reads_back_as_the_six_digits_it_was_sent_as() {
    let from = DeviceId::new();
    let envelope = pair_request(
        from,
        DeviceId::new(),
        &a_request(from),
        TraceId::new(),
        0,
    )
    .expect("a request");

    let sent = serde_json::to_value(&envelope).expect("the request");
    let payload: PairRequest =
        serde_json::from_value(sent["payload"].clone()).expect("the payload decodes");

    assert_eq!(payload.code, "000123", "前导零在 JSON 里保留");
    assert_eq!(payload.from, from, "请求里写的是发起方，不是被问的那台");
    assert_eq!(payload.display_name, "Pixel", "对方看到的名称来自发起方");
    assert_eq!(
        payload.code().expect("six digits").as_text(),
        "000123",
        "读回来还是同一个码"
    );
}

#[test]
fn a_withdrawal_carries_nothing() {
    let envelope = pair_cancel(DeviceId::new(), DeviceId::new(), TraceId::new(), 0)
        .expect("a withdrawal");

    let sent = serde_json::to_value(&envelope).expect("the withdrawal");
    assert_eq!(sent["event"], "_synra.pair.cancel");
    assert!(
        sent.get("payload").is_none(),
        "撤回不需要理由，也就没有载荷: {sent}"
    );
}
