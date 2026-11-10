use synra_protocol::ids::{DeviceId, TransferId};

use super::super::*;
use super::{plugin, session};

fn an_inbox() -> SyncInbox {
    SyncInbox::begin(
        session("round-1"),
        plugin("@acme/chat"),
        DeviceId::new(),
        TransferId::new(),
        "1.2.0",
        "sha256-declared",
        3,
    )
    .expect("a round")
}

#[test]
fn chunks_are_assembled_in_index_order_not_arrival_order() {
    // ★ 这是这个类型存在的全部理由：会话知道哪一块到了，检查序列知道整包要验什么，
    // 而**字节**没有地方放 —— daemon 发文件、不收文件，它的入站路径处理的是意图。
    let mut inbox = an_inbox();
    let id = session("round-1");

    // 倒着发，而且中间插一次重传。
    inbox.absorb(&id, 2, b"ccc".to_vec()).expect("third");
    inbox.absorb(&id, 0, b"aaa".to_vec()).expect("first");
    inbox.absorb(&id, 2, b"ccc".to_vec()).expect("third again");
    inbox.absorb(&id, 1, b"bbb".to_vec()).expect("second");

    assert_eq!(inbox.held(), 3, "a retransmission added a chunk");
    // 按 index 而不是按到达顺序 —— 那是「发送端哈希过的包」与「它的一个排列」之间的区别。
    assert_eq!(inbox.assemble().expect("assembled"), b"aaabbbccc");
    assert!(inbox.session().is_complete());
}

#[test]
fn a_package_with_a_hole_is_refused_rather_than_padded() {
    // 用「恰好到了的那几块」拼出来的包会因为一个理由失败它的摘要，而那个理由说不出是哪一块丢了。
    let mut inbox = an_inbox();
    let id = session("round-1");
    inbox.absorb(&id, 0, b"aaa".to_vec()).expect("first");
    inbox.absorb(&id, 2, b"ccc".to_vec()).expect("third");

    match inbox.assemble() {
        Err(SyncError::Incomplete { missing, indexes }) => {
            assert_eq!(missing, 1);
            assert_eq!(indexes, vec![1]);
        }
        other => panic!("expected an incomplete refusal, got {other:?}"),
    }
}

#[test]
fn a_chunk_from_another_round_is_counted_and_refused() {
    // 非零的计数是「有人往这台设备发了一个它不在里面的轮次」的唯一证据，
    // 而 `WrongSession` 存在正是因为混轮会以一个摘要到最后一刻才发现不了的方式损坏一个包。
    let mut inbox = an_inbox();

    match inbox.absorb(&session("round-2"), 0, b"aaa".to_vec()) {
        Err(SyncError::WrongSession { theirs, ours }) => {
            assert_eq!(theirs, "round-2");
            assert_eq!(ours, "round-1");
        }
        other => panic!("expected a session refusal, got {other:?}"),
    }
    assert_eq!(inbox.refused_chunks(), 1);
    assert_eq!(inbox.held(), 0, "a foreign chunk was stored");
}

#[test]
fn an_index_beyond_the_declaration_is_refused_and_not_counted_as_foreign() {
    // 越界与错轮次是两件事：前者是发送端数错了，后者是发送端在另一个轮次里 ——
    // 把它们合成一个计数会让「有人发错轮次」这个信号被数错冲淡。
    let mut inbox = an_inbox();
    match inbox.absorb(&session("round-1"), 3, b"ddd".to_vec()) {
        Err(SyncError::ChunkOutOfRange { index, total }) => {
            assert_eq!(index, 3);
            assert_eq!(total, 3);
        }
        other => panic!("expected a range refusal, got {other:?}"),
    }
    assert_eq!(inbox.refused_chunks(), 0);
}
