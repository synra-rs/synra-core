use synra_protocol::ids::DeviceId;

use super::super::*;
use super::plugin;

#[test]
fn a_record_starts_empty_and_ends_with_a_verdict() {
    // 记录在**开始**时建立，结束时才有结局 —— 所以「没有结局」与「有结局没有结束时间」这两种
    // 自相矛盾的状态在类型上是分开的。
    let started = SyncRecord::new(
        plugin("@acme/chat"),
        DeviceId::new(),
        SyncAction::Ask {
            ours: String::new(),
            theirs: None,
        },
        1_000,
    );

    assert!(started.verdict.is_none());
    assert!(started.finished_at_ms.is_none());
    assert!(started.trace_id.is_none(), "还没认出是哪一轮");
    assert_eq!(started.bytes_transferred, 0);

    let done = started
        .identified(
            SyncId::new("sync-1"),
            SyncDirection::Push,
            Some("1.2.0".to_owned()),
            TraceId::new(),
        )
        .finished(SyncVerdict::Succeeded, 4_096, 2_000)
        .expect("the first verdict is accepted");

    assert_eq!(done.id.as_str(), "sync-1");
    assert_eq!(done.direction, SyncDirection::Push);
    assert_eq!(done.version.as_deref(), Some("1.2.0"));
    assert_eq!(done.verdict, Some(SyncVerdict::Succeeded));
    assert_eq!(done.finished_at_ms, Some(2_000));
    assert_eq!(done.bytes_transferred, 4_096);
    assert!(done.trace_id.is_some());
}

#[test]
fn a_second_verdict_is_refused_because_it_would_replace_the_first() {
    // ★ 这是 `finished` 返回 `Result` 而不是 `self` 的原因：覆盖结局是「最后的说法赢」，
    // 而那种错没人看得出来 —— 一条先失败后成功的记录会读成成功。
    let done = SyncRecord::new(
        plugin("@acme/chat"),
        DeviceId::new(),
        SyncAction::Ask {
            ours: String::new(),
            theirs: None,
        },
        1_000,
    )
    .finished(
        SyncVerdict::Failed {
            error: "the signature did not verify".to_owned(),
        },
        0,
        2_000,
    )
    .expect("the first verdict is accepted");

    match done.clone().finished(SyncVerdict::Succeeded, 10, 3_000) {
        Err(SyncError::StepRefused { step, why }) => {
            assert_eq!(step, "sync-record");
            assert!(why.contains("already"), "{why}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // 而原记录没有被改动：它仍然说失败。
    assert_eq!(
        done.verdict,
        Some(SyncVerdict::Failed {
            error: "the signature did not verify".to_owned()
        })
    );
}

#[test]
fn a_skipped_round_is_not_a_failed_one() {
    // 三态而不是布尔：跳过意味着双方已经一致，不需要任何人做什么；失败意味着有人得看一眼。
    // 合成一个 `ok: false` 会让界面把两件事说成一件。
    let skipped = SyncRecord::new(
        plugin("@acme/chat"),
        DeviceId::new(),
        SyncAction::Skip {
            why: "both devices have the same artifact".to_owned(),
        },
        1_000,
    )
    .finished(
        SyncVerdict::Skipped {
            reason: "both devices have the same artifact".to_owned(),
        },
        0,
        1_500,
    )
    .expect("a verdict");

    assert!(matches!(skipped.verdict, Some(SyncVerdict::Skipped { .. })));
    assert_ne!(
        skipped.verdict,
        Some(SyncVerdict::Failed {
            error: String::new()
        })
    );
}

#[test]
fn a_record_round_trips_through_a_database_row() {
    // 表那一半在 `synra-store`（迁移 v10）；这一半把两者接起来，而往返是唯一能证明
    // 「投影列与文档说的是同一件事」的办法 —— 三种结局各走一遍，因为 `Skipped` 与 `Failed`
    // 携带的内容不同，只测一种会漏掉另一种的字段。
    for (verdict, action) in [
        (
            SyncVerdict::Succeeded,
            SyncAction::Push {
                why: "the peer had nothing".to_owned(),
            },
        ),
        (
            SyncVerdict::Skipped {
                reason: "both ends agree".to_owned(),
            },
            SyncAction::Skip {
                why: "same digest".to_owned(),
            },
        ),
        (
            SyncVerdict::Failed {
                error: "the signature did not verify".to_owned(),
            },
            SyncAction::Refuse {
                why: "the publisher is untrusted here".to_owned(),
            },
        ),
    ] {
        let record = SyncRecord::new(plugin("@acme/chat"), DeviceId::new(), action, 1_000)
            .identified(
                SyncId::new("sync-1"),
                SyncDirection::Push,
                Some("1.2.0".to_owned()),
                TraceId::new(),
            )
            .finished(verdict, 4_096, 2_000)
            .expect("a verdict");

        let row = record.to_row().expect("serialises");
        // 投影列与文档来自同一个记录，而不是各写各的。
        assert_eq!(row.sync_id, "sync-1");
        assert_eq!(row.plugin_id, "@acme/chat");
        assert_eq!(row.peer_device, record.peer.to_string());
        assert_eq!(row.started_at_ms, 1_000);
        assert_eq!(row.finished_at_ms, Some(2_000));

        // 而整份记录回得来：包括决定里的原因、结局里的错误、字节数与追踪。
        assert_eq!(SyncRecord::from_row(&row).expect("deserialises"), record);
    }
}

#[test]
fn a_row_that_is_not_this_rounds_document_is_an_error_rather_than_a_guess() {
    // 坏文档必须是错误：一个「猜出来」的记录会让历史页面显示一轮从未发生过的同步。
    let row = synra_store::records::SyncLogRow {
        sync_id: "sync-1".to_owned(),
        plugin_id: "@acme/chat".to_owned(),
        peer_device: "device-b".to_owned(),
        started_at_ms: 1_000,
        finished_at_ms: None,
        document: "{ this is not json".to_owned(),
    };
    assert!(SyncRecord::from_row(&row).is_err());
}
