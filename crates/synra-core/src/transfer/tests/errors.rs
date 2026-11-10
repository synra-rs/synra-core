use std::path::PathBuf;

use synra_protocol::ids::TransferId;

use super::super::TransferError;

#[test]
fn every_error_explains_itself() {
    let errors = [
        TransferError::Read { path: PathBuf::from("/tmp/a"), why: "denied".to_owned() },
        TransferError::Write { path: PathBuf::from("/tmp/b"), why: "full".to_owned() },
        TransferError::ChunkSize { size: 0, max: 256 },
        TransferError::UnknownTransfer(TransferId::new()),
        TransferError::BlockTooLong { len: 9, size: 4 },
        TransferError::BlockOutOfRange { index: 9, total: 3 },
        TransferError::Incomplete { missing: 2, total: 5 },
        TransferError::DigestMismatch { actual: "a".to_owned(), expected: "b".to_owned() },
        TransferError::CompletionMismatch { found: "c".to_owned(), promised: "d".to_owned() },
        TransferError::ZeroChunkSize(0),
    ];
    for error in &errors {
        let text = error.to_string();
        assert!(text.len() > 15, "{error:?} -> {text}");
        assert!(!text.contains('{'), "{error:?} -> {text}");
    }
    // And the mismatch names both digests, because "integrity mismatch" alone leaves a user with nothing to compare.
    let text = errors[7].to_string();
    assert!(text.contains('a') && text.contains('b'), "{text}");
}
