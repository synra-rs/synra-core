//! The instance pool's property tests.

use super::*;
use proptest::prelude::*;

use core::time::Duration;

/// One pool operation, as a value.
#[derive(Debug, Clone)]
enum Op {
    Acquire(Option<String>),
    Release(u64),
    EndConversation(String),
    EvictIdle(u64),
}

fn arbitrary_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        proptest::option::of("[a-c]").prop_map(|c| Op::Acquire(c.map(|text: String| text))),
        (0u64..20).prop_map(Op::Release),
        "[a-c]".prop_map(Op::EndConversation),
        (0u64..10_000).prop_map(Op::EvictIdle),
    ]
}

proptest! {
    /// Whatever the sequence of operations, a stateless pool never holds more instances than its quota. The quota
    /// is what makes the pool a bound on memory rather than a suggestion, so a sequence that could exceed it is a
    /// sequence that could exhaust the machine.
    #[test]
    fn a_stateless_pool_never_exceeds_its_quota(
        limit in 0u32..6,
        ops in proptest::collection::vec(arbitrary_op(), 0..80),
    ) {
        let pool = InstancePool::new(InstancePolicy::Stateless, limit);
        let mut at = 0u64;
        for op in ops {
            at += 1;
            match op {
                Op::Acquire(conversation) => { let _ = pool.acquire(conversation.as_deref(), at); }
                Op::Release(handle) => { let _ = pool.release(handle, at); }
                Op::EndConversation(conversation) => { let _ = pool.end_conversation(&conversation); }
                Op::EvictIdle(now) => { let _ = pool.evict_idle(now); }
            }
            prop_assert!(pool.live() <= limit, "held {} of {}", pool.live(), limit);
        }
    }

    /// A stateful pool never hands two different conversations the same live instance. Round-robin would silently
    /// lose the plugin's state, and the symptom would be a plugin that works when only one thing is happening.
    #[test]
    fn a_stateful_pool_never_shares_an_instance_across_conversations(
        limit in 1u32..4,
        ops in proptest::collection::vec(arbitrary_op(), 0..60),
    ) {
        let pool = InstancePool::new(InstancePolicy::Stateful, limit);
        let mut at = 0u64;
        // Conversation to handle, for the instances that are live and bound.
        let mut bound: std::collections::HashMap<u64, String> = std::collections::HashMap::new();
        let mut busy: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for op in ops {
            at += 1;
            match op {
                Op::Acquire(conversation) => {
                    if let Ok(handle) = pool.acquire(conversation.as_deref(), at) {
                        // A handle already bound to a conversation may only be handed to that conversation.
                        if let (Some(existing), Some(wanted)) = (bound.get(&handle), conversation.as_deref()) {
                            prop_assert_eq!(existing, wanted, "instance {} served two conversations", handle);
                        }
                        if let Some(wanted) = conversation {
                            bound.insert(handle, wanted.to_owned());
                        }
                        prop_assert!(busy.insert(handle), "instance {} was handed out while busy", handle);
                    }
                }
                Op::Release(handle) => {
                    let _ = pool.release(handle, at);
                    busy.remove(&handle);
                }
                Op::EndConversation(conversation) => {
                    if let Some(handle) = pool.end_conversation(&conversation) {
                        prop_assert!(!busy.contains(&handle), "a busy instance was freed");
                        bound.remove(&handle);
                    }
                }
                Op::EvictIdle(now) => {
                    let evicted = pool.evict_idle(now);
                    for handle in evicted {
                        prop_assert!(!busy.contains(&handle), "a busy instance was evicted");
                        bound.remove(&handle);
                    }
                }
            }
        }
    }

    /// Every handle a pool issues is unique for the life of the pool. A reused handle would make a stale release
    /// hit an unrelated instance, which surfaces as a plugin whose state jumps between conversations.
    #[test]
    fn handles_are_never_reused(ops in proptest::collection::vec(arbitrary_op(), 0..60)) {
        // Recycling after one call, so every acquire makes a fresh instance and the counter is what is under test.
        let pool = InstancePool::new(InstancePolicy::Stateless, 4).with_recycling(1, Duration::ZERO);
        let mut seen = std::collections::HashSet::new();
        let mut at = 0u64;

        for op in ops {
            at += 1;
            match op {
                Op::Acquire(conversation) => {
                    if let Ok(handle) = pool.acquire(conversation.as_deref(), at) {
                        prop_assert!(seen.insert(handle), "handle {} was issued twice", handle);
                    }
                }
                Op::Release(handle) => { let _ = pool.release(handle, at); }
                Op::EndConversation(conversation) => { let _ = pool.end_conversation(&conversation); }
                Op::EvictIdle(now) => { let _ = pool.evict_idle(now); }
            }
        }
    }

    /// A stopped pool is empty and refuses everything, whatever the sequence that came before. A stopped plugin's
    /// instances hold memory and state that no longer correspond to anything.
    #[test]
    fn a_stopped_pool_is_empty_and_refuses(
        policy_stateful in any::<bool>(),
        ops in proptest::collection::vec(arbitrary_op(), 0..40),
    ) {
        let policy = if policy_stateful { InstancePolicy::Stateful } else { InstancePolicy::Stateless };
        let pool = InstancePool::new(policy, 4);
        let mut at = 0u64;
        for op in ops {
            at += 1;
            match op {
                Op::Acquire(conversation) => { let _ = pool.acquire(conversation.as_deref(), at); }
                Op::Release(handle) => { let _ = pool.release(handle, at); }
                Op::EndConversation(conversation) => { let _ = pool.end_conversation(&conversation); }
                Op::EvictIdle(now) => { let _ = pool.evict_idle(now); }
            }
        }

        pool.stop();
        prop_assert_eq!(pool.live(), 0);
        prop_assert!(!pool.is_running());
        prop_assert!(matches!(pool.acquire(None, at), Err(PoolRefusal::NotRunning)));
    }
}
