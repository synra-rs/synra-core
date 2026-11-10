//! Receiving a file: the side that decides whether the bytes are the file.
//!
//! # Why the digest is checked here and nowhere else
//!
//! Because a per-block check would tell you a block arrived, not that the file did. The one digest over the whole object is
//! what makes "the transfer succeeded" mean something, and it is checked **after** every block is in place — which is why a
//! short block, a reordered splice or a wrong byte all end at the same place: a refusal.

mod flow;
mod model;

pub use model::{InboundProgress, Received, Receiving, bundle_of, version_of};

#[cfg(test)]
mod tests {
    use super::*;
    use synra_protocol::ids::PluginId;
    use synra_protocol::session::TransferMeta;

    fn a_plugin_id() -> PluginId {
        PluginId::try_from("@acme/chat".to_owned()).expect("a plugin id")
    }

    #[test]
    fn a_bundle_proposal_names_its_plugin() {
        // ★ 这条测试是第 139 轮欠下的。那一轮把 `bundle` 加进了结构、让 `Decision::Finished` 带上它、
        // 让 listener 说得出来 —— 但没有一条测试说过「插件包带着它的 plugin_id」这句话。
        let meta = TransferMeta::PluginBundle {
            plugin_id: a_plugin_id(),
            version: "1.2.0".to_owned(),
        };

        assert_eq!(bundle_of(&meta), Some(a_plugin_id()));
    }

    #[test]
    fn an_attachment_proposal_names_no_plugin() {
        // 另一半，而且是没有它时最容易出的错：把所有传输都当成包。
        let meta = TransferMeta::Attachment {
            file_name: "notes.txt".to_owned(),
            mime_type: None,
            context_id: None,
        };

        assert_eq!(bundle_of(&meta), None);
    }
}
