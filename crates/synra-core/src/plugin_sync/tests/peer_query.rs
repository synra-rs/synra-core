use synra_protocol::ids::DeviceId;
use synra_store::PluginVersionRecord;

use super::super::*;

#[test]
fn a_peer_answers_with_its_list_over_a_real_link() {
    // ★ Both halves, on one connection: the asker builds a request and reads the answer, while the answering side reads
    // the request and replies from its own tables. Each half has its own test; this one is the only thing that says the
    // two ends actually meet on a link — a request one side can build and an answer the other can build is not yet an
    // exchange a user can get a plan out of.
    use crate::link::Inbound;
    use crate::link::PeerLink;
    use crate::link::memory::MemoryStream;
    use crate::peer::Flags;
    use std::time::{Duration, Instant};
    use synra_protocol::handshake::Agreed;

    let (near, far) = MemoryStream::pair_with_capacity(4 * 1024 * 1024);
    let agreed = Agreed {
        common: Vec::new(),
        missing_required: Vec::new(),
    };
    let ours = DeviceId::new();
    let peer = DeviceId::new();
    let mut asking = PeerLink::new(near, ours, peer, agreed.clone(), Flags::no_timeout());
    let mut answering = PeerLink::new(far, peer, ours, agreed, Flags::no_timeout());

    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/chat", true, true, "installed", 1_000, 1_000)
        .expect("a plugin");
    db.record_plugin_version(&PluginVersionRecord {
        plugin_id: "@acme/chat",
        version: "1.2.0",
        artifact: "plugin.wasm",
        digest: "sha256-abc",
        manifest: "{}",
        installed_ms: 1_000,
        ..Default::default()
    })
    .expect("a version");

    let answerer = std::thread::spawn(move || {
        let request = match answering.receive_inbound().expect("a request") {
            Inbound::Envelope(envelope) => envelope,
            Inbound::Block { .. } => panic!("no blocks travel on this link"),
        };
        let reply = answer_plugin_list(&db, &request, peer, 1_000).expect("an answer");
        answering.send(&reply).expect("it sends");
    });

    let list = ask_plugin_list(
        &mut asking,
        ours,
        peer,
        TraceId::new(),
        1_000,
        Instant::now() + Duration::from_secs(10),
    )
    .expect("an answer");

    answerer.join().expect("the answering thread");
    assert_eq!(
        list.plugins.len(),
        1,
        "one plugin travels: {:?}",
        list.plugins
    );
    assert_eq!(list.plugins[0].version.as_deref(), Some("1.2.0"));
    assert_eq!(list.plugins[0].digest.as_deref(), Some("sha256-abc"));
}
