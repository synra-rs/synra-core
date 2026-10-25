use parking_lot::Mutex;
use std::sync::Arc;

pub(super) fn configure(
    host: &mut synra_core::Host,
    db: Arc<Mutex<synra_store::SynraDb>>,
    profile: synra_core::LocalPeer,
) {
    let network = synra_core::device_credentials::initialize_native_network(
        db,
        profile,
        synra_core::reading_millis(synra_store::sqlite::now_ms()) / 1000,
    )
    .map_err(|error| error.to_string());
    if let Err(why) = &network {
        eprintln!("synra-daemon: authenticated networking is unavailable: {why}");
    }
    host.configure_network(network);
}
