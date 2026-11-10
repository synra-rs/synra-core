use std::sync::Arc;

use parking_lot::Mutex;
use synra_protocol::ids::PluginId;

use super::KernelHost;

mod calls;
mod fetch;

fn id(name: &str) -> PluginId {
    PluginId::try_from(name.to_owned()).expect("a plugin id")
}

fn host_with(grants: &[(&str, bool)]) -> KernelHost {
    let mut db = synra_store::SynraDb::open_in_memory().expect("a database");
    db.migrate().expect("migrates");
    db.insert_plugin("@acme/notes", true, true, "healthy", 1, 1).expect("a plugin row");
    let decisions: Vec<(String, bool)> =
        grants.iter().map(|(cap, granted)| ((*cap).to_owned(), *granted)).collect();
    db.record_grants("@acme/notes", &decisions, 1, "digest").expect("decisions");
    KernelHost::new(Arc::new(Mutex::new(db)), "9.9.9")
}
