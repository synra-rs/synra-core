use super::{EventRegistry, PluginKey};

mod bounds;
mod matching;
mod numbering;
mod reporting;
mod unregister;

fn key(name: &str) -> PluginKey {
    PluginKey::new(name)
}

fn rules(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn registry() -> EventRegistry {
    EventRegistry::new()
}
