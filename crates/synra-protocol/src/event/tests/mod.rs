//! Event names, ownership and delivery policy.

use crate::ids::PluginId;

fn slug(text: &str) -> PluginId {
    PluginId::parse(&format!("@acme/{text}")).expect("valid plugin id")
}

mod names;
mod catalog;
mod proptests;
