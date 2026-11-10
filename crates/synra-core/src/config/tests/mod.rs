//! Configuration keys, value validation and storage.

use serde_json::json;

use super::{Catalog, Setting, SettingKey, SettingKind};

fn key(text: &str) -> SettingKey {
    SettingKey::parse(text).expect("a valid key")
}

fn catalog() -> Catalog {
    let mut catalog = Catalog::new();
    catalog
        .register(
            Setting::new("transfer.maxConcurrent", SettingKind::Integer, json!(2), "how many at once")
                .expect("a valid setting"),
        )
        .register(
            Setting::new("transfer.resume", SettingKind::Bool, json!(true), "continue a broken transfer")
                .expect("a valid setting"),
        )
        .register(
            Setting::new("ui.locale", SettingKind::Text, json!("en"), "the language")
                .expect("a valid setting"),
        )
        .register(
            Setting::new("internal.schemaVersion", SettingKind::Integer, json!(1), "written by the kernel")
                .expect("a valid setting")
                .reserved(),
        );
    catalog
}

mod keys;
mod kinds;
mod overrides;
mod patch;
mod document;
mod catalog;
