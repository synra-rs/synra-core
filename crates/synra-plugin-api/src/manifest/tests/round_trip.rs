use synra_capability::Capability;
use super::super::types::{Manifest, ManifestContext};
use super::parse;

#[test]
fn a_full_manifest_parses_and_survives_a_round_trip() {
    // The example from the design document, so a change to the shape is caught here rather than by an
    // author whose manifest stopped loading.
    let text = r#"{
            "$schema": "https://synra-app.dev/schema/manifest/v1.json",
            "id": "@synra-plugin/chat",
            "version": "1.2.0",
            "title": "Chat",
            "description": "cross-device chat",
            "icon": "assets/icon.svg",
            "publisher": { "id": "synra-official", "name": "Synra Official", "url": "https://synra-app.dev" },
            "license": "MIT",
            "repository": "https://github.com/synra/plugin-chat",
            "sdk": { "min": "1.0.0", "preferred": "1.2.0" },
            "wit": "synra:plugin@1.0.0",
            "runtime": {
                "headless": { "artifact": "dist/plugin.wasm", "stateful": false, "hints": ["cpu-heavy"] },
                "ui": { "artifact": "dist/ui.zip", "entry": "index.html", "defaultPage": "home" }
            },
            "capabilities": [
                { "cap": "log:*" },
                { "cap": "device:list" },
                { "cap": "device:send:*" },
                { "cap": "storage:local:read" },
                { "cap": "event:emit:_plugin.@synra-plugin/chat.*" },
                { "cap": "ui:page" },
                { "cap": "network:fetch:api.github.com" }
            ],
            "actions": [
                { "name": "send-message",
                  "args": { "type": "object", "required": ["target", "body"],
                            "properties": { "target": { "type": "string", "maxLength": 64 },
                                            "body": { "type": "string", "maxLength": 65536 } } },
                  "returns": { "type": "object", "properties": { "messageId": { "type": "string", "maxLength": 64 } } },
                  "description": "send a message" }
            ],
            "shareHandlers": [{ "kinds": ["text", "url"], "description": "recognise message text" }],
            "events": [
                { "name": "_plugin.@synra-plugin/chat.text",
                  "payload": { "type": "object", "required": ["body"],
                               "properties": { "body": { "type": "string", "maxLength": 65536 },
                                               "sentAtMs": { "type": "integer" } },
                               "additionalProperties": false } },
                { "name": "_plugin.@synra-plugin/chat.typing",
                  "payload": { "type": "object", "properties": {}, "additionalProperties": false } }
            ],
            "handles": [
                { "event": "_plugin.@synra-plugin/chat.*" },
                { "event": "_synra.transfer.completed" },
                { "event": "_synra.device.changed" }
            ],
            "compose": [{ "id": "@synra-plugin/format", "version": "^1.0.0", "optional": false }],
            "network": { "outbound": [{ "host": "api.github.com" }] },
            "pages": [
                { "key": "home", "title": "Chat", "path": "/home", "icon": "chat" },
                { "key": "settings", "title": "Settings", "path": "/settings" }
            ],
            "resources": { "preferredMemoryMb": 32, "preferredTimeoutMs": 2000 },
            "locales": { "zh-CN": { "title": "聊天", "description": "跨设备聊天" } }
        }"#;

    let manifest = parse(text);
    assert_eq!(manifest.validate(&ManifestContext::default()), Ok(()));
    assert!(manifest.is_hybrid());
    assert_eq!(manifest.capabilities.len(), 7);
    assert_eq!(manifest.events.len(), 2);
    assert_eq!(manifest.pages.len(), 2);
    assert_eq!(manifest.localised_title("zh-CN"), "聊天");

    let json = serde_json::to_string(&manifest).expect("serialises");
    let back = Manifest::from_json(&json).expect("re-parses");
    assert_eq!(back, manifest);
    // And the capability set compiles, which is what the loader actually uses.
    assert!(
        manifest
            .capability_set()
            .expect("compiles")
            .contains(&Capability::parse("device:list").expect("valid"))
    );
}

#[test]
fn a_full_manifest_with_its_artifacts_validates() {
    let text = r#"{
            "id": "@synra-plugin/chat",
            "version": "1.0.0",
            "title": "Chat",
            "publisher": { "id": "synra-official" },
            "sdk": { "min": "1.0.0" },
            "wit": "synra:plugin@1.0.0",
            "runtime": {
                "headless": { "artifact": "dist/plugin.wasm", "stateful": false },
                "ui": { "artifact": "dist/ui.zip", "entry": "index.html" }
            },
            "capabilities": [{ "cap": "log:*" }],
            "actions": [{ "name": "send" }],
            "handles": [{ "event": "_synra.device.changed" }]
        }"#;
    let manifest = parse(text);
    let context = ManifestContext {
        host_sdk: Some("1.0.0".to_owned()),
        host_wit: Some("synra:plugin@1.0.0".to_owned()),
        present_artifacts: Some(vec![
            "dist/plugin.wasm".to_owned(),
            "dist/ui.zip".to_owned(),
        ]),
    };
    assert_eq!(manifest.validate(&context), Ok(()));
}
