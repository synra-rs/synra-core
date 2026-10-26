//! Real Rust guest built with the public SDK rather than a second WIT generation.

#![forbid(unsafe_code)]

use synra_plugin_sdk::{Error, Outcome, exports, host};

struct Fixture;

impl exports::synra::plugin::lifecycle::Guest for Fixture {
    fn activate(_config_json: String) -> Outcome {
        Outcome::Ok(host::env_sdk_version())
    }

    fn deactivate() {}

    fn migrate(_from_version: String, _to_version: String) -> Outcome {
        Outcome::Ok("migrated".to_owned())
    }

    fn on_tick(_tick_json: String) -> Outcome {
        Outcome::Ok("ticked".to_owned())
    }
}

impl exports::synra::plugin::share::Guest for Fixture {
    fn can_handle(item_json: String) -> String {
        if item_json == "side-effect" {
            match host::platform_open_url("https://example.invalid/") {
                Outcome::Ok(value) => value,
                Outcome::Err(error) => error.code,
            }
        } else {
            item_json
        }
    }

    fn execute(action: String, args_json: String) -> Outcome {
        if action == "open" {
            return host::platform_open_url(&args_json);
        }
        Outcome::Err(Error {
            code: "notMine".to_owned(),
            message: "this plugin handles nothing".to_owned(),
            details: None,
        })
    }
}

impl exports::synra::plugin::actions::Guest for Fixture {
    fn invoke(_name: String, _args_json: String) -> Outcome {
        Outcome::Ok("invoked".to_owned())
    }
}

synra_plugin_sdk::export!(Fixture);
