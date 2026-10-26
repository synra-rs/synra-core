//! A minimal headless plugin. All host capabilities must be declared and granted before use.

#![forbid(unsafe_code)]

use synra_plugin_sdk::{Error, Outcome, exports};

struct Plugin;

impl exports::synra::plugin::lifecycle::Guest for Plugin {
    fn activate(_config_json: String) -> Outcome {
        Outcome::Ok(String::new())
    }

    fn deactivate() {}

    fn migrate(_from_version: String, _to_version: String) -> Outcome {
        Outcome::Ok(String::new())
    }

    fn on_tick(_tick_json: String) -> Outcome {
        Outcome::Ok(String::new())
    }
}

impl exports::synra::plugin::share::Guest for Plugin {
    fn can_handle(_item_json: String) -> String {
        r#"{"handled":false}"#.to_owned()
    }

    fn execute(_action: String, _args_json: String) -> Outcome {
        refused()
    }
}

impl exports::synra::plugin::actions::Guest for Plugin {
    fn invoke(_name: String, _args_json: String) -> Outcome {
        refused()
    }
}

fn refused() -> Outcome {
    Outcome::Err(Error {
        code: "actionNotFound".to_owned(),
        message: "this plugin has not implemented an action".to_owned(),
        details: None,
    })
}

synra_plugin_sdk::export!(Plugin);
