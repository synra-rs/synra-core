//! Produce authorization examples from the same parser and grant set as the host.

use serde::Serialize;
use synra_capability::{Capability, CapabilitySet};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Decision<'a> {
    grants: &'a [&'a str],
    query: &'a str,
    valid_grants: bool,
    valid_query: bool,
    allowed: bool,
}

fn decide<'a>(grants: &'a [&'a str], query: &'a str) -> Decision<'a> {
    let mut set = CapabilitySet::new();
    let valid_grants = grants.iter().all(|grant| set.insert_str(grant).is_ok());
    let parsed = Capability::parse(query);
    Decision {
        grants,
        query,
        valid_grants,
        valid_query: parsed.is_ok(),
        allowed: valid_grants && parsed.is_ok_and(|candidate| set.grants(&candidate)),
    }
}

fn main() -> Result<(), serde_json::Error> {
    let decisions = [
        decide(&[], "platform:read-clipboard"),
        decide(&["platform:read-clipboard"], "platform:read-clipboard"),
        decide(&["platform:write-clipboard"], "platform:read-clipboard"),
        decide(&["platform:*"], "platform:read-clipboard"),
        decide(&["platform:clipboard:read"], "platform:read-clipboard"),
        decide(&["device:send:*"], "device:send:desktop_A"),
        decide(&["device:send:*"], "device:send:desktop_A:meta"),
        decide(&["network:fetch:**"], "network:fetch"),
        decide(&["network:fetch:**"], "network:fetch:example.test:POST"),
        decide(&["network:**:POST"], "network:fetch:example.test:POST"),
        decide(&["network:**:POST"], "network:fetch:example.test:GET"),
        decide(
            &["network:fetch:example.test:POST"],
            "network:fetch:example.test:POST",
        ),
        decide(
            &["network:fetch:example.test:POST"],
            "network:fetch:Example.Test:POST",
        ),
        decide(&["storage:**"], "network:fetch:example.test"),
        decide(&["fs:read:/data/*"], "fs:read:/data/leaf"),
        decide(&["fs:read:/data/*"], "fs:read:/data/nested/leaf"),
        decide(&["fs:read:/data/**"], "fs:read:/data/nested/leaf"),
        decide(
            &["event:emit:_plugin.@acme/chat.*"],
            "event:emit:_plugin.@acme/chat.open",
        ),
        decide(
            &["event:emit:_plugin.@acme/chat.*"],
            "event:emit:_plugin.@acme/chat.open.more",
        ),
        decide(
            &["network:fetch:api.*.test"],
            "network:fetch:api.example.test",
        ),
        decide(&["*"], "platform:read-clipboard"),
        decide(&["**"], "platform:read-clipboard"),
        decide(&["*:read"], "fs:read"),
        decide(&["unknown:read"], "fs:read"),
        decide(&["fs::read"], "fs:read"),
        decide(&["fs:**"], "fs:read\n"),
        decide(&["fs:**"], "fs:read:/data/file\n"),
        decide(&["fs:**"], "fs:read:a:b:c:d:e"),
    ];
    serde_json::to_writer_pretty(std::io::stdout().lock(), &decisions)
}
