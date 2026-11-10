//! The diagnostic bundle's tests.

use std::path::{Path, PathBuf};

use crate::audit::AuditEntry;
use crate::metrics::MetricsSnapshot;

use super::plan::*;
use super::records::*;
use super::sections::*;

use super::*;
use rstest::rstest;

fn sources() -> BundleSources {
    BundleSources {
        environment: Some(EnvSummary {
            app_version: "1.0.0".to_owned(),
            kernel_version: "1.0.0".to_owned(),
            os: "windows".to_owned(),
            arch: "x86_64".to_owned(),
            webview_version: Some("120.0".to_owned()),
        }),
        config: Some(serde_json::json!({ "listen_port": 32100 })),
        devices: Some(vec![DeviceRecord {
            device_id: "0193".to_owned(),
            paired: true,
            online: true,
        }]),
        plugins: Some(vec![PluginRecord {
            plugin_id: "@synra-plugin/chat".to_owned(),
            version: "1.0.0".to_owned(),
            active: true,
            had_refusals: true,
        }]),
        metrics: Some(Box::new(MetricsSnapshot::default())),
        log_lines: Some(vec![
            "ts=1 level=INFO event=start peer=abc".to_owned(),
            "ts=2 level=ERROR payload=the secret message".to_owned(),
            "ts=3 level=DEBUG device_name=my-laptop".to_owned(),
        ]),
        crashes: Some(Vec::new()),
        probes: Some(Vec::new()),
        audit: Some(Vec::new()),
    }
}

fn plan() -> BundlePlan {
    BundlePlan::plan(sources(), 1_700_000_000_000, PathBuf::from("/tmp/bundle.json"))
}

mod consent;
mod contents;
mod rendering;
mod receipts;
mod sections;
