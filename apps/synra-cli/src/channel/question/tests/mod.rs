use crate::args::{DevicesArgs, LogsArgs, SendArgs};

mod inventory;
mod options;

pub(super) fn devices_args(all: bool) -> DevicesArgs {
    DevicesArgs {
        all,
        scan_ms: None,
        cached: false,
    }
}

pub(super) fn send_args(text: Option<&str>, file: Option<&str>) -> SendArgs {
    SendArgs {
        to: "dev_a".to_owned(),
        text: text.map(ToOwned::to_owned),
        file: file.map(ToOwned::to_owned),
        context: None,
    }
}

pub(super) fn logs_args(lines: u32, trace: Option<&str>, verbose: bool) -> LogsArgs {
    LogsArgs {
        follow: false,
        trace: trace.map(ToOwned::to_owned),
        lines,
        verbose,
    }
}
