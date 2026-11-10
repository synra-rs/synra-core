use std::path::PathBuf;

use super::DaemonOptions;

mod defaults;
mod paths;
mod resolution;

fn options(data_dir: &str) -> DaemonOptions {
    DaemonOptions {
        data_dir: PathBuf::from(data_dir),
        ..DaemonOptions::default()
    }
}

/// A data directory that is absolute on whichever platform the test is running on.
///
/// Windows treats `/tmp/x` as drive-relative rather than absolute, so a fixture that used one form would be an
/// absolute path on one platform and not on the other.
fn root() -> &'static str {
    if cfg!(windows) {
        "C:\\synra-data"
    } else {
        "/tmp/synra-data"
    }
}
