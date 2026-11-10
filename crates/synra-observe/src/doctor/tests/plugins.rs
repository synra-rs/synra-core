use super::super::{ProbeStatus, probe_plugin_dir};
use super::unique_suffix;

#[test]
fn a_missing_plugin_directory_is_not_a_problem() {
    // A fresh install has no plugins, and reporting that as a fault would make every new install look
    // broken.
    let dir = std::env::temp_dir().join(format!("synra-doctor-plugins-{}", unique_suffix()));
    let _ = std::fs::remove_dir_all(&dir);

    let result = probe_plugin_dir(&dir);
    assert_eq!(result.status, ProbeStatus::Ok, "{result:?}");
    assert!(result.detail.contains("no plugins"));
}

#[test]
fn a_plugin_directory_is_counted_rather_than_described() {
    let dir = std::env::temp_dir().join(format!("synra-doctor-plugins2-{}", unique_suffix()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("creates");
    for index in 0..3 {
        std::fs::write(dir.join(format!("plugin{index}")), b"x").expect("writes");
    }

    let result = probe_plugin_dir(&dir);
    assert_eq!(result.status, ProbeStatus::Ok);
    assert!(result.detail.contains('3'), "{}", result.detail);

    let _ = std::fs::remove_dir_all(&dir);
}
