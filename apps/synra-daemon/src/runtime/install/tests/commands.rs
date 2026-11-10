use super::*;

#[test]
fn the_command_installs_and_answers_that_it_is_not_enabled() {
    // The whole path a client uses: `Request::PluginInstall` → `Kernel::plugin_install` → the pipeline → a row. What it
    // asserts is the answer, because a command that installed silently would leave the caller believing nothing happened.
    let dir = TempDir::new("install-command");
    let source = package(dir.path(), "source", &manifest(&["log:*"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let runtime = crate::runtime::tests::runtime(dir.path());

    let answer = runtime
        .plugin_install(source.to_str().expect("a UTF-8 path"))
        .expect("the command installs");

    assert_eq!(answer["pluginId"], "@acme/hello");
    assert_eq!(answer["version"], "1.2.3");
    assert_eq!(answer["enabled"], false);
    assert!(answer["warnings"].as_array().is_some_and(Vec::is_empty));
}

#[test]
fn the_command_reports_a_refusal_as_an_invalid_argument() {
    let dir = TempDir::new("install-command-bad");
    let source =
        package(dir.path(), "source", &manifest(&["platform:teleport"], "plugin.wasm"), &[("plugin.wasm", wasm())]);
    let runtime = crate::runtime::tests::runtime(dir.path());

    let refusal = runtime
        .plugin_install(source.to_str().expect("a UTF-8 path"))
        .expect_err("the command refuses");

    assert_eq!(refusal.code, synra_protocol::error::ErrorCode::InvalidArgument);
    assert!(refusal.message.contains("capability-syntax"), "{}", refusal.message);
}
