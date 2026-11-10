use proptest::prelude::*;

use super::super::{FILES, PluginDataRoot, SUBDIRECTORIES};

/// A path a plugin might supply, including the shapes that are meant to escape.
fn arbitrary_plugin_path() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{1,8}",
        "[a-z]{1,8}/[a-z]{1,8}",
        "\\.\\./[a-z]{1,8}",
        "\\.\\./\\.\\./[a-z]{1,8}",
        "/[a-z]{1,8}",
        "/etc/[a-z]{1,8}",
        "[a-z]{1,8}/\\.\\./[a-z]{1,8}",
        "\\./[a-z]{1,8}",
        "[a-z]{1,8}//[a-z]{1,8}",
    ]
}

proptest! {
    /// Whatever a plugin supplies, a successful resolution is inside the sandbox. This is the property the
    /// whole module exists for: a resolved path a caller then opens must not be able to name the user's
    /// files.
    #[test]
    fn a_resolved_path_is_always_inside(path in arbitrary_plugin_path()) {
        let parent = std::env::temp_dir().join(format!("synra-sandbox-prop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        let sandbox = match PluginDataRoot::ensure(&parent, "@synra-plugin/prop") {
            Ok(sandbox) => sandbox,
            Err(_) => return Ok(()),
        };

        if let Ok(resolved) = sandbox.resolve(FILES, &path) {
            prop_assert!(
                sandbox.contains(&resolved),
                "{:?} resolved outside the sandbox to {}",
                path,
                resolved.display(),
            );
        }

        let _ = std::fs::remove_dir_all(&parent);
    }

    /// A subdirectory name that is not one of the two is always refused, whatever it looks like. The list is
    /// closed so a plugin cannot name a directory it was never promised.
    #[test]
    fn only_the_documented_subdirectories_resolve(name in ".{0,20}") {
        let parent = std::env::temp_dir().join(format!("synra-sandbox-sub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        let sandbox = match PluginDataRoot::ensure(&parent, "@synra-plugin/prop") {
            Ok(sandbox) => sandbox,
            Err(_) => return Ok(()),
        };

        let allowed = SUBDIRECTORIES.contains(&name.as_str());
        prop_assert_eq!(sandbox.subdirectory(&name).is_ok(), allowed);

        let _ = std::fs::remove_dir_all(&parent);
    }
}
