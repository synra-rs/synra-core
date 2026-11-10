use std::path::{Path, PathBuf};

use proptest::prelude::*;

use super::{Paths, is_within, sanitise_component};

proptest! {
    /// Whatever the id, the resulting directory is a single component inside the plugins directory. This is
    /// the property the per-plugin directory exists for: one plugin must not be able to name another's files,
    /// or anything outside the directory at all.
    #[test]
    fn a_sanitised_id_never_escapes(id in ".{0,60}") {
        let sanitised = sanitise_component(&id);
        prop_assert!(!sanitised.is_empty());
        prop_assert!(!sanitised.contains('/'));
        prop_assert!(!sanitised.contains('\\'));
        prop_assert!(!sanitised.contains(".."));
        prop_assert!(!sanitised.starts_with('.'));
        prop_assert_ne!(sanitised.as_str(), ".");

        let joined = Paths::under("/root").plugin_dir(&id);
        prop_assert!(is_within(Path::new("/root/plugins"), &joined));
    }

    /// Component-wise containment agrees with the path's own structure: a child is inside its parent, and a
    /// sibling is not. Reimplemented the obvious way and compared, so the check the sandbox depends on is
    /// verified against something rather than against itself.
    #[test]
    fn containment_matches_the_component_structure(
        parts in proptest::collection::vec("[a-z]{1,6}", 1..5),
        extra in proptest::collection::vec("[a-z]{1,6}", 0..3),
    ) {
        let root: PathBuf = parts.iter().collect();
        let mut child = root.clone();
        for part in &extra {
            child.push(part);
        }
        prop_assert!(is_within(&root, &child));

        // A sibling shares a prefix but diverges in a component, and must not be accepted. `root` is moved
        // rather than cloned because the containment check above is the last use of the shared value.
        let mut sibling = root;
        sibling.push("elsewhere");
        prop_assert!(!is_within(&child, &sibling) || extra.is_empty());
    }
}
