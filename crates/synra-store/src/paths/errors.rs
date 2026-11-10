/// Why a path is not usable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// A directory could not be created.
    #[error("the directory {path:?} cannot be created: {detail}")]
    Unwritable {
        /// The directory.
        path: String,
        /// What the operating system said.
        detail: String,
    },

    /// A plugin supplied a path that leaves its sandbox.
    #[error("the path {path:?} is outside {root:?}")]
    Escapes {
        /// The path as the plugin wrote it.
        path: String,
        /// The sandbox root.
        root: String,
    },

    /// A plugin supplied a path that is not relative.
    #[error("the path {0:?} is absolute, and a plugin's paths are relative to its sandbox")]
    Absolute(String),

    /// A path could not be resolved.
    #[error("the path {path:?} cannot be resolved: {detail}")]
    Unresolvable {
        /// The path.
        path: String,
        /// What the operating system said.
        detail: String,
    },

    /// A directory tree could not be removed.
    #[error("the directory {path:?} cannot be removed: {detail}")]
    RemovalFailed {
        /// The directory.
        path: String,
        /// What the operating system said.
        detail: String,
    },

    /// A component of a path is not usable.
    #[error("the path {path:?} has an unusable component {component:?}")]
    BadComponent {
        /// The whole path.
        path: String,
        /// The offending component.
        component: String,
    },
}
