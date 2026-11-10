use crate::args::{DbAction, DbArgs};

mod backup;
mod inspect;

/// A directory that removes itself, so a failing test does not leave a database behind.
struct Root(std::path::PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-db-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a directory");
        Self(path)
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn args(action: DbAction) -> DbArgs {
    DbArgs { action }
}
