use std::path::Path;
use super::{Paths, PluginFiles};

/// A layout under a directory nobody else uses, removed when the test ends.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!("synra-pf-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }

    fn paths(&self) -> Paths {
        Paths::new(self.0.join("data"), self.0.join("cache"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fill(path: &Path) {
    std::fs::create_dir_all(path).expect("a directory");
    std::fs::write(path.join("plugin.wasm"), b"\0asm").expect("a file");
}

#[test]
fn artifacts_go_and_data_stays_by_default() {
    // ★ The default is the whole point: a user who uninstalls a plugin they may reinstall keeps its settings, and
    // deleting them unless asked would be the interface deciding what is replaceable.
    let scratch = Scratch::new("default");
    let paths = scratch.paths();
    fill(&paths.plugin_dir("@acme/hello"));
    fill(&paths.plugin_sandbox_dir("@acme/hello"));

    let removal = PluginFiles::new(paths.clone())
        .remove("@acme/hello", false)
        .expect("removes");

    assert!(removal.leftovers.is_empty(), "nothing was held back");
    assert_eq!(removal.bytes_freed, 4, "the artifact's four bytes");
    assert!(!paths.plugin_dir("@acme/hello").exists(), "artifacts are gone");
    assert!(paths.plugin_sandbox_dir("@acme/hello").exists(), "data is kept");
}

#[test]
fn asking_for_the_data_removes_it_too() {
    let scratch = Scratch::new("data");
    let paths = scratch.paths();
    fill(&paths.plugin_dir("@acme/hello"));
    fill(&paths.plugin_sandbox_dir("@acme/hello"));

    let removal = PluginFiles::new(paths.clone())
        .remove("@acme/hello", true)
        .expect("removes");

    assert!(removal.leftovers.is_empty(), "nothing was held back: {:?}", removal.leftovers);
    assert_eq!(removal.bytes_freed, 8, "artifact and sandbox");
    assert!(!paths.plugin_dir("@acme/hello").exists());
    assert!(!paths.plugin_sandbox_dir("@acme/hello").exists());
}

#[cfg(windows)]
#[test]
fn a_locked_file_is_reported_as_a_leftover_rather_than_failing() {
    // ★ A loaded engine keeps its wasm file open on Windows, and a deletion then fails. The row is already gone, so
    // refusing would leave the files behind and say nothing; the leftover list is how the caller tells the user.
    use std::os::windows::fs::OpenOptionsExt as _;

    let scratch = Scratch::new("locked");
    let paths = scratch.paths();
    let directory = paths.plugin_dir("@acme/hello");
    fill(&directory);
    // Share mode zero: no other open — including the one a removal needs — may touch the file.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(directory.join("plugin.wasm"))
        .expect("an exclusive handle");

    let removal = PluginFiles::new(paths.clone())
        .remove("@acme/hello", false)
        .expect("the refusal is reported, not thrown");
    assert_eq!(removal.leftovers, vec![directory.clone()], "the directory that survived");
    // ★ And the number does not lie: the directory is still on disk, so nothing was freed.
    assert_eq!(removal.bytes_freed, 0, "a surviving directory frees no space");
    assert!(directory.exists(), "the files are still there, as reported");

    drop(held);
    let removal = PluginFiles::new(paths).remove("@acme/hello", false).expect("removes");
    assert!(removal.leftovers.is_empty(), "a later attempt finishes the job");
    assert_eq!(removal.bytes_freed, 4, "the bytes go when the files do");
}

#[test]
fn a_second_removal_is_not_an_error() {
    // "This plugin should not be here" is satisfied by a directory that is not there.
    let scratch = Scratch::new("twice");
    let paths = scratch.paths();
    fill(&paths.plugin_dir("@acme/hello"));

    PluginFiles::new(paths.clone()).remove("@acme/hello", false).expect("first");
    let second = PluginFiles::new(paths).remove("@acme/hello", false).expect("second");
    assert_eq!(second.bytes_freed, 0, "there was nothing left to free");
}

#[test]
fn the_size_is_the_artifacts_and_the_data_when_asked() {
    // ★ Measured before the removal, and only the data when it is going: the number is what a user is told a removal
    // frees, so counting a sandbox that stays would be telling them they got space back they did not.
    let scratch = Scratch::new("size");
    let paths = scratch.paths();
    fill(&paths.plugin_dir("@acme/hello"));
    fill(&paths.plugin_sandbox_dir("@acme/hello"));
    let files = PluginFiles::new(paths);

    assert_eq!(files.size_of("@acme/hello", false), 4, "the artifact's four bytes");
    assert_eq!(files.size_of("@acme/hello", true), 8, "artifact and sandbox");
    assert_eq!(files.size_of("@acme/absent", true), 0, "a directory that is not there");
}

#[test]
fn a_sweep_takes_orphan_artifacts_and_leaves_everything_else() {
    // ★ The second chance a leftover gets: the row is gone, so the artifact directory is trash no later code can
    // reach. The sandbox is not — data kept on purpose is a user's settings — and a stray file in the artifact root is
    // somebody else's business.
    let scratch = Scratch::new("sweep");
    let paths = scratch.paths();
    fill(&paths.plugin_dir("@acme/hello"));
    fill(&paths.plugin_dir("@acme/orphan"));
    fill(&paths.plugin_sandbox_dir("@acme/orphan"));
    std::fs::write(paths.plugins_dir().join("README"), b"keep").expect("a stray file");

    let sweep = PluginFiles::new(paths.clone())
        .sweep_orphans(&["@acme/hello".to_owned()])
        .expect("sweeps");

    assert_eq!(sweep.removed, vec![paths.plugin_dir("@acme/orphan")]);
    assert_eq!(sweep.bytes_freed, 4, "the orphan's artifact bytes, not its data");
    assert!(sweep.leftovers.is_empty());
    assert!(paths.plugin_dir("@acme/hello").exists(), "an installed plugin is not touched");
    assert!(!paths.plugin_dir("@acme/orphan").exists());
    assert!(
        paths.plugin_sandbox_dir("@acme/orphan").exists(),
        "data is kept until the user says otherwise"
    );
    assert!(paths.plugins_dir().join("README").exists(), "a file is not a directory");
}

#[cfg(windows)]
#[test]
fn a_sweep_reports_an_orphan_it_still_cannot_remove() {
    use std::os::windows::fs::OpenOptionsExt as _;

    let scratch = Scratch::new("sweep-locked");
    let paths = scratch.paths();
    let directory = paths.plugin_dir("@acme/orphan");
    fill(&directory);
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(directory.join("plugin.wasm"))
        .expect("an exclusive handle");

    let sweep = PluginFiles::new(paths.clone())
        .sweep_orphans(&[])
        .expect("the sweep reports rather than throws");
    assert_eq!(sweep.removed, Vec::<std::path::PathBuf>::new());
    assert_eq!(sweep.leftovers, vec![directory]);
    assert_eq!(sweep.bytes_freed, 0, "nothing left the disk");

    drop(held);
    let sweep = PluginFiles::new(paths).sweep_orphans(&[]).expect("sweeps");
    assert_eq!(sweep.bytes_freed, 4, "the next start finishes the job");
    assert!(sweep.leftovers.is_empty());
}
