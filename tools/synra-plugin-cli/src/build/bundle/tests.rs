use super::*;

fn project() -> (tempfile::TempDir, BuildPlan) {
    let root = tempfile::tempdir().unwrap();
    let scaffold = crate::template::Scaffold::new(
        "@acme/bundle",
        "0.1.0",
        "Bundle",
        crate::template::TemplateKind::Headless,
    )
    .unwrap();
    for file in scaffold.files {
        let path = root.path().join(file.path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, file.contents).unwrap();
    }
    let mut plan = BuildPlan::resolve(root.path()).unwrap();
    plan.steps[0].program = "synra-deliberately-missing-builder".to_owned();
    (root, plan)
}

#[test]
fn an_unowned_output_is_refused_before_running_any_build_step() {
    let (root, plan) = project();
    std::fs::create_dir(root.path().join("dist")).unwrap();
    std::fs::write(root.path().join("dist/valuable.txt"), "keep").unwrap();
    let error = run(&plan).unwrap_err();
    assert!(error.contains("not owned"), "{error}");
    assert_eq!(
        std::fs::read(root.path().join("dist/valuable.txt")).unwrap(),
        b"keep"
    );
}

#[test]
fn concurrent_build_is_refused_before_writing_outputs() {
    let (root, plan) = project();
    let lock = std::fs::File::create(root.path().join(".synra-build.lock")).unwrap();
    fs2::FileExt::try_lock_exclusive(&lock).unwrap();
    assert!(run(&plan).unwrap_err().contains("already running"));
    assert!(!root.path().join("dist").exists());
}

#[test]
fn an_interrupted_publication_restores_the_old_package_before_a_failed_build() {
    let (root, plan) = project();
    let backup = root.path().join(".synra-build-previous");
    std::fs::create_dir(&backup).unwrap();
    let owner = Owner {
        project: std::fs::canonicalize(root.path())
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        plugin: "@acme/bundle".to_owned(),
    };
    std::fs::write(backup.join(MARKER), serde_json::to_vec(&owner).unwrap()).unwrap();
    std::fs::write(backup.join("signature.json"), "old signature").unwrap();
    let error = run(&plan).unwrap_err();
    assert!(
        error.contains("synra-deliberately-missing-builder"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(root.path().join("dist/signature.json")).unwrap(),
        b"old signature"
    );
    assert!(!backup.exists());
}

#[test]
fn abandoned_owned_staging_is_cleaned_but_unmarked_files_are_preserved() {
    let (root, plan) = project();
    let stale = root.path().join(".synra-build-abandoned");
    let unknown = root.path().join(".synra-build-user-files");
    std::fs::create_dir(&stale).unwrap();
    std::fs::create_dir(&unknown).unwrap();
    let owner = Owner {
        project: std::fs::canonicalize(root.path())
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        plugin: "@acme/bundle".to_owned(),
    };
    std::fs::write(stale.join(MARKER), serde_json::to_vec(&owner).unwrap()).unwrap();
    std::fs::write(stale.join("ui.zip"), "obsolete output").unwrap();
    std::fs::write(unknown.join("valuable.txt"), "keep").unwrap();
    assert!(run(&plan).is_err());
    assert!(!stale.exists());
    assert_eq!(
        std::fs::read(unknown.join("valuable.txt")).unwrap(),
        b"keep"
    );
}
