use super::*;

#[test]
fn an_artifact_with_an_entry_builds() {
    let artifact = artifact(&[("index.html", 100), ("app.js", 200), ("app.css", 50)]);
    assert_eq!(artifact.entry(), "index.html");
    assert_eq!(artifact.len(), 3);
    assert_eq!(artifact.total_bytes(), 350);
    assert!(!artifact.is_empty());
}

#[test]
fn an_empty_listing_is_refused() {
    // An artifact with no files has no interface, and a page that loads nothing is a blank window rather than an
    // error a user can act on.
    assert_eq!(UiArtifact::build(index(&[])), Err(ArtifactError::Empty));
}

#[test]
fn too_many_files_is_refused_before_the_paths_are_checked() {
    // The count is what bounds the work: a listing of a million entries should fail on its count rather than after
    // a million path validations.
    let files: Vec<(String, u64)> = (0..=MAX_ARTIFACT_FILES)
        .map(|index| (format!("file{index}.js"), 1))
        .collect();
    let mut listing = index(&[]);
    listing.files = files;
    match UiArtifact::build(listing) {
        Err(ArtifactError::TooManyFiles { found, limit }) => {
            assert_eq!(found, MAX_ARTIFACT_FILES + 1);
            assert_eq!(limit, MAX_ARTIFACT_FILES);
        }
        other => panic!("expected a count refusal, got {other:?}"),
    }
}

#[test]
fn an_oversized_artifact_is_refused() {
    let listing = with_entry(&[("blob.bin", MAX_ARTIFACT_BYTES)]);
    match UiArtifact::build(listing) {
        Err(ArtifactError::TooLarge { limit, .. }) => assert_eq!(limit, MAX_ARTIFACT_BYTES),
        other => panic!("expected a size refusal, got {other:?}"),
    }
}

#[test]
fn a_duplicate_path_is_refused() {
    // An archive with two entries under one name is one whose extraction order decides the contents, and nothing
    // about it says which the author meant.
    let mut listing = with_entry(&[("app.js", 10)]);
    listing.files.push(("app.js".to_owned(), 20));
    match UiArtifact::build(listing) {
        Err(ArtifactError::DuplicatePath { path }) => assert_eq!(path, "app.js"),
        other => panic!("expected a duplicate refusal, got {other:?}"),
    }
}

#[test]
fn a_missing_entry_document_is_refused() {
    // A manifest naming an entry the bundle does not have is a blank window, and the refusal says which name.
    let mut listing = index(&[("app.js", 10)]);
    listing.entry = "index.html".to_owned();
    match UiArtifact::build(listing) {
        Err(ArtifactError::MissingEntry { entry }) => assert_eq!(entry, "index.html"),
        other => panic!("expected a missing entry, got {other:?}"),
    }
}

#[test]
fn the_default_page_is_carried_from_the_manifest() {
    let mut listing = with_entry(&[]);
    listing.default_page = Some("settings".to_owned());
    let artifact = UiArtifact::build(listing).expect("builds");
    assert_eq!(artifact.default_page(), Some("settings"));
}
