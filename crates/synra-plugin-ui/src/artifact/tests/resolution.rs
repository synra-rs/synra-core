use super::*;

#[test]
fn a_request_for_a_file_in_the_index_is_served() {
    let artifact = artifact(&[("index.html", 100), ("app.js", 200)]);
    let file = artifact.resolve("app.js").expect("resolves");
    assert_eq!(file.size, 200);
    assert_eq!(file.content_type.as_deref(), Some("text/javascript; charset=utf-8"));
}

#[test]
fn a_request_for_something_not_in_the_index_is_refused() {
    // A well-formed path that names nothing is a 404 in the ordinary sense — a stale reference after a rebuild.
    let artifact = artifact(&[("index.html", 100)]);
    assert!(matches!(
        artifact.resolve("missing.js"),
        Err(ArtifactError::MissingEntry { .. })
    ));
}

#[test]
fn a_traversal_is_refused_by_resolve_too() {
    // The lookup is what makes traversal impossible, and this asserts the path check runs before it — a traversal
    // that happened to name a real key would otherwise be served.
    let artifact = artifact(&[("index.html", 100), ("secret", 10)]);
    assert!(matches!(
        artifact.resolve("../secret"),
        Err(ArtifactError::BadPath { .. })
    ));
}

#[test]
fn the_index_is_the_only_thing_that_decides_what_can_be_served() {
    // There is no path arithmetic: a path either is a key or is not. A path that normalises to a real file but is
    // not spelled that way is refused.
    let artifact = artifact(&[("index.html", 100), ("assets/app.js", 200)]);
    assert!(artifact.resolve("assets/app.js").is_ok());
    assert!(artifact.resolve("assets/./app.js").is_err());
    assert!(artifact.resolve("assets//app.js").is_err());
    assert!(artifact.resolve("./assets/app.js").is_err());
}
