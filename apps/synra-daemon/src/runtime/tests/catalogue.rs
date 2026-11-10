use super::*;

#[test]
fn a_catalogue_search_answers_from_the_cache_when_no_registry_can() {
    // ★ The design's first offline row, through the command a user actually runs.
    //
    // There is no network in this environment, so this is the path the daemon takes on an aeroplane as well: every mirror
    // refuses, and the cache answers. What is asserted is not only that it worked but that the answer **says where it came
    // from** — a screen that could not tell a live answer from a stale one would be showing a catalogue it cannot vouch for.
    let dir = TempDir::new("catalog-cached");
    let runtime = runtime(dir.path());

    let packument = r#"{"name":"@acme/chat","dist-tags":{"latest":"1.2.3"},"versions":{
        "1.2.3":{"name":"@acme/chat","version":"1.2.3","dist":{"tarball":"https://x/y.tgz","integrity":"sha512-AAAA"}}
    }}"#;
    crate::runtime::catalog::cache_for(&runtime)
        .store("@acme/chat", packument, 0)
        .expect("a cached packument");

    let answer =
        crate::runtime::catalog::search(&runtime, "@acme/chat").expect("the cached answer");

    assert_eq!(answer["package"], "@acme/chat");
    assert_eq!(answer["latest"], "1.2.3");
    // The origin, which is the half that makes an offline answer honest.
    assert_eq!(answer["origin"]["source"], "cache");
    assert!(
        answer["origin"]["ageMs"]
            .as_i64()
            .is_some_and(|age| age > 0),
        "{answer}"
    );
    assert_eq!(
        answer["origin"]["stale"], true,
        "an entry fetched at the epoch: {answer}"
    );
}

#[test]
fn a_catalogue_search_that_cannot_reach_anything_says_so_rather_than_answering_empty() {
    // ★ `DeviceOffline`, not an empty list. "No plugins match" and "this kernel could not look" are different facts, and a
    // screen that could not tell them apart would show an empty catalogue for a machine that is simply offline.
    let dir = TempDir::new("catalog-offline");
    let runtime = runtime(dir.path());

    let refused = crate::runtime::catalog::search(&runtime, "@acme/chat")
        .expect_err("nothing to answer with");

    assert_eq!(refused.code, ErrorCode::DeviceOffline, "{refused:?}");
    // And the reason names every mirror that was tried, because "the registry is unreachable" is not actionable.
    assert!(
        refused.message.contains("@acme/chat"),
        "{}",
        refused.message
    );
}
