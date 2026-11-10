use synra_plugin_api::publisher::PublisherTrustStore;
use super::super::{DependencyGraph, Stage, VerifyError, verify};
use super::Fixture;

#[test]
fn a_dependency_cycle_stops_at_that_step_and_names_the_cycle() {
    // ★ The check a single plugin's own edges cannot make: a cycle is a property of the graph.
    let mut fixture = Fixture::new();
    let mut graph = DependencyGraph::new();
    graph.set("@acme/hello".to_owned(), vec!["@acme/other".to_owned()]);
    graph.set("@acme/other".to_owned(), vec!["@acme/hello".to_owned()]);
    fixture.graph = graph;

    match verify(&fixture.candidate(None, false), &PublisherTrustStore::new()) {
        Err((stage, VerifyError::DependencyCycle { cycle })) => {
            assert_eq!(stage, Stage::DependencyAcyclic);
            // The path closes on itself, which is what makes it readable: `a -> b -> a`.
            assert_eq!(cycle.first(), cycle.last(), "{cycle:?}");
            assert!(cycle.len() >= 2, "{cycle:?}");
        }
        other => panic!("expected a cycle refusal, got {other:?}"),
    }
}

#[test]
fn a_graph_without_a_cycle_passes() {
    let mut fixture = Fixture::new();
    let mut graph = DependencyGraph::new();
    graph.set("@acme/hello".to_owned(), vec!["@acme/a".to_owned(), "@acme/b".to_owned()]);
    graph.set("@acme/a".to_owned(), vec!["@acme/c".to_owned()]);
    graph.set("@acme/b".to_owned(), vec!["@acme/c".to_owned()]);
    graph.set("@acme/c".to_owned(), Vec::new());
    fixture.graph = graph;

    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable());
}

#[test]
fn a_cycle_this_plugin_is_not_part_of_is_not_its_problem() {
    // The question is "would installing this loop". A cycle among plugins it does not depend on would not.
    let mut fixture = Fixture::new();
    let mut graph = DependencyGraph::new();
    graph.set("@acme/hello".to_owned(), vec!["@acme/good".to_owned()]);
    graph.set("@acme/good".to_owned(), Vec::new());
    graph.set("@acme/x".to_owned(), vec!["@acme/y".to_owned()]);
    graph.set("@acme/y".to_owned(), vec!["@acme/x".to_owned()]);
    fixture.graph = graph;

    let report = verify(&fixture.candidate(None, false), &PublisherTrustStore::new()).expect("a report");
    assert!(report.is_acceptable());
}

#[test]
fn a_plugin_that_depends_on_itself_is_a_cycle() {
    let graph: DependencyGraph =
        [("@acme/hello".to_owned(), vec!["@acme/hello".to_owned()])].into_iter().collect();
    assert_eq!(graph.cycle_from("@acme/hello"), Some(vec!["@acme/hello".to_owned(), "@acme/hello".to_owned()]));
}

#[test]
fn a_deep_chain_does_not_overflow_a_stack() {
    // The search is iterative rather than recursive because a dependency graph is data from a package, and a deep one
    // would be a stack overflow in the process checking whether the package is safe to run.
    let mut graph = DependencyGraph::new();
    for index in 0..20_000 {
        graph.set(format!("@acme/p{index}"), vec![format!("@acme/p{}", index + 1)]);
    }
    graph.set("@acme/p20000".to_owned(), Vec::new());
    assert_eq!(graph.cycle_from("@acme/p0"), None);
}
