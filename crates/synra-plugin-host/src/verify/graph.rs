//! The dependency graph, as a value a caller can build and a verifier can walk.
//!
//! # Why this is a type and not a `BTreeMap`
//!
//! Two reasons, and they are the same two that made the registry's containers types.
//!
//! `synra-plugin-host` is semi-stable, and a standard container in a public signature is a promise about
//! `std::collections` rather than about this crate: naming `BTreeMap` makes "this crate changed no line" compatible
//! with "a consumer's build broke".
//!
//! And a graph is not a map. What a caller has is *edges* — "this plugin needs that one" — and what a verifier asks is
//! whether a walk from a plugin comes back to it. A `BTreeMap<String, Vec<String>>` says the storage; this says the
//! meaning, and it is why `find_cycle` takes a graph rather than a map.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Which plugins depend on which.
///
/// Ordered by plugin name, because the walk that finds a cycle has to produce **the same** cycle twice: a report that
/// named a different path on each run would be one nobody could act on.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DependencyGraph(BTreeMap<String, Vec<String>>);

impl DependencyGraph {
    /// An empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `plugin` depends on `dependency`.
    ///
    /// Appends rather than replaces, so a caller can build the graph one declaration at a time — which is what reading
    /// a package's manifest per plugin produces.
    pub fn add(&mut self, plugin: impl Into<String>, dependency: impl Into<String>) {
        self.0.entry(plugin.into()).or_default().push(dependency.into());
    }

    /// Records every dependency of one plugin at once.
    pub fn set(&mut self, plugin: impl Into<String>, dependencies: Vec<String>) {
        self.0.insert(plugin.into(), dependencies);
    }

    /// What a plugin depends on.
    ///
    /// An empty slice for a plugin the graph has never heard of, which is the right answer for both "it has no
    /// dependencies" and "it is not in the graph" — a walk that had to distinguish them would stop at the first
    /// unknown name.
    #[must_use]
    pub fn edges(&self, plugin: &str) -> &[String] {
        self.0.get(plugin).map_or(&[], Vec::as_slice)
    }

    /// Every plugin the graph has an entry for.
    pub fn plugins(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// How many plugins the graph has an entry for.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the graph has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A cycle reachable from a plugin, as the path that closes it.
    ///
    /// # Why the search starts where it does
    ///
    /// Because a cycle this plugin is not part of is somebody else's problem: the question the pipeline asks is
    /// "would installing this loop", and a cycle among three plugins it does not depend on would not.
    ///
    /// The path is returned rather than a boolean, because "there is a cycle" leaves an author with a graph to search
    /// and "a -> b -> a" does not.
    ///
    /// # Why this is iterative
    ///
    /// Because a dependency graph is data from a package, and a deep one would be a stack overflow in the process that
    /// is checking whether the package is safe to run.
    #[must_use]
    pub fn cycle_from(&self, start: &str) -> Option<Vec<String>> {
        let mut path: Vec<String> = Vec::new();
        let mut on_path: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut finished: std::collections::HashSet<String> = std::collections::HashSet::new();

        // An explicit stack rather than recursion: see above.
        let mut stack: Vec<(String, usize)> = vec![(start.to_owned(), 0)];
        let _ = on_path.insert(start.to_owned());
        path.push(start.to_owned());

        while let Some((node, next)) = stack.pop() {
            let edges = self.edges(&node);
            // The bound is checked before the read rather than with a `?`, because a `?` here would return `None` —
            // which means "no cycle" — for a graph that had merely been walked to the end of one node's edges.
            let Some(child) = edges.get(next).cloned() else {
                let _ = on_path.remove(&node);
                let _ = finished.insert(node);
                let _ = path.pop();
                continue;
            };
            stack.push((node, next + 1));
            if on_path.contains(&child) {
                // The path from the child's first appearance is the cycle, and it ends where it starts.
                let mut cycle: Vec<String> =
                    path.iter().skip_while(|node| **node != child).cloned().collect();
                cycle.push(child);
                return Some(cycle);
            }
            if finished.contains(&child) {
                continue;
            }
            let _ = on_path.insert(child.clone());
            path.push(child.clone());
            stack.push((child, 0));
        }

        None
    }
}

impl FromIterator<(String, Vec<String>)> for DependencyGraph {
    fn from_iter<T: IntoIterator<Item = (String, Vec<String>)>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(edges: &[(&str, &[&str])]) -> DependencyGraph {
        let mut built = DependencyGraph::new();
        for (plugin, dependencies) in edges {
            built.set(
                (*plugin).to_owned(),
                dependencies.iter().map(|name| (*name).to_owned()).collect(),
            );
        }
        built
    }

    #[test]
    fn a_plugin_the_graph_has_never_heard_of_has_no_dependencies() {
        // Rather than `None`, which a walk would have to handle at every step: "it has none" and "it is not in the
        // graph" lead to the same place, and a walk that stopped at the first unknown name would report a cycle in
        // every graph that mentions a plugin only as a dependency.
        let built = graph(&[("a", &["b"])]);
        assert_eq!(built.edges("a"), ["b".to_owned()]);
        assert!(built.edges("b").is_empty());
        assert!(built.edges("never-seen").is_empty());
        assert_eq!(built.len(), 1);
        assert!(!built.is_empty());
    }

    #[test]
    fn adding_one_edge_at_a_time_builds_the_same_graph() {
        let mut built = DependencyGraph::new();
        built.add("a", "b");
        built.add("a", "c");
        assert_eq!(built.edges("a"), ["b".to_owned(), "c".to_owned()]);
        // Appending rather than replacing, because a caller builds this one declaration at a time.
        let at_once = graph(&[("a", &["b", "c"])]);
        assert_eq!(built, at_once);
    }

    #[test]
    fn a_cycle_is_the_path_that_closes_it() {
        let built = graph(&[("a", &["b"]), ("b", &["c"]), ("c", &["a"])]);
        let cycle = built.cycle_from("a").expect("a cycle");
        assert_eq!(cycle.first(), cycle.last(), "{cycle:?}");
        assert_eq!(cycle.first().map(String::as_str), Some("a"));
        assert_eq!(cycle.len(), 4, "{cycle:?}");
    }

    #[test]
    fn a_plugin_that_depends_on_itself_is_a_cycle() {
        let built = graph(&[("a", &["a"])]);
        assert_eq!(built.cycle_from("a"), Some(vec!["a".to_owned(), "a".to_owned()]));
    }

    #[test]
    fn a_cycle_the_start_is_not_part_of_is_not_its_problem() {
        // The question is "would installing this loop". A cycle among plugins it does not depend on would not.
        let built = graph(&[("mine", &["good"]), ("good", &[]), ("x", &["y"]), ("y", &["x"])]);
        assert_eq!(built.cycle_from("mine"), None);
        assert!(built.cycle_from("x").is_some(), "but the cycle is there");
    }

    #[test]
    fn a_graph_with_no_cycle_walks_to_the_end() {
        let built = graph(&[("a", &["b", "c"]), ("b", &["d"]), ("c", &["d"]), ("d", &[])]);
        assert_eq!(built.cycle_from("a"), None);
    }

    #[test]
    fn a_shared_dependency_is_not_a_cycle() {
        // ★ The walk marks a node finished rather than only "on the path", and this is the fixture that tells the two
        // apart: `a` reaches `d` twice, and a search that treated the second arrival as a loop would report one.
        let built = graph(&[("a", &["b", "d"]), ("b", &["d"]), ("d", &[])]);
        assert_eq!(built.cycle_from("a"), None);
    }

    #[test]
    fn the_cycle_is_the_same_on_every_run() {
        // A report that named a different path each time would be one nobody could act on, which is why the graph is
        // ordered and the walk follows that order.
        let built = graph(&[("a", &["b", "c"]), ("b", &["a"]), ("c", &["a"])]);
        let first = built.cycle_from("a");
        for _ in 0..8 {
            assert_eq!(built.cycle_from("a"), first);
        }
    }

    #[test]
    fn a_very_deep_chain_does_not_overflow_a_stack() {
        // The search is iterative because a dependency graph is data from a package.
        let mut built = DependencyGraph::new();
        for index in 0..20_000 {
            built.set(format!("p{index}"), vec![format!("p{}", index + 1)]);
        }
        built.set("p20000".to_owned(), Vec::new());
        assert_eq!(built.cycle_from("p0"), None);
    }

    #[test]
    fn a_graph_round_trips_through_json() {
        // It crosses the IPC boundary with the rest of a candidate, so the shape has to survive the trip.
        let built = graph(&[("a", &["b"]), ("b", &[])]);
        let json = serde_json::to_string(&built).expect("serialises");
        assert!(json.starts_with('{'), "{json}");
        let back: DependencyGraph = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, built);
    }
}
