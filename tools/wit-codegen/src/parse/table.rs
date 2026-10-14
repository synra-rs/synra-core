use std::collections::BTreeMap;

use crate::parse::{Contract, Function, Gate};

impl Contract {
    /// The capability table: each host function's import name, and what it is gated on.
    ///
    /// A `BTreeMap` rather than a `Vec`, because the host looks a gate up by name and the CLI looks a name up by
    /// import — and a sorted map makes both a binary search and the generated file's diff stable.
    #[must_use]
    pub fn capability_table(&self) -> BTreeMap<String, Gate> {
        let mut table = BTreeMap::new();
        let Some(host) = self.host() else {
            return table;
        };
        for function in &host.functions {
            table.insert(function.import_name(&self.package, &host.name), function.gate.clone());
        }
        table
    }

    /// Every capability the table mentions, sorted and deduplicated.
    ///
    /// The list a manifest's `capabilities` block is validated against, and the list the permission dialog shows.
    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        let mut capabilities: Vec<String> = self
            .capability_table()
            .values()
            .filter_map(|gate| gate.capability().map(str::to_owned))
            .collect();
        capabilities.sort();
        capabilities.dedup();
        capabilities
    }

    /// The functions a plugin may call with no capability.
    #[must_use]
    pub fn ungated(&self) -> Vec<&Function> {
        // Only the *host's* functions: the interfaces a plugin exports are the host calling the plugin, so listing their
        // entry points here would put `activate` in a list a reviewer reads as "host calls any plugin may make".
        self.host().map_or_else(Vec::new, |host| {
            host.functions.iter().filter(|function| function.gate.is_ungated()).collect()
        })
    }

    /// Every function name, whether gated or not.
    ///
    /// The list the plugin CLI checks an artifact's imports against — a built component names functions, and one naming
    /// a function this file does not declare is one the host cannot answer.
    #[must_use]
    pub fn provided_names(&self) -> Vec<String> {
        // Only the host's functions: a component's import section names what the *host* provides, and the plugin's own
        // exported entry points are what it implements rather than what it may call.
        self.host().map_or_else(Vec::new, |host| {
            host.functions.iter().map(|function| function.name.clone()).collect()
        })
    }

    /// A summary for a person.
    #[must_use]
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("{}@{}", self.package, self.version)];
        lines.push(format!("world {}", self.world));
        // Only the interfaces the world *names*. `types` is declared in the file and named by nobody: it is a bag of
        // shared definitions, not something a plugin implements or the host provides, and listing it as an export with
        // no functions is noise a reader has to work out.
        for (name, direction) in &self.world_names {
            let functions = self
                .interfaces
                .iter()
                .find(|interface| interface.name == *name)
                .map_or(0, |interface| interface.functions.len());
            lines.push(format!("{} {name} ({functions} function(s))", direction.as_str()));
        }
        let table = self.capability_table();
        let ungated = table.values().filter(|gate| gate.is_ungated()).count();
        lines.push(format!(
            "{} gated function(s), {ungated} ungated, {} distinct capabilit(ies)",
            table.len() - ungated,
            self.capabilities().len()
        ));
        lines
    }
}
