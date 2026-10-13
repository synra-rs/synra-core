//! Reading the WIT contract, and deriving what the host must enforce.
//!
//! # Why a parser rather than a toolchain
//!
//! A WIT file has a real parser (`wit-parser`) and this module is not a replacement for it: it reads the subset this
//! contract uses — packages, interfaces, functions, the annotations that carry capabilities — and refuses anything it
//! does not understand. A full parse would be better and would be a dependency whose version has to move with the
//! interface's, for a file this repository owns and changes deliberately.
//!
//! What matters is that it **refuses rather than guesses**. A line it cannot read is an error naming the line, not a
//! function silently missing from the capability table — because the one outcome that must not be possible is a host
//! function that is reachable without a gate.
//!
//! # What it derives
//!
//! The capability table: which capability each host function needs. That table is the thing three places have to agree
//! about and the thing they would otherwise each write down:
//!
//! * the host, which checks the gate before a call runs;
//! * the plugin CLI, which refuses an artifact that imports a function the host does not provide;
//! * the manifest's validation, which checks that a plugin declaring an entry point has declared what it needs.
//!
//! # The annotations
//!
//! `@ungated` and `@capability("…")` are read from the doc comment immediately above a function. A function with
//! neither is [`ParseError::UngatedFunction`] — deliberately an error rather than a default, because defaulting to
//! ungated is a hole and defaulting to gated invents a capability nobody chose.

use std::collections::BTreeMap;

/// Why a WIT file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// A line the parser does not understand.
    ///
    /// With the line number, because the file is written by hand and the error is the only thing that says which line
    /// went wrong.
    #[error("line {line}: {reason}")]
    Syntax {
        /// Which line, counting from one.
        line: usize,
        /// What was found.
        reason: String,
    },

    /// A function with neither `@ungated` nor `@capability`.
    ///
    /// ★ The refusal this whole module exists for. A host function without a gate is one any plugin can call, and the
    /// failure is silent: nothing in the kernel would be wrong, and nothing would say so.
    #[error("line {line}: `{function}` has neither @ungated nor @capability, so the host would not know what to check")]
    UngatedFunction {
        /// Which line.
        line: usize,
        /// The function.
        function: String,
    },

    /// The same function name twice in one interface.
    ///
    /// A WIT toolchain would refuse it too, and the reason it matters here is that the second would silently replace
    /// the first in the table — so a capability could be removed by adding a line.
    #[error("line {line}: `{function}` is declared twice in `{interface}`")]
    DuplicateFunction {
        /// Which line.
        line: usize,
        /// The function.
        function: String,
        /// The interface.
        interface: String,
    },

    /// There is no package declaration.
    #[error("the file declares no package")]
    NoPackage,

    /// The world imports or exports something that does not exist.
    ///
    /// A world naming an interface the file does not define is a world a toolchain would refuse, and the failure it
    /// would produce in the kernel is a missing import at load time.
    #[error("the world names `{name}`, which no interface in this file defines")]
    UndefinedInterface {
        /// What was named.
        name: String,
    },
}

/// What a host function is gated on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// No capability, because the call only reads a fact about the environment.
    Ungated,
    /// The capability string the host checks before the call.
    Capability(String),
}

impl Gate {
    /// The capability, when there is one.
    #[must_use]
    pub fn capability(&self) -> Option<&str> {
        match self {
            Self::Ungated => None,
            Self::Capability(capability) => Some(capability),
        }
    }

    /// Whether anything is checked.
    #[must_use]
    pub const fn is_ungated(&self) -> bool {
        matches!(self, Self::Ungated)
    }
}

/// One host function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// Its WIT name, as it appears in the file and in a component's imports.
    pub name: String,
    /// What the host checks before calling it.
    pub gate: Gate,
    /// The line it is declared on, for a message.
    pub line: usize,
}

impl Function {
    /// The import name a component would use.
    ///
    /// `synra:plugin/host#log` — the package, the interface, and the function. That is the string that appears in a
    /// compiled component's import section, which is why the CLI's check compares against this rather than against the
    /// bare name.
    #[must_use]
    pub fn import_name(&self, package: &str, interface: &str) -> String {
        format!("{package}/{interface}#{}", self.name)
    }
}

/// One interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Its name.
    pub name: String,
    /// Its functions, in the order the file declares them.
    ///
    /// Ordered rather than a map, because the order is what a reviewer reads and a generated table that reordered
    /// would produce a diff on every run.
    pub functions: Vec<Function>,
    /// Whether the world imports it or the plugin exports it.
    pub direction: Direction,
}

/// Which way an interface crosses the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// The plugin imports it: the host provides these.
    Import,
    /// The plugin exports it: the host calls these.
    Export,
}

impl Direction {
    /// The word, for a message.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
        }
    }
}

/// The parsed contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contract {
    /// The package, as `synra:plugin`.
    pub package: String,
    /// Its version, as declared.
    pub version: String,
    /// Every interface, in the order the file declares them.
    pub interfaces: Vec<Interface>,
    /// The world's name.
    pub world: String,
    /// Every name the world mentions, with its direction, in the order it mentions them.
    ///
    /// Kept rather than reduced to a direction on each interface, because "which interfaces the plugin must implement"
    /// is what the world says and not a default an interface happens to carry.
    pub world_names: Vec<(String, Direction)>,
    /// The name of the interface the world imports, when it imports exactly one.
    ///
    /// Recorded rather than derived from [`Direction`], because "which interface is the host" is a fact the world
    /// states and a search for the first import is a guess that depends on the order interfaces were declared. This
    /// kernel has one host; a second import would be a contract this parser cannot decide a table for, and
    /// [`Contract::host`] returns `None` for it rather than picking one.
    pub host_interface: Option<String>,
}

impl Contract {
    /// Reads a WIT file.
    ///
    /// # Errors
    ///
    /// [`ParseError`] naming the line. Nothing is inferred: a construct this parser does not understand is a refusal
    /// rather than a function left out of the table.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let package = parse_package(text)?;

        let mut interfaces: Vec<Interface> = Vec::new();
        let mut world: Option<(String, Vec<(String, Direction)>)> = None;
        let mut current: Option<Interface> = None;
        // The annotations seen since the last line that was not one, which is what a function's gate is read from.
        let mut pending: Vec<String> = Vec::new();
        // Every function name that carried an annotation. Needed because `Gate::Ungated` cannot be told from a default,
        // and the difference is whether the author said so.
        let mut annotated_functions: Vec<String> = Vec::new();

        for (index, raw) in text.lines().enumerate() {
            let line = index + 1;
            let trimmed = raw.trim();

            // A doc comment carrying an annotation. `///` and `//!` are both comments, so the text after the slashes
            // is what is read — and this branch comes **before** the one that skips comments, because a `///` line
            // starts with `//` and would otherwise be skipped as prose.
            if let Some(comment) = trimmed.strip_prefix("///").or_else(|| trimmed.strip_prefix("//!")) {
                let comment = comment.trim();
                if comment.starts_with('@') {
                    pending.push(comment.to_owned());
                }
                continue;
            }

            // An annotation written on its own line. The design document's example spells them this way — `@ungated`
            // rather than `/// @ungated` — and this parser accepts both: the annotation is the same either way, and
            // refusing the documented form would be a parser an author has to read the source to use.
            if let Some(annotation) = trimmed.strip_prefix('@') {
                pending.push(format!("@{annotation}"));
                continue;
            }

            // ★ A blank line does not end a doc comment. The contract puts a blank line before each group of functions
            // and around each annotation, because that is how a person reads it — and a parser that cleared its pending
            // annotations on a blank line refused every function in the file. Whitespace is layout; only a new
            // declaration is a boundary.
            if trimmed.starts_with("//") || trimmed.is_empty() {
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("interface ") {
                if let Some(finished) = current.take() {
                    interfaces.push(finished);
                }
                let name = rest
                    .split(['{', ' '])
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                if name.is_empty() {
                    return Err(ParseError::Syntax {
                        line,
                        reason: "an interface with no name".to_owned(),
                    });
                }
                current = Some(Interface {
                    name,
                    functions: Vec::new(),
                    // Decided by the world's `import`/`export` lines, and corrected below. An interface the world does
                    // not name keeps this, which is why the world check exists.
                    direction: Direction::Export,
                });
                pending.clear();
                continue;
            }

            // ★ WIT is whitespace-insensitive, so `world plugin { import host; export lifecycle; }` is one line — and a
            // parser that read only the first name on a world line dropped every other one, leaving a contract with no
            // imported interface and therefore no capability table at all. A parse that succeeds and produces no gates
            // is the worst failure this file can have, so the whole line is scanned rather than its first token.
            if let Some(rest) = trimmed.strip_prefix("world ") {
                if let Some(finished) = current.take() {
                    interfaces.push(finished);
                }
                let name = rest
                    .split(['{', ' '])
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_owned();

                // Every `import` and `export` in the body, which is what follows the first brace:
                // `world plugin { import host; }` puts the name and the brace *before* the first clause, so a scan of
                // the whole line looked for `import ` at a position holding `plugin { import` and found nothing.
                let body = rest.split_once('{').map_or("", |(_, body)| body);
                let mut names: Vec<(String, Direction)> = Vec::new();
                for clause in body.split(';') {
                    let clause = clause.trim();
                    let (direction, tail) = if let Some(tail) = clause.strip_prefix("import ") {
                        (Direction::Import, tail)
                    }
                    else if let Some(tail) = clause.strip_prefix("export ") {
                        (Direction::Export, tail)
                    }
                    else {
                        continue;
                    };
                    // A clause with no name — the trailing half a split leaves — is dropped, which is what keeps
                    // `; }` from becoming an interface called `}`.
                    let named = tail.trim().trim_end_matches(['}', '{']).trim().to_owned();
                    if !named.is_empty() {
                        names.push((named, direction));
                    }
                }

                world = Some((name, names));
                pending.clear();
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("import ") {
                let name = rest.trim_end_matches(';').trim().to_owned();
                match &mut world {
                    Some((_, names)) => names.push((name, Direction::Import)),
                    None => {
                        return Err(ParseError::Syntax {
                            line,
                            reason: "an import outside a world".to_owned(),
                        });
                    }
                }
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("export ") {
                let name = rest.trim_end_matches(';').trim().to_owned();
                match &mut world {
                    Some((_, names)) => names.push((name, Direction::Export)),
                    None => {
                        return Err(ParseError::Syntax {
                            line,
                            reason: "an export outside a world".to_owned(),
                        });
                    }
                }
                continue;
            }

            // `use types.{…};` — a reference to another interface's types. Nothing in the capability table depends on
            // it, so it is read and dropped rather than refused: refusing would mean the parser failed on a construct it
            // fully understands.
            if trimmed.starts_with("use ") {
                continue;
            }

            // A function: `name: func(…) -> …;`. The signature is not read — the table is about gates — but its
            // presence is what says this line declares one.
            //
            // `async` is not a WIT keyword today; it is accepted because a signature that grew one should not be read
            // as a function with no gate.
            if let Some((name, _)) = split_function(trimmed) {
                let Some(interface) = current.as_mut() else {
                    return Err(ParseError::Syntax {
                        line,
                        reason: format!("`{name}` is declared outside an interface"),
                    });
                };

                if interface.functions.iter().any(|existing| existing.name == name) {
                    return Err(ParseError::DuplicateFunction {
                        line,
                        function: name,
                        interface: interface.name.clone(),
                    });
                }

                // ★ Only the host's functions need a gate. The interfaces a plugin *exports* are the host calling the
                // plugin, so a gate on one would be the plugin checking the host.
                //
                // Which interface is the host is not known while reading, because the world may come before or after it.
                // So an unannotated function is recorded as ungated here and the *set of annotated names* is kept — a
                // `Gate::Ungated` cannot be told from a default, and the difference is the whole point. The host's own
                // functions are re-checked after the world has been applied, below.
                let annotated = read_gate(&pending);
                if annotated.is_some() {
                    annotated_functions.push(name.clone());
                }
                let gate = annotated.unwrap_or(Gate::Ungated);
                pending.clear();

                interface.functions.push(Function { name, gate, line });
                continue;
            }

            // A type declaration inside `types`, or a closing brace, or an enum's variants. None of them carry a gate,
            // and all of them are constructs this parser understands well enough to skip.
            //
            // `pending` is *not* cleared here: an annotation belongs to the next declaration, and a construct between
            // the two is not one. Clearing on every unrecognised line was the second half of the bug the blank-line
            // rule above fixed.
        }

        if let Some(finished) = current.take() {
            interfaces.push(finished);
        }

        let (world_name, world_names) = world.ok_or(ParseError::NoPackage)?;

        // The world's direction is applied to the interfaces it names, and a name it mentions that no interface defines
        // is refused: a world importing something absent is a component that would fail to load.
        for (name, direction) in &world_names {
            let Some(interface) = interfaces.iter_mut().find(|interface| interface.name == *name) else {
                return Err(ParseError::UndefinedInterface { name: name.clone() });
            };
            interface.direction = *direction;
        }

        // ★ The host's functions are re-checked now that the world has been applied. A function on the imported
        // interface with no annotation is [`ParseError::UngatedFunction`] — the refusal this whole module exists for,
        // because a host call without a gate is one **any plugin can make** and nothing in the kernel would be wrong.
        //
        // This runs here rather than during the walk because a world may be written before or after the interface it
        // names, so "is this the host" is not knowable until the whole file has been read.
        let imported: Vec<String> = world_names
            .iter()
            .filter(|(_, direction)| *direction == Direction::Import)
            .map(|(name, _)| name.clone())
            .collect();
        for interface in &interfaces {
            if !imported.contains(&interface.name) {
                continue;
            }
            for function in &interface.functions {
                if !annotated_functions.contains(&function.name) {
                    return Err(ParseError::UngatedFunction {
                        line: function.line,
                        function: function.name.clone(),
                    });
                }
            }
        }

        // The interface the world imports, when there is exactly one. A second import is a contract this parser cannot
        // decide a table for, and `host()` returns `None` for it rather than picking one.
        let host_interface = match imported.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        };

        Ok(Self {
            package: package.0,
            version: package.1,
            interfaces,
            world: world_name,
            world_names,
            host_interface,
        })
    }

    /// The host's interface, which is the one the capability table is about.
    #[must_use]
    pub fn host(&self) -> Option<&Interface> {
        let name = self.host_interface.as_deref()?;
        self.interfaces.iter().find(|interface| interface.name == name)
    }

    /// Every interface a plugin exports.
    #[must_use]
    pub fn exports(&self) -> Vec<&Interface> {
        // Only the interfaces the world *names* as exports. `types` is declared in the file and named by nobody, so a
        // filter on direction alone listed it — its default — and a reader would think the plugin had to implement it.
        self.world_names
            .iter()
            .filter(|(_, direction)| *direction == Direction::Export)
            .filter_map(|(name, _)| self.interfaces.iter().find(|interface| interface.name == *name))
            .collect()
    }

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

/// The package declaration, as `(name, version)`.
fn parse_package(text: &str) -> Result<(String, String), ParseError> {
    for (index, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        let Some(rest) = trimmed.strip_prefix("package ") else {
            continue;
        };
        let rest = rest.trim_end_matches(';').trim();

        // `synra:plugin@1.0.0`, and a package with no version is legal WIT. The version is kept as text rather than
        // parsed: this tool does not compare versions, it reports them.
        return match rest.split_once('@') {
            Some((name, version)) => Ok((name.to_owned(), version.to_owned())),
            None if rest.is_empty() => Err(ParseError::Syntax {
                line: index + 1,
                reason: "a package declaration with no name".to_owned(),
            }),
            None => Ok((rest.to_owned(), String::new())),
        };
    }
    Err(ParseError::NoPackage)
}

/// Splits `name: func(…) -> …;` into the name and the signature.
///
/// `None` when the line is not a function declaration, which is how every other construct is skipped.
fn split_function(line: &str) -> Option<(String, &str)> {
    let (name, rest) = line.split_once(':')?;
    let name = name.trim();
    // A name is an identifier: a keyword or a dotted path would be something else, and `use types.{…}` is already
    // handled above.
    if name.is_empty() || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
        return None;
    }
    let rest = rest.trim();
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    // `func` is the keyword that makes it a function. Without it this is a type declaration inside `types` —
    // `log-level: enum { … }` is not WIT, and `record device-target { … }` has no colon, but a future construct might.
    if !rest.starts_with("func") {
        return None;
    }
    Some((name.to_owned(), rest))
}

/// Reads the gate from the annotations above a function.
///
/// `None` when there is no annotation at all, which the caller turns into [`ParseError::UngatedFunction`].
fn read_gate(annotations: &[String]) -> Option<Gate> {
    // The last annotation wins, so a function carrying two is one whose gate is the one nearest it — which is what a
    // reader assumes, and the alternative is a parse that depends on the order of a set.
    for annotation in annotations.iter().rev() {
        let annotation = annotation.trim();
        if annotation.starts_with("@ungated") {
            return Some(Gate::Ungated);
        }
        if let Some(rest) = annotation.strip_prefix("@capability") {
            let rest = rest.trim();
            // `("log:*")`, with the parentheses and the quotes. Both required: a bare `@capability` with no argument is
            // a gate nobody chose, and accepting it would invent a capability whose string is empty.
            let inner = rest
                .strip_prefix('(')?
                .strip_suffix(')')?
                .trim()
                .trim_matches('"');
            if inner.is_empty() {
                return None;
            }
            return Some(Gate::Capability(inner.to_owned()));
        }
        // An annotation this parser does not know, such as `@since("1.1.0")`, is skipped rather than refused: it is a
        // note for a reader, and refusing would mean adding one broke the build.
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature contract, for the parser's own tests.
    const SMALL: &str = r#"
package synra:plugin@1.0.0;

interface types {
    enum log-level { trace, info }
}

interface host {
    use types.{log-level};

    /// A fact about the environment.
    @ungated
    env-sdk-version: func() -> string;

    /// Write a line.
    @capability("log:*")
    log: func(level: log-level, message: string, ctx: option<string>);
}

interface lifecycle {
    activate: func(config-json: string) -> string;
}

world plugin {
    import host;
    export lifecycle;
}
"#;

    fn contract() -> Contract {
        Contract::parse(SMALL).expect("parses")
    }

    // ── The package ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_package_and_its_version_are_read() {
        let contract = contract();
        assert_eq!(contract.package, "synra:plugin");
        assert_eq!(contract.version, "1.0.0");
        assert_eq!(contract.world, "plugin");
    }

    #[test]
    fn a_package_with_no_version_is_read_rather_than_refused() {
        // Legal WIT, and refusing it would make this parser stricter than the language for no gain: nothing here
        // compares versions.
        let contract = Contract::parse("package synra:plugin;\nworld plugin { import host; }\ninterface host {\n@ungated\nx: func();\n}")
            .expect("parses");
        assert_eq!(contract.package, "synra:plugin");
        assert_eq!(contract.version, "");
    }

    #[test]
    fn a_file_with_no_package_is_refused() {
        assert_eq!(Contract::parse("interface host {\n}\n"), Err(ParseError::NoPackage));
    }

    // ── Gates ─────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn every_function_gets_its_gate() {
        let contract = contract();
        let table = contract.capability_table();
        assert_eq!(table.get("synra:plugin/host#env-sdk-version"), Some(&Gate::Ungated));
        assert_eq!(
            table.get("synra:plugin/host#log"),
            Some(&Gate::Capability("log:*".to_owned()))
        );
    }

    #[test]
    fn a_function_with_no_annotation_is_refused_rather_than_defaulted() {
        // ★ The refusal this module exists for. Defaulting to ungated is a hole; defaulting to gated invents a
        // capability nobody chose. Both are worse than an error naming the line.
        let text = "package synra:plugin@1.0.0;\n\ninterface host {\n    sneaky: func() -> string;\n}\n\nworld plugin { import host; }\n";
        match Contract::parse(text) {
            Err(ParseError::UngatedFunction { line, function }) => {
                assert_eq!(line, 4);
                assert_eq!(function, "sneaky");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_capability_with_no_argument_is_not_a_gate() {
        // `@capability` with nothing after it would otherwise be a capability whose string is empty, which the host
        // could never match — a function reachable by nobody, or worse, by whoever owns the empty capability.
        let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @capability\n    x: func();\n}\nworld plugin { import host; }\n";
        assert!(matches!(Contract::parse(text), Err(ParseError::UngatedFunction { .. })));
    }

    #[test]
    fn a_comment_between_an_annotation_and_its_function_does_not_drop_the_gate() {
        // The annotation and the function it belongs to are usually adjacent and not always — a multi-paragraph doc
        // comment is the normal case.
        let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @capability(\"log:*\")\n    ///\n    /// Writes a line, and says why.\n    log: func(message: string);\n}\nworld plugin { import host; }\n";
        let contract = Contract::parse(text).expect("parses");
        assert_eq!(
            contract.capability_table().get("synra:plugin/host#log").cloned(),
            Some(Gate::Capability("log:*".to_owned()))
        );
    }

    #[test]
    fn an_unknown_annotation_is_skipped_rather_than_refused() {
        // A note for a reader — `@since`, say — must not make the build fail, or adding one would be a breaking change.
        let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @since(\"1.1.0\")\n    /// @capability(\"log:*\")\n    log: func(message: string);\n}\nworld plugin { import host; }\n";
        let contract = Contract::parse(text).expect("parses");
        assert_eq!(
            contract.capability_table().get("synra:plugin/host#log").cloned(),
            Some(Gate::Capability("log:*".to_owned()))
        );
    }

    #[test]
    fn the_last_annotation_wins() {
        // A function carrying two gates is a mistake, and the one nearest it is what a reader assumes. The alternative
        // is a parse whose result depends on the order of a set.
        let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @capability(\"a\")\n    /// @capability(\"b\")\n    x: func();\n}\nworld plugin { import host; }\n";
        let contract = Contract::parse(text).expect("parses");
        assert_eq!(
            contract.capability_table().get("synra:plugin/host#x"),
            Some(&Gate::Capability("b".to_owned()))
        );
    }

    // ── The world ─────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_world_decides_each_interfaces_direction() {
        let contract = contract();
        assert_eq!(contract.host().map(|interface| interface.name.as_str()), Some("host"));
        let exports: Vec<&str> = contract
            .exports()
            .iter()
            .map(|interface| interface.name.as_str())
            .collect();
        assert_eq!(exports, vec!["lifecycle"]);
    }

    #[test]
    fn a_world_naming_an_interface_that_does_not_exist_is_refused() {
        // A component built from it would fail to load, and the message a toolchain gives names the interface rather
        // than the file.
        let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @ungated\n    x: func();\n}\nworld plugin { import host; export telepathy; }\n";
        assert_eq!(
            Contract::parse(text),
            Err(ParseError::UndefinedInterface { name: "telepathy".to_owned() })
        );
    }

    #[test]
    fn the_world_does_not_have_to_come_last() {
        // The file is written by hand, and a world between two interfaces is legal WIT. A parser that required an order
        // would be a parser an author has to know about.
        let text = "package synra:plugin@1.0.0;\nworld plugin { import host; export lifecycle; }\ninterface host {\n    /// @ungated\n    x: func();\n}\ninterface lifecycle {\n    activate: func();\n}\n";
        let contract = Contract::parse(text).expect("parses");
        assert_eq!(contract.host().map(|interface| interface.name.as_str()), Some("host"));
        assert_eq!(contract.exports().len(), 1);
    }

    // ── Refusals ──────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_same_function_twice_is_refused() {
        // The second would silently replace the first, so a capability could be removed by adding a line.
        let text = "package synra:plugin@1.0.0;\ninterface host {\n    /// @capability(\"a\")\n    x: func();\n    /// @ungated\n    x: func();\n}\nworld plugin { import host; }\n";
        match Contract::parse(text) {
            Err(ParseError::DuplicateFunction { line, function, interface }) => {
                assert_eq!(line, 6);
                assert_eq!(function, "x");
                assert_eq!(interface, "host");
            }
            other => panic!("expected a duplicate refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_function_outside_an_interface_is_refused() {
        let text = "package synra:plugin@1.0.0;\n/// @ungated\nx: func();\nworld plugin { }\n";
        assert!(matches!(Contract::parse(text), Err(ParseError::Syntax { .. })));
    }

    #[test]
    fn an_import_outside_a_world_is_refused() {
        // `import host;` inside an interface is not WIT, and reading it as one would put the interface in the wrong
        // direction — which is the difference between "the host provides this" and "the plugin must implement it".
        let text = "package synra:plugin@1.0.0;\ninterface host {\n    import other;\n}\nworld plugin { import host; }\n";
        assert!(matches!(Contract::parse(text), Err(ParseError::Syntax { .. })));
    }

    // ── What it derives ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_capability_list_is_sorted_and_deduplicated() {
        // Two functions may share a capability — `storage-get` and `storage-keys` are both reads — and the list a
        // permission dialog shows must name it once.
        let contract = contract();
        let capabilities = contract.capabilities();
        assert_eq!(capabilities, vec!["log:*".to_owned()]);
        let mut sorted = capabilities.clone();
        sorted.sort();
        assert_eq!(capabilities, sorted);
    }

    #[test]
    fn the_ungated_functions_are_listed() {
        // The exception the design document names, and the list a reviewer checks: an entry here is a host call any
        // plugin may make.
        let contract = contract();
        let ungated: Vec<&str> = contract
            .ungated()
            .iter()
            .map(|function| function.name.as_str())
            .collect();
        assert_eq!(ungated, vec!["env-sdk-version"]);
    }

    #[test]
    fn the_provided_names_include_both_gated_and_ungated_functions() {
        // The list the plugin CLI checks an artifact's imports against: a component naming a function this file does
        // not declare is one the host cannot answer, whether or not the call would have needed a capability.
        let contract = contract();
        let names = contract.provided_names();
        assert!(names.contains(&"log".to_owned()));
        assert!(names.contains(&"env-sdk-version".to_owned()));
        // And the exported entry points are not on it: those are what the *plugin* provides.
        assert!(!names.contains(&"activate".to_owned()));
    }

    #[test]
    fn the_import_name_is_the_one_a_component_carries() {
        // `synra:plugin/host#log` — what appears in a compiled component's import section. A check against the bare name
        // would match a function in another interface.
        let contract = contract();
        let function = &contract.host().expect("a host").functions[1];
        assert_eq!(function.import_name("synra:plugin", "host"), "synra:plugin/host#log");
    }

    #[test]
    fn the_summary_names_the_world_and_counts_what_it_found() {
        let lines = contract().summary_lines();
        assert!(lines[0].contains("synra:plugin@1.0.0"), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("world plugin")), "{lines:?}");
        assert!(lines.iter().any(|line| line.starts_with("import host")), "{lines:?}");
        assert!(lines.iter().any(|line| line.contains("gated function")), "{lines:?}");
    }

    #[test]
    fn an_empty_file_parses_to_nothing_rather_than_failing_oddly() {
        // No package, so it is refused — but with the error that says so, not a panic from an index.
        assert_eq!(Contract::parse(""), Err(ParseError::NoPackage));
        assert_eq!(Contract::parse("\n\n// just a comment\n"), Err(ParseError::NoPackage));
    }

    #[test]
    fn parse_errors_explain_themselves() {
        let errors = [
            ParseError::Syntax {
                line: 3,
                reason: "nothing here and nothing expected".to_owned(),
            },
            ParseError::UngatedFunction { line: 4, function: "x".to_owned() },
            ParseError::DuplicateFunction {
                line: 5,
                function: "x".to_owned(),
                interface: "host".to_owned(),
            },
            ParseError::NoPackage,
            ParseError::UndefinedInterface { name: "y".to_owned() },
        ];
        for error in errors {
            let text = error.to_string();
            assert!(text.len() > 20, "{error:?} -> {text}");
            assert!(!text.contains('{'), "{error:?} -> {text}");
        }
    }
}
