use crate::parse::gate::read_gate;
use crate::parse::signature::{read_signature, split_function};
use crate::parse::{Direction, Function, Gate, Interface, ParseError};

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
            if let Some((name, signature)) = split_function(trimmed) {
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

                let (params, returns) = read_signature(signature);
                interface.functions.push(Function { name, gate, params, returns, line });
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
