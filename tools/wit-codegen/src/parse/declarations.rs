use crate::parse::Gate;

/// One host function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// Its WIT name, as it appears in the file and in a component's imports.
    pub name: String,
    /// What the host checks before calling it.
    pub gate: Gate,
    /// The parameters, as `(name, WIT type)` pairs, in declaration order.
    ///
    /// Kept as WIT text rather than mapped here, because the mapping belongs to whatever is being *generated*: a Rust
    /// trait and a TypeScript declaration spell the same `option<string>` differently, and a parser that chose would be
    /// choosing for both.
    pub params: Vec<(String, String)>,
    /// The return type, as WIT text. `None` for a function that returns nothing.
    pub returns: Option<String>,
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
