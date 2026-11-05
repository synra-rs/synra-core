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
