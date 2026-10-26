# A Rust SDK must be tested by compiling a Rust guest

Native SDK tests passed while the public Outcome and LogLevel were host model
types, not the types generated host functions actually accepted. The uncompiled
guest fixture used nonexistent variant constructors and could not reveal this.
The SDK now exposes the generated types and checks an actual function signature.
It no longer links the manifest and signing dependency graph into a guest.

The fixture's comments claimed that export macros required weakening the
workspace unsafe policy, installing a missing target and finding wasm-tools.
Compiling it after correcting its API disproved the policy claim: forbid unsafe
remained in place. Generated macro expansion was not the same as hand-written
unsafe export code. Treat compiler evidence as stronger than an old diagnosis.

The wasip2 build then succeeded and produced a component, but instantiation failed
because Rust std introduced WASI cli, io and clock imports. The sandbox correctly
provided none of them. Compiler success was not proof that the selected target
matched the host. Building an unknown-unknown core module and encoding the SDK's
embedded WIT avoids granting ambient WASI to make the fixture green.

A second production gap appeared at PluginSet: artifact imports contained only
interface container names. Capability rules described functions. Import discovery
now inspects functions within the exact Host interface, skips shared value types
and preserves unknown imports and resources for rejection. Test both this load
check and the call gate; a direct backend call cannot prove a plugin can load.

Finally, the CLI template emitted obsolete C exports, and the build only checked
whether an expected file existed. The actual Cargo output was elsewhere. Cargo
JSON metadata now identifies the current cdylib even with a different library name
and target directory. Only successfully encoded output replaces the destination.
Tests retain an old component, then fail compilation and separately produce a
valid module without plugin exports; neither failure may become a stale success.

The explicit authoring gate uses a pinned SDK fixture and a separate compiler
cache. Its child processes have deadlines and offline dependency resolution.
Normal unit tests do not spawn recursive Cargo or silently skip missing fixtures.
