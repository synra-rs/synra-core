# A guest fixture was blamed for a missing host result buffer

The real string-return test had been ignored as a canonical ABI fixture problem.
Removing only the ignore, with the original ANSWERS component unchanged, reported
`expected 1 result(s), got 0`. The return-area pointer in the component was valid;
the host passed an empty result array to every exported function.

Changing the fixture between an output pointer parameter and an i32 return moved
errors around without checking who owned the result buffer. Read the engine call
API before treating a result-count error as a core ABI error. Typed calls now
check parameters and results before guest execution, lift owned values and run
post-return. Repeated calls exercise cleanup, and a trapping post-return must
never become a successful answer.

The linker tests compared two manually maintained lists of names and shapes.
They agreed even though the production host represented WIT variants, enums,
records and tuples with different component types. Generated bindings now own
the host signatures; a component assembled from the production WIT world links
against that exact implementation. Semantic adapter tests also check actual
Host effects because type correctness alone cannot catch swapped arguments.

That full-world component exposed a separate startup failure: fuel consumption
was enabled but the new store had zero fuel. Even valid constructors trapped.
Startup now has its own finite fuel and deadline, verified with both a normal
constructor and an infinite one. A call with no time limit is tested after
advancing beyond the startup deadline, so increasing that deadline cannot
silently weaken the regression.

When a real-component test fails, check these independently:

1. Does the component validate against the production WIT, including named types?
2. Does the linker provide those exact types, rather than matching names alone?
3. Can a normal constructor execute under a finite startup budget?
4. Are all expected results read and is post-return completed before reuse?
5. Does a denied import leave the actual host untouched and count one attempt?

These tests establish the ABI boundary, not the full SDK build or platform flow.
