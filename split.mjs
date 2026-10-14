// Splits one long source file into a directory of modules at exact line boundaries.
//
// Every boundary is asserted before anything is written. An off-by-one here produces a file that is plausible and wrong,
// or fails to compile for a reason unrelated to the split — and both cost more than the assertion does.
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const root = process.argv[2]
const specPath = process.argv[3]
const spec = JSON.parse(readFileSync(specPath, 'utf8'))

const srcFile = join(root, spec.source)
if (!existsSync(srcFile)) throw new Error(`no such file: ${srcFile}`)
const original = readFileSync(srcFile, 'utf8').split('\n')

const at = (n) => original[n - 1]
/// Fails loudly rather than writing a subtly wrong file.
const expect = (n, needle) => {
  const line = at(n)
  if (line === undefined || !line.includes(needle)) {
    throw new Error(`line ${n} should contain ${JSON.stringify(needle)} but is ${JSON.stringify(line)}`)
  }
}
for (const [n, needle] of spec.expect) expect(Number(n), needle)

const slice = (from, to) =>
  original
    .slice(from - 1, to)
    .join('\n')
    .replace(/\s+$/, '') + '\n'

const outDir = join(root, spec.output)
rmSync(outDir, { recursive: true, force: true })
mkdirSync(outDir, { recursive: true })

// §1 — mod.rs: the original module documentation, plus the re-exports.
const moduleDoc = spec.docLines
  ? original
      .slice(spec.docLines[0] - 1, spec.docLines[1])
      .filter((l) => l.startsWith('//!'))
      .join('\n') + '\n'
  : ''

const reexports = spec.reexports.map((r) => `pub use ${r};`).join('\n')

let modBody = `${moduleDoc}${spec.modNote || ''}

${spec.modules.map((m) => `pub mod ${m};`).join('\n')}

${reexports}
`
if (spec.hasTests) modBody += '\n#[cfg(test)]\nmod tests;\n'

writeFileSync(join(outDir, 'mod.rs'), modBody, 'utf8')
console.log(`  mod.rs        ${modBody.split('\n').length - 1} lines`)

// §2 — one file per section.
for (const file of spec.files) {
  const body = `${file.header}\n${slice(file.from, file.to)}`
  writeFileSync(join(outDir, file.name), body, 'utf8')
  console.log(`  ${file.name.padEnd(13)} ${body.split('\n').length - 1} lines`)
}

// §3 — the tests, lifted out of the `mod tests { … }` wrapper.
//
// Both the header **and the wrapper's own closing brace** go, because the text between them becomes a module body: what was
// `mod tests { …tests… }` becomes `…tests…` at the top level of `tests.rs`. Nested `mod proptests` blocks are unaffected —
// they keep their own braces and simply become siblings instead of children.
//
// Finding that brace needs a real Rust scanner, not brace counting: `{` inside raw strings, format arguments and
// `"{{"` escapes is not a brace, so this file of 1319 lines counts 505 openings against 501 closings and is nevertheless
// valid. What identifies the wrapper's close is position — it is the last line of the block and sits at column zero,
// while the last thing before it is indented.
if (spec.hasTests) {
  const raw = slice(spec.testsFrom, original.length)
  const withoutHeader = raw.replace(/^#\[cfg\(test\)\]\nmod tests \{\n/, '')
  if (withoutHeader === raw) {
    throw new Error('the test block does not start with the expected wrapper')
  }
  const lines = withoutHeader.split('\n')
  let last = lines.length - 1
  while (last >= 0 && lines[last].trim() === '') last--
  if (lines[last] !== '}') {
    throw new Error(`the test block does not end with a closing brace: ${JSON.stringify(lines[last])}`)
  }
  lines.splice(last, 1)
  const text = `${spec.testsHeader}\n${lines.join('\n').replace(/\s+$/, '')}\n`
  writeFileSync(join(outDir, 'tests.rs'), text, 'utf8')
  console.log(`  tests.rs      ${text.split('\n').length - 1} lines`)
}

rmSync(srcFile)
console.log(`  removed ${spec.source}`)
