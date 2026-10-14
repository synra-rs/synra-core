// Applies the import and re-export corrections a split needs.
//
// A split moves items between modules, so every `use` that crossed a boundary has to be restated. Which module a name now
// lives in is a decision the split made, not something derivable from the source, so these are written down rather than
// re-discovered by compiling and fixing one error at a time.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const root = process.argv[2]
const dir = join(root, process.argv[3])
const edits = JSON.parse(readFileSync(process.argv[4], 'utf8'))

for (const edit of edits) {
  const path = join(dir, edit.file)
  if (!existsSync(path)) throw new Error(`no such file: ${path}`)
  let text = readFileSync(path, 'utf8')
  for (const [from, to] of edit.replace) {
    if (!text.includes(from)) {
      // Idempotent: a second run must not fail because the first one already applied this.
      if (to && text.includes(to)) continue
      throw new Error(`${edit.file}: could not find ${JSON.stringify(from.slice(0, 70))}`)
    }
    text = text.split(from).join(to)
  }
  writeFileSync(path, text, 'utf8')
  console.log(`  ${edit.file}: ok`)
}
