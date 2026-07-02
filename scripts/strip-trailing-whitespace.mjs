import { readdir, readFile, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const root = process.argv[2]
if (!root) {
  console.error('usage: node scripts/strip-trailing-whitespace.mjs <dir>')
  process.exit(2)
}

const textExtensions = new Set([
  '.css',
  '.html',
  '.js',
  '.json',
  '.svg',
  '.xml'
])

async function walk(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  for (const entry of entries) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      await walk(path)
      continue
    }
    if (!entry.isFile() || !isTextOutput(entry.name)) {
      continue
    }
    await stripFile(path)
  }
}

function isTextOutput(name) {
  for (const ext of textExtensions) {
    if (name.endsWith(ext)) {
      return true
    }
  }
  return false
}

async function stripFile(path) {
  const info = await stat(path)
  if (info.size === 0) {
    return
  }
  const before = await readFile(path, 'utf8')
  const after = before.replace(/[ \t]+$/gm, '')
  if (after !== before) {
    await writeFile(path, after)
  }
}

await walk(root)
