import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { projectDirectory } from './support.mjs'

test('the test suite itself opens no listener or connection', async () => {
  const directory = join(projectDirectory, 'test')
  for (const name of await readdir(directory)) {
    if (!name.endsWith('.test.mjs') || name === 'network-test-safety.test.mjs') continue
    const source = await readFile(join(directory, name), 'utf8')
    assert.equal(/\bcreateServer\s*\(|\bserver\.listen\s*\(/.test(source), false, `${name} opens a listener`)
    assert.equal(/\b(?:net|http|https|tls|dgram)\.(?:connect|request|createConnection|createSocket)\s*\(/.test(source), false, `${name} opens a connection`)
  }
})
