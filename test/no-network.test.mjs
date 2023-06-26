import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import test from 'node:test'
import { promisify } from 'node:util'

import { CLI, apiReport, files, fullPolicy, logOf, projectDirectory, record, withRoot } from './support.mjs'

const execFileAsync = promisify(execFile)

/**
 * "This tool talks to nobody", proved rather than asserted.
 *
 * It matters more here than in most of this catalog: the input is an access
 * log, so anything this process sent anywhere would be sending exactly the data
 * the tool exists to remove. Three independent checks, because each of them can
 * be true while the property is false:
 *
 * 1. A module resolution hook that refuses every network builtin, with the
 *    binary run under it over a real log. If any code path reached for a
 *    socket, the import would fail and the run would not produce a report. A
 *    control run proves the hook actually fires, because a guard that never
 *    fires proves nothing.
 * 2. A live loopback listener whose address is planted in the log, which then
 *    records that nothing ever knocked. Log content is data: a URL in a record
 *    is not an instruction to fetch it.
 * 3. A scan of the shipped source for the globals and spellings a hook cannot
 *    see -- `fetch`, `eval`, a child process that would open a socket on this
 *    package's behalf, and the non-deterministic sources this package also
 *    forbids itself.
 */

const NETWORK_MODULES = [
  'net', 'http', 'https', 'http2', 'dgram', 'dns', 'tls', 'cluster', 'quic', 'inspector',
]

const HOOK_SOURCE = `
const blocked = new Set(${JSON.stringify(NETWORK_MODULES)})
export async function resolve(specifier, context, next) {
  const bare = specifier.startsWith('node:') ? specifier.slice(5) : specifier
  if (blocked.has(bare.split('/')[0])) throw new Error('BLOCKED_NETWORK_IMPORT:' + specifier)
  return next(specifier, context)
}
`

const GUARD_SOURCE = `
import { register } from 'node:module'
register('./hook.mjs', import.meta.url)
`

const PROBE_SOURCE = `
import net from 'node:net'
process.stdout.write(typeof net)
`

async function withGuard(body) {
  const directory = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-guard-'))
  try {
    await writeFile(join(directory, 'hook.mjs'), HOOK_SOURCE)
    await writeFile(join(directory, 'guard.mjs'), GUARD_SOURCE)
    await writeFile(join(directory, 'probe.mjs'), PROBE_SOURCE)
    return await body({ directory, guard: pathToFileURL(join(directory, 'guard.mjs')).href })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

test('the binary completes a real run with every network builtin refused at resolution', async () => {
  await withGuard(async ({ directory, guard }) => {
    // The control first: a script that does reach for a socket must fail under
    // the same guard, or this case would pass on a hook that never fires.
    await assert.rejects(
      () => execFileAsync(process.execPath, ['--import', guard, join(directory, 'probe.mjs')]),
      /BLOCKED_NETWORK_IMPORT:node:net/,
    )

    const { stdout } = await withRoot(files([record(), record()]), (root) =>
      execFileAsync(process.execPath, ['--import', guard, CLI, '--root', root, '--out', 'redacted.log', '--json']))

    assert.equal(JSON.parse(stdout).summary.written, 2)
  })
})

test('a URL in a record is data: the listener it names is never contacted', async () => {
  const knocks = []
  const server = createServer((request, response) => {
    knocks.push(request.url)
    response.end('no')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  try {
    const planted = [
      record({ request: { url: `http://127.0.0.1:${port}/v1/search?token=t-1`, headers: { authorization: 'Bearer abcdefghijklmnop' } } }),
      record({ note: `see http://127.0.0.1:${port}/callback for details` }),
    ]
    const report = await apiReport({ 'access.log': logOf(planted), 'redaction-policy.json': fullPolicy() })

    assert.equal(report.summary.written, 2)
    assert.deepEqual(knocks, [], 'a URL in a log is a string, not an instruction')
  } finally {
    await new Promise((resolve) => server.close(resolve))
  }
})

test('the shipped source reaches for nothing a resolution hook cannot see', async () => {
  const sources = []
  for (const directory of ['src', 'bin']) {
    for (const name of await readdir(join(projectDirectory, directory))) {
      sources.push([join(directory, name), await readFile(join(projectDirectory, directory, name), 'utf8')])
    }
  }

  assert.equal(sources.length >= 7, true, 'every shipped module must be scanned')
  for (const [name, text] of sources) {
    for (const forbidden of [
      'fetch(', 'XMLHttpRequest', 'WebSocket', 'eval(', 'new Function(',
      'child_process', 'execSync', 'navigator', 'localCompare', 'localeCompare',
      'Intl.Collator', 'Math.random', 'Date.now', 'new Date',
    ]) {
      assert.equal(text.includes(forbidden), false, `${name} must not reach for ${forbidden}`)
    }
  }
})

test('no dependency is declared, so nothing can be pulled in at install time', async () => {
  const manifest = JSON.parse(await readFile(join(projectDirectory, 'package.json'), 'utf8'))

  assert.equal(manifest.dependencies, undefined)
  assert.equal(manifest.devDependencies, undefined)
  assert.equal(manifest.peerDependencies, undefined)
  assert.equal(manifest.optionalDependencies, undefined)
})

test('the package imports only node builtins and its own files', async () => {
  for (const directory of ['src', 'bin']) {
    for (const name of await readdir(join(projectDirectory, directory))) {
      const text = await readFile(join(projectDirectory, directory, name), 'utf8')
      for (const match of text.matchAll(/from '([^']+)'/g)) {
        const specifier = match[1]
        assert.equal(
          specifier.startsWith('node:') || specifier.startsWith('./') || specifier.startsWith('../'),
          true,
          `${name} imports ${specifier}`,
        )
      }
    }
  }
})
