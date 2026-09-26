import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

/**
 * The seven error rules whose demotion flips the exit code from 1 to 0.
 *
 * These are the record-level refusals: the run completes, the record is
 * withheld, and the only thing making that a failure is the severity of its
 * rule. Demote one to `warning` and the same input exits 0 -- a green build over
 * a log that quietly lost a record.
 *
 * This file shares nothing with the rest of the suite: no severity table, no
 * rule-id list, no fixture module, no loop over a map. Every expectation is a
 * literal written at the place it is asserted, because three declarations can
 * be edited together and an exit code cannot be edited at all.
 */

const execFileAsync = promisify(execFile)
const CLI = join(dirname(fileURLToPath(import.meta.url)), '../bin/access-log-pii-redactor.mjs')

async function run(logLines, policyDocument, extraArgs = []) {
  const root = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-exit-'))
  try {
    const log = logLines instanceof Uint8Array
      ? logLines
      : `${logLines.map((line) => (typeof line === 'string' ? line : JSON.stringify(line))).join('\n')}\n`
    await writeFile(join(root, 'access.log'), log)
    await writeFile(join(root, 'redaction-policy.json'), JSON.stringify(policyDocument))
    try {
      const { stdout } = await execFileAsync(process.execPath, [CLI, '--root', root, '--json', ...extraArgs])
      return { code: 0, report: JSON.parse(stdout) }
    } catch (error) {
      return { code: error.code, report: JSON.parse(error.stdout) }
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

const KEEP = { schemaVersion: '1', redactFields: ['ts'] }
const GOOD = { ts: '2026-09-12T10:15:00Z', status: 200 }

test('a clean log over the same policy exits 0, which is what makes the rest of this file mean something', async () => {
  const { code, report } = await run([GOOD, GOOD], KEEP)

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.quarantined, 0)
})

test('record-not-json makes a completed run exit 1', async () => {
  const { code, report } = await run([GOOD, '{"a":,}'], KEEP)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.summary.quarantined, 1)
  assert.equal(report.summary.written, 1)
})

test('record-not-object makes a completed run exit 1', async () => {
  const { code, report } = await run([GOOD, '[1,2,3]'], KEEP)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.summary.quarantined, 1)
})

test('record-not-utf8 makes a completed run exit 1', async () => {
  const log = Buffer.concat([
    Buffer.from(`${JSON.stringify(GOOD)}\n`),
    Buffer.from('{"a":"'),
    Buffer.from([0xff, 0xfe]),
    Buffer.from('"}\n'),
  ])
  const { code, report } = await run(log, KEEP)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.summary.quarantined, 1)
})

test('record-residual-identifier makes a completed run exit 1', async () => {
  const { code, report } = await run(
    [GOOD, { ts: 'x', seats: { 'ada@example.invalid': 'row-4' } }],
    { schemaVersion: '1', redactFields: ['ts'], detectors: ['email-address'] },
  )

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.summary.quarantined, 1)
})

test('record-too-deep makes a completed run exit 1', async () => {
  let deep = { ts: 'x', leaf: 1 }
  for (let index = 0; index < 20; index += 1) deep = { ts: 'x', nest: deep }
  const { code, report } = await run([GOOD, deep], KEEP)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.summary.quarantined, 1)
})

test('record-too-large makes a completed run exit 1', async () => {
  const { code, report } = await run([GOOD, { ts: 'x', filler: 'q'.repeat(500) }], KEEP, ['--max-line-bytes', '200'])

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.summary.quarantined, 1)
})

test('record-too-many-fields makes a completed run exit 1', async () => {
  const wide = { ts: 'x' }
  for (let index = 0; index < 300; index += 1) wide[`f${index}`] = index
  const { code, report } = await run([GOOD, wide], KEEP)

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.summary.quarantined, 1)
})

test('a warning on its own never costs the run its exit code', async () => {
  const { code, report } = await run(
    [{ ts: 'x', ip: 'not-an-address' }],
    { schemaVersion: '1', redactFields: ['ts'], addressFields: ['ip'] },
  )

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
})
