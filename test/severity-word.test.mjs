import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

/**
 * Severity, pinned by what the tool actually prints, for every rule in the
 * catalog.
 *
 * This file deliberately shares nothing with the rest of the suite. It imports
 * no severity table, reads no documented catalog, and takes no expectation from
 * a map, a fixture module or a loop variable: every rule id, every count and
 * every printed line is written out inline, at the place it is asserted.
 *
 * That is the whole point. A frozen table, a markdown catalog and a test's
 * expected-value map are three declarations, and one edit that changes all
 * three leaves every assertion that compares them satisfied -- including an
 * assertion made inside a loop over that same map. Nothing below can be
 * satisfied by editing a declaration: `assert.equal(report.summary.errors, 1)`
 * is false the moment a rule stops being an error, and
 * `stderr.includes('ERROR   ...')` is false the moment it stops being printed
 * as one.
 *
 * Eight of the error rules also make the run `incomplete`, so they exit 2
 * whether their severity says `error` or `warning`; for those the exit code is
 * not the discriminator and the error count and the printed word are.
 * `test/severity-exit.test.mjs` covers the seven that complete the run, where
 * the exit code itself flips on a demotion.
 */

const execFileAsync = promisify(execFile)
const CLI = join(dirname(fileURLToPath(import.meta.url)), '../bin/access-log-pii-redactor.mjs')

/** Build a root, run the real binary over it with the human report on, tear the root down. */
async function audit(inputs, extraArgs = [], plant) {
  const root = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-word-'))
  try {
    for (const [name, content] of Object.entries(inputs)) {
      const bytes = typeof content === 'string' || content instanceof Uint8Array ? content : JSON.stringify(content)
      await writeFile(join(root, name), bytes)
    }
    if (plant !== undefined) await plant(root)
    try {
      const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, '--root', root, ...extraArgs], {
        maxBuffer: 64 * 1024 * 1024,
      })
      return { code: 0, report: JSON.parse(stdout), stderr }
    } catch (error) {
      return { code: error.code, report: JSON.parse(error.stdout), stderr: error.stderr ?? '' }
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

const lines = (records) => `${records.map((entry) => (typeof entry === 'string' ? entry : JSON.stringify(entry))).join('\n')}\n`
const GOOD = { ts: '2026-09-12T10:15:00Z', status: 200 }
const KEEP = { schemaVersion: '1', redactFields: ['ts'] }

test('address-unrecognised prints WARNING and costs no error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([{ ts: 'x', ip: 'not-an-address' }]),
    'redaction-policy.json': { schemaVersion: '1', redactFields: ['ts'], addressFields: ['ip'] },
  })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING access.log:1/ip address-unrecognised'), true)
})

test('field-replaced-wholly prints INFO and costs no error or warning', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([{ ts: 'x', user: { email: 'a@b.invalid' } }]),
    'redaction-policy.json': { schemaVersion: '1', redactFields: ['user'] },
  })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('INFO    access.log:1/user field-replaced-wholly'), true)
})

test('field-shape-unexpected prints WARNING and costs no error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([{ ts: 'x', ip: { v4: '203.0.113.1' } }]),
    'redaction-policy.json': { schemaVersion: '1', redactFields: ['ts'], addressFields: ['ip'] },
  })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING access.log:1/ip field-shape-unexpected'), true)
})

test('input-too-large prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([GOOD, GOOD]),
    'redaction-policy.json': KEEP,
  }, ['--max-input-bytes', '10'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   access.log:0 input-too-large'), true)
})

test('input-unreadable prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({ 'redaction-policy.json': KEEP })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   access.log:0 input-unreadable'), true)
})

test('no-records-processed prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': '\n\n',
    'redaction-policy.json': KEEP,
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   access.log:0 no-records-processed'), true)
})

test('output-unwritable prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit(
    { 'access.log': lines([GOOD]), 'redaction-policy.json': KEEP },
    ['--out', 'occupied', '--force'],
    (root) => mkdir(join(root, 'occupied')),
  )

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   occupied:0 output-unwritable'), true)
})

test('path-escapes-root prints ERROR and counts one error', async () => {
  const outside = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-outside-'))
  try {
    await writeFile(join(outside, 'elsewhere.log'), lines([GOOD]))
    const { code, report, stderr } = await audit(
      { 'redaction-policy.json': KEEP },
      [],
      (root) => symlink(join(outside, 'elsewhere.log'), join(root, 'access.log')),
    )

    assert.equal(report.summary.errors, 1)
    assert.equal(report.summary.warnings, 0)
    assert.equal(report.status, 'incomplete')
    assert.equal(code, 2)
    assert.equal(stderr.includes('ERROR   access.log:0 path-escapes-root'), true)
  } finally {
    await rm(outside, { recursive: true, force: true })
  }
})

test('policy-target-never-seen prints WARNING and costs no error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([{ ts: 'x' }]),
    'redaction-policy.json': { schemaVersion: '1', redactFields: ['ts', 'absent'] },
  })

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING redaction-policy.json:0/redactFields/absent policy-target-never-seen'), true)
})

test('record-not-json prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([GOOD, '{"a":,}']),
    'redaction-policy.json': KEEP,
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   access.log:2 record-not-json'), true)
})

test('record-not-object prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([GOOD, '"just a string"']),
    'redaction-policy.json': KEEP,
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   access.log:2 record-not-object'), true)
})

test('record-not-utf8 prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': Buffer.concat([
      Buffer.from(`${JSON.stringify(GOOD)}\n`),
      Buffer.from([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d, 0x0a]),
    ]),
    'redaction-policy.json': KEEP,
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   access.log:2 record-not-utf8'), true)
})

test('record-residual-identifier prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([GOOD, { ts: 'x', seats: { 'ada@example.invalid': 1 } }]),
    'redaction-policy.json': { schemaVersion: '1', redactFields: ['ts'], detectors: ['email-address'] },
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   access.log:2 record-residual-identifier'), true)
})

test('record-too-deep prints ERROR and counts one error', async () => {
  let deep = { ts: 'x', leaf: 1 }
  for (let index = 0; index < 20; index += 1) deep = { ts: 'x', nest: deep }
  const { code, report, stderr } = await audit({
    'access.log': lines([GOOD, deep]),
    'redaction-policy.json': KEEP,
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   access.log:2 record-too-deep'), true)
})

test('record-too-large prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([GOOD, { ts: 'x', filler: 'q'.repeat(500) }]),
    'redaction-policy.json': KEEP,
  }, ['--max-line-bytes', '200'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   access.log:2 record-too-large'), true)
})

test('record-too-many-fields prints ERROR and counts one error', async () => {
  const wide = { ts: 'x' }
  for (let index = 0; index < 300; index += 1) wide[`f${index}`] = index
  const { code, report, stderr } = await audit({
    'access.log': lines([GOOD, wide]),
    'redaction-policy.json': KEEP,
  })

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'fail')
  assert.equal(code, 1)
  assert.equal(stderr.includes('ERROR   access.log:2 record-too-many-fields'), true)
})

test('time-budget-exceeded prints ERROR and counts one error', async () => {
  const many = new Array(20000).fill(JSON.stringify(GOOD)).join('\n')
  const { code, report, stderr } = await audit({
    'access.log': `${many}\n`,
    'redaction-policy.json': KEEP,
  }, ['--max-runtime-ms', '1'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('time-budget-exceeded'), true)
  assert.equal(stderr.includes('ERROR   access.log:'), true)
})

test('too-many-findings prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines(['{"a":,}', '{"b":,}', '{"c":,}']),
    'redaction-policy.json': KEEP,
  }, ['--max-findings', '1'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.findings.length, 1)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   access.log:0 too-many-findings'), true)
})

test('too-many-records prints ERROR and counts one error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([GOOD, GOOD, GOOD]),
    'redaction-policy.json': KEEP,
  }, ['--max-records', '2'])

  assert.equal(report.summary.errors, 1)
  assert.equal(report.summary.warnings, 0)
  assert.equal(report.status, 'incomplete')
  assert.equal(code, 2)
  assert.equal(stderr.includes('ERROR   access.log:2 too-many-records'), true)
})

test('value-over-limit prints WARNING and costs no error', async () => {
  const { code, report, stderr } = await audit({
    'access.log': lines([{ ts: 'x', note: 'q'.repeat(300) }]),
    'redaction-policy.json': KEEP,
  }, ['--max-value-length', '100'])

  assert.equal(report.summary.errors, 0)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.status, 'pass')
  assert.equal(code, 0)
  assert.equal(stderr.includes('WARNING access.log:1/note value-over-limit'), true)
})
