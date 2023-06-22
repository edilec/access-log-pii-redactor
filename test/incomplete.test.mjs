import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { apiReport, cliRun, files, findingsFor, fullPolicy, logOf, policy, raisedRules, record, withRoot } from './support.mjs'

/**
 * `incomplete`, one case per place the flag is set.
 *
 * Each of these rules is `error` severity, so deleting its `incomplete = true`
 * would leave the finding in place and change the status from `incomplete` to
 * `fail` and the exit code from 2 to 1. Every case below asserts both, so the
 * flag is not defended only by the accompanying finding -- which is exactly how
 * a sibling tool came to report `pass` over an input it had never read.
 *
 * The distinction being defended: `fail` says "I read it and it is wrong",
 * `incomplete` says "I could not obtain the evidence". A consumer that treats
 * the second as the first ships a log it believes was redacted.
 */

test('a log that could not be resolved is incomplete, never a pass and never a plain failure', async () => {
  await withRoot({ 'redaction-policy.json': fullPolicy() }, async (root) => {
    const result = await cliRun(['--root', root, '--json'])
    const report = JSON.parse(result.stdout)

    assert.equal(report.status, 'incomplete')
    assert.equal(result.code, 2)
    assert.equal(report.summary.checked, 0)
  })
})

test('a log that resolves outside the root is incomplete', async () => {
  const outside = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-outside-'))
  try {
    await writeFile(join(outside, 'far.log'), logOf([record()]))
    await withRoot({ 'redaction-policy.json': fullPolicy() }, async (root) => {
      await symlink(join(outside, 'far.log'), join(root, 'access.log'))
      const result = await cliRun(['--root', root, '--json'])
      const report = JSON.parse(result.stdout)

      assert.equal(report.status, 'incomplete')
      assert.equal(result.code, 2)
    })
  } finally {
    await rm(outside, { recursive: true, force: true })
  }
})

test('a log that is not a regular file is incomplete', async () => {
  await withRoot({ 'redaction-policy.json': fullPolicy() }, async (root) => {
    await mkdir(join(root, 'access.log'))
    const result = await cliRun(['--root', root, '--json'])

    assert.equal(JSON.parse(result.stdout).status, 'incomplete')
    assert.equal(result.code, 2)
  })
})

test('a log above the byte bound is incomplete', async () => {
  const result = await withRoot(files([record()]), (root) =>
    cliRun(['--root', root, '--max-input-bytes', '10', '--json']))

  assert.equal(JSON.parse(result.stdout).status, 'incomplete')
  assert.equal(result.code, 2)
})

test('a destination that could not be opened is incomplete', async () => {
  await withRoot(files([record()]), async (root) => {
    await mkdir(join(root, 'blocked'))
    const result = await cliRun(['--root', root, '--out', 'blocked', '--force', '--json'])

    assert.equal(JSON.parse(result.stdout).status, 'incomplete')
    assert.equal(result.code, 2)
  })
})

test('a run stopped by the record bound is incomplete', async () => {
  const result = await withRoot(files([record(), record()]), (root) =>
    cliRun(['--root', root, '--max-records', '1', '--json']))

  assert.equal(JSON.parse(result.stdout).status, 'incomplete')
  assert.equal(result.code, 2)
})

test('a run stopped by the time budget is incomplete', async () => {
  let now = 0
  const report = await apiReport(files([record(), record(), record()]), {
    clock: () => {
      now += 50
      return now
    },
    limits: { maxRuntimeMs: 60 },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.records < 3, true)
})

test('a report truncated by the findings bound is incomplete', async () => {
  const result = await withRoot(files(['{"a":,}', '{"b":,}']), (root) =>
    cliRun(['--root', root, '--max-findings', '1', '--json']))

  assert.equal(JSON.parse(result.stdout).status, 'incomplete')
  assert.equal(result.code, 2)
})

test('a log with no records at all is incomplete rather than a green run over nothing', async () => {
  const result = await withRoot({ 'access.log': '\n \n\n', 'redaction-policy.json': fullPolicy() }, (root) =>
    cliRun(['--root', root, '--json']))
  const report = JSON.parse(result.stdout)

  assert.equal(report.status, 'incomplete')
  assert.equal(result.code, 2)
  assert.equal(report.summary.checked, 0)
  assert.equal(report.summary.blank, 3)
  assert.equal(findingsFor(report, 'no-records-processed').length, 1)
})

test('a run that stopped early does not claim a policy target was never seen', async () => {
  const stopped = await apiReport(
    { 'access.log': logOf([{ ts: 'x' }, { ts: 'x', absent: 1 }]), 'redaction-policy.json': policy({ redactFields: ['ts', 'absent'] }) },
    { limits: { maxRecords: 1 } },
  )

  assert.equal(stopped.status, 'incomplete')
  assert.deepEqual(raisedRules(stopped), ['too-many-records'])

  const complete = await apiReport(
    { 'access.log': logOf([{ ts: 'x' }, { ts: 'x', absent: 1 }]), 'redaction-policy.json': policy({ redactFields: ['ts', 'absent'] }) },
  )
  assert.deepEqual(raisedRules(complete), [], 'read to the end, both targets were seen')

  const missing = await apiReport(
    { 'access.log': logOf([{ ts: 'x' }]), 'redaction-policy.json': policy({ redactFields: ['ts', 'absent'] }) },
  )
  assert.deepEqual(raisedRules(missing), ['policy-target-never-seen'], 'read to the end, one target was not')
})

test('no path through this tool reports pass without having read a record', async () => {
  const cases = [
    { inputs: { 'redaction-policy.json': fullPolicy() }, args: [] },
    { inputs: { 'access.log': '', 'redaction-policy.json': fullPolicy() }, args: [] },
    { inputs: files([record()]), args: ['--max-input-bytes', '10'] },
    { inputs: files([record()]), args: ['--max-records', '1'] },
  ]

  for (const { inputs, args } of cases) {
    const result = await withRoot(inputs, (root) => cliRun(['--root', root, '--json', ...args]))
    const report = JSON.parse(result.stdout)
    if (report.summary.checked === 0 || report.status === 'incomplete') {
      assert.notEqual(report.status, 'pass', `a pass with checked ${report.summary.checked}`)
      assert.equal(result.code, 2)
    }
  }
})
