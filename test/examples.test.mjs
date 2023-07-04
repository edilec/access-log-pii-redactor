import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { CANARIES, cliRun, findingsFor, projectDirectory, raisedRules, substringsOf } from './support.mjs'

/**
 * The shipped examples, run as the README says to run them.
 *
 * `npm run example` is part of `npm run check`, so the clean example failing
 * would already break the build. These cases add the broken one, whose whole
 * job is to be wrong in specific ways -- an example whose output nobody asserts
 * is an example that stops matching the tool it documents.
 */

async function example(name, extraArgs = []) {
  const root = join(projectDirectory, 'examples', name)
  const result = await cliRun(['--root', root, '--json', ...extraArgs])
  return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
}

test('each example directory holds exactly a log and a policy', async () => {
  for (const name of ['broken', 'clean']) {
    const entries = (await readdir(join(projectDirectory, 'examples', name))).sort()
    assert.deepEqual(entries, ['access.log', 'redaction-policy.json'])
  }
})

test('the clean example passes with nothing to report', async () => {
  const { code, report } = await example('clean')

  assert.equal(code, 0)
  assert.equal(report.status, 'pass')
  assert.deepEqual(report.findings, [])
  assert.equal(report.summary.records, 5)
  assert.equal(report.summary.written, 5)
  assert.equal(report.summary.quarantined, 0)
  assert.equal(report.summary.redactions, 23)
})

test('the clean example is a dry run: it names no destination and writes nothing', async () => {
  const { report } = await example('clean')

  assert.equal(report.output.file, null)
  await assert.rejects(() => readFile(join(projectDirectory, 'examples/clean/redacted.log')), /ENOENT/)
})

test('the clean example names every policy target in at least one record', async () => {
  const { report } = await example('clean')

  assert.equal(findingsFor(report, 'policy-target-never-seen').length, 0)
})

test('the broken example completes and fails, with a verdict rather than a gap', async () => {
  const { code, report } = await example('broken')

  assert.equal(code, 1)
  assert.equal(report.status, 'fail')
  assert.deepEqual(raisedRules(report), [
    'address-unrecognised',
    'record-not-json',
    'record-not-object',
    'record-residual-identifier',
  ])
  assert.equal(report.summary.errors, 3)
  assert.equal(report.summary.warnings, 1)
  assert.equal(report.summary.records, 5)
  assert.equal(report.summary.written, 2)
  assert.equal(report.summary.quarantined, 3)
})

test('the broken example withholds the never-seen claim, because it quarantined three records', async () => {
  // It used to make it: `queryParams:email` was reported as carried by no
  // record in the log, on a run that never looked inside line 2, line 3 or
  // line 5. The claim happened to be true of the lines it did read, which is
  // exactly why it is not evidence -- and it sent the reader to their policy
  // when the thing to fix was the exporter that wrote the doubled comma.
  const { report } = await example('broken')

  assert.equal(report.summary.quarantined, 3)
  assert.equal(findingsFor(report, 'policy-target-never-seen').length, 0)
})

test('the broken example quarantines its malformed line without echoing a byte of it', async () => {
  const { stdout, stderr } = await example('broken')
  const line = (await readFile(join(projectDirectory, 'examples/broken/access.log'), 'utf8')).split('\n')[1]

  assert.equal(line.includes(CANARIES.awsKey), true, 'the fixture must really carry the canary')
  for (const part of substringsOf(line, 12)) {
    assert.equal(`${stdout}${stderr}`.includes(part), false, `the broken example leaked "${part}"`)
  }
  for (const part of substringsOf(CANARIES.awsKey, 6)) {
    assert.equal(`${stdout}${stderr}`.includes(part), false, `the broken example leaked "${part}"`)
  }
})

test('the broken example locates each quarantined record by line', async () => {
  const { report } = await example('broken')

  assert.equal(findingsFor(report, 'record-not-json')[0].location.line, 2)
  assert.equal(findingsFor(report, 'record-not-object')[0].location.line, 3)
  assert.equal(findingsFor(report, 'address-unrecognised')[0].location.line, 4)
  assert.equal(findingsFor(report, 'record-residual-identifier')[0].location.line, 5)
})

test('the two examples share one policy, so the difference is the log alone', async () => {
  const clean = await readFile(join(projectDirectory, 'examples/clean/redaction-policy.json'), 'utf8')
  const broken = await readFile(join(projectDirectory, 'examples/broken/redaction-policy.json'), 'utf8')

  assert.equal(clean, broken)
})

test('the examples carry no credential that authenticates anything', async () => {
  for (const name of ['broken', 'clean']) {
    const log = await readFile(join(projectDirectory, 'examples', name, 'access.log'), 'utf8')
    for (const domain of log.matchAll(/@([A-Za-z0-9.-]+)/g)) {
      assert.equal(domain[1].endsWith('.invalid'), true, `${domain[1]} is not a reserved domain`)
    }
    for (const key of log.matchAll(/\bAKIA[0-9A-Z]{16}\b/g)) {
      assert.equal(key[0], 'AKIAIOSFODNN7EXAMPLE', 'only the vendor published placeholder appears in a fixture')
    }
  }
})
