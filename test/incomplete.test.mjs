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

/**
 * A record the run quarantined is a record the run did not read into.
 *
 * `policy-target-never-seen` says "no record in this log carried it", which is
 * a claim about every record. A quarantined record is counted and located, and
 * then never inspected: an over-long line is not parsed, a non-UTF-8 line is
 * not decoded, a line that is not JSON is not walked, and a record refused for
 * depth or field count has its walk abandoned partway. Each case below takes
 * the SAME record -- one that demonstrably carries all four targets, proved by
 * the control -- and has one limit quarantine it.
 */
const ALL_TARGETS = {
  client: { ip: '203.0.113.9' },
  request: { headers: { authorization: 'Bearer abcdefghijklmno' } },
  user: { email: 'ada@example.invalid' },
}

const FOUR_TARGETS = policy({
  addressFields: ['client.ip'],
  headerFields: ['request.headers'],
  headers: ['authorization'],
  redactFields: ['user.email'],
})

const quarantining = [
  ['a line over maxLineBytes', logOf([ALL_TARGETS]), { maxLineBytes: 40 }, 'record-too-large'],
  ['a record over maxDepth', logOf([ALL_TARGETS]), { maxDepth: 1 }, 'record-too-deep'],
  ['a record over maxFieldsPerRecord', logOf([ALL_TARGETS]), { maxFieldsPerRecord: 2 }, 'record-too-many-fields'],
  ['a line that is not JSON', `${JSON.stringify(ALL_TARGETS).replace('{"client"', '{,"client"')}\n`, {}, 'record-not-json'],
  ['bytes that are not UTF-8', new Uint8Array([...Buffer.from('{"a":"', 'utf8'), 0xff, 0xfe, ...Buffer.from('"}\n', 'utf8')]), {}, 'record-not-utf8'],
]

test('the control: read whole, this record carries all four targets and nothing is reported missing', async () => {
  // Without this the cases below would pass just as well against a record that
  // never carried the targets in the first place.
  const report = await apiReport({ 'access.log': logOf([ALL_TARGETS]), 'redaction-policy.json': FOUR_TARGETS })

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.quarantined, 0)
  assert.equal(findingsFor(report, 'policy-target-never-seen').length, 0)
})

for (const [label, log, limits, expectedRule] of quarantining) {
  test(`${label} does not let the run claim a policy target was never seen`, async () => {
    const report = await apiReport({ 'access.log': log, 'redaction-policy.json': FOUR_TARGETS }, { limits })

    assert.equal(report.summary.quarantined, 1, 'this case must really quarantine')
    assert.ok(raisedRules(report).includes(expectedRule), `expected ${expectedRule}, got ${raisedRules(report)}`)
    assert.deepEqual(
      findingsFor(report, 'policy-target-never-seen').map((finding) => finding.message),
      [],
      'the run claimed no record carried a target it never looked for',
    )
  })
}

test('one quarantined record withholds the claim for the whole run, however many others were read', async () => {
  // The claim is about every record, so one unread record is enough to void it
  // -- the same reasoning the stream-level guard already applies to a run that
  // stopped early, one level further down.
  const report = await apiReport(
    {
      'access.log': `${logOf([ALL_TARGETS, ALL_TARGETS])}${JSON.stringify(ALL_TARGETS).replace('{"client"', '{,"client"')}\n`,
      'redaction-policy.json': policy({ ...FOUR_TARGETS, queryParams: undefined, redactFields: ['user.email', 'never.here'] }),
    },
  )

  assert.equal(report.summary.records, 3)
  assert.equal(report.summary.quarantined, 1)
  assert.equal(findingsFor(report, 'policy-target-never-seen').length, 0)
})

test('a clean run still names a target no record carried, so the claim was not simply deleted', async () => {
  const report = await apiReport(
    {
      'access.log': logOf([ALL_TARGETS, ALL_TARGETS]),
      'redaction-policy.json': policy({ ...FOUR_TARGETS, redactFields: ['user.email', 'never.here'] }),
    },
  )

  assert.equal(report.summary.quarantined, 0)
  assert.deepEqual(
    findingsFor(report, 'policy-target-never-seen').map((finding) => finding.location.pointer),
    ['/redactFields/never.here'],
  )
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
