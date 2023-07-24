import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, HARD_LIMITS, validateLimits } from '../src/index.mjs'
import { apiReport, cliReport, files, findingsFor, fullPolicy, raisedRules, record } from './support.mjs'

/**
 * Every documented limit, enforced and reported by name.
 *
 * The distinction this package draws, and which `docs/redaction-rules.md`
 * states: a *record* bound quarantines that record -- a definite outcome, the
 * record is withheld and the run carries on -- while a *run* bound stops the
 * stream and leaves an unread remainder, which is `incomplete`. Neither is ever
 * a silent truncation.
 */

test('every default limit has a hard cap, and a caller may lower but not raise', () => {
  assert.deepEqual(Object.keys(DEFAULT_LIMITS).sort(), Object.keys(HARD_LIMITS).sort())
  for (const [key, value] of Object.entries(DEFAULT_LIMITS)) {
    assert.equal(value <= HARD_LIMITS[key], true, `${key} default must be within its cap`)
    assert.equal(validateLimits({ [key]: 1 })[key], 1)
    assert.throws(() => validateLimits({ [key]: HARD_LIMITS[key] + 1 }), new RegExp(`limits.${key}`))
    assert.throws(() => validateLimits({ [key]: 0 }), new RegExp(`limits.${key}`))
    assert.throws(() => validateLimits({ [key]: 1.5 }), new RegExp(`limits.${key}`))
  }
})

test('an unknown limit throws instead of being ignored', () => {
  assert.throws(() => validateLimits({ maxRecord: 5 }), /Unknown limit "maxRecord"/)
  assert.throws(() => validateLimits(null), /limits must be an object/)
})

test('an unknown option throws instead of being ignored', async () => {
  await assert.rejects(() => apiReport(files([record()]), { roots: '.' }), /Unknown option "roots"/)
})

test('a mistyped limit flag is a configuration error with an empty stdout', async () => {
  const result = await cliReport(files([record()]), ['--max-record', '5'])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr.includes('Unknown option "--max-record"'), true)
})

test('a repeated flag is refused rather than silently last-wins', async () => {
  const result = await cliReport(files([record()]), ['--max-records', '5', '--max-records', '6'])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr.includes('given more than once'), true)
})

test('more records than the bound stops the run and says so', async () => {
  const result = await cliReport(files([record(), record(), record()]), ['--max-records', '2'])

  assert.equal(result.code, 2)
  assert.equal(result.report.status, 'incomplete')
  assert.equal(result.report.summary.records, 2)
  const [finding] = findingsFor(result.report, 'too-many-records')
  assert.equal(finding.message.includes('maxRecords limit of 2'), true)
})

test('a log larger than the byte bound is refused unread', async () => {
  const result = await cliReport(files([record(), record()]), ['--max-input-bytes', '100'])

  assert.equal(result.code, 2)
  assert.equal(result.report.status, 'incomplete')
  assert.equal(result.report.summary.records, 0)
  assert.equal(result.report.summary.bytesRead, 0)
  const [finding] = findingsFor(result.report, 'input-too-large')
  assert.equal(finding.message.includes('maxInputBytes limit of 100'), true)
  assert.equal(finding.message.includes('it was not read'), true)
})

test('the time budget takes its milliseconds from an injected clock', async () => {
  let now = 0
  const report = await apiReport(files([record(), record(), record(), record()]), {
    clock: () => {
      now += 40
      return now
    },
    limits: { maxRuntimeMs: 60 },
  })

  assert.equal(report.status, 'incomplete')
  assert.equal(report.summary.records < 4, true, 'the run stopped before the end')
  const [finding] = findingsFor(report, 'time-budget-exceeded')
  assert.equal(finding.message.includes('maxRuntimeMs budget of 60'), true)
})

test('with no clock injected the run still completes, and reads no time of day', async () => {
  // The README used to say the budget "takes its milliseconds from an injected
  // clock", which is a claim about every run. It is injectABLE: with nothing
  // supplied it reads performance.now(), a monotonic counter. What the two
  // spellings share is the part that matters -- two runs with no clock at all
  // produce identical bytes, because no value the budget reads is written
  // anywhere.
  const inputs = files([record(), record(), record()])
  const first = await apiReport(inputs)
  const second = await apiReport(inputs)

  assert.equal(first.status, 'pass')
  assert.equal(first.summary.records, 3)
  assert.equal(JSON.stringify(first), JSON.stringify(second), 'two unclocked runs disagreed')
})

test('a clock that never advances lets the whole log through', async () => {
  const report = await apiReport(files([record(), record(), record()]), {
    clock: () => 0,
    limits: { maxRuntimeMs: 1 },
  })

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.records, 3)
})

test('more findings than the bound truncates deliberately and reports the truncation', async () => {
  const result = await cliReport(files(['{"a":,}', '{"b":,}', '{"c":,}', '{"d":,}']), ['--max-findings', '2'])

  assert.equal(result.code, 2)
  assert.equal(result.report.status, 'incomplete')
  assert.equal(result.report.findings.length, 2)
  const [finding] = findingsFor(result.report, 'too-many-findings')
  assert.equal(finding.message.includes('maxFindings limit of 2'), true)
  assert.match(finding.message, /\d+ were not reported/)
})

test('a record bound quarantines that record; the run completes and fails', async () => {
  const deep = (() => {
    let value = { leaf: 1 }
    for (let index = 0; index < 20; index += 1) value = { nest: value }
    return value
  })()
  const result = await cliReport(files([record(), deep, record()]))

  assert.equal(result.code, 1, 'a quarantined record is a completed failure, not an incomplete run')
  assert.equal(result.report.status, 'fail')
  assert.equal(result.report.summary.written, 2)
  assert.equal(result.report.summary.quarantined, 1)
})

test('a run bound leaves an unread remainder; the run is incomplete', async () => {
  const result = await cliReport(files([record(), record(), record()]), ['--max-records', '1'])

  assert.equal(result.code, 2)
  assert.equal(result.report.status, 'incomplete')
  assert.deepEqual(raisedRules(result.report), ['too-many-records'])
})

test('the value and query bounds are enforced per value', async () => {
  const long = record({ note: 'q'.repeat(300) })
  const many = record({ request: { url: `/a?${new Array(20).fill('k=v').join('&')}`, headers: {} } })
  const result = await cliReport(files([long, many]), ['--max-value-length', '100', '--max-query-params', '5'])

  const reasons = findingsFor(result.report, 'value-over-limit').map((finding) => finding.message)
  assert.equal(reasons.some((message) => message.includes('maxValueLength (100)')), true)
  assert.equal(reasons.some((message) => message.includes('maxQueryParams (5)')), true)
  assert.equal(result.report.status, 'pass', 'a bounded value is replaced whole, which is not a failure')
})

test('repeated occurrences of one note are aggregated rather than repeated', async () => {
  const long = () => record({ note: 'q'.repeat(300) })
  const result = await cliReport(files([long(), long(), long()]), ['--max-value-length', '100'])
  const found = findingsFor(result.report, 'value-over-limit')

  assert.equal(found.length, 1)
  assert.equal(found[0].location.line, 1, 'the line is the first occurrence')
  assert.equal(found[0].message.includes('3 occurrence(s)'), true)
})

/**
 * The other half of a bound: it must not fire on work that is inside it.
 *
 * Asking "have I done enough?" after each record reports a log of exactly
 * `maxRecords` records as one that held more, and a run that finished inside
 * its budget as one that ran out of it. Both are false `incomplete` reports
 * about a file that was read to its end, and a false refusal is a defect too.
 */
test('a log of exactly maxRecords records is complete, not stopped', async () => {
  const result = await cliReport(files([record(), record(), record()]), ['--max-records', '3'])

  assert.equal(result.code, 0)
  assert.equal(result.report.status, 'pass')
  assert.equal(result.report.summary.records, 3)
  assert.deepEqual(findingsFor(result.report, 'too-many-records'), [])
})

test('blank lines at the end of a log do not spend the record bound', async () => {
  const result = await cliReport(
    { 'access.log': `${JSON.stringify(record())}\n\n\n`, 'redaction-policy.json': fullPolicy() },
    ['--max-records', '1'],
  )

  assert.equal(result.code, 0)
  assert.equal(result.report.status, 'pass')
  assert.equal(result.report.summary.records, 1)
  assert.equal(result.report.summary.blank, 2)
})

test('a run that spends its whole budget on the last record is still complete', async () => {
  let now = 0
  const report = await apiReport(files([record(), record()]), {
    clock: () => {
      now += 40
      return now
    },
    limits: { maxRuntimeMs: 100 },
  })

  assert.equal(report.status, 'pass')
  assert.equal(report.summary.records, 2)
})
