import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, DETECTOR_NAMES, RULE_SEVERITY, byCodeUnit } from '../src/index.mjs'
import { apiReport, fullPolicy, record } from './support.mjs'

/**
 * The ordering sites that cannot be pinned, proved equivalent instead of left
 * as gaps.
 *
 * `test/ordering.test.mjs` pins the sites whose values can move under
 * collation. The rest order values drawn from alphabets on which code-unit
 * order and English collation agree on every pair -- rule ids and detector
 * names over `[a-z-]`, and this package's own limit names -- plus one
 * tiebreaker that no reachable input reaches at all. Substituting a collator at
 * any of them is an *equivalent* mutation: the output cannot change, so no test
 * can catch it, and saying so with an enumeration is more honest than either
 * claiming coverage or leaving the gap unmentioned.
 */

const collator = new Intl.Collator('en')

function everyOrderedPairAgrees(values, label) {
  let compared = 0
  for (const left of values) {
    for (const right of values) {
      assert.equal(
        Math.sign(byCodeUnit(left, right)),
        Math.sign(collator.compare(left, right)),
        `${label}: "${left}" vs "${right}" would move under collation`,
      )
      compared += 1
    }
  }
  return compared
}

test('every ordered pair of real rule ids collates exactly as it compares by code unit', () => {
  const ruleIds = Object.keys(RULE_SEVERITY)

  assert.equal(ruleIds.length > 15, true, 'the catalog must be the real one for this to prove anything')
  // The alphabet this proof rests on: lower case, digits and the hyphen. A
  // digit sorts before a letter both by code point and under English collation,
  // and the enumeration below checks that for every pair rather than asserting
  // it here.
  for (const ruleId of ruleIds) assert.match(ruleId, /^[a-z][a-z0-9-]*[a-z0-9]$/, 'the alphabet this proof rests on')
  assert.equal(everyOrderedPairAgrees(ruleIds, 'rule id'), ruleIds.length ** 2)
})

test('every ordered pair of detector names collates exactly as it compares by code unit', () => {
  for (const name of DETECTOR_NAMES) assert.match(name, /^[a-z][a-z-]*[a-z]$/)
  assert.equal(everyOrderedPairAgrees(DETECTOR_NAMES, 'detector name'), DETECTOR_NAMES.length ** 2)
})

test('every ordered pair of limit names collates exactly as it compares by code unit', () => {
  const names = Object.keys(DEFAULT_LIMITS)

  assert.equal(names.length, 9)
  assert.equal(everyOrderedPairAgrees(names, 'limit name'), names.length ** 2)
})

/**
 * The message comparison, proved unreachable rather than claimed to be pinned.
 *
 * `compareFindings` falls through to the message only when two findings agree
 * on file, line, pointer *and* rule id. No rule in this package can emit two
 * findings that agree on all four: a record raises at most one quarantine
 * finding, an aggregated note keeps one entry per rule and path, and a
 * never-seen target carries its own pointer. The set of ordered pairs that
 * reach that comparison is therefore empty, which is what makes substituting a
 * collator there an equivalent mutation.
 *
 * The case below drives a log that raises as many different kinds of finding at
 * once as this tool can, and asserts the four-part key is unique across all of
 * them. If a future rule breaks that, this fails and the comparison becomes
 * reachable -- at which point it needs a pinning case in `ordering.test.mjs`
 * rather than this one.
 */
test('no two findings share file, line, pointer and rule id, so the message tiebreaker is never reached', async () => {
  const dense = [
    JSON.stringify(record()),
    '{"broken":,}',
    '[1,2,3]',
    JSON.stringify({ ts: 'x', client: { ip: 'not-an-address' }, user: { email: 'a@b.invalid' } }),
    JSON.stringify({ ts: 'x', client: { ip: { nested: true } }, user: { email: 'a@b.invalid' } }),
    JSON.stringify({ ts: 'x', user: { email: { parts: ['a', 'b'] } }, long: 'q'.repeat(300) }),
    JSON.stringify({ ts: 'x', seats: { 'ada@example.invalid': 1 } }),
    JSON.stringify({ ts: 'x', request: { url: 12, headers: [] }, user: { email: 'a@b.invalid' } }),
  ]
  const report = await apiReport(
    { 'access.log': `${dense.join('\n')}\n`, 'redaction-policy.json': fullPolicy() },
    { limits: { maxValueLength: 100 } },
  )

  assert.equal(report.findings.length >= 8, true, 'the fixture must be dense enough to mean something')
  const keys = report.findings.map((finding) =>
    JSON.stringify([finding.location.file, finding.location.line, finding.location.pointer, finding.ruleId]))
  assert.equal(new Set(keys).size, keys.length, 'a collision would make the message comparison reachable')
})

test('the aggregated notes reach the report in an order the finding sort then decides', async () => {
  const rows = [
    JSON.stringify({ ts: 'x', beta: 'q'.repeat(300), user: { email: 'a@b.invalid' } }),
    JSON.stringify({ ts: 'x', Alpha: 'q'.repeat(300), user: { email: 'a@b.invalid' } }),
  ]
  const report = await apiReport(
    { 'access.log': `${rows.join('\n')}\n`, 'redaction-policy.json': fullPolicy() },
    { limits: { maxValueLength: 100 } },
  )
  const pointers = report.findings
    .filter((finding) => finding.ruleId === 'value-over-limit')
    .map((finding) => finding.location.pointer)

  // `/Alpha` is first seen on line 2 and `/beta` on line 1, so the line decides
  // and the pointer never gets a vote. That is the documented key, in order.
  assert.deepEqual(pointers, ['/beta', '/Alpha'])
})
