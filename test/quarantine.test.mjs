import assert from 'node:assert/strict'
import test from 'node:test'

import { LINE_SHAPES } from '../src/index.mjs'
import {
  CANARIES, apiReport, cliReport, cliWrite, files, findingsFor, fullPolicy, record, substringsOf,
} from './support.mjs'

/**
 * The acceptance case: a malformed record is quarantined by line number and
 * shape, and its content is never echoed.
 *
 * A parse error that prints the offending line defeats this entire tool, and
 * `JSON.parse` messages quote the input they choked on -- which is exactly the
 * line that never went through redaction. So the cases below do not check that
 * the report "looks redacted": they take the malformed line itself and assert
 * that no substring of it, down to twelve characters, appears anywhere on
 * either stream, and that every prefix of every canary it carries is absent
 * too.
 *
 * The malformed line is written with field names that occur nowhere else in
 * this package, so a collision would be a real leak rather than a coincidence.
 */

const MALFORMED = '{"zqfld":"AKIAIOSFODNN7EXAMPLE","pnum":"4111111111111111","eml":"ada@canary.invalid",,}'

const scanStreams = (result) => `${result.stdout}\n${result.stderr}`

function assertAbsent(haystack, needle, label, minimum = 6) {
  for (const part of substringsOf(needle, minimum)) {
    assert.equal(haystack.includes(part), false, `${label}: leaked "${part}"`)
  }
}

test('a malformed record is located by line and shape, and nothing of it is echoed', async () => {
  const result = await cliReport(files([record(), MALFORMED, record()]))
  const streams = scanStreams(result)

  assert.equal(result.code, 1)
  assert.equal(result.report.status, 'fail')
  assert.equal(result.report.summary.quarantined, 1)
  assert.equal(result.report.summary.written, 2)

  const [finding] = findingsFor(result.report, 'record-not-json')
  assert.equal(finding.location.line, 2)
  assert.equal(finding.location.file, 'access.log')
  assert.equal(LINE_SHAPES.includes('object-like'), true)
  assert.equal(finding.message.includes('object-like'), true)
  assert.equal(finding.message.includes(`${MALFORMED.length} byte(s)`), true)

  assertAbsent(streams, MALFORMED, 'the malformed line', 12)
  for (const canary of Object.values(CANARIES)) assertAbsent(streams, canary, 'a canary', 6)
})

test('no parser message is read, so no parser wording reaches either stream', async () => {
  const result = await cliReport(files([MALFORMED]))
  const streams = scanStreams(result).toLowerCase()

  for (const wording of ['unexpected token', 'unexpected end of json', 'at position', 'is not valid json input']) {
    assert.equal(streams.includes(wording), false, `a parser message reached the report: ${wording}`)
  }
})

test('a quarantined record is not written to the output', async () => {
  const result = await cliWrite(files([record(), MALFORMED]))

  assert.equal(result.code, 1)
  assert.equal(result.written.trim().split('\n').length, 1)
  assertAbsent(result.written, MALFORMED, 'the output file', 12)
})

test('a record that parses but is not an object is quarantined by type, not by content', async () => {
  const array = `["2026-09-12","${CANARIES.awsKey}","${CANARIES.card}"]`
  const result = await cliReport(files([record(), array]))

  assert.equal(result.report.summary.quarantined, 1)
  const [finding] = findingsFor(result.report, 'record-not-object')
  assert.equal(finding.location.line, 2)
  assert.equal(finding.message.includes('array'), true)
  assertAbsent(scanStreams(result), array, 'the non-object record', 12)
})

test('a record that is not UTF-8 is quarantined undecoded, by byte count alone', async () => {
  const bad = Buffer.concat([
    Buffer.from('{"a":"'),
    Buffer.from([0xff, 0xfe, 0xfd]),
    Buffer.from(`${CANARIES.awsKey}"}`),
  ])
  const log = Buffer.concat([Buffer.from(`${JSON.stringify(record())}\n`), bad, Buffer.from('\n')])
  const result = await cliReport({ 'access.log': log, 'redaction-policy.json': fullPolicy() })

  assert.equal(result.code, 1)
  assert.equal(result.report.summary.quarantined, 1)
  const [finding] = findingsFor(result.report, 'record-not-utf8')
  assert.equal(finding.location.line, 2)
  assert.equal(finding.message.includes(`${bad.length} byte(s)`), true)
  assertAbsent(scanStreams(result), CANARIES.awsKey, 'the aws canary', 6)
})

test('an over-long record is quarantined without being buffered or quoted', async () => {
  const long = JSON.stringify({ ts: '2026-09-12T10:15:00Z', filler: 'q'.repeat(600), key: CANARIES.awsKey })
  const result = await cliReport(files([record(), long]), ['--max-line-bytes', '400'])

  assert.equal(result.code, 1)
  assert.equal(result.report.summary.quarantined, 1)
  const [finding] = findingsFor(result.report, 'record-too-large')
  assert.equal(finding.location.line, 2)
  assert.equal(finding.message.includes('maxLineBytes limit of 400'), true)
  assertAbsent(scanStreams(result), long, 'the over-long line', 12)
})

test('a record nested deeper than the bound is quarantined whole', async () => {
  let deep = { leaf: CANARIES.awsKey }
  for (let index = 0; index < 20; index += 1) deep = { [`level${index}`]: deep }
  const result = await cliReport(files([record(), deep]))

  assert.equal(result.report.summary.quarantined, 1)
  const [finding] = findingsFor(result.report, 'record-too-deep')
  assert.equal(finding.location.line, 2)
  assert.equal(finding.message.includes('maxDepth limit of 12'), true)
  for (const canary of Object.values(CANARIES)) assertAbsent(scanStreams(result), canary, 'a canary', 6)
})

test('a record with more fields than the bound is quarantined whole', async () => {
  const wide = { ts: '2026-09-12T10:15:00Z' }
  for (let index = 0; index < 300; index += 1) wide[`f${index}`] = CANARIES.card
  const result = await cliReport(files([record(), wide]))

  assert.equal(result.report.summary.quarantined, 1)
  const [finding] = findingsFor(result.report, 'record-too-many-fields')
  assert.equal(finding.location.line, 2)
  assert.equal(finding.message.includes('maxFieldsPerRecord limit of 256'), true)
  assertAbsent(scanStreams(result), CANARIES.card, 'the card canary', 6)
})

test('an identifier that survives redaction quarantines the record it is a key of', async () => {
  const withKey = { ts: '2026-09-12T10:15:00Z', seats: { [CANARIES.email]: 'row-4' } }
  const result = await cliWrite(files([record(), withKey]))

  assert.equal(result.code, 1)
  assert.equal(result.report.summary.quarantined, 1)
  const [finding] = findingsFor(result.report, 'record-residual-identifier')
  assert.equal(finding.location.line, 2)
  assert.equal(finding.location.pointer, '')
  assertAbsent(`${scanStreams(result)}\n${result.written}`, CANARIES.email, 'the email canary', 6)
})

test('the quarantine count and the written count always add up to the records read', async () => {
  const report = await apiReport(files([record(), MALFORMED, record(), '[1,2,3]', record()]))

  assert.equal(report.summary.records, 5)
  assert.equal(report.summary.written + report.summary.quarantined, report.summary.records)
})
