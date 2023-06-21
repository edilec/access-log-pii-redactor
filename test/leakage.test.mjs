import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CANARIES, cliReport, cliWrite, files, findingsFor, fullPolicy, policy, record, substringsOf,
} from './support.mjs'

/**
 * The other half of the acceptance case: a synthetic secret that goes in does
 * not come out -- not in the redacted log, not on stdout, not on stderr.
 *
 * Every canary here is a published placeholder that authenticates nothing: the
 * vendor's own documented example access key, the standard test card number,
 * and a domain reserved by RFC 2606. Each case scans *every* substring of the
 * canary down to six characters across all three destinations at once, because
 * a leak test that checks the field somebody remembered is a test the next
 * field passes for free.
 */

function assertClean(haystack, label) {
  for (const [name, canary] of Object.entries(CANARIES)) {
    for (const part of substringsOf(canary, 6)) {
      assert.equal(haystack.includes(part), false, `${label}: leaked ${name} as "${part}"`)
    }
  }
}

const everywhere = (result) => `${result.stdout}\n${result.stderr}\n${result.written ?? ''}`

test('canaries in ordinary values reach neither the output nor either stream', async () => {
  const leaky = record({
    user: { id: 'u-1', email: CANARIES.email },
    note: `key ${CANARIES.awsKey} card ${CANARIES.card} token ${CANARIES.bearer} jwt ${CANARIES.jwt}`,
  })
  const result = await cliWrite(files([leaky, record()]))

  assert.equal(result.code, 0)
  assert.equal(result.report.status, 'pass')
  assert.equal(result.written.trim().split('\n').length, 2)
  assert.equal(result.written.includes('[redacted]'), true, 'something was actually replaced')
  assertClean(everywhere(result), 'a value')
})

test('a canary in a query parameter reaches neither the output nor either stream', async () => {
  const named = record({ request: { url: `/v1/search?token=${CANARIES.awsKey}`, headers: {} } })
  const unnamed = record({ request: { url: `/v1/search?note=${CANARIES.card}`, headers: {} } })
  const result = await cliWrite(files([named, unnamed]))

  assert.equal(result.report.summary.written, 2)
  assert.equal(result.written.includes('token=[redacted]'), true)
  assertClean(everywhere(result), 'a query parameter')
})

test('a percent-encoded canary in a query parameter is decoded before it is judged', async () => {
  const encoded = record({ request: { url: `/v1/accounts?who=${encodeURIComponent(CANARIES.email)}`, headers: {} } })
  const result = await cliWrite(files([encoded, record()]))

  assert.equal(result.written.includes('who=[redacted]'), true)
  assertClean(everywhere(result), 'an encoded query parameter')
})

test('a canary in a header reaches neither the output nor either stream', async () => {
  const named = record({ request: { url: '/v1/x', headers: { authorization: CANARIES.bearer } } })
  const unnamed = record({ request: { url: '/v1/x', headers: { 'x-trace': CANARIES.jwt } } })
  const result = await cliWrite(files([named, unnamed]))

  assert.equal(result.report.summary.written, 2)
  assertClean(everywhere(result), 'a header')
})

test('a canary exported as a JSON number is redacted, not printed', async () => {
  const numeric = record({ card: Number(CANARIES.card) })
  const result = await cliWrite(files([numeric, record()]))

  assert.equal(result.report.summary.written, 2)
  assert.equal(result.written.includes('"card":"[redacted]"'), true)
  assertClean(everywhere(result), 'a numeric value')
})

test('a value too long to scan is replaced whole rather than passed through', async () => {
  const long = record({ note: `${'q'.repeat(200)}${CANARIES.awsKey}${'q'.repeat(200)}` })
  const result = await cliWrite(files([long, record()]), ['--max-value-length', '100'])

  assert.equal(result.report.summary.written, 2)
  const [finding] = findingsFor(result.report, 'value-over-limit')
  assert.equal(finding.location.pointer, '/note')
  assert.equal(finding.message.includes('maxValueLength (100)'), true)
  assert.equal(result.written.includes('"note":"[redacted]"'), true)
  assertClean(everywhere(result), 'an over-long value')
})

test('an address the parser cannot read is replaced whole rather than passed through', async () => {
  const odd = record({ client: { ip: `proxy-hop-for-${CANARIES.email}` } })
  const result = await cliWrite(files([odd, record()]))

  assert.equal(result.report.summary.written, 2)
  assert.equal(findingsFor(result.report, 'address-unrecognised').length, 1)
  assert.equal(result.written.includes('"ip":"[redacted]"'), true)
  assertClean(everywhere(result), 'an unreadable address')
})

test('a field the policy names but whose value is the wrong shape is replaced whole', async () => {
  const wrong = record({ client: { ip: { v4: CANARIES.email } } })
  const result = await cliWrite(files([wrong, record()]))

  const [finding] = findingsFor(result.report, 'field-shape-unexpected')
  assert.equal(finding.location.pointer, '/client/ip')
  assert.equal(result.written.includes('"ip":"[redacted]"'), true)
  assertClean(everywhere(result), 'a mis-shaped field')
})

test('stdout carries the report and nothing else, and a populated stderr is correct', async () => {
  const result = await cliReport(files([record()]))

  assert.doesNotThrow(() => JSON.parse(result.stdout))
  assert.equal(result.stdout.trimStart().startsWith('{'), true)
  assert.equal(result.stderr.length > 0, true, 'diagnostics belong on stderr, and an empty stderr would be the surprise')
  assert.equal(result.stderr.includes('{'), false, 'no part of the report is duplicated onto stderr')
})

/**
 * The honest limit, asserted rather than described.
 *
 * With every detector switched off, a value in a field the policy does not name
 * is not redacted -- and the run still reports `pass`, because the policy it was
 * given was satisfied. `README.md` says this in its own words; this case is what
 * keeps that sentence true.
 */
test('a field no policy target names and no detector covers is not redacted, and the run says pass', async () => {
  const quiet = policy({ redactFields: ['user.email'] })
  const leaky = record({ user: { id: 'u-1', email: CANARIES.email }, note: `contact ${CANARIES.email}` })
  const result = await cliWrite({ 'access.log': `${JSON.stringify(leaky)}\n`, 'redaction-policy.json': quiet })

  assert.equal(result.code, 0)
  assert.equal(result.report.status, 'pass')
  assert.equal(result.written.includes(CANARIES.email), true, 'the unnamed field is untouched; this is the documented limit')
  assert.equal(result.written.includes('"email":"[redacted]"'), true, 'the named field is redacted')
})

test('the same inputs produce byte-identical stdout twice', async () => {
  const inputs = files([record(), '{"broken":,}', record()])
  const first = await cliReport(inputs)
  const second = await cliReport(inputs)

  assert.equal(first.stdout, second.stdout)
  assert.equal(first.code, second.code)
})

test('the full policy leaves nothing of a canary in the output digest path', async () => {
  const result = await cliWrite(files([record({ note: CANARIES.awsKey })]), [], 'out.log')

  assert.equal(result.report.output.file, 'out.log')
  assert.equal(result.report.output.written, 1)
  assert.match(result.report.output.digest, /^[0-9a-f]{64}$/)
  assert.equal(typeof result.report.input.policyDigest, 'string')
  assertClean(everywhere(result), 'the written file')
  assert.equal(fullPolicy().detectors.length, result.report.input.detectors.length)
})
