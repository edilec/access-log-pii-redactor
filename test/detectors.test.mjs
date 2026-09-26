import assert from 'node:assert/strict'
import { performance } from 'node:perf_hooks'
import test from 'node:test'

import { DETECTOR_NAMES, detectorsMatching, luhn, redactDetected } from '../src/index.mjs'
import { CANARIES } from './support.mjs'

const all = new Set(DETECTOR_NAMES)
const only = (name) => new Set([name])

test('each detector fires on the published placeholder it is for', () => {
  assert.deepEqual(detectorsMatching(CANARIES.awsKey, all), ['aws-access-key-id'])
  assert.deepEqual(detectorsMatching(CANARIES.card, all), ['pan-digits'])
  assert.deepEqual(detectorsMatching(`mail ${CANARIES.email} here`, all), ['email-address'])
  assert.deepEqual(detectorsMatching(CANARIES.bearer, all), ['bearer-token'])
  assert.deepEqual(detectorsMatching(CANARIES.jwt, all), ['jwt'])
  assert.deepEqual(detectorsMatching('-----BEGIN RSA PRIVATE KEY-----', all), ['private-key-block'])
})

test('a detector that is not enabled does not fire', () => {
  assert.deepEqual(detectorsMatching(CANARIES.awsKey, only('pan-digits')), [])
  assert.deepEqual(detectorsMatching(CANARIES.awsKey, new Set()), [])
})

test('the card detector is gated on the check digit, not on digit count alone', () => {
  assert.equal(luhn('4111111111111111'), true)
  assert.equal(luhn('4111111111111112'), false)
  assert.deepEqual(detectorsMatching('4111111111111112', all), [], 'a run that fails the check digit is left alone')
  assert.deepEqual(detectorsMatching('4111 1111 1111 1111', all), ['pan-digits'], 'grouping by spaces is still a card')
  assert.deepEqual(detectorsMatching('4111-1111-1111-1111', all), ['pan-digits'], 'grouping by hyphens is still a card')
  assert.deepEqual(detectorsMatching('123456', all), [], 'a short run is not a card')
})

test('ordinary log values do not fire a detector', () => {
  for (const value of [
    '/v1/search?q=router', 'curl/8.6.0', '2026-09-12T10:15:00Z', '203.0.113.42',
    'u-4417', 'application/json', 'session=s-7781', 'Mozilla/5.0 (Macintosh)',
  ]) {
    assert.deepEqual(detectorsMatching(value, all), [], `${value} must not be treated as an identifier`)
  }
})

test('redaction replaces the match and leaves the rest of the value', () => {
  const { text, count } = redactDetected(`user ${CANARIES.email} ok`, all, '[redacted]')

  assert.equal(text, 'user [redacted] ok')
  assert.equal(count, 1)
})

test('an overlapping value is decided by one detector, in a fixed order', () => {
  const { text } = redactDetected(`Bearer ${CANARIES.jwt}`, all, '[redacted]')

  assert.equal(text, '[redacted]', 'bearer-token runs before jwt, so the whole credential goes once')
})

test('the shared patterns carry no state between calls', () => {
  for (let round = 0; round < 3; round += 1) {
    assert.deepEqual(detectorsMatching(CANARIES.awsKey, all), ['aws-access-key-id'], `round ${round}`)
    assert.equal(redactDetected(CANARIES.awsKey, all, '[x]').count, 1, `round ${round}`)
  }
})

/**
 * A scan that is superlinear in its input is not fixed by a length bound; the
 * bound only caps how bad it gets. This case is the regression test for that.
 *
 * It is not the guarantee itself -- a regular expression cannot be interrupted,
 * so no timer can bound one while it runs. The guarantee is the shape of the
 * patterns and the hand-written, `@`-anchored email scanner that replaced the
 * obvious pattern for exactly this reason: the pattern version took 4.8 seconds
 * over the sweep below, at the largest value `maxValueLength` allows. The
 * linear version takes about a tenth of a second.
 */
test('the worst-case input a bound allows is scanned in linear time', () => {
  const size = 4096
  const adversarial = [
    'a'.repeat(size),
    `${'a'.repeat(size - 2)}@`,
    `a@${'b'.repeat(size - 4)}.`,
    '@'.repeat(size),
    'a@'.repeat(size / 2),
    'a.b@'.repeat(size / 4),
    `${'a'.repeat(size / 2)}@${'b'.repeat(size / 2 - 1)}`,
    '1'.repeat(size),
    '1 '.repeat(size / 2),
    '1-'.repeat(size / 2),
    `AKIA${'A'.repeat(size - 4)}`,
    `Bearer ${' '.repeat(size - 7)}`,
    `eyJ${'a'.repeat(size - 3)}`,
    `${'-'.repeat(size - 10)}BEGIN AAAA`,
  ]

  const started = performance.now()
  for (const value of adversarial) redactDetected(value, all, '[redacted]')
  const elapsed = performance.now() - started

  assert.equal(elapsed < 1000, true, `the sweep took ${Math.round(elapsed)}ms; a scan has stopped being linear`)
})

test('an address is found wherever it sits, and a near-miss is left alone', () => {
  assert.deepEqual(detectorsMatching('ada@canary.invalid', all), ['email-address'])
  assert.deepEqual(detectorsMatching('<ada@canary.invalid>', all), ['email-address'])
  assert.deepEqual(detectorsMatching('.ada@canary.invalid', all), ['email-address'])
  assert.deepEqual(detectorsMatching('ada@localhost', all), [], 'one label is not a domain')
  assert.deepEqual(detectorsMatching('@canary.invalid', all), [], 'an empty local part is not an address')
  assert.deepEqual(detectorsMatching('ada@.invalid', all), [], 'an empty first label is not a domain')
  assert.equal(redactDetected('/users/ada@x.invalid/orders', all, '[r]').text, '/users/[r]/orders')
})

test('the detector vocabulary is closed and ordered', () => {
  assert.deepEqual(DETECTOR_NAMES, [
    'aws-access-key-id', 'bearer-token', 'email-address', 'jwt', 'pan-digits', 'private-key-block',
  ])
  assert.deepEqual([...DETECTOR_NAMES].sort(), [...DETECTOR_NAMES])
})
