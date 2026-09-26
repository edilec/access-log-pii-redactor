import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_LIMITS, RecordRefused, compilePolicy, escapePointer, redactRecord } from '../src/index.mjs'
import { CANARIES, apiReport, cliWrite, files, findingsFor, record } from './support.mjs'

const compile = (extra) => compilePolicy({ schemaVersion: '1', ...extra })
const run = (value, policy) => redactRecord(value, policy, DEFAULT_LIMITS, new Set())

test('a dotted path reaches a nested field and leaves its siblings alone', () => {
  const policy = compile({ redactFields: ['user.email'] })
  const { value, redactions } = run({ user: { id: 'u-1', email: CANARIES.email }, status: 200 }, policy)

  assert.deepEqual(JSON.parse(JSON.stringify(value)), { user: { id: 'u-1', email: '[redacted]' }, status: 200 })
  assert.equal(redactions, 1)
})

test('a path matches inside every element of an array, because an index is not a field name', () => {
  const policy = compile({ redactFields: ['items.email'] })
  const { value } = run({ items: [{ email: CANARIES.email }, { email: 'other@example.invalid' }, { id: 'x' }] }, policy)

  assert.deepEqual(JSON.parse(JSON.stringify(value)).items, [{ email: '[redacted]' }, { email: '[redacted]' }, { id: 'x' }])
})

test('a named field that holds an object or an array goes whole, and says so', () => {
  const policy = compile({ redactFields: ['user'] })
  const { value, notes } = run({ user: { email: CANARIES.email, sessions: [1, 2] } }, policy)

  assert.equal(value.user, '[redacted]')
  assert.deepEqual(notes.map((entry) => entry.reason), ['an object was replaced whole'])
})

test('header names fold and query parameter names do not', () => {
  const policy = compile({
    urlFields: ['url'],
    queryParams: ['token'],
    headerFields: ['headers'],
    headers: ['x-api-key'],
  })
  const { value } = run({
    url: '/a?token=t1&Token=t2&other=t3',
    headers: { 'X-API-Key': 'k1', 'x-other': 'k2' },
  }, policy)

  assert.equal(value.url, '/a?token=[redacted]&Token=t2&other=t3', 'a query parameter is case-sensitive on the wire')
  assert.equal(value.headers['X-API-Key'], '[redacted]', 'a header is not')
  assert.equal(value.headers['x-other'], 'k2')
})

test('a query string keeps its shape: order, separators and untouched parameters', () => {
  const policy = compile({ urlFields: ['url'], queryParams: ['token'] })
  const { value } = run({ url: '/search?q=a+b&token=xyz&page=2#frag' }, policy)

  assert.equal(value.url, '/search?q=a+b&token=[redacted]&page=2#frag')
})

test('a request target with no query is still scanned for identifiers', () => {
  const policy = compile({ urlFields: ['url'], detectors: ['email-address'] })
  const { value } = run({ url: `/users/${CANARIES.email}/orders` }, policy)

  assert.equal(value.url, '/users/[redacted]/orders')
})

test('a value the policy does not name is still scanned by the enabled detectors', () => {
  const policy = compile({ redactFields: ['user.email'], detectors: ['aws-access-key-id'] })
  const { value } = run({ user: { email: 'a@b.invalid' }, note: `key ${CANARIES.awsKey} here` }, policy)

  assert.equal(value.note, 'key [redacted] here')
})

test('types that carry nothing are left exactly as they were', () => {
  const policy = compile({ redactFields: ['user.email'], detectors: ['pan-digits'] })
  const { value } = run({ user: { email: 'a@b.invalid' }, ok: true, missing: null, bytes: 8241, ratio: 0.5 }, policy)

  assert.equal(value.ok, true)
  assert.equal(value.missing, null)
  assert.equal(value.bytes, 8241)
  assert.equal(value.ratio, 0.5)
})

test('a record refused for depth or width throws rather than being partly redacted', () => {
  const policy = compile({ redactFields: ['a'] })
  let deep = { leaf: 1 }
  for (let index = 0; index < 20; index += 1) deep = { nest: deep }

  assert.throws(() => run(deep, policy), (error) => error instanceof RecordRefused && error.ruleId === 'record-too-deep')

  const wide = {}
  for (let index = 0; index < 300; index += 1) wide[`f${index}`] = index
  assert.throws(() => run(wide, policy), (error) => error instanceof RecordRefused && error.ruleId === 'record-too-many-fields')
})

test('a refused record leaves the run\'s seen-set exactly as it found it', () => {
  // `seen` is what the run uses to say a policy target exists in the log. A
  // walk that is abandoned has looked at part of a record and nothing more, so
  // what it reached before throwing is not evidence -- and leaving it behind
  // made the answer depend on walk order: the same record marked
  // `addressFields:client.ip` seen when maxFieldsPerRecord stopped it (the walk
  // got that far) and did not when maxDepth stopped it (it did not).
  const policy = compile({
    addressFields: ['client.ip'],
    headerFields: ['request.headers'],
    headers: ['authorization'],
    redactFields: ['user.email'],
  })
  const carriesEverything = {
    client: { ip: '203.0.113.9' },
    request: { headers: { authorization: 'Bearer abcdefghijklmno' } },
    user: { email: CANARIES.email },
  }

  // The control: read whole, this record marks all four.
  const whole = new Set()
  redactRecord(carriesEverything, policy, DEFAULT_LIMITS, whole)
  assert.deepEqual([...whole].sort(), [
    'addressFields:client.ip',
    'headerFields:request.headers',
    'headers:authorization',
    'redactFields:user.email',
  ])

  for (const limits of [{ ...DEFAULT_LIMITS, maxDepth: 1 }, { ...DEFAULT_LIMITS, maxFieldsPerRecord: 2 }]) {
    const seen = new Set(['a-target-the-caller-already-had'])
    assert.throws(() => redactRecord(carriesEverything, policy, limits, seen), RecordRefused)
    assert.deepEqual([...seen], ['a-target-the-caller-already-had'],
      `a walk stopped by ${JSON.stringify(limits.maxDepth === 1 ? 'maxDepth' : 'maxFieldsPerRecord')} left marks behind`)
  }
})

test('a key that would reach the prototype setter stays an ordinary field', () => {
  const policy = compile({ redactFields: ['a'] })
  const { value } = run(JSON.parse('{"__proto__":{"polluted":true},"a":"x"}'), policy)

  assert.equal(JSON.stringify(value), '{"__proto__":{"polluted":true},"a":"[redacted]"}')
  assert.equal({}.polluted, undefined, 'nothing was written to Object.prototype')
})

test('field order is the record order, so a redacted log still diffs against its source', async () => {
  const result = await cliWrite(files([record()]))
  const source = Object.keys(record())
  const written = Object.keys(JSON.parse(result.written.trim()))

  assert.deepEqual(written, source)
})

test('a pointer escapes the two characters a JSON Pointer reserves', () => {
  assert.equal(escapePointer('a/b'), 'a~1b')
  assert.equal(escapePointer('a~b'), 'a~0b')
  assert.equal(escapePointer('plain'), 'plain')
})

test('the pointer on a note locates the exact value, index included', async () => {
  const report = await apiReport(files([record({ hops: [{ ip: '203.0.113.1' }, { ip: 'not-an-address' }] })]), {
    policy: 'redaction-policy.json',
  })
  assert.equal(findingsFor(report, 'address-unrecognised').length, 0, 'the fixture policy does not name hops.ip')

  const named = await apiReport({
    'access.log': `${JSON.stringify({ hops: [{ ip: '203.0.113.1' }, { ip: 'not-an-address' }] })}\n`,
    'redaction-policy.json': { schemaVersion: '1', addressFields: ['hops.ip'] },
  })
  const [finding] = findingsFor(named, 'address-unrecognised')
  assert.equal(finding.location.pointer, '/hops/1/ip')
})
