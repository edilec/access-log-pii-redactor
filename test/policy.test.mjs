import assert from 'node:assert/strict'
import test from 'node:test'

import { DEFAULT_PLACEHOLDER, POLICY_KEYS, POLICY_SCHEMA_VERSION, compilePolicy } from '../src/index.mjs'
import { CANARIES, cliReport, files, policy, record } from './support.mjs'

const minimal = (extra = {}) => ({ schemaVersion: POLICY_SCHEMA_VERSION, redactFields: ['user.email'], ...extra })

test('a policy compiles into sets and a target list', () => {
  const compiled = compilePolicy(minimal({
    urlFields: ['request.url'],
    queryParams: ['token'],
    headerFields: ['request.headers'],
    headers: ['Authorization'],
    addressFields: ['client.ip'],
    detectors: ['email-address'],
  }))

  assert.equal(compiled.placeholder, DEFAULT_PLACEHOLDER)
  assert.equal(compiled.headers.has('authorization'), true, 'header names fold, because they fold on the wire')
  assert.equal(compiled.queryParams.has('token'), true)
  assert.equal(compiled.redactFields.has('user.email'), true)
  assert.equal(compiled.addressPolicy.ipv4PrefixBits, 24)
  assert.deepEqual(compiled.targets, [
    'addressFields:client.ip',
    'headerFields:request.headers',
    'headers:authorization',
    'queryParams:token',
    'redactFields:user.email',
    'urlFields:request.url',
  ])
})

test('an unknown key is a configuration error, not an ignored typo', () => {
  assert.throws(() => compilePolicy(minimal({ queryParam: ['token'] })), /Unknown policy key "queryParam"/)
  assert.throws(() => compilePolicy(minimal({ addressPolicy: { ipv4Prefix: 24 } })), /Unknown policy.addressPolicy key "ipv4Prefix"/)
})

test('a policy that declares nothing to redact is refused', () => {
  assert.throws(() => compilePolicy({ schemaVersion: '1' }), /declares nothing to redact/)
  assert.throws(() => compilePolicy({ schemaVersion: '1', redactFields: [] }), /declares nothing to redact/)
})

test('a name with nowhere to be looked for is refused', () => {
  assert.throws(() => compilePolicy(minimal({ queryParams: ['token'] })), /urlFields names no field/)
  assert.throws(() => compilePolicy(minimal({ headers: ['authorization'] })), /headerFields names no field/)
})

test('the schema version is required and exact', () => {
  assert.throws(() => compilePolicy({ redactFields: ['a'] }), /schemaVersion/)
  assert.throws(() => compilePolicy({ schemaVersion: 1, redactFields: ['a'] }), /schemaVersion/)
  assert.throws(() => compilePolicy({ schemaVersion: '2', redactFields: ['a'] }), /schemaVersion/)
})

test('paths and names are checked against a bounded alphabet', () => {
  assert.throws(() => compilePolicy(minimal({ redactFields: ['a.b.c.d.e.f.g.h.i'] })), /segments/)
  assert.throws(() => compilePolicy(minimal({ redactFields: ['user email'] })), /segment that is not a field name/)
  assert.throws(() => compilePolicy(minimal({ redactFields: [''] })), /non-empty strings/)
  assert.throws(() => compilePolicy(minimal({ redactFields: ['a', 'a'] })), /more than once/)
  assert.throws(() => compilePolicy(minimal({ redactFields: 'user.email' })), /must be an array/)
  assert.throws(
    () => compilePolicy(minimal({ headerFields: ['request.headers'], headers: ['Authorization', 'AUTHORIZATION'] })),
    /more than once, ignoring case/,
  )
})

test('a control or bidi character in a policy entry is refused at the door', () => {
  const withNewline = `user${String.fromCharCode(0x0a)}email`
  const withOverride = `user${String.fromCharCode(0x202e)}email`

  assert.throws(() => compilePolicy(minimal({ redactFields: [withNewline] })), /control, separator or bidi/)
  assert.throws(() => compilePolicy(minimal({ redactFields: [withOverride] })), /control, separator or bidi/)
})

test('a pattern cannot be supplied by a policy, and an unknown detector is refused', () => {
  assert.throws(() => compilePolicy(minimal({ detectors: ['everything'] })), /Unknown detector "everything"/)
  assert.throws(() => compilePolicy(minimal({ detectors: ['.*'] })), /Patterns cannot be supplied by a policy/)
})

test('the placeholder is checked, including against the detectors themselves', () => {
  assert.equal(compilePolicy(minimal({ placeholder: '***' })).placeholder, '***')
  assert.throws(() => compilePolicy(minimal({ placeholder: '' })), /1-64 printable ASCII/)
  assert.throws(() => compilePolicy(minimal({ placeholder: 'a"b' })), /quote or a backslash/)
  assert.throws(() => compilePolicy(minimal({ placeholder: CANARIES.email })), /matched by the email-address detector/)
})

test('address policy values are checked', () => {
  assert.throws(() => compilePolicy(minimal({ addressPolicy: { ipv4: 'keep' } })), /must be one of drop, mask-host/)
  assert.throws(() => compilePolicy(minimal({ addressPolicy: { ipv4PrefixBits: 33 } })), /between 0 and 32/)
  assert.throws(() => compilePolicy(minimal({ addressPolicy: { ipv6PrefixBits: 129 } })), /between 0 and 128/)
  assert.throws(() => compilePolicy(minimal({ addressPolicy: { ipv4PrefixBits: 24.5 } })), /between 0 and 32/)
})

test('the documented key list is the list the code enforces', () => {
  assert.deepEqual([...POLICY_KEYS].sort(), [...POLICY_KEYS], 'the key list is ordered')
  for (const key of POLICY_KEYS) assert.match(key, /^[a-zA-Z]+$/)
})

test('an invalid policy leaves stdout empty and exits 2, so no report can be mistaken for a verdict', async () => {
  const broken = await cliReport(files([record()], policy({ queryParam: ['token'] })))

  assert.equal(broken.code, 2)
  assert.equal(broken.stdout, '')
  assert.equal(broken.stderr.includes('Unknown policy key'), true)
})

test('a policy that is not JSON, not UTF-8 or missing is a configuration error with no report', async () => {
  const notJson = await cliReport({ 'access.log': 'x\n', 'redaction-policy.json': '{,}' })
  assert.equal(notJson.code, 2)
  assert.equal(notJson.stdout, '')
  assert.equal(notJson.stderr.includes('is not valid JSON'), true)

  const notUtf8 = await cliReport({ 'access.log': 'x\n', 'redaction-policy.json': Buffer.from([0xff, 0xfe]) })
  assert.equal(notUtf8.code, 2)
  assert.equal(notUtf8.stdout, '')
  assert.equal(notUtf8.stderr.includes('is not valid UTF-8'), true)

  const missing = await cliReport({ 'access.log': 'x\n' })
  assert.equal(missing.code, 2)
  assert.equal(missing.stdout, '')
  assert.equal(missing.stderr.includes('could not be read'), true)
})

test('the parser message for a malformed policy is not read either', async () => {
  const result = await cliReport({ 'access.log': 'x\n', 'redaction-policy.json': '{"secretish": ,}' })

  assert.equal(result.stderr.toLowerCase().includes('unexpected token'), false)
  assert.equal(result.stderr.includes('secretish'), false)
})
