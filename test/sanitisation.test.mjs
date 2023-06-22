import assert from 'node:assert/strict'
import test from 'node:test'

import { hasForbiddenCharacter } from '../src/index.mjs'
import { CANARIES, FORBIDDEN, apiReport, cliReport, cliWrite, fullPolicy, logOf, policy, record } from './support.mjs'

/**
 * Control, DEL, C1, separator and bidi characters, stripped from every string
 * that reaches output -- not only from an excerpt field.
 *
 * The vector that matters here is the *identifier*: a pointer is built from the
 * keys a record supplied, so a key holding a newline forges a line in the human
 * report and invents a finding that was never emitted. A sibling tool in this
 * catalog sanitised its evidence carefully and left its identifiers raw, which
 * is why every case below arrives through a key rather than through a message.
 */

/**
 * A stream is clean when every one of its lines is.
 *
 * The line feeds that separate the lines are the report's own structure, so a
 * whole stream always "contains" a C0 character; what matters is that no line
 * carries one, because that is what a forged line would look like.
 */
function linesAreClean(text) {
  return text.split('\n').every((line) => !hasForbiddenCharacter(line))
}

/** Walk a whole report and collect every string in it, keys included. */
function everyString(value, path = '', found = []) {
  if (typeof value === 'string') found.push([path, value])
  else if (Array.isArray(value)) value.forEach((item, index) => everyString(item, `${path}/${index}`, found))
  else if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      found.push([`${path}/<key>`, key])
      everyString(child, `${path}/${key}`, found)
    }
  }
  return found
}

for (const [name, character] of Object.entries(FORBIDDEN)) {
  test(`${name} arriving through a record key does not survive into the report`, async () => {
    const dirty = { ts: 'x', [`ev${character}il`]: 'q'.repeat(300), user: { email: 'a@b.invalid' } }
    const result = await cliReport(
      { 'access.log': logOf([dirty]), 'redaction-policy.json': fullPolicy() },
      ['--max-value-length', '100'],
    )

    assert.equal(result.report.findings.length > 0, true, 'the case must actually produce a finding')
    for (const [where, text] of everyString(result.report)) {
      assert.equal(hasForbiddenCharacter(text), false, `${name} survived at ${where}`)
    }
    assert.equal(linesAreClean(result.stderr), true, `${name} survived into the human report`)
  })
}

test('a forged line in a key cannot forge a line in the human report', async () => {
  const newline = String.fromCharCode(0x0a)
  const forged = { ts: 'x', [`a${newline}ERROR   access.log:1 forged forged-finding invented`]: 'q'.repeat(300) }
  const result = await cliReport(
    { 'access.log': logOf([forged]), 'redaction-policy.json': policy({ redactFields: ['ts'] }) },
    ['--max-value-length', '100'],
  )

  const errorLines = result.stderr.split('\n').filter((line) => line.startsWith('ERROR'))
  assert.equal(errorLines.length, 0, 'no line was forged')
  assert.equal(result.stderr.includes('forged-finding'), true, 'the text is still reported, on one line')
})

test('a bidi override in a key cannot reverse what the report displays', async () => {
  const override = String.fromCharCode(0x202e)
  const dirty = { ts: 'x', [`gpj.${override}eliftxet`]: 'q'.repeat(300) }
  const result = await cliReport(
    { 'access.log': logOf([dirty]), 'redaction-policy.json': policy({ redactFields: ['ts'] }) },
    ['--max-value-length', '100'],
  )

  assert.equal(linesAreClean(result.stdout), true)
  assert.equal(linesAreClean(result.stderr), true)
})

test('a canary used as a key is redacted out of the pointer, not just out of the value', async () => {
  const dirty = { ts: 'x', [`${CANARIES.awsKey}`]: 'q'.repeat(300) }
  const result = await cliReport(
    { 'access.log': logOf([dirty]), 'redaction-policy.json': policy({ redactFields: ['ts'] }) },
    ['--max-value-length', '100'],
  )

  assert.equal(result.stdout.includes(CANARIES.awsKey), false)
  assert.equal(result.stderr.includes(CANARIES.awsKey), false)
  assert.equal(result.stdout.includes('[redacted]'), true, 'the pointer says where, without saying what')
})

test('a file name carrying a control character is refused as configuration', async () => {
  const result = await cliReport({ 'access.log': logOf([record()]), 'redaction-policy.json': fullPolicy() }, [
    '--log', `access${String.fromCharCode(0x0a)}.log`,
  ])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(linesAreClean(result.stderr), true)
})

test('an unknown option carrying a control character is flattened before it is quoted back', async () => {
  const result = await cliReport({ 'access.log': 'x\n', 'redaction-policy.json': fullPolicy() }, [
    `--we${String.fromCharCode(0x1b)}ird`,
  ])

  assert.equal(result.code, 2)
  assert.equal(linesAreClean(result.stderr), true)
})

test('every string in a report full of findings is clean, keys included', async () => {
  const messy = [
    record(),
    '{"broken":,}',
    '[1,2,3]',
    JSON.stringify({ ts: 'x', client: { ip: 'not-an-address' }, user: { email: 'a@b.invalid' } }),
    JSON.stringify({ ts: 'x', [`k${String.fromCharCode(0x9b)}ey`]: 'q'.repeat(300) }),
  ]
  const report = await apiReport(
    { 'access.log': `${messy.join('\n')}\n`, 'redaction-policy.json': fullPolicy() },
    { limits: { maxValueLength: 100 } },
  )

  assert.equal(report.findings.length >= 4, true)
  for (const [where, text] of everyString(report)) {
    assert.equal(hasForbiddenCharacter(text), false, `a forbidden character survived at ${where}`)
  }
})

test('the redacted output escapes what it cannot strip, and stays one record per line', async () => {
  const dirty = { ts: 'x', user: { email: 'a@b.invalid' }, note: `a${String.fromCharCode(0x0a)}b${String.fromCharCode(0x2029)}c` }
  const result = await cliWrite({ 'access.log': logOf([dirty]), 'redaction-policy.json': fullPolicy() })

  assert.equal(result.written.trim().split('\n').length, 1, 'a newline in a value cannot forge a record')
  assert.equal(JSON.parse(result.written.trim()).note.length, 5, 'the value itself is unchanged')
  assert.equal(linesAreClean(result.written), true)
})
