import assert from 'node:assert/strict'
import test from 'node:test'

import {
  LINE_SHAPES, byCodeUnit, decodeUtf8, describeJsonType, escapeOutputUnsafe, excerpt,
  hasForbiddenCharacter, isPlainObject, shapeOfLine,
} from '../src/index.mjs'
import { FORBIDDEN } from './support.mjs'

test('decoding is the decoder decision, never an inference from decoded text', () => {
  assert.deepEqual(decodeUtf8(Buffer.from('{"a":1}')), { ok: true, text: '{"a":1}' })
  assert.equal(decodeUtf8(Buffer.from([0xff, 0xfe])).ok, false)
  // A file that legitimately holds U+FFFD decodes: the replacement character is
  // content here, not evidence of anything.
  assert.equal(decodeUtf8(Buffer.from('ok �')).ok, true)
  assert.equal(decodeUtf8(Buffer.from([0xe2, 0x82])).ok, false, 'a truncated sequence is not valid UTF-8')
})

test('every forbidden class is detected and stripped', () => {
  for (const [name, character] of Object.entries(FORBIDDEN)) {
    assert.equal(hasForbiddenCharacter(`a${character}b`), true, `${name} must be detected`)
    assert.equal(hasForbiddenCharacter(excerpt(`a${character}b`)), false, `${name} must not survive excerpt`)
  }
  assert.equal(hasForbiddenCharacter('plain text, ascii and accents alike: resume, cafe'), false)
  assert.equal(hasForbiddenCharacter('Arabic and Hebrew letters carry their own direction'), false)
})

test('excerpt flattens, collapses and bounds', () => {
  assert.equal(excerpt('a\tb\n c'), 'a b c')
  assert.equal(excerpt('  padded  '), 'padded')
  assert.equal(excerpt('x'.repeat(30), 10), `${'x'.repeat(10)}...`)
  assert.equal(excerpt(12), '12')
})

test('output escaping turns the characters JSON.stringify leaves raw into escapes', () => {
  const line = JSON.stringify({ a: `x${String.fromCharCode(0x2028)}y${String.fromCharCode(0x85)}z` })
  const escaped = escapeOutputUnsafe(line)

  assert.equal(escaped.includes('\\u2028'), true)
  assert.equal(escaped.includes('\\u0085'), true)
  assert.equal(hasForbiddenCharacter(escaped), false)
  assert.deepEqual(JSON.parse(escaped), JSON.parse(line), 'escaping changes the spelling, never the value')
})

test('output escaping leaves ordinary text alone', () => {
  const line = JSON.stringify({ note: 'resume at the cafe, 100% done' })

  assert.equal(escapeOutputUnsafe(line), line)
})

test('a line shape is a token from a closed vocabulary and never the character it saw', () => {
  assert.equal(shapeOfLine('{"a":1'), 'object-like')
  assert.equal(shapeOfLine('  [1,2'), 'array-like')
  assert.equal(shapeOfLine('"unterminated'), 'string-like')
  assert.equal(shapeOfLine('-12.'), 'number-like')
  assert.equal(shapeOfLine('7up'), 'number-like')
  assert.equal(shapeOfLine('true-ish'), 'literal-like')
  assert.equal(shapeOfLine('%%%'), 'other')
  assert.equal(shapeOfLine('   '), 'empty')

  for (const sample of ['{x', '[x', '"x', '9x', 'nx', '@x', ' ']) {
    assert.equal(LINE_SHAPES.includes(shapeOfLine(sample)), true, `${sample} must map into the vocabulary`)
  }
  for (const sample of ['{x', '[x', '"x', '9x', 'nx', '@x']) {
    assert.equal(shapeOfLine(sample).includes(sample[0]), false, 'the shape never contains the character it saw')
  }
})

test('describeJsonType says what a value was without reproducing it', () => {
  assert.equal(describeJsonType(null), 'null')
  assert.equal(describeJsonType([1, 2]), 'array')
  assert.equal(describeJsonType({}), 'object')
  assert.equal(describeJsonType('secret-value'), 'string')
  assert.equal(describeJsonType(7), 'number')
  assert.equal(describeJsonType(true), 'boolean')
})

test('isPlainObject refuses arrays, null and class instances', () => {
  assert.equal(isPlainObject({}), true)
  assert.equal(isPlainObject(Object.create(null)), true)
  assert.equal(isPlainObject([]), false)
  assert.equal(isPlainObject(null), false)
  assert.equal(isPlainObject(new Date(0)), false)
})

test('byCodeUnit is a total order that puts upper case first', () => {
  assert.equal(byCodeUnit('a', 'a'), 0)
  assert.equal(byCodeUnit('Z', 'a') < 0, true)
  assert.equal(byCodeUnit('a-b', 'a_b') < 0, true)
  assert.equal(byCodeUnit('README', 'assets') < 0, true)
})
