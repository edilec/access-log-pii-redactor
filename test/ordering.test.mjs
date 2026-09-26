import assert from 'node:assert/strict'
import test from 'node:test'

import { compilePolicy, redactAccessLog, validateLimits } from '../src/index.mjs'
import { cliRun, files, findingsFor, fullPolicy, logOf, policy, record, withRoot } from './support.mjs'

/**
 * Ordering, pinned by what the tool emits.
 *
 * A source scan for `.localeCompare(` is not a determinism test: `Intl.Collator`
 * collates identically and spells differently, so the scan passes while the
 * output silently starts depending on the ICU data of whichever Node build is
 * running. Pinning the comparator itself is no better -- every call site can be
 * swapped on its own.
 *
 * Every case below chooses values an English collator orders the other way
 * round, pushes them through a real entry point, and asserts the exact emitted
 * sequence, so that swapping any one site fails a test rather than going
 * unnoticed. The collator is constructed here and asserted to disagree, which
 * is what makes these cases cases at all.
 *
 * Four sites cannot be pinned this way, because their real values -- rule ids
 * and detector names over `[a-z-]`, this package's own limit names, and a
 * tiebreaker no reachable input reaches -- cannot move under collation. Those
 * are proved equivalent in `test/ordering-equivalence.test.mjs` rather than
 * left as gaps.
 */

const collator = new Intl.Collator('en')
const disagrees = (left, right) => {
  assert.equal(left < right, true, `${left} precedes ${right} by code unit`)
  assert.equal(collator.compare(left, right) > 0, true, `a collator puts ${right} first, which is what makes this a case`)
}

test('the disagreements every case below relies on are real', () => {
  disagrees('Zed', 'alpha')
  disagrees('Z-access.log', 'a-policy.json')
  disagrees('/Zed', '/alpha')
  disagrees('redactFields:Zed', 'redactFields:alpha')
})

test('findings are ordered by file, and the log comes before the policy by code unit', async () => {
  await withRoot({
    'Z-access.log': logOf([record({ ts: 'x', client: { ip: 'not-an-address' } })]),
    'a-policy.json': policy({ addressFields: ['client.ip'], redactFields: ['never.seen'] }),
  }, async (root) => {
    const result = await cliRun(['--root', root, '--log', 'Z-access.log', '--policy', 'a-policy.json', '--json'])
    const report = JSON.parse(result.stdout)

    assert.deepEqual(report.findings.map((finding) => finding.location.file), ['Z-access.log', 'a-policy.json'])
  })
})

test('line numbers are compared as numbers, not as text', async () => {
  const many = []
  for (let index = 0; index < 12; index += 1) many.push(index === 0 ? JSON.stringify(record()) : '{"broken":,}')
  await withRoot({ 'access.log': `${many.join('\n')}\n`, 'redaction-policy.json': fullPolicy() }, async (root) => {
    const result = await cliRun(['--root', root, '--json'])
    const lines = JSON.parse(result.stdout).findings
      .filter((finding) => finding.location.file === 'access.log')
      .map((finding) => finding.location.line)

    assert.deepEqual(lines, [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    assert.notDeepEqual(lines, [...lines].sort(), 'a text sort would put 10 before 2, which is what this pins')
  })
})

test('findings at one line are ordered by pointer, by code unit', async () => {
  const dirty = { ts: 'x', Zed: 'q'.repeat(300), alpha: 'q'.repeat(300) }
  await withRoot({
    'access.log': logOf([dirty]),
    'redaction-policy.json': policy({ redactFields: ['ts'] }),
  }, async (root) => {
    const result = await cliRun(['--root', root, '--max-value-length', '100', '--json'])
    const pointers = JSON.parse(result.stdout).findings.map((finding) => finding.location.pointer)

    assert.deepEqual(pointers, ['/Zed', '/alpha'])
  })
})

test('the first unknown limit reported is the first by code unit', () => {
  assert.throws(() => validateLimits({ Zed: 1, alpha: 1 }), /Unknown limit "Zed"/)
})

test('the first unknown option reported is the first by code unit', async () => {
  await assert.rejects(() => redactAccessLog({ root: '.', Zed: 1, alpha: 1 }), /Unknown option "Zed"/)
})

test('the first unknown policy key reported is the first by code unit', () => {
  assert.throws(
    () => compilePolicy({ schemaVersion: '1', redactFields: ['a'], Zed: 1, alpha: 1 }),
    /Unknown policy key "Zed"/,
  )
})

test('the first unknown address policy key reported is the first by code unit', () => {
  assert.throws(
    () => compilePolicy({ schemaVersion: '1', redactFields: ['a'], addressPolicy: { Zed: 1, alpha: 1 } }),
    /Unknown policy.addressPolicy key "Zed"/,
  )
})

test('the compiled target list is ordered by code unit', () => {
  const compiled = compilePolicy({ schemaVersion: '1', redactFields: ['Zed', 'alpha', 'Zebra'] })

  assert.deepEqual(compiled.targets, ['redactFields:Zebra', 'redactFields:Zed', 'redactFields:alpha'])
})

test('the never-seen findings follow the target order through the pointer', async () => {
  await withRoot({
    'access.log': logOf([{ ts: 'x', kept: 1 }]),
    'redaction-policy.json': policy({ redactFields: ['Zed', 'alpha'] }),
  }, async (root) => {
    const result = await cliRun(['--root', root, '--json'])
    const pointers = JSON.parse(result.stdout).findings.map((finding) => finding.location.pointer)

    assert.deepEqual(pointers, ['/redactFields/Zed', '/redactFields/alpha'])
  })
})

test('two runs over the same input produce byte-identical stdout', async () => {
  const inputs = files([record(), '{"broken":,}', record({ client: { ip: 'nope' } })])
  const first = await withRoot(inputs, (root) => cliRun(['--root', root, '--json']))
  const second = await withRoot(inputs, (root) => cliRun(['--root', root, '--json']))

  assert.equal(first.stdout, second.stdout)
})
