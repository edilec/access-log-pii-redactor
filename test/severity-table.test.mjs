import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { RULE_SEVERITY, createFinding } from '../src/index.mjs'
import { projectDirectory } from './support.mjs'

/**
 * The frozen table against the documented catalog, in both directions.
 *
 * This case is worth having and it is *not* what pins severity. A table, a
 * markdown catalog and a test's expected map are three declarations, and one
 * edit that changes all three leaves every assertion that compares them
 * satisfied -- which is exactly how 40 of one sibling tool's 52 error rules
 * survived a coordinated demotion. `test/severity-exit.test.mjs` and
 * `test/severity-word.test.mjs` are the pins: they assert exit codes and
 * printed words that no edit to a declaration can satisfy.
 */

const CATALOG_ROW = /^\| `([a-z0-9-]+)` \| (error|warning|info) \|/gm

async function documentedCatalog() {
  const text = await readFile(join(projectDirectory, 'docs/redaction-rules.md'), 'utf8')
  const rows = new Map()
  for (const match of text.matchAll(CATALOG_ROW)) rows.set(match[1], match[2])
  return rows
}

test('every rule in the table is documented with the same severity', async () => {
  const documented = await documentedCatalog()

  for (const [ruleId, severity] of Object.entries(RULE_SEVERITY)) {
    assert.equal(documented.has(ruleId), true, `${ruleId} is in the table and not in docs/redaction-rules.md`)
    assert.equal(documented.get(ruleId), severity, `${ruleId} is documented as ${documented.get(ruleId)}`)
  }
})

test('every documented rule is in the table', async () => {
  const documented = await documentedCatalog()

  assert.equal(documented.size > 15, true, 'the catalog must have been parsed for this to prove anything')
  for (const [ruleId, severity] of documented) {
    assert.equal(Object.hasOwn(RULE_SEVERITY, ruleId), true, `${ruleId} is documented and not in RULE_SEVERITY`)
    assert.equal(RULE_SEVERITY[ruleId], severity)
  }
})

test('the catalog is ordered and its severities are from the allowed set', () => {
  const ruleIds = Object.keys(RULE_SEVERITY)

  assert.deepEqual(ruleIds, [...ruleIds].sort(), 'the table is ordered, so a new rule lands where it belongs')
  for (const severity of Object.values(RULE_SEVERITY)) {
    assert.equal(['error', 'warning', 'info'].includes(severity), true)
  }
})

test('a finding cannot be built for a rule the table does not know', () => {
  assert.throws(() => createFinding({ ruleId: 'invented-rule', message: 'x', file: 'a' }), /not in RULE_SEVERITY/)
})

test('a finding takes its severity from the table and nowhere else', () => {
  for (const [ruleId, severity] of Object.entries(RULE_SEVERITY)) {
    assert.equal(createFinding({ ruleId, message: 'x', file: 'a' }).severity, severity)
  }
})

test('the counts written in prose match the table they describe', async () => {
  // The comment above RULE_SEVERITY said "sixteen error rules" while the table
  // held fifteen, and the rule documentation's proof section counts them too.
  // A number in prose that nothing checks drifts the moment a rule is added.
  const errorRules = Object.values(RULE_SEVERITY).filter((severity) => severity === 'error').length
  const ruleCount = Object.keys(RULE_SEVERITY).length
  const source = await readFile(join(projectDirectory, 'src/index.mjs'), 'utf8')
  const rules = await readFile(join(projectDirectory, 'docs/redaction-rules.md'), 'utf8')

  assert.ok(source.includes(`${errorRules} error rules`),
    `src/index.mjs does not say "${errorRules} error rules"; the table holds that many`)
  assert.ok(rules.includes(`Each of the ${errorRules} error rules`),
    `docs/redaction-rules.md does not count ${errorRules} error rules`)
  assert.ok(rules.includes(`the ${ruleCount} rule ids`),
    `docs/redaction-rules.md does not count ${ruleCount} rule ids`)

  // And the numbers are not all the same, so a single wrong count could not
  // satisfy every assertion above.
  assert.notEqual(errorRules, ruleCount)
})
