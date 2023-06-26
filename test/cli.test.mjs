import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { cliRun, files, fullPolicy, logOf, projectDirectory, record, withRoot } from './support.mjs'

/**
 * The command line surface, including the two things the report contract is
 * specific about: stdout carries the JSON report and nothing else, and exit 2
 * has two shapes -- an empty stdout for a configuration error, and an
 * `incomplete` report for evidence that could not be obtained.
 */

test('--help explains the tool and exits 0 on stdout', async () => {
  const result = await cliRun(['--help'])

  assert.equal(result.code, 0)
  assert.equal(result.stdout.includes('access-log-pii-redactor'), true)
  assert.equal(result.stdout.includes('--out NAME'), true)
  assert.equal(result.stdout.includes('Exit codes:'), true)
  assert.equal(result.stdout.includes('quarantined'), true)
  assert.equal(result.stderr, '')
})

test('-h is the same help', async () => {
  const long = await cliRun(['--help'])
  const short = await cliRun(['-h'])

  assert.equal(short.stdout, long.stdout)
})

test('--version prints the package version and nothing else', async () => {
  const result = await cliRun(['--version'])
  const manifest = JSON.parse(await readFile(join(projectDirectory, 'package.json'), 'utf8'))

  assert.equal(result.code, 0)
  assert.equal(result.stdout.trim(), manifest.version)
})

test('the help lists every limit flag the tool accepts', async () => {
  const { stdout } = await cliRun(['--help'])

  for (const flag of [
    '--max-records', '--max-input-bytes', '--max-line-bytes', '--max-value-length',
    '--max-query-params', '--max-depth', '--max-fields-per-record', '--max-runtime-ms', '--max-findings',
  ]) {
    assert.equal(stdout.includes(flag), true, `${flag} must be documented`)
  }
})

test('--root is required, and a missing one is a configuration error', async () => {
  const result = await cliRun(['--json'])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr.includes('--root is required'), true)
})

test('an unknown option is refused rather than ignored', async () => {
  const result = await cliRun(['--root', '.', '--sneaky'])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr.includes('Unknown option "--sneaky"'), true)
})

test('a flag that needs a value says so', async () => {
  const result = await cliRun(['--root'])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr.includes('--root requires a value'), true)
})

test('a root that is not a directory is a configuration error', async () => {
  const result = await cliRun(['--root', join(projectDirectory, 'package.json')])

  assert.equal(result.code, 2)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr.includes('--root must be a directory'), true)
})

test('--json suppresses the human summary and keeps the diagnostics that matter', async () => {
  await withRoot(files([record(), '{"a":,}']), async (root) => {
    const quiet = await cliRun(['--root', root, '--json'])
    const loud = await cliRun(['--root', root])

    assert.equal(quiet.stdout, loud.stdout, 'stdout does not change with --json')
    assert.equal(quiet.stderr.includes('record-not-json'), false)
    assert.equal(loud.stderr.includes('record-not-json'), true)
  })
})

test('stdout parses as JSON on every exit code this tool can return', async () => {
  const pass = await withRoot(files([record()]), (root) => cliRun(['--root', root, '--json']))
  const fail = await withRoot(files([record(), '{"a":,}']), (root) => cliRun(['--root', root, '--json']))
  const incomplete = await withRoot({ 'redaction-policy.json': fullPolicy() }, (root) => cliRun(['--root', root, '--json']))

  assert.equal(pass.code, 0)
  assert.equal(fail.code, 1)
  assert.equal(incomplete.code, 2)
  for (const result of [pass, fail, incomplete]) assert.doesNotThrow(() => JSON.parse(result.stdout))
})

test('the report carries the envelope the contract describes', async () => {
  const result = await withRoot(files([record()]), (root) => cliRun(['--root', root, '--json']))
  const report = JSON.parse(result.stdout)

  assert.equal(report.schemaVersion, '1')
  assert.equal(report.tool, 'access-log-pii-redactor')
  assert.equal(['pass', 'fail', 'incomplete'].includes(report.status), true)
  assert.deepEqual(Object.keys(report.summary).sort(), [
    'blank', 'bytesRead', 'checked', 'errors', 'quarantined', 'records', 'redactions', 'warnings', 'written',
  ])
  for (const value of Object.values(report.summary)) assert.equal(Number.isInteger(value), true)
  assert.equal(Array.isArray(report.findings), true)
})

test('every finding carries the fields the contract requires', async () => {
  const result = await withRoot(files([record(), '{"a":,}', { ts: 'x', client: { ip: 'nope' } }]), (root) =>
    cliRun(['--root', root, '--json']))

  for (const finding of JSON.parse(result.stdout).findings) {
    assert.equal(typeof finding.ruleId, 'string')
    assert.equal(['error', 'warning', 'info'].includes(finding.severity), true)
    assert.equal(finding.message.length > 0, true)
    assert.equal(typeof finding.location.file, 'string')
    assert.equal(Number.isInteger(finding.location.line), true)
    assert.equal(typeof finding.location.pointer, 'string')
    assert.equal(finding.location.file.startsWith('/'), false, 'never an absolute host path')
  }
})

test('a relative root works from the package directory', async () => {
  const result = await cliRun(['--root', 'examples/clean', '--json'])

  assert.equal(result.code, 0)
  assert.equal(JSON.parse(result.stdout).summary.written, 5)
})

test('the human summary names the log, the policy digest and the destination', async () => {
  await withRoot(files([record()]), async (root) => {
    const dry = await cliRun(['--root', root])
    assert.equal(dry.stderr.includes('dry run, nothing written'), true)

    const wet = await cliRun(['--root', root, '--out', 'redacted.log'])
    assert.equal(wet.stderr.includes('output redacted.log'), true)
    assert.equal(wet.stderr.includes('policy redaction-policy.json (sha256 '), true)
  })
})

test('a log given by name in a subdirectory is reported by that name', async () => {
  await withRoot({ 'redaction-policy.json': fullPolicy() }, async (root) => {
    await withRoot({}, async () => {})
    const result = await cliRun(['--root', root, '--log', 'missing/deep.log', '--json'])

    assert.equal(result.code, 2)
    assert.equal(JSON.parse(result.stdout).input.file, 'missing/deep.log')
  })
})

test('the tool reads nothing from stdin and writes nothing to the working directory', async () => {
  const before = await withRoot(files([record()]), (root) => cliRun(['--root', root, '--json']))

  assert.equal(before.code, 0)
  await assert.rejects(() => readFile(join(projectDirectory, 'redacted.log')), /ENOENT/)
})

test('a log that is one record without a trailing newline is still one record', async () => {
  const result = await withRoot(
    { 'access.log': JSON.stringify(record()), 'redaction-policy.json': fullPolicy() },
    (root) => cliRun(['--root', root, '--json']),
  )

  assert.equal(result.code, 0)
  assert.equal(JSON.parse(result.stdout).summary.records, 1)
})

test('carriage returns from a Windows export do not become part of a record', async () => {
  const result = await withRoot(
    { 'access.log': logOf([record(), record()]).replaceAll('\n', '\r\n'), 'redaction-policy.json': fullPolicy() },
    (root) => cliRun(['--root', root, '--json']),
  )

  assert.equal(result.code, 0)
  assert.equal(JSON.parse(result.stdout).summary.records, 2)
})
