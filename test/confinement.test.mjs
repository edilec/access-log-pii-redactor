import assert from 'node:assert/strict'
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { isInside } from '../src/index.mjs'
import { CANARIES, cliRun, files, findingsFor, fullPolicy, logOf, record, withRoot } from './support.mjs'

/**
 * Path confinement, on both sides.
 *
 * Refusing `..` and absolute paths is not confinement: a symbolic link planted
 * inside the root contains neither and points anywhere. And resolving only one
 * side is not confinement either -- it is a false refusal waiting to happen,
 * because a root reached through a link (`/var` that is really `/private/var`,
 * which is this very test's `tmpdir` on macOS) would never match its own
 * children. Both sides are resolved, and both halves are tested here.
 */

test('isInside is about containment, not about shared spelling', () => {
  assert.equal(isInside('/a/b', '/a/b'), true)
  assert.equal(isInside('/a/b', '/a/b/c'), true)
  assert.equal(isInside('/a/b', '/a/bc'), false, 'a sibling whose name starts the same is not inside')
  assert.equal(isInside('/a/b', '/a'), false)
})

test('a log reached through a symlink out of the root is refused unread', async () => {
  const outside = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-outside-'))
  try {
    await writeFile(join(outside, 'secret.log'), logOf([record({ note: CANARIES.awsKey })]))
    await withRoot({ 'redaction-policy.json': fullPolicy() }, async (root) => {
      await symlink(join(outside, 'secret.log'), join(root, 'access.log'))
      const result = await cliRun(['--root', root, '--json'])
      const report = JSON.parse(result.stdout)

      assert.equal(result.code, 2)
      assert.equal(report.status, 'incomplete')
      assert.equal(report.summary.records, 0)
      assert.equal(findingsFor(report, 'path-escapes-root').length, 1)
      assert.equal(`${result.stdout}${result.stderr}`.includes(CANARIES.awsKey), false, 'nothing out of the tree was read')
    })
  } finally {
    await rm(outside, { recursive: true, force: true })
  }
})

test('a policy reached through a symlink out of the root is refused as configuration', async () => {
  const outside = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-outside-'))
  try {
    await writeFile(join(outside, 'policy.json'), JSON.stringify(fullPolicy()))
    await withRoot({ 'access.log': logOf([record()]) }, async (root) => {
      await symlink(join(outside, 'policy.json'), join(root, 'redaction-policy.json'))
      const result = await cliRun(['--root', root, '--json'])

      assert.equal(result.code, 2)
      assert.equal(result.stdout, '')
      assert.equal(result.stderr.includes('outside --root'), true)
    })
  } finally {
    await rm(outside, { recursive: true, force: true })
  }
})

test('a legitimate log under a symlinked root is read, not refused', async () => {
  const real = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-real-'))
  const links = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-link-'))
  try {
    await writeFile(join(real, 'access.log'), logOf([record(), record()]))
    await writeFile(join(real, 'redaction-policy.json'), JSON.stringify(fullPolicy()))
    const linked = join(links, 'root')
    await symlink(real, linked)

    const result = await cliRun(['--root', linked, '--out', 'redacted.log', '--json'])
    const report = JSON.parse(result.stdout)

    assert.equal(result.code, 0, 'hardening that refuses valid work is a defect too')
    assert.equal(report.summary.written, 2)
    assert.equal((await readFile(join(real, 'redacted.log'), 'utf8')).trim().split('\n').length, 2)
  } finally {
    await rm(real, { recursive: true, force: true })
    await rm(links, { recursive: true, force: true })
  }
})

test('a log in a subdirectory of the root is read', async () => {
  await withRoot({ 'redaction-policy.json': fullPolicy() }, async (root) => {
    await mkdir(join(root, 'day1'))
    await writeFile(join(root, 'day1', 'access.log'), logOf([record()]))
    const result = await cliRun(['--root', root, '--log', 'day1/access.log', '--json'])

    assert.equal(result.code, 0)
    assert.equal(JSON.parse(result.stdout).input.file, 'day1/access.log')
  })
})

test('a name that steps out of the root is a configuration error', async () => {
  await withRoot(files([record()]), async (root) => {
    for (const argument of [['--log', '../elsewhere.log'], ['--policy', '../elsewhere.json']]) {
      const result = await cliRun(['--root', root, ...argument, '--json'])
      assert.equal(result.code, 2)
      assert.equal(result.stdout, '', 'a configuration error carries no report')
    }
  })
})

test('a missing log is missing evidence: a report that says so, never a pass', async () => {
  await withRoot({ 'redaction-policy.json': fullPolicy() }, async (root) => {
    const result = await cliRun(['--root', root, '--json'])
    const report = JSON.parse(result.stdout)

    assert.equal(result.code, 2)
    assert.equal(report.status, 'incomplete')
    assert.equal(findingsFor(report, 'input-unreadable').length, 1)
    assert.equal(report.findings[0].location.file, 'access.log', 'the name is relative to the root, never a host path')
  })
})

test('a directory named as the log is not a regular file', async () => {
  await withRoot({ 'redaction-policy.json': fullPolicy() }, async (root) => {
    await mkdir(join(root, 'access.log'))
    const result = await cliRun(['--root', root, '--json'])
    const report = JSON.parse(result.stdout)

    assert.equal(result.code, 2)
    assert.equal(report.status, 'incomplete')
    assert.equal(findingsFor(report, 'input-unreadable').length, 1)
  })
})

test('no absolute host path appears anywhere in a report', async () => {
  await withRoot(files([record(), '{"broken":,}']), async (root) => {
    const result = await cliRun(['--root', root, '--out', 'redacted.log'])

    assert.equal(result.stdout.includes(root), false)
    assert.equal(result.stderr.includes(root), false)
  })
})
