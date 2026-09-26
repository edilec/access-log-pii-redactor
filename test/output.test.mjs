import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { chmod, link, mkdir, readFile, readdir, stat, symlink, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import test from 'node:test'

import { CANARIES, cliRun, cliWrite, files, findingsFor, fullPolicy, logOf, record, withRoot } from './support.mjs'

/**
 * Writing the redacted log.
 *
 * The input is read-only and the destination is separate, so the two things
 * that can go wrong are writing somewhere this run also reads, and writing
 * somewhere nobody asked for. Both are refused before a byte is written.
 */

test('a dry run writes nothing and still reports what it would have written', async () => {
  await withRoot(files([record(), record()]), async (root) => {
    const result = await cliRun(['--root', root, '--json'])
    const report = JSON.parse(result.stdout)

    assert.equal(result.code, 0)
    assert.equal(report.output.file, null)
    assert.equal(report.output.written, 2)
    assert.match(report.output.digest, /^[0-9a-f]{64}$/)
    assert.deepEqual((await readdir(root)).sort(), ['access.log', 'redaction-policy.json'])
  })
})

test('the reported digest is the digest of the bytes on disk', async () => {
  await withRoot(files([record(), record({ note: CANARIES.awsKey })]), async (root) => {
    const result = await cliRun(['--root', root, '--out', 'redacted.log', '--json'])
    const report = JSON.parse(result.stdout)
    const written = await readFile(join(root, 'redacted.log'))

    assert.equal(report.output.digest, createHash('sha256').update(written).digest('hex'))
    assert.equal(written.toString().trim().split('\n').length, 2)
    for (const line of written.toString().trim().split('\n')) assert.doesNotThrow(() => JSON.parse(line))
  })
})

test('a dry run and a written run produce the same bytes', async () => {
  const inputs = files([record(), record({ note: CANARIES.email })])
  const dry = await cliWrite(inputs, [], 'a.log')
  const wet = await cliWrite(inputs, [], 'b.log')

  assert.equal(dry.report.output.digest, wet.report.output.digest)
})

test('an existing destination is not replaced without being asked', async () => {
  await withRoot({ ...files([record()]), 'redacted.log': 'keep me\n' }, async (root) => {
    const refused = await cliRun(['--root', root, '--out', 'redacted.log', '--json'])

    assert.equal(refused.code, 2)
    assert.equal(refused.stdout, '', 'a configuration error carries no report')
    assert.equal(refused.stderr.includes('--force'), true)
    assert.equal(await readFile(join(root, 'redacted.log'), 'utf8'), 'keep me\n')

    const forced = await cliRun(['--root', root, '--out', 'redacted.log', '--force', '--json'])
    assert.equal(forced.code, 0)
    assert.equal((await readFile(join(root, 'redacted.log'), 'utf8')).includes('keep me'), false)
  })
})

/**
 * The hard-link case, which a path comparison cannot see.
 *
 * A hard link has no target: two names for one inode resolve to two different
 * real paths, so `realpath(out) !== realpath(log)` is true and the write goes
 * ahead -- over the input. A tool in this catalog destroyed its own input
 * exactly that way. The device and inode numbers are what survive the second
 * name.
 */
test('a destination that is another name for the input is refused, link or not', async () => {
  await withRoot(files([record(), record()]), async (root) => {
    await link(join(root, 'access.log'), join(root, 'alias.log'))
    const before = await readFile(join(root, 'access.log'), 'utf8')

    const refused = await cliRun(['--root', root, '--out', 'alias.log', '--force', '--json'])

    assert.equal(refused.code, 2)
    assert.equal(refused.stdout, '')
    assert.equal(refused.stderr.includes('same file as --log access.log'), true)
    assert.equal(await readFile(join(root, 'access.log'), 'utf8'), before, 'the input is exactly as it was')
  })
})

test('a destination that is the log or the policy under its own name is refused', async () => {
  await withRoot(files([record()]), async (root) => {
    const overLog = await cliRun(['--root', root, '--out', 'access.log', '--force', '--json'])
    assert.equal(overLog.code, 2)
    assert.equal(overLog.stderr.includes('same file as --log access.log'), true)

    const overPolicy = await cliRun(['--root', root, '--out', 'redaction-policy.json', '--force', '--json'])
    assert.equal(overPolicy.code, 2)
    assert.equal(overPolicy.stderr.includes('same file as --policy redaction-policy.json'), true)

    assert.equal((await readFile(join(root, 'access.log'), 'utf8')).includes('203.0.113.42'), true)
  })
})

test('a destination that is a directory is a configuration error, with no report', async () => {
  await withRoot(files([record(), record()]), async (root) => {
    await mkdir(join(root, 'occupied'))
    const result = await cliRun(['--root', root, '--out', 'occupied', '--force', '--json'])

    assert.equal(result.code, 2)
    assert.equal(result.stdout, '', 'the run never had a usable destination, so there is nothing to report about one')
    assert.equal(result.stderr.includes('not a regular file'), true)
  })
})

/**
 * The one route left to `output-unwritable`.
 *
 * Every destination that is *unsafe* -- a symlink, a parent that leaves the
 * root, a hard link to an input, a directory -- is refused as a configuration
 * error before anything is opened. What reaches this rule is a destination that
 * passed every check, was exactly the file it named, and could not be written
 * anyway.
 */
test('a destination that cannot be opened is reported, and nothing is read', async () => {
  await withRoot(files([record(), record()]), async (root) => {
    await mkdir(join(root, 'locked'))
    await chmod(join(root, 'locked'), 0o555)
    const result = await cliRun(['--root', root, '--out', 'locked/redacted.log', '--force', '--json'])
    const report = JSON.parse(result.stdout)

    assert.equal(result.code, 2)
    assert.equal(report.status, 'incomplete')
    assert.equal(report.summary.records, 0)
    assert.equal(findingsFor(report, 'output-unwritable').length, 1)
    assert.equal(findingsFor(report, 'output-unwritable')[0].location.file, 'locked/redacted.log')
  })
})

test('a destination outside the root is refused before anything is opened', async () => {
  await withRoot(files([record()]), async (root) => {
    const outside = await cliRun(['--root', root, '--out', '../escaped.log', '--json'])
    assert.equal(outside.code, 2)
    assert.equal(outside.stdout, '')
    assert.equal(outside.stderr.includes('".."'), true)

    const absolute = await cliRun(['--root', root, '--out', join(root, 'absolute.log'), '--json'])
    assert.equal(absolute.code, 2)
    assert.equal(absolute.stderr.includes('must be relative'), true)
  })
})

test('a destination reached through a symlink out of the root is refused', async () => {
  await withRoot(files([record()]), async (root) => {
    await mkdir(join(root, 'nested'))
    await symlink('/tmp', join(root, 'nested', 'escape'))
    const result = await cliRun(['--root', root, '--out', 'nested/escape/redacted.log', '--json'])

    assert.equal(result.code, 2)
    assert.equal(result.stdout, '')
    assert.equal(result.stderr.includes('outside --root'), true)
  })
})

test('the output is one JSON object per line, and nothing else', async () => {
  const result = await cliWrite(files([record(), '{"broken":,}', record()]))
  const lines = result.written.split('\n')

  assert.equal(lines[lines.length - 1], '', 'every record ends with a newline')
  for (const line of lines.slice(0, -1)) {
    assert.equal(typeof JSON.parse(line), 'object')
    assert.equal(line.includes('\n'), false)
  }
})

test('a control character in a value is escaped, never written raw', async () => {
  const sneaky = { ts: 'x', user: { email: 'a@b.invalid' }, note: `one${String.fromCharCode(0x2028)}two` }
  const result = await cliWrite({ 'access.log': logOf([sneaky]), 'redaction-policy.json': fullPolicy() })
  const bytes = Buffer.from(result.written, 'utf8')

  assert.equal(bytes.includes(Buffer.from([0xe2, 0x80, 0xa8])), false, 'U+2028 must not be written raw')
  assert.equal(result.written.includes('\\u2028'), true)
  assert.equal(JSON.parse(result.written.trim()).note.length, 7)
})

test('the input is never modified', async () => {
  await withRoot(files([record(), record()]), async (root) => {
    const before = await stat(join(root, 'access.log'))
    const bytes = await readFile(join(root, 'access.log'))

    await cliRun(['--root', root, '--out', 'redacted.log', '--json'])

    const after = await stat(join(root, 'access.log'))
    assert.equal(after.size, before.size)
    assert.deepEqual(await readFile(join(root, 'access.log')), bytes)
  })
})

test('--force without --out is a usage error rather than a silent no-op', async () => {
  await withRoot(files([record()]), async (root) => {
    const result = await cliRun(['--root', root, '--force', '--json'])

    assert.equal(result.code, 2)
    assert.equal(result.stdout, '')
  })
})

test('a partial run says so, and says the output it wrote is partial too', async () => {
  await withRoot(files([record(), record(), record()]), async (root) => {
    const result = await cliRun(['--root', root, '--out', 'partial.log', '--max-records', '2'])
    const report = JSON.parse(result.stdout)

    assert.equal(result.code, 2)
    assert.equal(report.status, 'incomplete')
    assert.equal(report.output.written, 2)
    assert.equal((await readFile(join(root, 'partial.log'), 'utf8')).trim().split('\n').length, 2)
    assert.equal(result.stderr.includes('any output it wrote is partial'), true)
  })
})
