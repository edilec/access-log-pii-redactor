import assert from 'node:assert/strict'
import { link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import { cliRun, files, record, withRoot } from './support.mjs'

/**
 * The output destination, driven through the real binary.
 *
 * This file exists because knowing about a hole does not close it. Measured
 * across this catalog: ten tools accepted a destination that overwrote a file
 * they were never asked to touch and four of them exited 0 saying the write
 * succeeded. This tool was one of them. It had already closed two of the three
 * holes -- it resolved the parent and compared it against the root, and it
 * compared device and inode against its inputs -- and the third one still cost
 * a file: a symbolic link at `--out` looked to `stat` like an ordinary existing
 * file, so `--force` replaced it, and the redacted log landed on a file in
 * another tree. Measured before the fix: exit 0, empty stderr, the file gone.
 *
 * Each hole needs its own case because no one of them catches the others:
 *
 * 1. A symlink at the destination. `realpath` and `stat` both *follow* it,
 *    which is the dangerous act; only `lstat` sees the link itself.
 * 2. A symlinked parent. A lexical prefix check passes for `root/link/out`
 *    where `link` leaves the root.
 * 3. A hard link to an input. No target to resolve and no shared path, so
 *    `realpath` and string comparison both call it a different file.
 *
 * And the allowed cases are not optional: a guard that refuses everything
 * passes every data-loss case above while making the tool useless. Half of
 * this file is destinations that must still be written.
 */

const PRECIOUS = 'a file this run was never asked to touch\n'

/** A root, and an unrelated tree beside it that no argument ever names. */
async function withOutside(body) {
  const outside = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-outside-'))
  try {
    return await body(outside)
  } finally {
    await rm(outside, { recursive: true, force: true })
  }
}

/** Every refusal is a configuration error: exit 2, empty stdout, no report. */
function assertRefused(result, needle) {
  assert.equal(result.code, 2, `expected exit 2, got ${result.code}`)
  assert.equal(result.stdout, '', 'a refused destination is a configuration error, so stdout carries no report')
  assert.equal(result.stderr.includes(needle), true, `stderr did not mention "${needle}": ${result.stderr}`)
}

test('HOLE 1: a symlink at the destination is refused, and the file it points at survives', async () => {
  await withOutside(async (outside) => {
    const victim = join(outside, 'victim.txt')
    await writeFile(victim, PRECIOUS)

    await withRoot(files([record(), record()]), async (root) => {
      await symlink(victim, join(root, 'redacted.log'))

      const forced = await cliRun(['--root', root, '--out', 'redacted.log', '--force', '--json'])
      assertRefused(forced, 'is a symbolic link')
      assert.equal(await readFile(victim, 'utf8'), PRECIOUS, 'the file outside the root must be untouched')

      const unforced = await cliRun(['--root', root, '--out', 'redacted.log', '--json'])
      assertRefused(unforced, 'is a symbolic link')
      assert.equal(await readFile(victim, 'utf8'), PRECIOUS)
    })
  })
})

test('HOLE 1: a symlink whose target does not exist yet creates nothing outside the root', async () => {
  await withOutside(async (outside) => {
    const absent = join(outside, 'not-yet.log')

    await withRoot(files([record()]), async (root) => {
      await symlink(absent, join(root, 'redacted.log'))

      const result = await cliRun(['--root', root, '--out', 'redacted.log', '--force', '--json'])

      assertRefused(result, 'is a symbolic link')
      await assert.rejects(() => stat(absent), /ENOENT/, 'a dangling link must not become a new file outside the root')
      assert.deepEqual(await readdir(outside), [])
    })
  })
})

test('HOLE 2: a symlinked parent directory is refused, and the file beyond it survives', async () => {
  await withOutside(async (outside) => {
    const victim = join(outside, 'victim.txt')
    await writeFile(victim, PRECIOUS)

    await withRoot(files([record()]), async (root) => {
      // `root/bridge` is lexically inside the root and really is not.
      await symlink(outside, join(root, 'bridge'))

      const result = await cliRun(['--root', root, '--out', 'bridge/victim.txt', '--force', '--json'])

      assertRefused(result, 'outside --root')
      assert.equal(await readFile(victim, 'utf8'), PRECIOUS)
    })
  })
})

test('HOLE 3: a hard link to an input is refused on device and inode, not on path', async () => {
  await withRoot(files([record(), record()]), async (root) => {
    await link(join(root, 'access.log'), join(root, 'alias.log'))
    const before = await readFile(join(root, 'access.log'), 'utf8')

    const result = await cliRun(['--root', root, '--out', 'alias.log', '--force', '--json'])

    assertRefused(result, 'same file as --log access.log')
    assert.equal(result.stderr.includes('device'), true, 'the refusal names the identity it compared')
    assert.equal(await readFile(join(root, 'access.log'), 'utf8'), before, 'the input is exactly as it was')
  })
})

test('a lexical ".." escape is refused, and the file beyond it survives', async () => {
  await withOutside(async (outside) => {
    const victim = join(outside, 'victim.txt')
    await writeFile(victim, PRECIOUS)

    await withRoot(files([record()]), async (root) => {
      const result = await cliRun(['--root', root, '--out', `../${join(outside, 'victim.txt').split('/').pop()}`, '--force', '--json'])

      assertRefused(result, '".."')
      assert.equal(await readFile(victim, 'utf8'), PRECIOUS)
    })
  })
})

test('a destination that is a directory is refused rather than opened', async () => {
  await withRoot(files([record()]), async (root) => {
    await mkdir(join(root, 'redacted.log'))

    const result = await cliRun(['--root', root, '--out', 'redacted.log', '--force', '--json'])

    assertRefused(result, 'not a regular file')
    assert.equal((await stat(join(root, 'redacted.log'))).isDirectory(), true)
  })
})

/**
 * The allowed cases. A guard that refuses everything passes every case above.
 */

test('ALLOWED: a new file in the root is written', async () => {
  await withRoot(files([record(), record()]), async (root) => {
    const result = await cliRun(['--root', root, '--out', 'redacted.log', '--json'])

    assert.equal(result.code, 0, result.stderr)
    assert.equal((await readFile(join(root, 'redacted.log'), 'utf8')).trim().split('\n').length, 2)
  })
})

test('ALLOWED: a nested destination inside the root is written', async () => {
  await withRoot(files([record()]), async (root) => {
    await mkdir(join(root, 'build'))

    const result = await cliRun(['--root', root, '--out', 'build/redacted.log', '--json'])

    assert.equal(result.code, 0, result.stderr)
    assert.equal(JSON.parse(result.stdout).output.file, 'build/redacted.log')
    const written = await readFile(join(root, 'build/redacted.log'), 'utf8')
    assert.equal(typeof JSON.parse(written.trim()), 'object')
  })
})

test('ALLOWED: an existing regular file is replaced when --force asks for it', async () => {
  await withRoot({ ...files([record()]), 'redacted.log': 'stale\n' }, async (root) => {
    const result = await cliRun(['--root', root, '--out', 'redacted.log', '--force', '--json'])

    assert.equal(result.code, 0, result.stderr)
    assert.equal((await readFile(join(root, 'redacted.log'), 'utf8')).includes('stale'), false)
  })
})

test('ALLOWED: a symlinked directory that stays inside the root is not falsely refused', async () => {
  await withRoot(files([record()]), async (root) => {
    // The parent is a link, and it leads back inside the root. Refusing this
    // would be a false refusal, which is a defect too.
    await mkdir(join(root, 'real-build'))
    await symlink(join(root, 'real-build'), join(root, 'build'))

    const result = await cliRun(['--root', root, '--out', 'build/redacted.log', '--json'])

    assert.equal(result.code, 0, result.stderr)
    assert.equal((await readFile(join(root, 'real-build', 'redacted.log'), 'utf8')).trim().split('\n').length, 1)
  })
})

test('ALLOWED: a root reached through a symlink is not falsely refused', async () => {
  await withOutside(async (scene) => {
    await withRoot(files([record()]), async (root) => {
      const linked = join(scene, 'linked-root')
      await symlink(root, linked)

      const result = await cliRun(['--root', linked, '--out', 'redacted.log', '--json'])

      assert.equal(result.code, 0, result.stderr)
      assert.equal((await readFile(join(root, 'redacted.log'), 'utf8')).trim().split('\n').length, 1)
    })
  })
})
