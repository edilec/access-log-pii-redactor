/**
 * access-log-pii-redactor -- the output-destination guard.
 *
 * A tool that writes anything can destroy the wrong file. Measured across this
 * catalog rather than imagined: ten tools accepted a destination that overwrote
 * something they were never asked to touch, and four of them exited 0 saying
 * the write succeeded. This tool was one of them -- `--out` with `--force` on a
 * symbolic link planted inside the root wrote the redacted log through the link
 * onto a file in another tree, and exited 0.
 *
 * Three holes, and each needs its own check because no one of them catches the
 * others. Guarding one or two is what every tool that lost data had already
 * done, and this tool had guarded two.
 *
 * 1. A SYMLINK AT THE DESTINATION writes wherever the link points, which may be
 *    anywhere on the machine. `realpath` on the destination does not help -- it
 *    resolves the link, and resolving is precisely the dangerous act. `stat`
 *    follows it too, so a link that pointed at a file outside the root looked
 *    like an ordinary existing file that `--force` was allowed to replace. The
 *    link is refused on sight, by `lstat`, before anything is opened. A link
 *    whose target does not exist yet is refused by the same check, so a
 *    dangling link cannot quietly create a file outside the root either.
 * 2. A SYMLINKED PARENT does the same thing one level up, so the parent is
 *    resolved and compared against the real root rather than compared
 *    lexically. A lexical prefix check passes for `root/link/out` where `link`
 *    leaves the root.
 * 3. A HARD LINK TO AN INPUT has no target to resolve and shares no path with
 *    the input, so `realpath` and string comparison both say it is a different
 *    file. It is the same file. Only device plus inode sees that.
 *
 * `--out` is not a safe place to put a path the tool has not checked, and "the
 * caller named it" is not a check: the caller named a path, not the file the
 * path resolves to.
 *
 * A refused destination is a configuration error. The CLI exits 2 with an empty
 * stdout, because a run that never had a usable destination has nothing to
 * report about one.
 */

import { lstat, realpath } from 'node:fs/promises'
import { dirname, resolve, sep } from 'node:path'

/** Raised when a destination cannot be written to safely. The caller exits 2. */
export class DestinationError extends TypeError {
  constructor(message) {
    super(message)
    this.name = 'DestinationError'
  }
}

/**
 * Refuse an output destination that would write somewhere the caller did not
 * name, or over something the caller is reading.
 *
 * `inputs` carry the `stat` result taken when each input was located and read,
 * not a fresh one: the identity to compare against is the identity of the file
 * this run actually opened.
 *
 * @param {string} destination Absolute path as the caller assembled it.
 * @param {object} options
 * @param {Array<{label: string, info: {dev: number, ino: number}}>} [options.inputs]
 * @param {string|null} [options.root] Real path of the permitted root.
 * @param {string} [options.label] Option name to name in a refusal.
 * @returns {Promise<{target: string, existing: import('node:fs').Stats|null}>}
 *   The path that is safe to open, and its `lstat` if it already exists.
 */
export async function assertWritableDestination(destination, options = {}) {
  const { inputs = [], root = null, label = '--out' } = options
  const target = resolve(destination)

  let existing = null
  try {
    existing = await lstat(target)
  } catch (error) {
    if (error.code !== 'ENOENT') {
      throw new DestinationError(`${label} could not be inspected: ${error.code ?? 'unknown error'}`)
    }
  }

  if (existing !== null && existing.isSymbolicLink()) {
    throw new DestinationError(
      `${label} is a symbolic link. Writing through it would put the redacted log wherever the `
      + 'link points, which is not the path you named, so it is refused. Name the real destination.',
    )
  }
  if (existing !== null && !existing.isFile()) {
    throw new DestinationError(`${label} exists and is not a regular file.`)
  }

  let parent
  try {
    parent = await realpath(dirname(target))
  } catch (error) {
    throw new DestinationError(`${label}: its directory could not be resolved: ${error.code ?? 'unknown error'}`)
  }

  if (root !== null) {
    const base = await realpath(resolve(root))
    if (parent !== base && !parent.startsWith(base + sep)) {
      throw new DestinationError(
        `${label} resolves outside --root. A link or a ".." segment on the way there does not widen it.`,
      )
    }
  }

  if (existing === null) return { target, existing: null }

  // Same file as an input? Compare identity, not paths.
  for (const input of inputs) {
    if (input.info.dev === existing.dev && input.info.ino === existing.ino) {
      throw new DestinationError(
        `${label} is the same file as ${input.label}; this run would destroy its own input. `
        + `They share device ${existing.dev} and inode ${existing.ino}, so a hard link does not `
        + 'make them different files.',
      )
    }
  }
  return { target, existing }
}
