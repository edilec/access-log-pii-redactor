/**
 * access-log-pii-redactor -- stream an exported access log, apply a declared
 * redaction policy, and write the redacted records to a separate destination.
 *
 * The product is the guarantee that nothing sensitive leaves, so the code is
 * arranged around three properties, each pinned by a test that fails when it is
 * removed:
 *
 * 1. **A malformed record is quarantined, never echoed.** It is located by line
 *    number, described by a structural shape token and a byte count, and
 *    withheld from the output. No parser message reaches the report: a
 *    `JSON.parse` error quotes the input it choked on, so this package never
 *    reads one. That is the acceptance case, and `test/quarantine.test.mjs`
 *    scans both streams for every substring of the offending line.
 * 2. **Every failure redacts more, never less.** A value too long to scan, an
 *    address the parser cannot read, a field that is not the shape the policy
 *    expects: each is replaced whole and reported. There is no branch that
 *    leaves a value untouched because something went wrong.
 * 3. **A run that stopped early cannot report a conclusion the stopped loop was
 *    responsible for.** The stream sets a stop reason and the report is built
 *    from a `consumed` flag set only where the stream ended of its own accord --
 *    so a break can never fall through into a success branch, which is how a
 *    sibling tool in this catalog came to write "confirmed" about a group it
 *    had not finished checking.
 *
 * Nothing here opens a socket, and nothing here reads a wall clock: the time
 * budget takes its milliseconds from an injected monotonic source.
 */

import { createHash } from 'node:crypto'
import { open, realpath, stat } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, normalize, resolve, sep } from 'node:path'
import { performance } from 'node:perf_hooks'

import { detectorsMatching, redactDetected, reportText } from './detectors.mjs'
import { POLICY_SCHEMA_VERSION, compilePolicy } from './policy.mjs'
import { RecordRefused, redactRecord } from './redact.mjs'
import {
  byCodeUnit,
  decodeUtf8,
  describeJsonType,
  escapeOutputUnsafe,
  excerpt,
  hasForbiddenCharacter,
  isPlainObject,
  shapeOfLine,
} from './text.mjs'

export const TOOL_ID = 'access-log-pii-redactor'
export const REPORT_SCHEMA_VERSION = '1'

export const DEFAULT_LOG_NAME = 'access.log'
export const DEFAULT_POLICY_NAME = 'redaction-policy.json'

/**
 * Limits, each enforced and each reported by name when it is reached.
 *
 * Reaching one is never a silent truncation. A per-record bound quarantines
 * that record -- a definite, reported outcome -- and the run carries on. A
 * run-level bound stops the stream, which leaves an unread remainder, so the
 * report is `incomplete` and says which limit stopped it.
 */
export const DEFAULT_LIMITS = Object.freeze({
  maxDepth: 12,
  maxFieldsPerRecord: 256,
  maxFindings: 1000,
  maxInputBytes: 67108864,
  maxLineBytes: 65536,
  maxQueryParams: 64,
  maxRecords: 100000,
  maxRuntimeMs: 30000,
  maxValueLength: 4096,
})

/** A caller may lower a limit, never raise it past these caps. */
export const HARD_LIMITS = Object.freeze({
  maxDepth: 64,
  maxFieldsPerRecord: 4096,
  maxFindings: 20000,
  maxInputBytes: 1073741824,
  maxLineBytes: 1048576,
  maxQueryParams: 1024,
  maxRecords: 10000000,
  maxRuntimeMs: 600000,
  maxValueLength: 65536,
})

/**
 * The authoritative rule severity table.
 *
 * Severity is the whole difference between a run that fails and one that
 * passes. Written as a literal at each construction site it drifts silently,
 * and demoting any of the 15 error rules below turns "a record was withheld
 * because it could not be redacted" into a green build. That count is written
 * as a numeral and asserted against the table in `test/severity-table.test.mjs`
 * -- it said "sixteen" while the table held fifteen, and the number here is
 * what tells a maintainer how much ground the severity guard has to cover.
 *
 * `test/severity-table.test.mjs` asserts this table against the documented
 * catalog in both directions. That is worth having and it is not the test: a
 * table, a markdown catalog and a test's expected-value map are three
 * declarations, and one edit that changes all three leaves every assertion that
 * compares them satisfied. `test/severity-exit.test.mjs` and
 * `test/severity-word.test.mjs` drive real logs through the real binary and pin
 * the exit code, the error count and the printed severity word with literal
 * values written out at the place they are asserted.
 */
export const RULE_SEVERITY = Object.freeze({
  'address-unrecognised': 'warning',
  'field-replaced-wholly': 'info',
  'field-shape-unexpected': 'warning',
  'input-too-large': 'error',
  'input-unreadable': 'error',
  'no-records-processed': 'error',
  'output-unwritable': 'error',
  'path-escapes-root': 'error',
  'policy-target-never-seen': 'warning',
  'record-not-json': 'error',
  'record-not-object': 'error',
  'record-not-utf8': 'error',
  'record-residual-identifier': 'error',
  'record-too-deep': 'error',
  'record-too-large': 'error',
  'record-too-many-fields': 'error',
  'time-budget-exceeded': 'error',
  'too-many-findings': 'error',
  'too-many-records': 'error',
  'value-over-limit': 'warning',
})

const MESSAGE_LIMIT = 400
const SUGGESTION_LIMIT = 300
const LOCATION_LIMIT = 200
const MAX_NAME_LENGTH = 200
/**
 * The policy's own byte bound.
 *
 * Deliberately not `maxInputBytes`: that limit is about the subject of the run,
 * and lowering it to say "this log should be small" must not start refusing the
 * configuration that decides what to redact.
 */
const MAX_POLICY_BYTES = 1048576
const READ_CHUNK = 65536
const WRITE_FLUSH_BYTES = 262144
const NEWLINE = 0x0a
const CARRIAGE_RETURN = 0x0d

const ALLOWED_OPTIONS = Object.freeze(['clock', 'force', 'limits', 'log', 'out', 'policy', 'root'])

/**
 * Validate limit overrides.
 *
 * An unknown key throws rather than being ignored. A documented limit that a
 * typo silently disables is a limit that is not enforced; the CLI turns this
 * throw into a configuration error with an empty stdout.
 */
export function validateLimits(overrides = {}) {
  if (!isPlainObject(overrides)) throw new TypeError('limits must be an object')
  const limits = { ...DEFAULT_LIMITS }
  for (const key of Object.keys(overrides).sort(byCodeUnit)) {
    if (!Object.hasOwn(DEFAULT_LIMITS, key)) {
      throw new TypeError(`Unknown limit "${excerpt(key, 60)}"; known limits are ${Object.keys(DEFAULT_LIMITS).sort(byCodeUnit).join(', ')}`)
    }
    const value = overrides[key]
    const cap = HARD_LIMITS[key]
    if (!Number.isInteger(value) || value < 1 || value > cap) {
      throw new TypeError(`limits.${key} must be an integer between 1 and ${cap}`)
    }
    limits[key] = value
  }
  return Object.freeze(limits)
}

/**
 * True when `candidate` is the real root itself or lies beneath it.
 *
 * Both sides must already be real paths. Comparing a real root against a path
 * that has not been resolved refuses legitimate files whenever the root is
 * reached through a symbolic link -- a `/var` that is really `/private/var` is
 * enough -- and a false refusal is a defect too.
 */
export function isInside(root, candidate) {
  return candidate === root || candidate.startsWith(root.endsWith(sep) ? root : root + sep)
}

/**
 * A file name given on the command line, checked as configuration.
 *
 * This is emphatically *not* the confinement: a symbolic link planted inside
 * the root passes every check here and contains no `..` at all. `locate` is
 * what catches that, by resolving the real path of both sides.
 */
function validateName(name, flag) {
  if (typeof name !== 'string' || name.length === 0 || name.length > MAX_NAME_LENGTH) {
    throw new TypeError(`${flag} must be a relative file name of 1-${MAX_NAME_LENGTH} characters`)
  }
  if (hasForbiddenCharacter(name)) {
    throw new TypeError(`${flag} must not contain a control, separator or bidi character`)
  }
  if (isAbsolute(name)) throw new TypeError(`${flag} must be relative to --root, not an absolute path`)
  if (normalize(name).split(/[\\/]/).includes('..')) {
    throw new TypeError(`${flag} must not step outside --root with ".."`)
  }
  return name
}

/** Build a finding, taking its severity from the one table. */
export function createFinding(row) {
  const severity = RULE_SEVERITY[row.ruleId]
  if (severity === undefined) {
    throw new Error(`Rule "${row.ruleId}" is not in RULE_SEVERITY; add it to the table and to docs/redaction-rules.md.`)
  }
  const finding = {
    ruleId: row.ruleId,
    severity,
    message: reportText(row.message, MESSAGE_LIMIT),
    location: {
      file: reportText(row.file, LOCATION_LIMIT),
      line: row.line ?? 0,
      pointer: reportText(row.pointer ?? '', LOCATION_LIMIT),
    },
  }
  if (row.suggestion !== undefined) finding.suggestion = reportText(row.suggestion, SUGGESTION_LIMIT)
  return finding
}

/**
 * The documented sort key: `location.file`, `location.line`, `location.pointer`,
 * `ruleId`, `message`.
 *
 * The line is compared as a number, so line 9 precedes line 10 -- comparing it
 * as text would order a log by the spelling of its line numbers. Every other
 * component is compared by code unit.
 */
export function compareFindings(a, b) {
  return (
    byCodeUnit(a.location.file, b.location.file) ||
    a.location.line - b.location.line ||
    byCodeUnit(a.location.pointer, b.location.pointer) ||
    byCodeUnit(a.ruleId, b.ruleId) ||
    byCodeUnit(a.message, b.message)
  )
}

class FindingSink {
  constructor() {
    this.rows = []
  }

  add(row) {
    this.rows.push(row)
  }
}

/**
 * Resolve one declared name inside the real root and inspect it, refusing
 * anything that leaves the root.
 *
 * The `stat` belongs here rather than at the two call sites. Resolving a name
 * and then inspecting it as two steps answers one question -- "can this run
 * obtain this file?" -- in two places, and the second answer was a branch no
 * test could reach: `realpath` succeeding and `stat` failing needs the file to
 * be unlinked, or to lose its permissions, in the window between the two calls.
 * An `incomplete` flag set only on a path nothing exercises is an `incomplete`
 * flag that can be deleted with the whole suite still green, which is precisely
 * how a tool in this catalog came to report a completed failure about a file it
 * had never read. Asking once leaves one refusal for every way of not obtaining
 * the file, and it is the refusal the tests already drive.
 */
async function locate(realRoot, name) {
  const target = resolve(realRoot, name)
  try {
    const real = await realpath(target)
    if (!isInside(realRoot, real)) return { ok: false, reason: 'escapes' }
    // Inside the same `try`: a `stat` that throws here is one more way of not
    // obtaining the file, and it leaves by the same door.
    return { ok: true, real, info: await stat(real) }
  } catch (error) {
    // The entry may exist as a link that resolves nowhere. Confine the nearest
    // existing ancestor first, so a symlinked parent cannot decide where a
    // "missing" file would have been read from.
    try {
      const realParent = await realpath(dirname(target))
      if (!isInside(realRoot, realParent)) return { ok: false, reason: 'escapes' }
    } catch {
      return { ok: false, reason: 'unreadable', code: error.code }
    }
    return { ok: false, reason: 'unreadable', code: error.code }
  }
}

/**
 * Read and compile the policy.
 *
 * Every failure here throws. The policy is configuration: a run whose rules
 * could not be read never had a subject, so it produces no report at all rather
 * than a report that might be mistaken for a verdict about a log.
 */
async function loadPolicy(realRoot, name) {
  const located = await locate(realRoot, name)
  if (!located.ok) {
    throw new TypeError(located.reason === 'escapes'
      ? `--policy ${name} resolves outside --root`
      : `--policy ${name} could not be read: ${located.code ?? 'unknown error'}`)
  }
  const info = located.info
  if (!info.isFile()) throw new TypeError(`--policy ${name} is not a regular file`)
  if (info.size > MAX_POLICY_BYTES) throw new TypeError(`--policy ${name} is larger than ${MAX_POLICY_BYTES} bytes`)
  const handle = await open(located.real, 'r')
  let bytes
  try {
    bytes = await handle.readFile()
  } finally {
    await handle.close()
  }
  const decoded = decodeUtf8(bytes)
  if (!decoded.ok) throw new TypeError(`--policy ${name} is not valid UTF-8`)
  let document
  try {
    document = JSON.parse(decoded.text)
  } catch {
    // The parser's message quotes the document. A policy is less sensitive than
    // a log, but the habit of never reading one is the point.
    throw new TypeError(`--policy ${name} is not valid JSON`)
  }
  return {
    policy: compilePolicy(document),
    digest: createHash('sha256').update(bytes).digest('hex'),
    real: located.real,
    info,
  }
}

/**
 * Open the destination, refusing to write over anything this run reads.
 *
 * `realpath` alone is not enough here. A hard link has no target: two names for
 * one inode resolve to two different real paths, so a path comparison passes
 * and the run overwrites its own input. The device and inode numbers are the
 * identity that survives that, which is what is compared.
 */
async function openOutput(realRoot, name, force, inputs, sink) {
  const target = resolve(realRoot, name)
  let realParent
  try {
    realParent = await realpath(dirname(target))
  } catch (error) {
    throw new TypeError(`--out ${name}: its directory could not be resolved: ${error.code ?? 'unknown error'}`)
  }
  if (!isInside(realRoot, realParent)) throw new TypeError(`--out ${name} resolves outside --root`)
  const final = join(realParent, basename(target))

  let existing = null
  try {
    existing = await stat(final)
  } catch {
    existing = null
  }
  if (existing !== null) {
    for (const input of inputs) {
      if (existing.dev === input.info.dev && existing.ino === input.info.ino) {
        throw new TypeError(`--out ${name} is the same file as ${input.label}; this run would destroy its own input`)
      }
    }
    if (existing.isFile() && !force) {
      throw new TypeError(`--out ${name} already exists; pass --force to replace it`)
    }
  }

  try {
    return { handle: await open(final, force ? 'w' : 'wx'), file: name }
  } catch (error) {
    sink.add({
      file: name,
      ruleId: 'output-unwritable',
      message: `The destination could not be opened: ${error.code ?? 'unknown error'}. No record was read, because a run that cannot write its redacted output has nothing to offer.`,
      suggestion: 'Name a destination this process can create inside --root.',
    })
    return null
  }
}

/** Batching writer: lines are buffered until a flush is worth doing. */
class OutputSink {
  constructor(handle) {
    this.handle = handle
    this.pending = []
    this.pendingBytes = 0
    this.hash = createHash('sha256')
    this.lines = 0
  }

  async push(line) {
    this.hash.update(line)
    this.lines += 1
    if (this.handle === null) return
    this.pending.push(line)
    this.pendingBytes += Buffer.byteLength(line)
    if (this.pendingBytes >= WRITE_FLUSH_BYTES) await this.flush()
  }

  async flush() {
    if (this.handle === null || this.pending.length === 0) return
    const payload = this.pending.join('')
    this.pending = []
    this.pendingBytes = 0
    await this.handle.write(payload)
  }

  digest() {
    return this.hash.digest('hex')
  }
}

/** A note key that cannot be forged by a field name, because every part is quoted. */
function noteKey(ruleId, matchPath, reason) {
  return JSON.stringify([ruleId, matchPath, reason])
}

/**
 * Redact an exported access log.
 *
 * @param {object} options
 * @param {string} options.root Directory holding the log, the policy and any output.
 * @param {string} [options.log] Log file name, relative to the root.
 * @param {string} [options.policy] Policy file name, relative to the root.
 * @param {string} [options.out] Destination for the redacted log, relative to the
 *   root. Omitted, the run is a dry run: every record is redacted and checked,
 *   and nothing is written.
 * @param {boolean} [options.force] Replace an existing destination.
 * @param {object} [options.limits] Limit overrides; an unknown key throws.
 * @param {Function} [options.clock] Monotonic millisecond source for the time
 *   budget. Injected so a test can drive the budget without waiting, and so
 *   that nothing in this package reads a wall clock.
 * @returns {Promise<object>} the report.
 */
export async function redactAccessLog(options = {}) {
  if (!isPlainObject(options)) throw new TypeError('options must be an object')
  for (const key of Object.keys(options).sort(byCodeUnit)) {
    if (!ALLOWED_OPTIONS.includes(key)) {
      throw new TypeError(`Unknown option "${excerpt(key, 60)}"; known options are ${ALLOWED_OPTIONS.join(', ')}`)
    }
  }
  const limits = validateLimits(options.limits ?? {})
  if (typeof options.root !== 'string' || options.root.length === 0) throw new TypeError('root must be a non-empty string')
  if (options.clock !== undefined && typeof options.clock !== 'function') throw new TypeError('clock must be a function returning milliseconds')
  if (options.force !== undefined && typeof options.force !== 'boolean') throw new TypeError('force must be a boolean')

  const logName = validateName(options.log ?? DEFAULT_LOG_NAME, '--log')
  const policyName = validateName(options.policy ?? DEFAULT_POLICY_NAME, '--policy')
  const outName = options.out === undefined || options.out === null ? null : validateName(options.out, '--out')

  let realRoot
  try {
    realRoot = await realpath(options.root)
  } catch (error) {
    throw new TypeError(`--root could not be resolved: ${error.code ?? 'unknown error'}`)
  }
  if (!(await stat(realRoot)).isDirectory()) throw new TypeError('--root must be a directory')

  const { policy, digest: policyDigest, info: policyInfo } = await loadPolicy(realRoot, policyName)

  const clock = options.clock ?? (() => performance.now())
  const started = clock()
  const sink = new FindingSink()
  const state = {
    records: 0,
    written: 0,
    quarantined: 0,
    blank: 0,
    redactions: 0,
    bytesRead: 0,
    consumed: false,
    read: false,
    incomplete: false,
  }
  const seen = new Set()
  const notes = new Map()
  const detectors = [...policy.detectors].sort(byCodeUnit)
  const files = { logName, policyName, policyDigest, outName, outDigest: null, detectors }

  const located = await locate(realRoot, logName)
  if (!located.ok) {
    state.incomplete = true
    sink.add(located.reason === 'escapes'
      ? {
        file: logName,
        ruleId: 'path-escapes-root',
        message: `${logName} resolves outside --root, so it was refused unread.`,
        suggestion: 'Keep the log inside the declared root; a symbolic link out of the tree is refused.',
      }
      : {
        file: logName,
        ruleId: 'input-unreadable',
        message: `${logName} could not be resolved inside --root: ${located.code ?? 'unknown error'}.`,
        suggestion: 'Check the file name and its permissions.',
      })
    return buildReport(sink, state, limits, files)
  }

  const info = located.info
  if (!info.isFile()) {
    state.incomplete = true
    sink.add({ file: logName, ruleId: 'input-unreadable', message: `${logName} is not a regular file, so nothing was read from it.` })
    return buildReport(sink, state, limits, files)
  }
  if (info.size > limits.maxInputBytes) {
    state.incomplete = true
    sink.add({
      file: logName,
      ruleId: 'input-too-large',
      message: `${logName} is ${info.size} bytes, above the maxInputBytes limit of ${limits.maxInputBytes}; it was not read.`,
      suggestion: 'Raise --max-input-bytes, or split the log and redact each part.',
    })
    return buildReport(sink, state, limits, files)
  }

  let output = null
  if (outName !== null) {
    // The policy's identity is the one `locate` established before the file was
    // read, not a fresh `stat` that could throw out of this function unguarded.
    output = await openOutput(realRoot, outName, options.force === true, [
      { label: `--log ${logName}`, info },
      { label: `--policy ${policyName}`, info: policyInfo },
    ], sink)
    if (output === null) {
      state.incomplete = true
      return buildReport(sink, state, limits, files)
    }
  }

  const out = new OutputSink(output === null ? null : output.handle)
  /**
   * "May this run start another record?", asked before each one rather than
   * after.
   *
   * Asking afterwards reports a log of exactly `maxRecords` records as one that
   * held more, and a run that finished inside its budget as one that ran out of
   * it -- a false `incomplete` about a file that was read to its end.
   * Hardening that refuses valid work is a defect too, so the question is asked
   * where the answer is about input that still remains. A blank line is not a
   * record and never triggers it.
   */
  const stopBefore = () => {
    if (state.records >= limits.maxRecords) return 'records'
    if (clock() - started > limits.maxRuntimeMs) return 'time'
    return null
  }
  const context = { policy, limits, state, sink, seen, notes, out, logName, stopBefore }
  let stopReason = null

  const handle = await open(located.real, 'r')
  try {
    state.read = true
    const stream = handle.createReadStream({ highWaterMark: READ_CHUNK })
    let pending = []
    let pendingBytes = 0
    let skipping = false
    let lineNumber = 0

    const quarantineOverlongLine = () => {
      lineNumber += 1
      state.records += 1
      state.quarantined += 1
      sink.add({
        file: logName,
        line: lineNumber,
        ruleId: 'record-too-large',
        message: `Line ${lineNumber} is longer than the maxLineBytes limit of ${limits.maxLineBytes}; it was quarantined unparsed, and no part of it was written or reported.`,
        suggestion: 'Raise --max-line-bytes if records this long are expected.',
      })
    }

    for await (const chunk of stream) {
      /**
       * `bytesRead` is a statistic, not a second bound.
       *
       * The byte limit is enforced once, against the file's size, before a byte
       * is read -- so an oversized log is refused unread rather than half
       * processed. Counting again here and stopping at the same number could
       * only fire for a file that grew after that check, and a bound that can
       * fire only in a race is a bound no test can pin. A log that is being
       * appended to while it is read is bounded by `maxRuntimeMs` instead, and
       * `docs/redaction-rules.md` says so.
       */
      state.bytesRead += chunk.length
      let start = 0
      while (start < chunk.length) {
        const newline = chunk.indexOf(NEWLINE, start)
        if (newline === -1) {
          if (!skipping) {
            const rest = chunk.subarray(start)
            pendingBytes += rest.length
            if (pendingBytes > limits.maxLineBytes) {
              // Drop what has accumulated and resynchronise at the next
              // newline. Holding the rest of an unbounded line in memory so it
              // could be described is the defect the bound exists to prevent.
              skipping = true
              pending = []
              pendingBytes = 0
            } else pending.push(rest)
          }
          break
        }
        const piece = chunk.subarray(start, newline)
        start = newline + 1
        if (skipping) {
          skipping = false
          // An over-long line is a record, so it asks the same question first.
          stopReason = stopBefore()
          if (stopReason !== null) break
          quarantineOverlongLine()
        } else {
          pending.push(piece)
          pendingBytes += piece.length
          if (pendingBytes > limits.maxLineBytes) {
            pending = []
            pendingBytes = 0
            quarantineOverlongLine()
          } else {
            const line = pending.length === 1 ? pending[0] : Buffer.concat(pending)
            pending = []
            pendingBytes = 0
            lineNumber += 1
            const outcome = await processLine(line, lineNumber, context)
            if (outcome !== 'blank' && outcome !== 'record') {
              // The line was not processed: it is still waiting, which is what
              // makes the run incomplete.
              lineNumber -= 1
              stopReason = outcome
              break
            }
          }
        }
      }
      if (stopReason !== null) break
    }

    if (stopReason === null) {
      if (skipping) {
        // A trailing line, over the bound, that never ended.
        stopReason = stopBefore()
        if (stopReason === null) quarantineOverlongLine()
      } else if (pendingBytes > 0) {
        lineNumber += 1
        const outcome = await processLine(Buffer.concat(pending), lineNumber, context)
        if (outcome !== 'blank' && outcome !== 'record') {
          // The line was not processed: it is still waiting, which is what
          // makes the run incomplete.
          lineNumber -= 1
          stopReason = outcome
        }
      }
    }

    /**
     * The only place `consumed` is set.
     *
     * Completeness is claimed where the stream ended of its own accord, never
     * inferred from the absence of an error further down: every early exit sets
     * a stop reason, and a stop reason is the one thing this line asks about.
     */
    if (stopReason === null) state.consumed = true

    await out.flush()
  } finally {
    await handle.close()
    if (output !== null) await output.handle.close()
  }

  /**
   * The stop reason, consulted after the loop rather than at the `break`.
   *
   * Every early exit above sets a reason and nothing else; this is where a
   * reason becomes a finding and an `incomplete` status. An unrecorded reason
   * throws rather than falling through, because the failure this guards against
   * is precisely a stop that reaches a success branch without being noticed.
   */
  if (!state.consumed) {
    state.incomplete = true
    if (stopReason === 'records') {
      sink.add({
        file: logName,
        line: state.records,
        ruleId: 'too-many-records',
        message: `The log holds more than the maxRecords limit of ${limits.maxRecords}; the run stopped there, and the rest of the file was neither read nor redacted.`,
        suggestion: 'Raise --max-records, or split the log.',
      })
    } else if (stopReason === 'time') {
      sink.add({
        file: logName,
        line: state.records,
        ruleId: 'time-budget-exceeded',
        message: `The run passed the maxRuntimeMs budget of ${limits.maxRuntimeMs} after ${state.records} record(s) and stopped; the rest of the file was neither read nor redacted.`,
        suggestion: 'Raise --max-runtime-ms, or split the log.',
      })
    } else {
      throw new Error(`The stream stopped for an unrecorded reason (${String(stopReason)}); refusing to report a partial run as anything at all.`)
    }
  }

  /**
   * Aggregated value notes, in first-seen order.
   *
   * They are not sorted here. `buildReport` sorts every finding by the one
   * documented key, so a second ordering at this point could only agree with it
   * or be overruled by it -- and an ordering whose result nothing can observe is
   * an ordering no test can pin. Insertion order into the map is fixed by the
   * log, so this loop is deterministic either way.
   */
  for (const entry of notes.values()) {
    sink.add({
      file: logName,
      line: entry.line,
      pointer: entry.pointer,
      ruleId: entry.ruleId,
      message: `${entry.reason}. The value was replaced whole. First seen at line ${entry.line}; ${entry.count} occurrence(s) in this run.`,
      suggestion: 'Only the position is reported: the value was not scanned, quoted or truncated.',
    })
  }

  /**
   * A policy target nothing ever matched, reported only for a run that read the
   * whole log **and looked inside every record in it**.
   *
   * This is the conclusion the stream is responsible for: "no record carried
   * this header" is a statement about every record, so the run has to have seen
   * every record to make it.
   *
   * `state.consumed` alone was not that. A quarantined record is counted and
   * located, and then never inspected: a line over `maxLineBytes` is not
   * parsed, a line that is not UTF-8 is not decoded, a line that is not JSON is
   * not walked, and a record refused for depth or field count has its walk
   * abandoned partway. A one-record log whose record carried all four targets
   * produced four findings each saying no record carried them, as soon as any
   * one of those limits quarantined it -- a claim on evidence the run did not
   * obtain, and one that sends the operator to their policy when the thing to
   * fix is the limit they set. The run already withholds this for a stream that
   * stopped early, for exactly the same reason; a record that was read but not
   * read *into* is the same gap one level down.
   */
  if (state.consumed && state.quarantined === 0) {
    for (const target of policy.targets) {
      if (seen.has(target)) continue
      sink.add({
        file: policyName,
        pointer: `/${target.replace(':', '/')}`,
        ruleId: 'policy-target-never-seen',
        message: `The policy names ${target} and no record in this log carried it, so nothing was redacted on its account.`,
        suggestion: 'Check the target against a real record: a policy that matches nothing looks exactly like a log with nothing to redact.',
      })
    }
  }

  /**
   * The vacuous pass, refused explicitly.
   *
   * A readable log with no records would otherwise report `pass` with
   * `checked: 0` -- green on no evidence at all. Confined to a run that read
   * the file to the end, because a run that stopped early has already said so
   * under its own rule, and repeating it here would backstop that flag so
   * thoroughly that removing it would change nothing observable.
   */
  if (state.read && state.consumed && state.records === 0) {
    state.incomplete = true
    sink.add({
      file: logName,
      ruleId: 'no-records-processed',
      message: `${logName} held no records, so this run has no evidence to be green on.`,
      suggestion: 'Point --log at an exported log with one JSON record per line.',
    })
  }

  files.outDigest = out.digest()
  return buildReport(sink, state, limits, files)
}

/**
 * Classify and redact one line.
 *
 * Returns `'blank'`, `'record'`, or the reason this run may not start another
 * record -- in which case the line was not processed at all and is still
 * waiting, which is what makes the run incomplete.
 *
 * Every refusal here quarantines: the record is counted, located by line
 * number, described by shape, and never written. No branch writes a record it
 * could not fully redact, and no branch reports one it refused.
 */
async function processLine(bytes, lineNumber, context) {
  const { policy, limits, state, sink, seen, notes, out, logName } = context

  let payload = bytes
  if (payload.length > 0 && payload[payload.length - 1] === CARRIAGE_RETURN) {
    payload = payload.subarray(0, payload.length - 1)
  }

  const decoded = decodeUtf8(payload)
  if (decoded.ok && decoded.text.trim() === '') {
    state.blank += 1
    return 'blank'
  }

  // Asked here, where a blank line has already been ruled out and before the
  // record is counted, so a bound is never spent on a line that holds nothing.
  const stop = context.stopBefore()
  if (stop !== null) return stop

  state.records += 1

  if (!decoded.ok) {
    state.quarantined += 1
    sink.add({
      file: logName,
      line: lineNumber,
      ruleId: 'record-not-utf8',
      message: `Line ${lineNumber} is ${payload.length} byte(s) that are not valid UTF-8; it was quarantined undecoded. Whether bytes decode is the decoder's decision, never an inference from the decoded text.`,
      suggestion: 'Re-export the log as UTF-8.',
    })
    return 'record'
  }

  const text = decoded.text

  let parsed
  try {
    parsed = JSON.parse(text)
  } catch {
    /**
     * The parser's message is never read.
     *
     * `JSON.parse` quotes the input it choked on -- its message carries a slice
     * of the line with it. Printing that would hand the report exactly the
     * content this tool exists to keep out of it, and a malformed line is the
     * one line that never went through redaction. So the catch binds nothing,
     * and the finding is built from the line number, the byte count and a shape
     * token drawn from a closed vocabulary.
     */
    state.quarantined += 1
    sink.add({
      file: logName,
      line: lineNumber,
      ruleId: 'record-not-json',
      message: `Line ${lineNumber} is not valid JSON: ${payload.length} byte(s), ${shapeOfLine(text)}. It was quarantined; its content is not reported, and no parser message is read.`,
      suggestion: 'Repair the exporter, or drop the line before redacting; this run withheld it.',
    })
    return 'record'
  }

  if (!isPlainObject(parsed)) {
    state.quarantined += 1
    sink.add({
      file: logName,
      line: lineNumber,
      ruleId: 'record-not-object',
      message: `Line ${lineNumber} parsed as ${describeJsonType(parsed)} rather than an object, so no field could be matched against the policy. It was quarantined.`,
      suggestion: 'Export one JSON object per line.',
    })
    return 'record'
  }

  let redacted
  try {
    redacted = redactRecord(parsed, policy, limits, seen)
  } catch (error) {
    if (!(error instanceof RecordRefused)) throw error
    state.quarantined += 1
    sink.add({
      file: logName,
      line: lineNumber,
      ruleId: error.ruleId,
      message: error.ruleId === 'record-too-deep'
        ? `Line ${lineNumber} nests deeper than the maxDepth limit of ${error.detail}; it was quarantined unredacted.`
        : `Line ${lineNumber} holds more fields than the maxFieldsPerRecord limit of ${error.detail}; it was quarantined unredacted.`,
      suggestion: 'Raise the limit if records of this shape are expected; until then the record is withheld rather than partly redacted.',
    })
    return 'record'
  }

  for (const entry of redacted.notes) {
    const key = noteKey(entry.ruleId, entry.matchPath, entry.reason)
    const existing = notes.get(key)
    if (existing === undefined) notes.set(key, { ...entry, line: lineNumber, count: 1 })
    else existing.count += 1
  }

  const line = `${escapeOutputUnsafe(JSON.stringify(redacted.value))}\n`

  /**
   * The residue check: the last thing between a redacted record and the
   * destination.
   *
   * The walk redacts values. Keys are structural and are left alone, so a
   * record whose *key* is an email address would carry it into the output, as
   * would any value the walk failed to reach. Re-running the enabled detectors
   * over the serialized line catches both. A record that still matches is
   * quarantined rather than patched: rewriting a key would change the shape of
   * somebody's log, and this tool would rather withhold a record than hand back
   * one it cannot vouch for.
   */
  const residue = detectorsMatching(line, policy.detectors)
  if (residue.length > 0) {
    state.quarantined += 1
    sink.add({
      file: logName,
      line: lineNumber,
      ruleId: 'record-residual-identifier',
      message: `Line ${lineNumber} still matched the ${residue.join(', ')} detector after redaction -- most often an identifier used as a field name, which is structure rather than a value. It was quarantined and not written; neither the match nor its position is reported.`,
      suggestion: 'Rename the field in the exporter, or name its parent in redactFields.',
    })
    return 'record'
  }

  state.redactions += redacted.redactions
  state.written += 1
  await out.push(line)
  return 'record'
}

function buildReport(sink, state, limits, files) {
  let findings = sink.rows.map((row) => createFinding(row)).sort(compareFindings)
  let truncated = false

  if (findings.length > limits.maxFindings) {
    const dropped = findings.length - limits.maxFindings + 1
    findings = findings.slice(0, limits.maxFindings - 1)
    findings.push(createFinding({
      file: files.logName,
      ruleId: 'too-many-findings',
      message: `The run produced more findings than the maxFindings limit of ${limits.maxFindings}; ${dropped} were not reported and this report is partial.`,
      suggestion: 'Raise --max-findings, or narrow the input.',
    }))
    findings.sort(compareFindings)
    truncated = true
  }

  let errors = 0
  let warnings = 0
  for (const finding of findings) {
    if (finding.severity === 'error') errors += 1
    else if (finding.severity === 'warning') warnings += 1
  }

  const status = state.incomplete || truncated ? 'incomplete' : errors > 0 ? 'fail' : 'pass'

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: TOOL_ID,
    status,
    summary: {
      checked: state.records,
      errors,
      warnings,
      records: state.records,
      written: state.written,
      quarantined: state.quarantined,
      blank: state.blank,
      redactions: state.redactions,
      bytesRead: state.bytesRead,
    },
    input: {
      file: reportText(files.logName, LOCATION_LIMIT),
      policy: reportText(files.policyName, LOCATION_LIMIT),
      policyDigest: files.policyDigest,
      policySchemaVersion: POLICY_SCHEMA_VERSION,
      detectors: files.detectors ?? [],
    },
    output: {
      file: files.outName === null || files.outName === undefined ? null : reportText(files.outName, LOCATION_LIMIT),
      written: state.written,
      digest: files.outDigest,
    },
    findings,
  }
}

/** stdout carries this and nothing else, so it can be piped straight into a parser. */
export function serializeReport(report) {
  return JSON.stringify(report, null, 2)
}

/** 0 completed and passed, 1 completed and failed, 2 the run could not be completed. */
export function exitCodeFor(report) {
  if (report.status === 'incomplete') return 2
  return report.status === 'fail' ? 1 : 0
}

const SEVERITY_WIDTH = 7

/** The human summary. It goes to stderr; stdout is the JSON report alone. */
export function formatReport(report) {
  const { summary } = report
  const lines = [
    `log ${report.input.file}: ${summary.records} record(s), ${summary.blank} blank line(s), ${summary.bytesRead} byte(s) read.`,
    `policy ${report.input.policy} (sha256 ${report.input.policyDigest.slice(0, 16)}): ${summary.redactions} value(s) redacted.`,
    `output ${report.output.file ?? '(dry run, nothing written)'}: ${summary.written} written, ${summary.quarantined} quarantined. status ${report.status}.`,
  ]
  for (const finding of report.findings) {
    lines.push(
      `${finding.severity.toUpperCase().padEnd(SEVERITY_WIDTH)} ` +
      `${finding.location.file}:${finding.location.line}${finding.location.pointer} ${finding.ruleId} ${finding.message}`,
    )
  }
  return `${lines.join('\n')}\n`
}

export { DETECTOR_NAMES, detectorsMatching, luhn, redactDetected, reportText } from './detectors.mjs'
export { maskAddress, maskAddressField, maskIpv4, maskIpv6, parseIpv4, parseIpv6 } from './address.mjs'
export { DEFAULT_PLACEHOLDER, POLICY_KEYS, POLICY_SCHEMA_VERSION, compilePolicy } from './policy.mjs'
export { RecordRefused, escapePointer, redactRecord } from './redact.mjs'
export {
  LINE_SHAPES, byCodeUnit, decodeUtf8, describeJsonType, escapeOutputUnsafe, excerpt,
  hasForbiddenCharacter, isPlainObject, shapeOfLine,
} from './text.mjs'
