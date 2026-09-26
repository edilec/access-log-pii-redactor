/**
 * Fixtures and runners shared by the test suite.
 *
 * Two entry points are exercised throughout: `apiReport` calls the exported
 * function, and `cliRun` spawns the real binary and reads the real exit code.
 * Several guarantees in this package can only be pinned by the second -- an
 * exit code cannot be satisfied by editing a table.
 *
 * Everything here builds *inputs*. Nothing here decides what a test expects: no
 * severity, no rule id, no count and no ordering lives in this file, so a test
 * cannot accidentally assert a value against the same declaration that produced
 * it.
 */

import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

import { redactAccessLog } from '../src/index.mjs'

const execFileAsync = promisify(execFile)

export const projectDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const CLI = join(projectDirectory, 'bin/access-log-pii-redactor.mjs')

/**
 * Synthetic canaries.
 *
 * Every one is a published placeholder that cannot authenticate anything: the
 * vendor's own documented example key, the standard test card number, and a
 * domain RFC 2606 reserves for exactly this. No real credential appears in any
 * fixture in this repository.
 */
export const CANARIES = Object.freeze({
  awsKey: 'AKIAIOSFODNN7EXAMPLE',
  card: '4111111111111111',
  email: 'ada@example.invalid',
  bearer: 'Bearer AbCdEfGh01234567',
  jwt: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZGEifQ.signaturegoeshere',
})

/** A policy document, with only the keys a case names. */
export function policy(extra = {}) {
  return { schemaVersion: '1', ...extra }
}

/** The policy the examples use, in full. */
export const fullPolicy = () => policy({
  urlFields: ['request.url'],
  queryParams: ['token'],
  headerFields: ['request.headers'],
  headers: ['authorization', 'x-api-key'],
  addressFields: ['client.ip'],
  redactFields: ['user.email'],
  detectors: ['aws-access-key-id', 'bearer-token', 'email-address', 'jwt', 'pan-digits', 'private-key-block'],
})

/** One record carrying every target the full policy names. */
export const record = (extra = {}) => ({
  ts: '2026-09-12T10:15:00Z',
  client: { ip: '203.0.113.42' },
  request: {
    method: 'GET',
    url: '/v1/search?q=router&token=t-90f1a2',
    headers: { authorization: 'Bearer abcdefghijklmnop', 'x-api-key': 'k-1122', 'user-agent': 'curl/8.6.0' },
  },
  user: { id: 'u-4417', email: 'amelia@example.invalid' },
  status: 200,
  ...extra,
})

/** Records as a JSON Lines document. A string is written verbatim. */
export function logOf(records) {
  if (typeof records === 'string') return records
  return `${records.map((entry) => (typeof entry === 'string' ? entry : JSON.stringify(entry))).join('\n')}\n`
}

/**
 * Create a temporary root, write the named files into it, run `body(root)`, and
 * remove the tree afterwards whatever happened.
 *
 * A string is written verbatim and a `Uint8Array` byte for byte, so a test can
 * plant text that is not JSON, or bytes that are not UTF-8 at all.
 */
export async function withRoot(files, body) {
  const root = await mkdtemp(join(tmpdir(), 'access-log-pii-redactor-'))
  try {
    for (const [name, content] of Object.entries(files)) {
      const bytes = typeof content === 'string' || content instanceof Uint8Array
        ? content
        : `${JSON.stringify(content, null, 2)}\n`
      await writeFile(join(root, name), bytes)
    }
    return await body(root)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}

/** The two default file names, with the records and policy a case supplies. */
export const files = (records, policyDocument = fullPolicy()) => ({
  'access.log': logOf(records),
  'redaction-policy.json': policyDocument,
})

/** Run the exported API over a temporary root. */
export async function apiReport(inputs, options = {}) {
  return withRoot(inputs, (root) => redactAccessLog({ root, ...options }))
}

/** Spawn the real binary. Returns the exit code and both streams; never throws on a non-zero exit. */
export async function cliRun(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], {
      cwd: projectDirectory,
      maxBuffer: 64 * 1024 * 1024,
    })
    return { code: 0, stdout, stderr }
  } catch (error) {
    return { code: error.code, stdout: error.stdout ?? '', stderr: error.stderr ?? '' }
  }
}

/** Spawn the real binary over a temporary root, and parse whatever stdout carried. */
export async function cliReport(inputs, extraArgs = []) {
  return withRoot(inputs, async (root) => {
    const result = await cliRun(['--root', root, ...extraArgs])
    return { ...result, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
  })
}

/**
 * Run the binary and read back what it wrote, inside one temporary root.
 *
 * The redacted file is the thing this tool produces, so a case that asserts
 * about it has to read the real bytes rather than the report's account of them.
 */
export async function cliWrite(inputs, extraArgs = [], outName = 'redacted.log') {
  return withRoot(inputs, async (root) => {
    const result = await cliRun(['--root', root, '--out', outName, ...extraArgs])
    let written = null
    try {
      written = await readFile(join(root, outName), 'utf8')
    } catch {
      written = null
    }
    return { ...result, written, report: result.stdout === '' ? null : JSON.parse(result.stdout) }
  })
}

/** Every rule id a report raised, deduplicated and ordered. */
export const raisedRules = (report) =>
  [...new Set(report.findings.map((finding) => finding.ruleId))].sort()

/** The findings for one rule id, in emitted order. */
export const findingsFor = (report, ruleId) => report.findings.filter((finding) => finding.ruleId === ruleId)

/**
 * One character from each class the report contract names, built from code
 * points so every test file that uses them stays plain ASCII and readable.
 */
export const FORBIDDEN = Object.freeze({
  'C0 NUL': String.fromCharCode(0x00),
  'C0 LF': String.fromCharCode(0x0a),
  'C0 ESC': String.fromCharCode(0x1b),
  DEL: String.fromCharCode(0x7f),
  'C1 NEL': String.fromCharCode(0x85),
  'C1 CSI': String.fromCharCode(0x9b),
  'line separator': String.fromCharCode(0x2028),
  'paragraph separator': String.fromCharCode(0x2029),
  'bidi LRM': String.fromCharCode(0x200e),
  'bidi RLM': String.fromCharCode(0x200f),
  'bidi RLO': String.fromCharCode(0x202e),
  'bidi isolate': String.fromCharCode(0x2066),
})

/**
 * Every substring of `needle` of at least `minimum` characters, longest first.
 *
 * A leak test that checks for the whole canary is a test the next partial leak
 * passes for free: a message that quotes the first twelve characters of a key
 * has leaked it just as thoroughly as one that quotes all twenty.
 */
export function substringsOf(needle, minimum = 6) {
  const parts = []
  for (let start = 0; start < needle.length; start += 1) {
    for (let end = needle.length; end - start >= minimum; end -= 1) {
      parts.push(needle.slice(start, end))
    }
  }
  return parts
}
