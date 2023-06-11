/**
 * The redaction policy: what to remove, and from where.
 *
 * A policy is *configuration*, not evidence. The log is the subject of a run;
 * the policy is the rule it is judged by. So every problem in this file throws,
 * the CLI turns the throw into exit 2 with an empty stdout, and no report is
 * produced -- a run whose rules could not be read never had a subject to report
 * about. Contrast `src/index.mjs`, where a log that cannot be read produces an
 * `incomplete` report naming the file, because there the run did have a subject
 * and failed to obtain evidence about it.
 *
 * Two decisions are worth stating outright:
 *
 * - **An unknown key throws.** `queryParam` instead of `queryParams` would
 *   otherwise be a policy that silently redacts nothing while every test stays
 *   green. A one-character typo must not turn a leak into a clean run.
 * - **An empty policy throws.** A policy that names no field, no header, no
 *   query parameter, no address and no detector would redact nothing and report
 *   `pass`, which is the vacuous pass this catalog has been bitten by before.
 */

import { DETECTOR_NAMES, detectorsMatching, isDetectorName } from './detectors.mjs'
import { byCodeUnit, excerpt, hasForbiddenCharacter, isPlainObject } from './text.mjs'

export const POLICY_SCHEMA_VERSION = '1'

export const DEFAULT_PLACEHOLDER = '[redacted]'

export const MAX_POLICY_ENTRIES = 256
export const MAX_PATH_SEGMENTS = 8
export const MAX_NAME_LENGTH = 64

/** The keys a policy document may carry. Anything else is a configuration error. */
export const POLICY_KEYS = Object.freeze([
  'addressFields',
  'addressPolicy',
  'description',
  'detectors',
  'headerFields',
  'headers',
  'placeholder',
  'queryParams',
  'redactFields',
  'schemaVersion',
  'urlFields',
])

export const ADDRESS_POLICY_KEYS = Object.freeze(['ipv4', 'ipv4PrefixBits', 'ipv6', 'ipv6PrefixBits'])

export const ADDRESS_ACTIONS = Object.freeze(['drop', 'mask-host'])

export const DEFAULT_ADDRESS_POLICY = Object.freeze({
  ipv4: 'mask-host',
  ipv4PrefixBits: 24,
  ipv6: 'mask-host',
  ipv6PrefixBits: 48,
})

/** The four lists whose entries are dotted field paths. */
export const PATH_LISTS = Object.freeze(['addressFields', 'headerFields', 'redactFields', 'urlFields'])

const PATH_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/
const QUERY_NAME = /^[A-Za-z0-9._~%[\]+-]{1,64}$/
const PLACEHOLDER_SHAPE = /^[ -~]{1,64}$/

function fail(message) {
  throw new TypeError(excerpt(message, 300))
}

function requireArrayOfStrings(value, key) {
  if (value === undefined) return []
  if (!Array.isArray(value)) fail(`policy.${key} must be an array of strings`)
  if (value.length > MAX_POLICY_ENTRIES) {
    fail(`policy.${key} has ${value.length} entries, above the limit of ${MAX_POLICY_ENTRIES}`)
  }
  const seen = new Set()
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.length === 0) fail(`policy.${key} must contain non-empty strings`)
    if (entry.length > MAX_NAME_LENGTH * MAX_PATH_SEGMENTS) fail(`policy.${key} contains an entry that is too long`)
    if (hasForbiddenCharacter(entry)) {
      fail(`policy.${key} contains a control, separator or bidi character; an entry that prints differently from the value it matches is not auditable`)
    }
    if (seen.has(entry)) fail(`policy.${key} lists "${entry}" more than once`)
    seen.add(entry)
  }
  return value
}

/**
 * A dotted path addressing a field inside a record.
 *
 * `user.email` reaches the `email` key of the `user` object. Array indices are
 * never written: a path matches inside every element of an array it meets, so
 * `items.email` covers `items[0].email` and every sibling. A key that contains
 * a literal `.` cannot be addressed, which `docs/redaction-policy.md` states as
 * a limit rather than working around with an escape nobody would get right.
 */
export function parsePath(path, key) {
  const segments = path.split('.')
  if (segments.length > MAX_PATH_SEGMENTS) {
    fail(`policy.${key} entry "${path}" has ${segments.length} segments, above the limit of ${MAX_PATH_SEGMENTS}`)
  }
  for (const segment of segments) {
    if (!PATH_SEGMENT.test(segment)) {
      fail(`policy.${key} entry "${path}" has a segment that is not a field name of 1-${MAX_NAME_LENGTH} characters over [A-Za-z0-9_-]`)
    }
  }
  return segments.join('.')
}

function validateAddressPolicy(value) {
  if (value === undefined) return { ...DEFAULT_ADDRESS_POLICY }
  if (!isPlainObject(value)) fail('policy.addressPolicy must be an object')
  for (const key of Object.keys(value).sort(byCodeUnit)) {
    if (!ADDRESS_POLICY_KEYS.includes(key)) {
      fail(`Unknown policy.addressPolicy key "${key}"; known keys are ${ADDRESS_POLICY_KEYS.join(', ')}`)
    }
  }
  const merged = { ...DEFAULT_ADDRESS_POLICY, ...value }
  for (const family of ['ipv4', 'ipv6']) {
    if (!ADDRESS_ACTIONS.includes(merged[family])) {
      fail(`policy.addressPolicy.${family} must be one of ${ADDRESS_ACTIONS.join(', ')}`)
    }
  }
  const bits = { ipv4PrefixBits: 32, ipv6PrefixBits: 128 }
  for (const [key, maximum] of Object.entries(bits)) {
    const given = merged[key]
    if (!Number.isInteger(given) || given < 0 || given > maximum) {
      fail(`policy.addressPolicy.${key} must be an integer between 0 and ${maximum}`)
    }
  }
  return merged
}

/**
 * Validate and compile a policy document.
 *
 * Returns a frozen shape with sets for matching and a target list for
 * reporting. The target list is what lets the run say "you named this header
 * and no record ever carried it" -- a policy that matches nothing is the most
 * common way a redactor leaks, and it looks identical to a clean log unless
 * somebody says so.
 */
export function compilePolicy(document) {
  if (!isPlainObject(document)) fail('The policy must be a JSON object')
  for (const key of Object.keys(document).sort(byCodeUnit)) {
    if (!POLICY_KEYS.includes(key)) {
      fail(`Unknown policy key "${key}"; known keys are ${POLICY_KEYS.join(', ')}`)
    }
  }
  if (document.schemaVersion !== POLICY_SCHEMA_VERSION) {
    fail(`policy.schemaVersion must be "${POLICY_SCHEMA_VERSION}"`)
  }
  if (document.description !== undefined && typeof document.description !== 'string') {
    fail('policy.description must be a string')
  }

  const placeholder = document.placeholder ?? DEFAULT_PLACEHOLDER
  if (typeof placeholder !== 'string' || !PLACEHOLDER_SHAPE.test(placeholder)) {
    fail('policy.placeholder must be 1-64 printable ASCII characters')
  }
  if (placeholder.includes('"') || placeholder.includes('\\')) {
    fail('policy.placeholder must not contain a quote or a backslash')
  }
  // A placeholder that a detector fires on would be re-redacted on the next
  // pass and would trip the residue check on every record.
  const selfMatching = detectorsMatching(placeholder, new Set(DETECTOR_NAMES))
  if (selfMatching.length > 0) {
    fail(`policy.placeholder is itself matched by the ${selfMatching.join(', ')} detector`)
  }

  const compiled = { placeholder, description: document.description ?? null }

  for (const key of PATH_LISTS) {
    const entries = requireArrayOfStrings(document[key], key)
    compiled[key] = new Set(entries.map((entry) => parsePath(entry, key)))
  }

  const headers = requireArrayOfStrings(document.headers, 'headers')
  for (const name of headers) {
    if (!HEADER_NAME.test(name)) fail(`policy.headers entry "${name}" is not an HTTP header name`)
  }
  // Header names are case-insensitive on the wire, so they are matched folded.
  // Two spellings of one header would fold together, which is a duplicate the
  // author should see rather than a silent merge.
  const folded = headers.map((name) => name.toLowerCase())
  for (let index = 0; index < folded.length; index += 1) {
    if (folded.indexOf(folded[index]) !== index) {
      fail(`policy.headers lists "${folded[index]}" more than once, ignoring case`)
    }
  }
  compiled.headers = new Set(folded)

  const queryParams = requireArrayOfStrings(document.queryParams, 'queryParams')
  for (const name of queryParams) {
    if (!QUERY_NAME.test(name)) fail(`policy.queryParams entry "${name}" is not a query parameter name`)
  }
  // Query parameter names are case-sensitive: `?Token=` and `?token=` are two
  // parameters, and folding them would redact one the author did not name.
  compiled.queryParams = new Set(queryParams)

  const detectors = requireArrayOfStrings(document.detectors, 'detectors')
  for (const name of detectors) {
    if (!isDetectorName(name)) {
      fail(`Unknown detector "${name}"; this build knows ${DETECTOR_NAMES.join(', ')}. Patterns cannot be supplied by a policy.`)
    }
  }
  compiled.detectors = new Set(detectors)

  compiled.addressPolicy = validateAddressPolicy(document.addressPolicy)

  /**
   * A name with nowhere to be looked for is a policy that cannot fire.
   *
   * `queryParams` are searched inside the fields `urlFields` names, and
   * `headers` inside the fields `headerFields` names. Declaring one without the
   * other reads as protection and provides none, so it is refused here rather
   * than left to be noticed as a warning after a log has already been exported.
   */
  if (compiled.queryParams.size > 0 && compiled.urlFields.size === 0) {
    fail('policy.queryParams names parameters to redact but policy.urlFields names no field to look in')
  }
  if (compiled.headers.size > 0 && compiled.headerFields.size === 0) {
    fail('policy.headers names headers to redact but policy.headerFields names no field to look in')
  }

  /**
   * Every declared target, as a stable id, ordered by code unit.
   *
   * The id is `<list>:<entry>` -- `headers:authorization`, `redactFields:user.email`
   * -- which is what a `policy-target-never-seen` finding points at.
   */
  const targets = []
  for (const key of [...PATH_LISTS, 'headers', 'queryParams']) {
    for (const entry of compiled[key]) targets.push(`${key}:${entry}`)
  }
  targets.sort(byCodeUnit)
  compiled.targets = Object.freeze(targets)

  if (targets.length === 0 && compiled.detectors.size === 0) {
    fail('The policy declares nothing to redact: no field, header, query parameter, address or detector. A policy that removes nothing would report a pass over an unredacted log.')
  }

  return Object.freeze(compiled)
}
