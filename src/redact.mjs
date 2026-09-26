/**
 * Redacting one parsed record.
 *
 * The walk is the whole product, so it is written to fail in one direction. At
 * every point where this module cannot do what the policy asked -- a value too
 * long to scan, an address it cannot read, a field that is not the shape the
 * policy expects -- it replaces the value *whole* and records that it did.
 * Nothing is ever passed through on the theory that it was probably harmless,
 * and no branch ends by leaving a value untouched because something went wrong.
 *
 * A record this module refuses outright throws `RecordRefused`; the caller
 * quarantines it by line number and shape and never writes it anywhere.
 */

import { maskAddressField } from './address.mjs'
import { detectorsMatching, redactDetected } from './detectors.mjs'

/** Used on its own, because this detector condemns a whole value rather than a span. */
const PRIVATE_KEY_ONLY = Object.freeze(new Set(['private-key-block']))
import { isPlainObject } from './text.mjs'

/** Thrown for a record that cannot be walked at all. Carries a rule id, never content. */
export class RecordRefused extends Error {
  constructor(ruleId, detail) {
    super(ruleId)
    this.name = 'RecordRefused'
    this.ruleId = ruleId
    this.detail = detail
  }
}

/** JSON Pointer escaping, so a key containing `/` or `~` still locates one field. */
export function escapePointer(segment) {
  return String(segment).replaceAll('~', '~0').replaceAll('/', '~1')
}

/**
 * A note about one value, aggregated by the caller.
 *
 * Notes carry a rule id, a pointer and a reason token -- never the value they
 * are about. A warning that quotes the value it refused to handle would leak
 * exactly the values this tool exists to remove.
 */
function note(notes, ruleId, pointer, matchPath, reason) {
  notes.push({ ruleId, pointer, matchPath, reason })
}

/**
 * Redact a string that is not otherwise targeted by the policy.
 *
 * The length bound is the only thing standing between a detector and an
 * unbounded scan, so it is checked before the scan and a longer value is
 * replaced whole rather than scanned, truncated, or passed through.
 */
function redactFreeText(text, context, pointer, matchPath, notes) {
  const { policy, limits } = context
  if (text.length > limits.maxValueLength) {
    note(notes, 'value-over-limit', pointer, matchPath, `longer than maxValueLength (${limits.maxValueLength})`)
    context.redactions += 1
    return policy.placeholder
  }
  if (policy.detectors.size === 0) return text
  // A private key block condemns the whole value. The pattern matches only the
  // armour, and the key material is what follows it.
  if (policy.detectors.has('private-key-block') && detectorsMatching(text, PRIVATE_KEY_ONLY).length > 0) {
    context.redactions += 1
    return policy.placeholder
  }
  const { text: redacted, count } = redactDetected(text, policy.detectors, policy.placeholder)
  context.redactions += count
  return redacted
}

function decodeComponent(value) {
  try {
    return decodeURIComponent(value)
  } catch {
    return null
  }
}

/**
 * Redact the named parameters of a URL or request target.
 *
 * The string is split rather than parsed by `URL`: a log carries request
 * targets like `/search?q=x`, which `URL` cannot take without a base, and
 * inventing a base would make the tool's behaviour depend on a host nobody
 * logged. Splitting on the first `?` and on `&` is exactly the structure a
 * query string has.
 *
 * A parameter the policy does not name is still scanned by the detectors, in
 * both its raw and its percent-decoded form: `?email=user%40example.invalid`
 * carries an address that no pattern would see before decoding.
 */
function redactUrl(text, context, pointer, matchPath, notes) {
  const { policy, limits } = context
  if (text.length > limits.maxValueLength) {
    note(notes, 'value-over-limit', pointer, matchPath, `longer than maxValueLength (${limits.maxValueLength})`)
    context.redactions += 1
    return policy.placeholder
  }

  const questionMark = text.indexOf('?')
  if (questionMark === -1) return redactFreeText(text, context, pointer, matchPath, notes)

  const head = text.slice(0, questionMark)
  let query = text.slice(questionMark + 1)
  let tail = ''
  const hash = query.indexOf('#')
  if (hash !== -1) {
    tail = query.slice(hash)
    query = query.slice(0, hash)
  }

  const pairs = query.split('&')
  if (pairs.length > limits.maxQueryParams) {
    note(notes, 'value-over-limit', pointer, matchPath, `has ${pairs.length} query parameters, above maxQueryParams (${limits.maxQueryParams})`)
    context.redactions += 1
    return policy.placeholder
  }

  const rebuilt = pairs.map((pair) => {
    const equals = pair.indexOf('=')
    if (equals === -1) {
      return redactFreeText(pair, context, pointer, matchPath, notes)
    }
    const name = pair.slice(0, equals)
    const value = pair.slice(equals + 1)
    const decodedName = decodeComponent(name)
    if (policy.queryParams.has(name) || (decodedName !== null && policy.queryParams.has(decodedName))) {
      context.seen.add(`queryParams:${policy.queryParams.has(name) ? name : decodedName}`)
      context.redactions += 1
      return `${name}=${policy.placeholder}`
    }
    const decodedValue = decodeComponent(value)
    if (decodedValue !== null && decodedValue !== value && policy.detectors.size > 0) {
      const probe = redactDetected(decodedValue, policy.detectors, policy.placeholder)
      if (probe.count > 0) {
        context.redactions += probe.count
        return `${name}=${policy.placeholder}`
      }
    }
    return `${name}=${redactFreeText(value, context, pointer, matchPath, notes)}`
  })

  const redactedHead = redactFreeText(head, context, pointer, matchPath, notes)
  const redactedTail = tail === '' ? '' : redactFreeText(tail, context, pointer, matchPath, notes)
  return `${redactedHead}?${rebuilt.join('&')}${redactedTail}`
}

/** Replace the values of the named headers; scan the rest as free text. */
function redactHeaders(value, context, pointer, matchPath, notes, depth) {
  const { policy } = context
  if (!isPlainObject(value)) {
    note(notes, 'field-shape-unexpected', pointer, matchPath, 'headerFields names a field that is not an object of header name to value')
    context.redactions += 1
    return policy.placeholder
  }
  /**
   * Built with a null prototype on purpose.
   *
   * On an ordinary object literal, `result['__proto__'] = x` reaches the
   * inherited setter: the field vanishes from the output and the object's
   * prototype changes instead. A record is untrusted input and may carry that
   * key, so results are built on an object that has no inherited setter to
   * reach. `JSON.stringify` treats it exactly like any other object.
   */
  const result = Object.create(null)
  for (const [name, headerValue] of Object.entries(value)) {
    context.fields += 1
    if (context.fields > context.limits.maxFieldsPerRecord) {
      throw new RecordRefused('record-too-many-fields', context.limits.maxFieldsPerRecord)
    }
    const childPointer = `${pointer}/${escapePointer(name)}`
    const folded = name.toLowerCase()
    if (policy.headers.has(folded)) {
      context.seen.add(`headers:${folded}`)
      context.redactions += 1
      result[name] = policy.placeholder
      continue
    }
    result[name] = walk(headerValue, context, childPointer, `${matchPath}.${name}`, notes, depth + 1)
  }
  return result
}

function redactAddress(value, context, pointer, matchPath, notes) {
  const { policy } = context
  if (typeof value !== 'string') {
    note(notes, 'field-shape-unexpected', pointer, matchPath, 'addressFields names a field whose value is not a string')
    context.redactions += 1
    return policy.placeholder
  }
  if (value.length > context.limits.maxValueLength) {
    note(notes, 'value-over-limit', pointer, matchPath, `longer than maxValueLength (${context.limits.maxValueLength})`)
    context.redactions += 1
    return policy.placeholder
  }
  const masked = maskAddressField(value, policy.addressPolicy)
  context.redactions += 1
  if (masked === null) {
    note(notes, 'address-unrecognised', pointer, matchPath, 'not an address this build can mask')
    return policy.placeholder
  }
  return masked
}

/**
 * Walk one value.
 *
 * `matchPath` is the dotted path a policy entry is written against and carries
 * no array indices, so `items.email` covers every element of `items`.
 * `pointer` is the JSON Pointer that locates this exact value for a human, and
 * does carry them.
 */
function walk(value, context, pointer, matchPath, notes, depth) {
  if (depth > context.limits.maxDepth) throw new RecordRefused('record-too-deep', context.limits.maxDepth)
  const { policy } = context

  if (matchPath !== '') {
    if (policy.redactFields.has(matchPath)) {
      context.seen.add(`redactFields:${matchPath}`)
      context.redactions += 1
      if (value !== null && typeof value === 'object') {
        note(notes, 'field-replaced-wholly', pointer, matchPath, Array.isArray(value) ? 'an array was replaced whole' : 'an object was replaced whole')
      }
      return policy.placeholder
    }
    if (policy.urlFields.has(matchPath)) {
      context.seen.add(`urlFields:${matchPath}`)
      if (typeof value !== 'string') {
        note(notes, 'field-shape-unexpected', pointer, matchPath, 'urlFields names a field whose value is not a string')
        context.redactions += 1
        return policy.placeholder
      }
      return redactUrl(value, context, pointer, matchPath, notes)
    }
    if (policy.addressFields.has(matchPath)) {
      context.seen.add(`addressFields:${matchPath}`)
      return redactAddress(value, context, pointer, matchPath, notes)
    }
    if (policy.headerFields.has(matchPath)) {
      context.seen.add(`headerFields:${matchPath}`)
      return redactHeaders(value, context, pointer, matchPath, notes, depth)
    }
  }

  if (Array.isArray(value)) {
    return value.map((element, index) => {
      context.fields += 1
      if (context.fields > context.limits.maxFieldsPerRecord) {
        throw new RecordRefused('record-too-many-fields', context.limits.maxFieldsPerRecord)
      }
      // An element inherits its array's match path: a policy is written against
      // field names, and an index is not a field name.
      return walk(element, context, `${pointer}/${index}`, matchPath, notes, depth + 1)
    })
  }

  if (isPlainObject(value)) {
    // A null prototype, for the `__proto__` reason spelled out in `redactHeaders`.
    const result = Object.create(null)
    for (const [key, child] of Object.entries(value)) {
      context.fields += 1
      if (context.fields > context.limits.maxFieldsPerRecord) {
        throw new RecordRefused('record-too-many-fields', context.limits.maxFieldsPerRecord)
      }
      result[key] = walk(
        child,
        context,
        `${pointer}/${escapePointer(key)}`,
        matchPath === '' ? key : `${matchPath}.${key}`,
        notes,
        depth + 1,
      )
    }
    return result
  }

  if (typeof value === 'string') return redactFreeText(value, context, pointer, matchPath, notes)

  // A number is scanned in its printed form. A payment account number exported
  // as a JSON number is still a payment account number, and `JSON.stringify`
  // would put every digit of it in the output.
  if (typeof value === 'number' && policy.detectors.size > 0) {
    const printed = String(value)
    const { count } = redactDetected(printed, policy.detectors, policy.placeholder)
    if (count > 0) {
      context.redactions += count
      return policy.placeholder
    }
  }

  return value
}

/**
 * Redact one record.
 *
 * @returns {{value: unknown, redactions: number, notes: Array, fields: number}}
 * @throws {RecordRefused} when the record cannot be walked within its bounds.
 */
export function redactRecord(record, policy, limits, seen) {
  const notes = []
  /**
   * Targets are marked in a set belonging to this record, and merged into the
   * caller's only once the walk has finished.
   *
   * `seen` is the run's evidence that a policy target exists in the log, and a
   * refused record is one the run never finished looking at. Marking straight
   * into the caller's set left whatever the doomed walk reached before it threw
   * -- so the same record answered "which targets does this log carry?"
   * differently depending on which limit stopped it and how far it had got:
   * `client.ip` counted as seen under maxFieldsPerRecord, because the walk
   * reached it first, and did not under maxDepth, because it did not. Evidence
   * from a walk that was abandoned is not evidence.
   */
  const marked = new Set()
  const context = { policy, limits, seen: marked, redactions: 0, fields: 0 }
  const value = walk(record, context, '', '', notes, 0)
  for (const target of marked) seen.add(target)
  return { value, redactions: context.redactions, notes, fields: context.fields }
}
