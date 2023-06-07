/**
 * The built-in identifier detectors.
 *
 * This catalog is closed on purpose. A redaction policy selects detectors by
 * name; it cannot supply a pattern of its own, and there is no `--pattern`
 * flag.
 *
 * The reason is that a regular expression cannot be bounded by a clock. The
 * engine does not yield, so a time check around the call cannot fire while the
 * call is running: two tools in this catalog ran 6.8 and 184 seconds inside a
 * declared 100 ms budget. Accepting a pattern from a configuration file would
 * put a caller-supplied backtracking bomb on the hot path of a stream that
 * reads a hundred thousand records, with no way to stop it. So patterns are
 * authored here, where they can be argued about, and two properties are kept:
 *
 * 1. **Shape.** In every pattern below, each quantified character class is
 *    disjoint from the literal that follows it, so no input can be split
 *    between the two in more than one way and the match is decided in a single
 *    left-to-right pass. None of them nests a quantifier inside a quantifier
 *    over an overlapping alphabet, which is the shape that backtracks
 *    exponentially.
 * 2. **Length.** The caller bounds the text handed to a detector by
 *    `maxValueLength` (see `src/index.mjs`). A longer value is not scanned at
 *    all: it is replaced whole, which is the fail-safe direction, and reported.
 *
 * What the catalog is *for*: it is a net under the policy, not a substitute for
 * one. The fields, headers, query parameters and addresses a policy names are
 * redacted because they were named. The detectors catch the sensitive value
 * that turns up in a field nobody named -- a token in a `user-agent`, an email
 * in a free-text `message`. A detector that does not fire proves nothing, and
 * `README.md` says so in its own words.
 */

/** Detector names, ordered by code unit. This is the whole vocabulary. */
export const DETECTOR_NAMES = Object.freeze([
  'aws-access-key-id',
  'bearer-token',
  'email-address',
  'jwt',
  'pan-digits',
  'private-key-block',
])

/**
 * A payment-account-number check digit.
 *
 * `pan-digits` fires only on a digit run that satisfies it. Without the check
 * every nanosecond timestamp in a log would be redacted; with it, roughly one
 * in ten still is, which is the fail-safe direction of a trade this tool
 * documents rather than hides.
 */
export function luhn(digits) {
  let sum = 0
  let double = false
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let value = digits.charCodeAt(index) - 48
    if (value < 0 || value > 9) return false
    if (double) {
      value *= 2
      if (value > 9) value -= 9
    }
    sum += value
    double = !double
  }
  return sum % 10 === 0
}

const DIGITS_ONLY = /[^0-9]/g

/**
 * Each entry: a global pattern and an acceptance test applied to the matched
 * text. The pattern decides where to look; the test decides whether what was
 * found is really of that kind.
 */
const DETECTORS = Object.freeze({
  // Access key ids: a documented four-letter prefix and sixteen upper-case
  // alphanumerics. `AKIAIOSFODNN7EXAMPLE` is the vendor's own published
  // placeholder and is what the fixtures use.
  'aws-access-key-id': {
    pattern: /\b(?:ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[0-9A-Z]{16}\b/g,
    accept: () => true,
  },
  // An HTTP bearer credential, wherever it appears: a whole `Authorization`
  // header, a log line that quotes one, a JSON field that copied one.
  'bearer-token': {
    pattern: /\b[Bb]earer[ \t]+[A-Za-z0-9._~+/=-]{8,}/g,
    accept: () => true,
  },
  // Anchored on `@` and expanded outwards by hand, rather than scanned for by a
  // pattern. See `findEmailSpans`: the obvious regular expression is quadratic
  // in the length of the value, which is exactly the superlinear cost a length
  // bound alone does not fix.
  'email-address': { find: findEmailSpans },
  // A compact JWS: the `eyJ` that every base64url `{"` header begins with,
  // then two more dot-separated segments.
  jwt: {
    pattern: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*/g,
    accept: () => true,
  },
  // Thirteen to nineteen digits, optionally grouped by a single space or
  // hyphen, that satisfy the check digit. The optional separator can only be
  // taken one way: skipping a separator that is present leaves the next `\d`
  // facing that separator, which fails immediately.
  'pan-digits': {
    pattern: /\b\d(?:[ -]?\d){11,18}\b/g,
    accept: (match) => {
      const digits = match.replace(DIGITS_ONLY, '')
      return digits.length >= 13 && digits.length <= 19 && luhn(digits)
    },
  },
  // The armour around a private key. The body is not matched: the header alone
  // is enough to condemn the whole value, and the caller replaces it whole.
  'private-key-block': {
    pattern: /-----BEGIN[A-Z ]{0,40}PRIVATE KEY-----/g,
    accept: () => true,
  },
})


/**
 * Email addresses, found in one left-to-right pass.
 *
 * The obvious pattern -- `local+@domain+(\.domain+)+` -- is **quadratic** in
 * the length of the value it scans. The local-part class is dense, so every
 * position in a long run of ordinary letters is a candidate start, and each one
 * scans forward to the end looking for an `@` that is not there: 4 KiB of
 * letters took half a second, and `maxValueLength` allows exactly that. A
 * length bound does not fix a superlinear scan, it only caps how bad it gets,
 * so the scan itself is linear instead.
 *
 * The trick is to anchor on the rare character. Each `@` is expanded left over
 * the local-part alphabet and right over the domain alphabet. Neither `@` nor
 * the characters that end a local part belong to the other side's alphabet, so
 * the walks around consecutive `@`s cannot overlap: every character of the
 * input is visited a bounded number of times, whatever the input looks like.
 *
 * The local-part alphabet is the practical one rather than the one RFC 5322
 * permits: `/`, `=`, `?` and `#` are legal in an address and are also the
 * punctuation of a URL, so including them would make `/users/ada@x.invalid`
 * redact the path as well as the address. An address that really uses those
 * characters is not detected, which `README.md` lists as a limit -- the fields,
 * headers and parameters a policy names are how such a value is removed.
 */
const LOCAL_PART = /[A-Za-z0-9._%+-]/
const DOMAIN_PART = /[A-Za-z0-9-]/

export function findEmailSpans(text) {
  const spans = []
  let cursor = 0
  let at = text.indexOf('@', cursor)

  while (at !== -1) {
    let start = at
    while (start > cursor && LOCAL_PART.test(text[start - 1])) start -= 1
    // A local part is never empty and never begins with a dot.
    while (start < at && text[start] === '.') start += 1

    let end = at + 1
    let labels = 0
    let dots = 0
    while (end < text.length && DOMAIN_PART.test(text[end])) {
      end += 1
      labels += 1
    }
    while (labels > 0 && end + 1 < text.length && text[end] === '.' && DOMAIN_PART.test(text[end + 1])) {
      end += 1
      dots += 1
      while (end < text.length && DOMAIN_PART.test(text[end])) end += 1
    }

    if (start < at && labels > 0 && dots > 0) {
      spans.push([start, end])
      cursor = end
    } else {
      cursor = at + 1
      end = at + 1
    }
    at = text.indexOf('@', Math.max(cursor, at + 1))
  }
  return spans
}

/** True when `name` is a detector this build knows. */
export function isDetectorName(name) {
  return typeof name === 'string' && Object.hasOwn(DETECTORS, name)
}

/**
 * The spans one detector claims, in order, without overlaps.
 *
 * `String.prototype.matchAll` requires a global pattern and iterates a *clone*
 * of it, so the shared frozen patterns carry no `lastIndex` between calls.
 * `RegExp.prototype.test` does not clone, which is why it is not used here.
 */
function spansOf(name, text) {
  const detector = DETECTORS[name]
  if (detector.find !== undefined) return detector.find(text)
  const spans = []
  for (const match of text.matchAll(detector.pattern)) {
    if (detector.accept(match[0])) spans.push([match.index, match.index + match[0].length])
  }
  return spans
}

/** The detector names that fire on `text`, ordered by code unit. */
export function detectorsMatching(text, enabled) {
  const found = []
  for (const name of DETECTOR_NAMES) {
    if (enabled.has(name) && spansOf(name, text).length > 0) found.push(name)
  }
  return found
}

/**
 * Replace everything the enabled detectors claim with `placeholder`.
 *
 * Every detector is asked for its spans, the spans are merged, and the text is
 * rebuilt once. Merging is what decides an overlap: `Bearer eyJ...` is one
 * replacement rather than a bearer token and a JWT inside it, and a value two
 * detectors both claim is replaced once rather than twice.
 *
 * Returns the rewritten text and the number of replacements, so the caller can
 * count redactions without ever seeing what was replaced.
 */
export function redactDetected(text, enabled, placeholder) {
  const spans = []
  for (const name of DETECTOR_NAMES) {
    if (enabled.has(name)) spans.push(...spansOf(name, text))
  }
  if (spans.length === 0) return { text, count: 0 }

  // Earliest start first, longest first on a tie: a total order on integers, so
  // the result does not depend on which detector was asked first.
  spans.sort((left, right) => left[0] - right[0] || right[1] - left[1])

  const parts = []
  let cursor = 0
  let count = 0
  for (const [start, end] of spans) {
    if (start < cursor) {
      // Overlapping or contained in the span already replaced.
      if (end > cursor) cursor = end
      continue
    }
    parts.push(text.slice(cursor, start), placeholder)
    cursor = end
    count += 1
  }
  parts.push(text.slice(cursor))
  return { text: parts.join(''), count }
}

/** Every detector, as a set. Used for strings this package itself emits. */
export const ALL_DETECTORS = Object.freeze(new Set(DETECTOR_NAMES))
