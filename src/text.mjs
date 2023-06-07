/**
 * Decoding, sanitising and ordering.
 *
 * Every value this module handles arrived in a file this tool did not write, so
 * every value it returns is data on its way to a report or to a redacted output
 * line -- never something that may shape a line of either.
 *
 * Nothing here touches the filesystem, the network, a locale or a clock.
 */

/**
 * Order by UTF-16 code unit.
 *
 * Locale-aware comparison -- the string method and the collator class alike --
 * reads ICU data that differs between Node builds, and it weighs punctuation
 * differently from its code point: under English collation `a_b` sorts before
 * `a-b`, and `Z` sorts after `a`. Log field names, header names and file names
 * all carry upper case, `-` and `_`, so a collated report would list findings
 * in a different order on a different machine, and two runs over the same log
 * would not be byte-identical.
 *
 * Neither spelling of the locale-aware comparison appears anywhere in this
 * package. `test/ordering.test.mjs` pins what the tool *emits* rather than what
 * its source says, because a scan of the source cannot tell one comparator from
 * the other.
 */
export function byCodeUnit(left, right) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

/**
 * The characters no untrusted value may carry into output, in four classes.
 *
 * Built from code points rather than written literally: a literal U+2028 or
 * U+2029 inside a module is a line terminator to the JavaScript parser, and the
 * rest are invisible in an editor. Spelling each one out keeps this file plain
 * ASCII and keeps the list reviewable.
 *
 * - **C0** (U+0000-U+001F) and **DEL** (U+007F). A newline forges a line in the
 *   human report -- and in a JSON Lines output file it forges a whole record.
 *   ESC opens a terminal escape sequence; NUL truncates a value in anything
 *   that receives it through C.
 * - **C1** (U+0080-U+009F). Easy to forget once C0 is handled, and two of them
 *   need no help: U+0085 NEL is a line break to a great many consumers, and
 *   U+009B is the 8-bit CSI, a terminal control introducer that needs no ESC in
 *   front of it.
 * - **Line and paragraph separators** (U+2028, U+2029).
 * - **Bidi and isolate controls** (U+200E, U+200F, U+202A-U+202E,
 *   U+2066-U+2069). U+202E RIGHT-TO-LEFT OVERRIDE reverses everything printed
 *   after it, so a header named `x-api-key` can be displayed as something else
 *   while the tool redacts the real one. Ordinary right-to-left text -- Arabic,
 *   Hebrew -- needs none of these: the letters carry their own direction, so
 *   refusing the overrides refuses nothing legitimate.
 */
const DEL_AND_C1 = `${String.fromCharCode(0x7f)}-${String.fromCharCode(0x9f)}`
const SEPARATORS = `${String.fromCharCode(0x2028)}${String.fromCharCode(0x2029)}`
const BIDI =
  `${String.fromCharCode(0x200e)}${String.fromCharCode(0x200f)}` +
  `${String.fromCharCode(0x202a)}-${String.fromCharCode(0x202e)}` +
  `${String.fromCharCode(0x2066)}-${String.fromCharCode(0x2069)}`

/**
 * Stripped from every untrusted string on its way into a finding -- messages,
 * file names, pointers, suggestions and evidence alike, not only an excerpt
 * field. Tab, newline and carriage return are left out of this class
 * deliberately: `excerpt` collapses them into a single space in the very next
 * step, which is the same result by a shorter route.
 */
const CONTROL = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(8)}` +
  `${String.fromCharCode(11)}${String.fromCharCode(12)}` +
  `${String.fromCharCode(14)}-${String.fromCharCode(31)}` +
  `${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
  'g',
)

/** The same four classes plus the three ASCII whitespace controls, for detection. */
const FORBIDDEN = new RegExp(
  `[${String.fromCharCode(0)}-${String.fromCharCode(31)}` +
  `${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
)

/**
 * The same set again, as a global matcher used to escape -- rather than strip
 * -- the characters that reach the redacted *output* file.
 *
 * Output is JSON, and `JSON.stringify` already escapes C0 and DEL. It does not
 * escape C1, U+2028, U+2029 or the bidi controls, all of which then sit in the
 * output file as raw bytes. They are escaped to `\uXXXX` rather than removed
 * because the output is the user's log: this tool removes what the policy says
 * to remove and nothing else, so a character that is merely awkward is made
 * safe to print without changing what the record says.
 */
const OUTPUT_UNSAFE = new RegExp(
  `[${DEL_AND_C1}${SEPARATORS}${BIDI}]`,
  'g',
)

/**
 * Detects any of the four classes anywhere in a string. Exported so tests can
 * walk an entire report and assert that nothing survived anywhere, rather than
 * checking the one field a developer remembered to sanitise.
 */
export function hasForbiddenCharacter(value) {
  return FORBIDDEN.test(String(value))
}

export const EXCERPT_LIMIT = 200

/**
 * A bounded, single-line, control-free rendering of an untrusted string.
 *
 * Every message, file name, pointer and suggestion that reaches a finding goes
 * through here. A tool in this catalog sanitised its evidence carefully and
 * left its identifiers raw, so a record id holding a newline printed two lines
 * into the human report and invented a finding that was never emitted.
 */
export function excerpt(value, limit = EXCERPT_LIMIT) {
  const flattened = String(value).replace(CONTROL, ' ').replace(/\s+/g, ' ').trim()
  if (flattened.length <= limit) return flattened
  return `${flattened.slice(0, limit)}...`
}

/**
 * Escape the characters `JSON.stringify` leaves raw and a line-oriented
 * consumer should not meet. Applied to the serialized record, so it reaches
 * string contents and object keys alike.
 */
export function escapeOutputUnsafe(line) {
  return line.replace(OUTPUT_UNSAFE, (character) =>
    `\\u${character.codePointAt(0).toString(16).padStart(4, '0')}`)
}

/**
 * Decode bytes as UTF-8, strictly.
 *
 * `fatal: true` is the whole point. Decoding leniently and then hunting for
 * U+FFFD cannot tell undecodable bytes from a record that legitimately contains
 * a replacement character, and that confusion has already let an unread input
 * report a pass in this catalog. The decoder decides; the decoded text never
 * gets a vote. Every byte this tool reads goes through here -- the policy
 * document included, because configuration is exactly where a sibling tool
 * hardened its data path and forgot.
 */
export function decodeUtf8(bytes) {
  try {
    return { ok: true, text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes) }
  } catch {
    return { ok: false, reason: 'not-utf8' }
  }
}

/** True for a plain object -- not an array, not null, not a class instance dressed up as one. */
export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

/**
 * Say what a value was, without reproducing any of it.
 *
 * Used for a record that parsed but is not an object. The report goes to
 * stdout, a stream that is piped, logged and pasted somewhere more public than
 * an access log ever was; echoing a rejected value there hands its content a
 * wider audience than it had. The line number on the finding says where it is,
 * which is all a reader needs; the value stays in the file it came from.
 */
export function describeJsonType(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (typeof value === 'object') return 'object'
  return typeof value
}

/**
 * The structural class of a line that did not parse, derived from its first
 * non-whitespace character and never containing it.
 *
 * This is the quarantine report's "shape". It is a token from a closed
 * vocabulary, chosen so that a malformed record can be located and classified
 * without one byte of it reaching the report. A parse error that prints the
 * offending line defeats this entire tool, and `JSON.parse` messages quote the
 * input -- which is why no parser message is ever recorded anywhere in this
 * package.
 */
export function shapeOfLine(text) {
  const trimmed = text.replace(/^[\s]+/, '')
  if (trimmed.length === 0) return 'empty'
  const first = trimmed[0]
  if (first === '{') return 'object-like'
  if (first === '[') return 'array-like'
  if (first === '"') return 'string-like'
  if (first === '-' || (first >= '0' && first <= '9')) return 'number-like'
  if (first === 't' || first === 'f' || first === 'n') return 'literal-like'
  return 'other'
}

/** The closed vocabulary `shapeOfLine` draws from, exported so tests can pin it. */
export const LINE_SHAPES = Object.freeze([
  'array-like', 'empty', 'literal-like', 'number-like', 'object-like', 'other', 'string-like',
])
