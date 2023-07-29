# access-log-pii-redactor

Stream an exported access log, redact the query parameters, headers, addresses
and identifiers a policy declares, and write the redacted records somewhere
else. Every record this tool cannot vouch for is quarantined: withheld from the
output, located by line number and shape, and never echoed into a message.

- **Repository:** [edilec/access-log-pii-redactor](https://github.com/edilec/access-log-pii-redactor)
- **Area:** Security & Privacy
- **License:** MIT

Zero dependencies, Node 22 or newer, Node built-ins only. No network access of
any kind. The input is opened read-only and is never modified.

## Why the malformed record is the interesting one

A redactor is judged by what escapes it, and the easiest way for something to
escape is through the error path. A line that does not parse is the one line
that never went through redaction -- and the obvious way to report it is to
print the parser's message, which quotes the offending input. That single habit
would defeat the entire tool.

So this package never reads a parser message. A malformed record is reported by
line number, byte count and a structural *shape* token from a closed vocabulary
(`object-like`, `array-like`, `number-like`, and four more). That is enough to
find it in the source file and nothing at all about what it contains.
`test/quarantine.test.mjs` takes the malformed line itself and asserts that no
substring of it, down to twelve characters, appears on stdout, on stderr, or in
the written output.

## Install

```sh
npm install --global access-log-pii-redactor
```

Or run it from a checkout with `node bin/access-log-pii-redactor.mjs`.

## Use

```sh
# Dry run: redact and check every record, write nothing.
access-log-pii-redactor --root ./exports

# Write the redacted log next to the input.
access-log-pii-redactor --root ./exports --out redacted.log

# Machine-readable report only.
access-log-pii-redactor --root ./exports --out redacted.log --json > report.json
```

The log is JSON Lines: one JSON object per line. `--root` is the directory
holding the log (`access.log`), the policy (`redaction-policy.json`) and the
destination; every name is relative to it, and anything that resolves outside it
is refused.

### The policy

```json
{
  "schemaVersion": "1",
  "urlFields": ["request.url"],
  "queryParams": ["token", "email"],
  "headerFields": ["request.headers"],
  "headers": ["authorization", "cookie", "x-api-key"],
  "addressFields": ["client.ip"],
  "addressPolicy": { "ipv4": "mask-host", "ipv4PrefixBits": 24, "ipv6": "mask-host", "ipv6PrefixBits": 48 },
  "redactFields": ["user.email"],
  "detectors": ["aws-access-key-id", "bearer-token", "email-address", "jwt", "pan-digits", "private-key-block"]
}
```

`docs/redaction-policy.md` is the full reference. An unknown key throws, a
policy that declares nothing to redact throws, and a name with nowhere to be
looked for -- `queryParams` without `urlFields` -- throws. A policy that
silently matches nothing is the most common way a redactor leaks, and it looks
exactly like a log with nothing to redact.

### What a record looks like going through

```
{"client":{"ip":"203.0.113.42"},"request":{"url":"/v1/search?q=router&token=t-90f1a2", ...
{"client":{"ip":"203.0.113.0"}, "request":{"url":"/v1/search?q=router&token=[redacted]", ...
```

Field order, structure and the parameters nobody named are preserved, so a
redacted log still diffs against its source and still parses with whatever read
the original.

## Output and exit codes

stdout carries the JSON report and nothing else, so it pipes straight into a
parser. stderr carries the human summary and diagnostics -- a populated stderr
is correct, not a warning sign.

| Exit | Meaning |
| ---: | --- |
| 0 | Every record was read, redacted and written. |
| 1 | The run completed and at least one record was quarantined. |
| 2 | Invalid configuration (**stdout is empty**), or evidence that could not be obtained (an `incomplete` report on stdout, never a `pass`). |

`docs/redaction-rules.md` carries the full rule catalog, the severity of each
rule, every limit with its default and cap, and why a quarantined record is a
completed failure while a run stopped by a limit is `incomplete`.

## Failing in one direction

Everything that can go wrong inside a record redacts *more*, never less:

- a value longer than `maxValueLength` is replaced whole rather than scanned or
  truncated;
- an address the parser cannot read is replaced whole rather than passed
  through;
- a field that is not the shape its policy target needs is replaced whole;
- a record that still matches an enabled detector *after* redaction -- an
  identifier used as a field name, most often -- is quarantined rather than
  patched, because rewriting a key would change the shape of somebody's log.

The destination is checked before anything is opened, and a destination that
would write somewhere else is refused as a **configuration error**: exit `2`,
empty stdout, nothing written. Three refusals, none of which catches the other
two:

- it is a **symbolic link**. `realpath` and `stat` both *follow* the link, and
  following it is the dangerous act, so `lstat` refuses it unresolved —
  including a link whose target does not exist yet, which would otherwise create
  a new file outside the root;
- it resolves **outside `--root`**. A lexical prefix check passes for
  `root/link/out` where `link` leaves the root, so the parent is resolved with
  `realpath` and then compared;
- it is **the same file as an input**. That check compares device and inode
  numbers rather than paths, because a hard link is a second name for one file
  and a path comparison cannot see it.

An existing regular file at the destination is still not replaced without
`--force`.

## Limits and non-goals

**This tool cannot tell you a log is free of personal data.** It removes what
the policy names and what the enabled detectors match. A `pass` means those
rules were applied to every record and every record was written; it is not a
statement about what is left.

- **A detector that does not fire proves nothing.** The catalog is six patterns
  for six shapes, each with limits listed in `docs/redaction-policy.md`: a
  secret access key has no distinctive shape, a `Basic` credential is not a
  bearer token, an email using RFC 5322's rarer local-part characters is not
  matched, and a card number written with unusual separators is not matched.
  Detectors are a net under the policy, never a substitute for one.
- **`pan-digits` over-redacts on purpose.** It fires on any 13-19 digit run that
  satisfies the Luhn check, which is roughly one nanosecond timestamp in ten.
- **Nothing is inferred about field names.** A field called `email` is not
  redacted because of its name; it is redacted because the policy named it or a
  detector matched its value.
- **Keys are structure, not values.** They are never rewritten. A record whose
  key carries an identifier is quarantined instead.
- **A key containing a literal `.` cannot be addressed** by a dotted path.
- **JSON Lines only.** Combined, common and W3C extended log formats are not
  parsed. A line that is not a JSON object is quarantined, not guessed at.
- **No `--dry-run` diff, no reversible tokenisation, no format-preserving
  encryption, no key management.** The placeholder is a constant string; nothing
  here can be undone, and nothing here derives a stable pseudonym from a value.
  If you need to correlate sessions after redaction, this is not that tool.
- **It does not act on any system.** It reads two files, writes one, and opens
  no socket. It discovers nothing, tests no credential, and contacts no service
  named in a log -- `test/no-network.test.mjs` plants a live listener in a
  record and proves nothing knocks.
- **The report is evidence about one file at one moment.** It says nothing about
  the exporter that produced the log, about what the log's upstream retained, or
  about copies of the log that already exist.

## Determinism

Two runs over the same log and policy produce byte-identical stdout and a
byte-identical output file. Every ordering is by UTF-16 code unit; neither
`localeCompare` nor `Intl.Collator` appears in `src/`, and `Date.now`,
`new Date` and `Math.random` do not either.

The time budget is the one thing that reads a clock, and it reads a millisecond
source a caller **may** inject; with none supplied it is `performance.now()`, a
monotonic counter rather than the time of day. Nothing it returns is written
into a report or an output file, so the budget can change only whether a run
stopped early -- never what it wrote before it did.

The report carries a SHA-256 of the policy that produced it and a SHA-256 of the
redacted stream, so a consumer can say which rules produced which file.

## Development

```sh
npm run check      # lint, test, run the example, check the package contents
npm test           # node --test
npm run example    # the clean example, as a dry run
```

## License

MIT. See [LICENSE](./LICENSE).
