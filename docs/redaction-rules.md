# Rule catalog, limits and status

Every finding this tool emits carries a `ruleId` from the catalog below, and
every `ruleId` takes its severity from one frozen table in `src/index.mjs`. A
rule id is part of the public surface: renaming one is a breaking change and is
recorded in `CHANGELOG.md`.

The table here and the table in the source are two declarations of one fact, and
`test/severity-table.test.mjs` checks them against each other in both
directions. That is worth having and it is not what pins severity: three
declarations can be edited together. What pins severity is
`test/severity-exit.test.mjs` and `test/severity-word.test.mjs`, which drive
real logs through the real binary and assert the exit code, the error count and
the printed severity word as literal values.

## Status, and what each outcome means

| Status | Exit | What happened |
| --- | ---: | --- |
| `pass` | 0 | Every record was read, redacted, checked again against the enabled detectors, and written. |
| `fail` | 1 | The run completed and at least one record was quarantined: withheld from the output, located by line number, its content never echoed. |
| `incomplete` | 2 | The run could not obtain the evidence it was asked for: the log could not be read, or a run-level limit stopped the stream and left an unread remainder. |

A configuration error -- an unknown flag, an invalid or unreadable policy, a
destination that is also an input -- exits 2 with an **empty stdout**. There is
no report, because a run whose rules could not be read never had a subject.

### Why a quarantined record is `fail` and not `incomplete`

Both readings are defensible and this tool commits to one. A quarantined record
has a *definite, reported outcome*: it was withheld, it is named by line number
and shape, and nothing was written about it or from it. The run's claim --
"everything in the output was redacted by this policy" -- is fully supported. A
run stopped by a limit is different: part of the file was never read, so there
is a remainder about which nothing at all is known, and that is what
`incomplete` exists to say.

## Rules

| Rule | Severity | What it means |
| --- | --- | --- |
| `address-unrecognised` | warning | A field named by `addressFields` held something this build cannot parse as an address. The value was replaced whole. |
| `field-replaced-wholly` | info | A field named by `redactFields` held an object or an array, so the whole subtree was replaced. |
| `field-shape-unexpected` | warning | A field named by `urlFields`, `addressFields` or `headerFields` was not the shape that target needs. The value was replaced whole. |
| `input-too-large` | error | The log is larger than `maxInputBytes`. It was not read. |
| `input-unreadable` | error | The log could not be resolved, inspected or read, or is not a regular file. |
| `no-records-processed` | error | The log was read to the end and held no records. A `pass` here would be green on no evidence. |
| `output-unwritable` | error | The destination could not be opened. No record was read. |
| `path-escapes-root` | error | The log resolves outside `--root`, so it was refused unread. |
| `policy-target-never-seen` | warning | The policy names a field, header or parameter that no record carried, so nothing was redacted on its account. Emitted only by a run that read the whole log and quarantined nothing: a record it did not look inside is not evidence that the target is absent. |
| `record-not-json` | error | A line did not parse. It was quarantined by line number, byte count and shape; no parser message is read and no content is reported. |
| `record-not-object` | error | A line parsed as something other than an object, so no field could be matched against the policy. |
| `record-not-utf8` | error | A line is not valid UTF-8. It was quarantined undecoded. |
| `record-residual-identifier` | error | After redaction, the serialized record still matched an enabled detector -- most often an identifier used as a field name. It was quarantined rather than patched. |
| `record-too-deep` | error | A record nests deeper than `maxDepth`. It was quarantined rather than partly redacted. |
| `record-too-large` | error | A line is longer than `maxLineBytes`. It was quarantined unparsed; no part of it was buffered to be described. |
| `record-too-many-fields` | error | A record holds more fields than `maxFieldsPerRecord`. It was quarantined rather than partly redacted. |
| `time-budget-exceeded` | error | The run passed `maxRuntimeMs` and stopped. The rest of the file was neither read nor redacted. |
| `too-many-findings` | error | The run produced more findings than `maxFindings`. The report is partial and says how many were dropped. |
| `too-many-records` | error | The log holds more records than `maxRecords`. The run stopped there. |
| `value-over-limit` | warning | A value was longer than `maxValueLength`, or a query string held more parameters than `maxQueryParams`. It was replaced whole rather than scanned or truncated. |

## Limits

Every limit is enforced, and reaching one is never a silent truncation. A
caller may lower a limit but never raise it past its cap.

| Limit | Flag | Default | Cap | Effect when reached |
| --- | --- | ---: | ---: | --- |
| `maxRecords` | `--max-records` | 100000 | 10000000 | The stream stops; `too-many-records`; `incomplete`. |
| `maxInputBytes` | `--max-input-bytes` | 67108864 | 1073741824 | The log is refused unread; `input-too-large`; `incomplete`. |
| `maxLineBytes` | `--max-line-bytes` | 65536 | 1048576 | That record is quarantined; `record-too-large`; the run continues. |
| `maxValueLength` | `--max-value-length` | 4096 | 65536 | That value is replaced whole; `value-over-limit`. |
| `maxQueryParams` | `--max-query-params` | 64 | 1024 | That query string is replaced whole; `value-over-limit`. |
| `maxDepth` | `--max-depth` | 12 | 64 | That record is quarantined; `record-too-deep`. |
| `maxFieldsPerRecord` | `--max-fields-per-record` | 256 | 4096 | That record is quarantined; `record-too-many-fields`. |
| `maxRuntimeMs` | `--max-runtime-ms` | 30000 | 600000 | The stream stops; `time-budget-exceeded`; `incomplete`. |
| `maxFindings` | `--max-findings` | 1000 | 20000 | The report is truncated deliberately; `too-many-findings`; `incomplete`. |

Two bounds are not caller-controlled. The policy document has its own 1 MiB
bound, deliberately separate from `maxInputBytes` so that saying "this log
should be small" cannot start refusing the configuration that decides what to
redact. And an address field accepts at most 16 comma-separated addresses, which
is `X-Forwarded-For` with room to spare.

`maxInputBytes` is checked against the file's size before a byte is read, so an
oversized log is refused rather than half processed. A log that is being
appended to while it is read is therefore bounded by `maxRuntimeMs` instead, not
by the byte limit.

## Sort order

Findings are ordered by `location.file`, then `location.line` **as a number**,
then `location.pointer`, then `ruleId`, then `message`. Every text comparison is
by UTF-16 code unit. Neither `localeCompare` nor `Intl.Collator` appears
anywhere in `src/`, and `test/ordering.test.mjs` pins the order the tool emits
rather than scanning the source for a spelling.

`location.line` is a documented extension to the report contract's `location`
object: a JSON Lines log is addressed by line, and the pointer inside a record
is relative to that line.

## The time budget

The budget is checked after each record, against a millisecond source that is
injected rather than read from a wall clock. Nothing in this package calls
`Date.now`, `new Date` or `Math.random`.

A regular expression cannot be bounded by a clock -- the engine does not yield,
so a check around the call cannot fire while the call is running. That is why a
policy cannot supply a pattern: the detector catalog is closed, its patterns are
authored in `src/detectors.mjs` where their shape can be argued about, and the
text handed to one is bounded by `maxValueLength` before the scan starts.

## How these guards were measured

Both guards were checked by breaking them and watching the suite, because a
guard nobody has broken is a guard nobody has tested.

**Severity.** Each of the 15 error rules was demoted to `warning` in a
*coordinated* edit -- the frozen table in `src/index.mjs` and the catalog above
together, which is what makes `test/severity-table.test.mjs` stay green -- and
the full suite was run against it. All 15 demotions were caught: 0 survived.
Seven of them are caught by the exit code itself flipping from 1 to 0; the other
eight already exit 2 because they make the run `incomplete`, and are caught by
the error count and the printed severity word.

**Ordering.** Each of the 11 call sites that order anything was swapped, one at
a time, to `new Intl.Collator('en').compare`, and the suite (less the source
scan in `test/no-network.test.mjs`, which sees the substitution itself) was run
against it. Seven sites failed at least one case. The four that did not are the
ones whose values cannot move under collation, and
`test/ordering-equivalence.test.mjs` proves each rather than leaving it as a
gap:

| Site | What it orders | Why a collator cannot change it |
| --- | --- | --- |
| the known-limit list in an error message | this package's 9 limit names | every ordered pair enumerated |
| `compareFindings` rule id | the 20 rule ids, over `[a-z0-9-]` | every ordered pair enumerated |
| `report.input.detectors` | the 6 detector names, over `[a-z-]` | every ordered pair enumerated |
| `compareFindings` message | nothing | no two findings share file, line, pointer and rule id, so the comparison is never reached |
