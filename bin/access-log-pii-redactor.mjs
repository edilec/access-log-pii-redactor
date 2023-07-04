#!/usr/bin/env node

import process from 'node:process'

import {
  DEFAULT_LOG_NAME,
  DEFAULT_POLICY_NAME,
  excerpt,
  exitCodeFor,
  formatReport,
  redactAccessLog,
  serializeReport,
} from '../src/index.mjs'

const VERSION = '0.1.0'

const HELP = `access-log-pii-redactor

Stream an exported access log, redact the query parameters, headers, addresses
and identifiers a policy declares, and write the redacted records somewhere
else. The input is never modified. A record that cannot be parsed, cannot be
walked within its bounds, or still matches a detector after redaction is
quarantined: it is located by line number and described by shape, its content is
never echoed into a message, and it is not written to the output.

Usage:
  access-log-pii-redactor --root DIR [--log NAME] [--policy NAME]
                          [--out NAME] [--force] [--json]
                          [--max-records N] [--max-input-bytes N]
                          [--max-line-bytes N] [--max-value-length N]
                          [--max-query-params N] [--max-depth N]
                          [--max-fields-per-record N] [--max-runtime-ms N]
                          [--max-findings N]

Options:
  --root DIR                 Directory holding the log, the policy and the
                             output (required)
  --log NAME                 Access log, relative to --root, one JSON record per
                             line (default ${DEFAULT_LOG_NAME})
  --policy NAME              Redaction policy, relative to --root
                             (default ${DEFAULT_POLICY_NAME})
  --out NAME                 Destination for the redacted log, relative to
                             --root. Omitted, the run is a dry run: every record
                             is redacted and checked and nothing is written.
  --force                    Replace an existing --out file
  --json                     Suppress the human summary on stderr
  --max-records N            Maximum records read (default 100000)
  --max-input-bytes N        Maximum bytes read (default 67108864)
  --max-line-bytes N         Maximum bytes in one record (default 65536)
  --max-value-length N       Maximum characters in a scanned value (default 4096)
  --max-query-params N       Maximum parameters in one query string (default 64)
  --max-depth N              Maximum nesting walked in a record (default 12)
  --max-fields-per-record N  Maximum fields walked in a record (default 256)
  --max-runtime-ms N         Time budget for the run (default 30000)
  --max-findings N           Maximum findings in one report (default 1000)
  -h, --help                 Show this help
  -v, --version              Show the version

Every option that carries a value may be given only once: a repeated flag is a
configuration error, not a silent last-wins.

Output:
  stdout  the JSON report only, so it can be piped straight into a parser
  stderr  the human summary and diagnostics

What a pass means:
  Every record in the log was read, redacted by the policy, checked once more
  against the enabled detectors, and written. It does not mean the log is free
  of personal data: a detector that does not fire proves nothing, and a field
  the policy does not name is not redacted. The report names every policy target
  that no record carried, because a policy that matches nothing looks exactly
  like a log with nothing to redact -- and withholds that entirely on a run that
  stopped early or quarantined a record, because neither one looked at every
  record it would be a claim about.

Exit codes:
  0  every record was redacted and written
  1  the run completed and at least one record was quarantined
  2  invalid configuration, including an unreadable or invalid policy (no report
     on stdout), or evidence that could not be obtained (an "incomplete" report
     on stdout, never a "pass")
`

const LIMIT_FLAGS = new Map([
  ['--max-depth', 'maxDepth'],
  ['--max-fields-per-record', 'maxFieldsPerRecord'],
  ['--max-findings', 'maxFindings'],
  ['--max-input-bytes', 'maxInputBytes'],
  ['--max-line-bytes', 'maxLineBytes'],
  ['--max-query-params', 'maxQueryParams'],
  ['--max-records', 'maxRecords'],
  ['--max-runtime-ms', 'maxRuntimeMs'],
  ['--max-value-length', 'maxValueLength'],
])

const VALUE_FLAGS = new Map([
  ['--log', 'log'],
  ['--out', 'out'],
  ['--policy', 'policy'],
  ['--root', 'root'],
])

function parseArguments(argv) {
  if (argv.includes('-h') || argv.includes('--help')) return { help: true }
  if (argv.includes('-v') || argv.includes('--version')) return { version: true }

  const options = { root: null, log: null, policy: null, out: null, force: false, json: false, limits: {} }
  const given = new Set()

  /**
   * A flag that carries a value is accepted once.
   *
   * Letting it repeat discards the earlier value with no diagnostic, so
   * `--out a.log --out b.log` writes a file nobody named and
   * `--max-records 5 --max-records 100000` enforces a bound nobody asked for.
   * That is the same defect as an ignored typo, which this tool also refuses.
   */
  const once = (name) => {
    if (given.has(name)) throw new Error(`${name} was given more than once`)
    given.add(name)
  }

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]
    const takeValue = (name) => {
      const value = argv[index + 1]
      if (value === undefined || value.startsWith('-')) throw new Error(`${name} requires a value`)
      index += 1
      return value
    }

    if (argument === '--json') options.json = true
    else if (argument === '--force') options.force = true
    else if (VALUE_FLAGS.has(argument)) {
      once(argument)
      options[VALUE_FLAGS.get(argument)] = takeValue(argument)
    } else if (LIMIT_FLAGS.has(argument)) {
      once(argument)
      const raw = takeValue(argument)
      if (!/^\d+$/.test(raw) || Number(raw) < 1) throw new Error(`${argument} requires a positive integer`)
      options.limits[LIMIT_FLAGS.get(argument)] = Number(raw)
    // argv is the one untrusted string that reaches a stream without passing
    // through a finding, so it is flattened exactly as a finding would be.
    } else throw new Error(`Unknown option "${excerpt(argument, 60)}"`)
  }

  if (options.root === null) throw new Error('--root is required')
  if (options.force && options.out === null) throw new Error('--force only means something with --out')
  return options
}

async function main(argv) {
  let options
  try {
    options = parseArguments(argv)
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${HELP}`)
    return 2
  }
  if (options.help) {
    process.stdout.write(HELP)
    return 0
  }
  if (options.version) {
    process.stdout.write(`${VERSION}\n`)
    return 0
  }

  let report
  try {
    report = await redactAccessLog({
      root: options.root,
      limits: options.limits,
      force: options.force,
      ...(options.log === null ? {} : { log: options.log }),
      ...(options.policy === null ? {} : { policy: options.policy }),
      ...(options.out === null ? {} : { out: options.out }),
    })
  } catch (error) {
    // A configuration error never had a subject, so stdout stays empty and a
    // consumer that pipes stdout gets nothing rather than a fabricated report.
    process.stderr.write(`${excerpt(error.message, 400)}\n`)
    return 2
  }

  process.stdout.write(`${serializeReport(report)}\n`)
  if (!options.json) process.stderr.write(formatReport(report))
  if (report.status === 'incomplete') {
    process.stderr.write(
      `incomplete: ${report.summary.records} record(s) were read from ${report.input.file}; this run is not a pass, and any output it wrote is partial.\n`,
    )
  }
  return exitCodeFor(report)
}

process.exitCode = await main(process.argv.slice(2))
