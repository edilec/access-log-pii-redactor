# Changelog

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Rule ids are
part of the public surface: renaming one is a breaking change and is recorded
here.

## [0.1.0] - 2026-10-14

### Added

- First implementation of `access-log-pii-redactor`: streams a JSON Lines access
  log, redacts the query parameters, headers, addresses and identifiers a policy
  declares, and writes the redacted records to a separate destination. Omitting
  `--out` makes the run a dry run that checks every record and writes nothing.
- Quarantine as a first-class outcome. A record that does not decode, does not
  parse, is not an object, exceeds a per-record bound, or still matches a
  detector after redaction is withheld from the output and reported by line
  number, byte count and a structural shape token from a closed vocabulary. No
  parser message is ever read, because `JSON.parse` quotes the input it choked
  on.
- A closed detector catalog -- `aws-access-key-id`, `bearer-token`,
  `email-address`, `jwt`, `pan-digits` (Luhn-gated) and `private-key-block` --
  selected by name. A policy cannot supply a pattern: a regular expression
  cannot be bounded by a clock, so the patterns are authored in the package and
  the text handed to one is bounded by `maxValueLength` first.
- Address masking by declared policy: an IPv4 host part removed, an IPv6 prefix
  kept, both to a configurable bit width, with one canonical spelling per
  result. Anything the parser cannot read is replaced whole and reported.
- A 20-rule catalog with one frozen `ruleId -> severity` table, documented in
  `docs/redaction-rules.md` and pinned behaviourally by exit code, error count
  and printed severity word.
- Enforced limits on records, input bytes, line bytes, value length, query
  parameters, depth, fields per record, runtime and findings, each reported by
  name when reached. A per-record bound quarantines that record; a run-level
  bound stops the stream and makes the run `incomplete`.
- `policy-target-never-seen`: a field, header or parameter the policy names that
  no record carried. A policy that matches nothing looks exactly like a log with
  nothing to redact, so the run says which is which -- and withholds the claim
  entirely when it did not read the whole log, or when it quarantined a record
  and so never looked inside one of the records the claim would be about.
- A CLI with `--help`, `--version`, `--json`, explicit input and output paths
  and the three documented exit codes; the JSON report on stdout alone.
- A SHA-256 of the policy and of the redacted stream in every report, so a
  consumer can say which rules produced which file.
- Examples for a clean and a deliberately broken log, both asserted by the test
  suite.

### Fixed

- **Data loss.** `--out` accepted a symbolic link at the destination. `stat`
  follows a link, so a link pointing at a file in another tree looked like an
  ordinary existing file that `--force` was allowed to replace, and the redacted
  log was written through it. Reproduced before the fix: a file outside the root
  holding `PRECIOUS-REDACTOR` was replaced by the redacted log and the run
  exited `0` with an empty stderr; with the link pointing at a path that did not
  exist yet, the run created that file outside the root instead. Both now exit
  `2` with an empty stdout and leave the tree outside the root untouched. This
  tool had already closed the other two holes -- it resolved the parent against
  the root, and it compared device and inode against its inputs -- which is
  exactly the shape of every tool in this catalog that lost a file.
  `test/destination-guard.test.mjs` drives the real binary through one case per
  hole plus five destinations that must still be **written**, because a guard
  that refuses everything passes every data-loss case while making the tool
  useless. Each of the three checks was removed in turn and the failures
  watched.
- A destination that is a directory is a configuration error now rather than an
  `output-unwritable` finding, so it has an empty stdout like every other bad
  usage. `output-unwritable` is what remains for a destination that passed every
  check and could not be opened anyway.

### Security

- Every string this package prints goes through the whole detector catalog, not
  the subset a policy enabled -- report messages, pointers, file names, and the
  diagnostic that refuses a policy. A policy entry used to be quoted back to
  stderr verbatim, so a credential pasted into `redactFields` was echoed by the
  very error that rejected it; flattening control characters and bounding the
  length, which is all that path did before, touches shape and never content.
- No network access of any kind: no socket is opened and no service named in a
  log is contacted. Proved by a module-resolution guard that refuses every
  network builtin, and by a live loopback listener planted in a record that
  records that nothing knocked.
- The input is opened read-only. The destination is checked before anything is
  opened, for all three ways a named path is not the file it names: a symbolic
  link at the destination, refused unresolved by `lstat` because `realpath` and
  `stat` both follow it and following it is the dangerous act; a parent that
  leaves the declared root, caught by resolving the parent rather than comparing
  strings; and a hard link to an input, caught on device and inode because a
  hard link is a second name for one file and a path comparison cannot see it.
  A refused destination is a configuration error: exit 2, empty stdout, nothing
  written. An existing regular file is still not replaced without `--force`.
- Path confinement resolves the real path of both the root and each input, so a
  symlink planted inside the root is refused while a legitimate file under a
  symlinked root is not.
- Strict UTF-8 decoding of every byte read, per record, so one undecodable line
  is quarantined rather than condemning the file.
- Control (C0), DEL, C1, line and paragraph separator and bidi characters are
  stripped from every string that reaches the report -- pointers built from
  record keys included -- and escaped rather than written raw into the redacted
  output.
- Every string this package emits is also passed through the whole detector
  catalog, so an identifier used as a field name cannot leak through the
  report's own location field.
- No credential appears in any fixture: the canaries are the vendor's published
  example access key, the standard test card number, and domains reserved by
  RFC 2606.

GitHub source release v0.1.0 — 2026-10-14.
