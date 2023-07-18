# The redaction policy

The policy is a JSON document that says what to remove and from where. It is
*configuration*, not evidence: every problem in it throws, the CLI exits 2 with
an empty stdout, and no report is produced. A run whose rules could not be read
never had a subject to report about.

The diagnostic quotes the entry it refused, because a typo is only fixable if
you can see it -- but the entry is a string from a file this tool did not write,
so it passes through the whole detector catalog first, exactly as every report
string does. A credential pasted into a policy list comes back as `[redacted]`;
`queryParam` for `queryParams` comes back as `queryParam`.

```json
{
  "schemaVersion": "1",
  "description": "Edge access log export",
  "urlFields": ["request.url"],
  "queryParams": ["token", "email"],
  "headerFields": ["request.headers"],
  "headers": ["authorization", "cookie", "x-api-key"],
  "addressFields": ["client.ip"],
  "addressPolicy": { "ipv4": "mask-host", "ipv4PrefixBits": 24, "ipv6": "mask-host", "ipv6PrefixBits": 48 },
  "redactFields": ["user.email"],
  "detectors": ["aws-access-key-id", "bearer-token", "email-address", "jwt", "pan-digits", "private-key-block"],
  "placeholder": "[redacted]"
}
```

`schemaVersion` must be the string `"1"`. Every other key is optional, and an
**unknown key throws** -- `queryParam` instead of `queryParams` would otherwise
be a policy that silently redacts nothing while every test stays green.

A policy that names no field, header, parameter, address or detector also
throws. A policy that removes nothing would report `pass` over an unredacted
log, and that is the vacuous pass this catalog has been bitten by before.

## Field paths

`redactFields`, `urlFields`, `addressFields` and `headerFields` hold dotted
paths: `user.email` reaches the `email` key of the `user` object. Each segment
is 1-64 characters over `[A-Za-z0-9_-]`, and a path holds at most 8 segments.

- **Array indices are never written.** A path matches inside every element of an
  array it meets, so `items.email` covers `items[0].email` and every sibling.
  The JSON Pointer in a finding does carry the index, because that locates one
  value for a human.
- **A key containing a literal `.` cannot be addressed.** This is a limit rather
  than a bug worked around with an escape nobody would get right: if your
  exporter writes keys like `request.url` as a single flat key, rename it there,
  or name its parent and accept the whole subtree going.

## What each list does

| Key | Applies to | Effect |
| --- | --- | --- |
| `redactFields` | any value at that path | Replaced with the placeholder. An object or an array goes whole, and the run reports `field-replaced-wholly`. |
| `urlFields` | a string at that path | The query parameters named by `queryParams` are replaced; the rest of the target keeps its shape, and every remaining part is still scanned by the detectors. |
| `queryParams` | parameter names inside `urlFields` | Case-**sensitive**: `?Token=` and `?token=` are two parameters, and folding them would redact one the author did not name. |
| `headerFields` | an object at that path | Its keys are header names. |
| `headers` | header names inside `headerFields` | Case-**insensitive**, because header names fold on the wire. |
| `addressFields` | a string at that path | Masked by `addressPolicy`. A comma-separated list, as in `X-Forwarded-For`, is masked element by element. |
| `detectors` | every remaining string, and every number | The built-in catalog, selected by name. |

`queryParams` without `urlFields`, or `headers` without `headerFields`, throws:
a name with nowhere to be looked for reads as protection and provides none.

## Addresses

`ipv4` and `ipv6` are each `mask-host` or `drop`. `mask-host` keeps
`ipv4PrefixBits` (0-32, default 24) or `ipv6PrefixBits` (0-128, default 48) and
zeroes everything below; `drop` replaces the address with the placeholder.

Masking is arithmetic, and the result has one canonical spelling: lower case, no
leading zeros, and the longest run of zero groups written `::`. So
`2001:0DB8:0001:0002::9` and `2001:db8:1:2::9` mask to the same string and can be
grouped by whatever reads the redacted log.

Anything the parser does not recognise is replaced whole and reported as
`address-unrecognised`: a leading zero (`010.1.1.1` is ambiguous), a zone id
(`fe80::1%eth0`), a hostname, or a list with one element among them that cannot
be read. The failure direction of a redactor is always *more* redaction.

## Detectors

The catalog is closed. A policy selects detectors by name and cannot supply a
pattern, because a regular expression cannot be bounded by a clock: the engine
does not yield, so a caller-supplied backtracking pattern on the hot path of a
hundred-thousand-record stream could not be stopped. See
`docs/redaction-rules.md` and the comment at the top of `src/detectors.mjs`.

| Detector | Fires on | Known limits |
| --- | --- | --- |
| `aws-access-key-id` | A documented four-letter prefix (`AKIA`, `ASIA`, `AROA` and the rest) followed by 16 upper-case alphanumerics. | Secret access keys have no distinctive shape and are not detected. |
| `bearer-token` | `Bearer ` followed by at least 8 token characters. | Another scheme's credential (`Basic`, `Digest`) is not detected. |
| `email-address` | A practical local part, `@`, then dot-separated labels. | The local-part alphabet is `[A-Za-z0-9._%+-]`; RFC 5322 permits `/`, `=`, `?` and more, and including them would make `/users/ada@x.invalid` redact the URL path as well. An address using those rarer characters is not detected. |
| `jwt` | `eyJ` followed by two more dot-separated base64url segments. | A JWS whose header does not begin `{"` is not detected. |
| `pan-digits` | 13-19 digits, optionally grouped by one space or hyphen, that satisfy the Luhn check digit. | Any other Luhn-valid number of that length is redacted too -- roughly one nanosecond timestamp in ten. A card written with other separators is not detected. |
| `private-key-block` | A `-----BEGIN ... PRIVATE KEY-----` header. The whole value goes, not just the armour. | A key body with no header is not detected. |

A detector that does not fire proves nothing. The detectors are a net under the
policy, not a substitute for one: the value in a field nobody named is what they
are for, and the fields you do name are how you actually redact.

## The placeholder

1-64 printable ASCII characters, no quote and no backslash, and it must not
itself match any detector -- a placeholder that does would be re-redacted on the
next pass and would trip the residue check on every record.
