/**
 * Address masking.
 *
 * An IP address in an access log is personal data in most of the places these
 * logs are kept, and it is also the field an operator most often still needs:
 * a network prefix is enough to tell a data centre from a home connection,
 * while the host part identifies a subscriber. So the policy declares how much
 * to keep, and this module keeps exactly that and zeroes the rest.
 *
 * Two properties matter more than the arithmetic:
 *
 * - **Anything unrecognised is replaced whole.** A value that is not an address
 *   this parser understands is never passed through on the theory that it was
 *   probably harmless. It becomes the placeholder and the run reports it. The
 *   failure direction of a redactor is always *more* redaction.
 * - **The output is canonical.** Masking produces one spelling for one result,
 *   so two runs over the same log are byte-identical and a masked address can
 *   be grouped by a consumer.
 */

/** No address this parser accepts is longer than this. A zone id is refused outright. */
export const MAX_ADDRESS_LENGTH = 45

/** The most comma-separated addresses accepted in one field, as in `X-Forwarded-For`. */
export const MAX_ADDRESS_LIST = 16

const IPV4_SHAPE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/**
 * Parse dotted-quad IPv4 into four octets.
 *
 * A leading zero is refused rather than guessed at: `010` is eight in one
 * reading and ten in another, and a parser that picks one silently re-points
 * the address. An address this function refuses is replaced whole by the
 * caller, so refusing is safe.
 */
export function parseIpv4(value) {
  const match = IPV4_SHAPE.exec(value)
  if (match === null) return null
  const octets = []
  for (let index = 1; index <= 4; index += 1) {
    const part = match[index]
    if (part.length > 1 && part[0] === '0') return null
    const number = Number(part)
    if (!Number.isInteger(number) || number > 255) return null
    octets.push(number)
  }
  return octets
}

/**
 * Parse IPv6 into eight 16-bit groups.
 *
 * Handles `::` compression once, and the IPv4-mapped tail (`::ffff:203.0.113.5`).
 * Refuses a zone id (`fe80::1%eth0`), which names a local interface rather than
 * a host and has no masked form worth defining.
 */
export function parseIpv6(value) {
  if (value.length > MAX_ADDRESS_LENGTH) return null
  if (value.includes('%')) return null
  if (!/^[0-9A-Fa-f:.]+$/.test(value)) return null

  const doubleColon = value.indexOf('::')
  if (doubleColon !== value.lastIndexOf('::')) return null

  const readGroups = (text, allowTail) => {
    if (text === '') return []
    const parts = text.split(':')
    const groups = []
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index]
      if (part.includes('.')) {
        if (!allowTail || index !== parts.length - 1) return null
        const octets = parseIpv4(part)
        if (octets === null) return null
        groups.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3])
        continue
      }
      if (part.length === 0 || part.length > 4 || !/^[0-9A-Fa-f]+$/.test(part)) return null
      groups.push(Number.parseInt(part, 16))
    }
    return groups
  }

  if (doubleColon === -1) {
    const groups = readGroups(value, true)
    return groups !== null && groups.length === 8 ? groups : null
  }

  const head = readGroups(value.slice(0, doubleColon), false)
  const tail = readGroups(value.slice(doubleColon + 2), true)
  if (head === null || tail === null) return null
  const missing = 8 - head.length - tail.length
  if (missing < 1) return null
  return [...head, ...new Array(missing).fill(0), ...tail]
}

/** Zero every bit below `prefixBits`, across an array of `size`-bit parts. */
function maskParts(parts, size, prefixBits) {
  return parts.map((part, index) => {
    const high = index * size
    if (prefixBits >= high + size) return part
    if (prefixBits <= high) return 0
    const keep = prefixBits - high
    return part & (((1 << keep) - 1) << (size - keep))
  })
}

/** `203.0.113.42` with a 24-bit prefix becomes `203.0.113.0`. */
export function maskIpv4(octets, prefixBits) {
  return maskParts(octets, 8, prefixBits).join('.')
}

/**
 * Format eight groups as RFC 5952 recommends: lower case, no leading zeros,
 * and the longest run of two or more zero groups written `::`. The leftmost
 * run wins a tie, which is what makes the output one spelling rather than
 * several.
 */
export function formatIpv6(groups) {
  let bestStart = -1
  let bestLength = 0
  let runStart = -1
  for (let index = 0; index <= groups.length; index += 1) {
    if (index < groups.length && groups[index] === 0) {
      if (runStart === -1) runStart = index
      continue
    }
    if (runStart !== -1) {
      const length = index - runStart
      if (length > bestLength) {
        bestLength = length
        bestStart = runStart
      }
      runStart = -1
    }
  }
  const text = groups.map((group) => group.toString(16))
  if (bestLength < 2) return text.join(':')
  const head = text.slice(0, bestStart).join(':')
  const tail = text.slice(bestStart + bestLength).join(':')
  return `${head}::${tail}`
}

/** `2001:db8:1:2::9` with a 48-bit prefix becomes `2001:db8:1::`. */
export function maskIpv6(groups, prefixBits) {
  return formatIpv6(maskParts(groups, 16, prefixBits))
}

/**
 * Mask one address by the declared policy.
 *
 * Returns `null` for anything this parser does not recognise, and for a family
 * the policy says to drop entirely. The caller turns both into the placeholder;
 * they differ only in what it reports.
 */
export function maskAddress(value, policy) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ADDRESS_LENGTH) return null
  const octets = parseIpv4(value)
  if (octets !== null) {
    return policy.ipv4 === 'drop' ? null : maskIpv4(octets, policy.ipv4PrefixBits)
  }
  const groups = parseIpv6(value)
  if (groups !== null) {
    return policy.ipv6 === 'drop' ? null : maskIpv6(groups, policy.ipv6PrefixBits)
  }
  return null
}

/**
 * Mask a field that may carry a list, as `X-Forwarded-For` does.
 *
 * Every element must mask successfully. One element this parser cannot read
 * condemns the whole field: masking the rest and leaving that one as it stands
 * would leave an address in the output, which is the one outcome this tool
 * exists to prevent. The masked list is rejoined with a single `, ` so the
 * result has one spelling.
 */
export function maskAddressField(value, policy) {
  if (typeof value !== 'string') return null
  if (!value.includes(',')) return maskAddress(value.trim(), policy)
  const parts = value.split(',')
  if (parts.length > MAX_ADDRESS_LIST) return null
  const masked = []
  for (const part of parts) {
    const one = maskAddress(part.trim(), policy)
    if (one === null) return null
    masked.push(one)
  }
  return masked.join(', ')
}
