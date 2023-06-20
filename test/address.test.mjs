import assert from 'node:assert/strict'
import test from 'node:test'

import { maskAddress, maskAddressField, maskIpv4, maskIpv6, parseIpv4, parseIpv6 } from '../src/index.mjs'

const POLICY = Object.freeze({ ipv4: 'mask-host', ipv4PrefixBits: 24, ipv6: 'mask-host', ipv6PrefixBits: 48 })

test('an IPv4 host part is removed and the network kept', () => {
  assert.equal(maskAddress('203.0.113.42', POLICY), '203.0.113.0')
  assert.equal(maskAddress('198.51.100.255', POLICY), '198.51.100.0')
  assert.equal(maskAddress('192.0.2.7', { ...POLICY, ipv4PrefixBits: 16 }), '192.0.0.0')
  assert.equal(maskAddress('192.0.2.7', { ...POLICY, ipv4PrefixBits: 0 }), '0.0.0.0')
  assert.equal(maskAddress('192.0.2.7', { ...POLICY, ipv4PrefixBits: 32 }), '192.0.2.7')
})

test('an IPv6 prefix is kept and the rest zeroed, in one canonical spelling', () => {
  assert.equal(maskAddress('2001:db8:1:2:3:4:5:9', POLICY), '2001:db8:1::')
  assert.equal(maskAddress('2001:db8:1:2:3:4:5:9', { ...POLICY, ipv6PrefixBits: 32 }), '2001:db8::')
  assert.equal(maskAddress('2001:db8:1:2:3:4:5:9', { ...POLICY, ipv6PrefixBits: 64 }), '2001:db8:1:2::')
  assert.equal(maskAddress('2001:0DB8:0001:0002:0003:0004:0005:0009', POLICY), '2001:db8:1::', 'case and leading zeros do not survive')
})

test('a family the policy drops produces no address at all', () => {
  assert.equal(maskAddress('203.0.113.42', { ...POLICY, ipv4: 'drop' }), null)
  assert.equal(maskAddress('2001:db8::1', { ...POLICY, ipv6: 'drop' }), null)
})

test('anything the parser cannot read is refused rather than guessed at', () => {
  for (const value of [
    '010.1.1.1', '1.2.3', '1.2.3.4.5', '256.1.1.1', '1.2.3.-1', 'fe80::1%eth0',
    '2001:db8::1::2', 'localhost', '', ' 203.0.113.1', '203.0.113.1 ', 'x'.repeat(50),
  ]) {
    assert.equal(maskAddress(value, POLICY), null, `${value} must be refused`)
  }
})

test('parsing is exact about what it accepts', () => {
  assert.deepEqual(parseIpv4('203.0.113.42'), [203, 0, 113, 42])
  assert.equal(parseIpv4('203.0.113.042'), null, 'a leading zero is ambiguous, so it is refused')
  assert.equal(parseIpv6('::').length, 8)
  assert.deepEqual(parseIpv6('::1').slice(6), [0, 1])
  assert.deepEqual(parseIpv6('::ffff:203.0.113.5').slice(5), [0xffff, 0xcb00, 0x7105])
  assert.equal(parseIpv6('1:2:3:4:5:6:7'), null, 'seven groups without :: is not an address')
  assert.equal(parseIpv6('1:2:3:4:5:6:7:8:9'), null)
})

test('masking is arithmetic, not string trimming', () => {
  assert.equal(maskIpv4([203, 0, 113, 255], 25), '203.0.113.128')
  assert.equal(maskIpv6([0x2001, 0x0db8, 0xabcd, 0xffff, 2, 3, 4, 5], 52), '2001:db8:abcd:f000::')
  assert.equal(maskIpv6([0x2001, 0x0db8, 0xabcd, 0xffff, 2, 3, 4, 5], 48), '2001:db8:abcd::')
})

test('a forwarded-for list is masked element by element, or refused whole', () => {
  assert.equal(maskAddressField('203.0.113.42, 198.51.100.7', POLICY), '203.0.113.0, 198.51.100.0')
  assert.equal(maskAddressField('203.0.113.42,198.51.100.7', POLICY), '203.0.113.0, 198.51.100.0')
  assert.equal(
    maskAddressField('203.0.113.42, unknown', POLICY),
    null,
    'one element nobody can read condemns the field: masking the rest would leave an address in the output',
  )
  assert.equal(maskAddressField(new Array(20).fill('203.0.113.1').join(','), POLICY), null, 'a list longer than the bound is refused')
})

test('masking two spellings of one address produces one result', () => {
  assert.equal(maskAddress('2001:db8:0:0:0:0:0:1', POLICY), maskAddress('2001:db8::1', POLICY))
  assert.equal(maskAddress('2001:DB8::1', POLICY), maskAddress('2001:db8::1', POLICY))
})
