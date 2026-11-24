// Makes boho-vectors.json: fixed-input test vectors for the Boho message formats that
// every implementation (JS, C++, Kotlin, Python) must reproduce byte for byte.
//   node tools/make-vectors.mjs           write test/fixtures/boho-vectors.json
//   node tools/make-vectors.mjs --check   fail if the file differs
import { readFileSync, writeFileSync } from 'node:fs'
import * as ref from '../test/reference.js'

const hex = b => Buffer.from(b).toString('hex')
const unhex = h => new Uint8Array(Buffer.from(h, 'hex'))
const seq = (n, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 255)
const text = s => new TextEncoder().encode(s)
const signal = s => Uint8Array.from([0xd0, ...text(s)])  // a SIGNAL-like plaintext

function challenge (sec, ms, counter, nonceHex) {
  const c = new Uint8Array(13)
  c[0] = ref.TYPE.SERVER_TIME_NONCE
  new DataView(c.buffer).setUint32(1, sec, true)
  new DataView(c.buffer).setUint16(5, ms, true)
  new DataView(c.buffer).setUint16(7, counter, true)
  c.set(unhex(nonceHex), 9)
  return c
}

export function makeVectors () {
  const keys = ['secret', 'interop-shared-key', '비밀키-한글', 'k'.repeat(100)]
    .map(key => ({ key, derived: hex(ref.deriveKey(key)) }))

  const logins = [
    { key: 'secret', id: 'dev1', challenge: challenge(1764000000, 123, 0x1234, 'a1b2c3d4'), clientNonce: '0001020304050607' },
    { key: 'interop-shared-key', id: '12345678', challenge: challenge(1764000001, 999, 0, '00000000'), clientNonce: 'f0e1d2c3b4a59687' },
    { key: '비밀키-한글', id: 'uno', challenge: challenge(0, 0, 0xffff, 'ffffffff'), clientNonce: 'ffffffffffffffff' }
  ].map(({ key, id, challenge: c, clientNonce }) => {
    const k = ref.deriveKey(key)
    const req = ref.authReq(k, c, ref.id8(id), unhex(clientNonce))
    const res = ref.verifyAuthReq(k, c, req.packet)
    return {
      key, id, challenge: hex(c), clientNonce,
      transcript: hex(req.session.transcript),
      sessionKey: hex(req.session.sessionKey),
      clientProof: hex(req.session.clientProof),
      serverProof: hex(req.session.serverProof),
      authReq: hex(req.packet),
      authRes: hex(res.packet)
    }
  })

  const ks = unhex(logins[0].sessionKey)
  const clock = (sec, ms, counter) => ({ sec, ms, counter })
  const messageInputs = [
    ['ENC', ref.DIR.CLIENT_TO_SERVER, clock(1764000000, 124, 0x1235), new Uint8Array(0)],
    ['ENC', ref.DIR.CLIENT_TO_SERVER, clock(1764000000, 125, 0x1236), signal('hello')],
    ['ENC', ref.DIR.SERVER_TO_CLIENT, clock(1764000000, 125, 0x1236), signal('hello')],
    ['ENC', ref.DIR.CLIENT_TO_SERVER, clock(1764000002, 0, 1), seq(15)],
    ['ENC', ref.DIR.CLIENT_TO_SERVER, clock(1764000002, 0, 2), seq(16)],
    ['ENC', ref.DIR.CLIENT_TO_SERVER, clock(1764000002, 0, 3), seq(17)],
    ['ENC', ref.DIR.SERVER_TO_CLIENT, clock(4294967295, 999, 65535), seq(59, 7)],
    ['ENC_E2E', ref.DIR.CLIENT_TO_SERVER, clock(1764000003, 500, 9), seq(10, 0xd2), unhex('b9' + 'aa'.repeat(31))]
  ]
  const messages = messageInputs.map(([type, dir, c, plaintext, e2eBody]) => ({
    sessionKey: hex(ks), type, dir, ...c, plaintext: hex(plaintext),
    e2eBody: e2eBody ? hex(e2eBody) : '',
    packet: hex(ref.seal(ref.TYPE[type], ks, dir, c, plaintext, e2eBody))
  }))

  const e2eKey = 'e2e-shared-key'
  const packs = [
    [clock(1764000000, 1, 1), '0102030405060708', new Uint8Array(0)],
    [clock(1764000000, 1, 2), '0102030405060708', text('on=1;level=70')],
    [clock(1764000000, 1, 2), '1112131415161718', text('on=1;level=70')],
    [clock(1764000009, 999, 65535), 'fffefdfcfbfaf9f8', seq(40)]
  ].map(([c, sender, plaintext]) => ({
    key: e2eKey, ...c, sender, plaintext: hex(plaintext),
    packet: hex(ref.sealPack(ref.deriveKey(e2eKey), c, unhex(sender), plaintext))
  }))

  // Packets every implementation must reject.
  const flip = (h, i, bit = 1) => { const b = unhex(h); b[i] ^= bit; return hex(b) }
  const set = (h, i, v) => { const b = unhex(h); b[i] = v; return hex(b) }
  const m = messages[1], p = packs[1], l = logins[0]
  const invalid = [
    { kind: 'message', reason: 'tag bit flipped', sessionKey: m.sessionKey, dir: m.dir, packet: flip(m.packet, 13) },
    { kind: 'message', reason: 'ciphertext bit flipped', sessionKey: m.sessionKey, dir: m.dir, packet: flip(m.packet, 21) },
    { kind: 'message', reason: 'clock changed', sessionKey: m.sessionKey, dir: m.dir, packet: flip(m.packet, 11) },
    { kind: 'message', reason: 'ENC relabelled ENC_E2E', sessionKey: m.sessionKey, dir: m.dir, packet: set(m.packet, 0, ref.TYPE.ENC_E2E) },
    { kind: 'message', reason: 'other direction', sessionKey: m.sessionKey, dir: ref.DIR.SERVER_TO_CLIENT, packet: m.packet },
    { kind: 'message', reason: 'other session key', sessionKey: logins[1].sessionKey, dir: m.dir, packet: m.packet },
    { kind: 'message', reason: 'length one short', sessionKey: m.sessionKey, dir: m.dir, packet: set(m.packet, 1, unhex(m.packet)[1] - 1) },
    { kind: 'message', reason: 'trailing byte on ENC', sessionKey: m.sessionKey, dir: m.dir, packet: m.packet + '00' },
    { kind: 'message', reason: 'milliseconds 1000', sessionKey: m.sessionKey, dir: m.dir, packet: set(set(m.packet, 9, 0xe8), 10, 0x03) },
    { kind: 'message', reason: 'shorter than header', sessionKey: m.sessionKey, dir: m.dir, packet: m.packet.slice(0, 40) },
    { kind: 'message', reason: 'classic ENC_488 type', sessionKey: m.sessionKey, dir: m.dir, packet: set(m.packet, 0, 0xb8) },
    { kind: 'pack', reason: 'tag bit flipped', key: p.key, packet: flip(p.packet, 21) },
    { kind: 'pack', reason: 'sender changed', key: p.key, packet: flip(p.packet, 13) },
    { kind: 'pack', reason: 'ciphertext bit flipped', key: p.key, packet: flip(p.packet, 29, 0x80) },
    { kind: 'pack', reason: 'other key', key: 'secret', packet: p.packet },
    { kind: 'pack', reason: 'classic ENC_PACK type', key: p.key, packet: set(p.packet, 0, 0xb6) },
    { kind: 'authReq', reason: 'proof bit flipped', key: l.key, challenge: l.challenge, packet: flip(l.authReq, 32) },
    { kind: 'authReq', reason: 'other challenge', key: l.key, challenge: logins[1].challenge, packet: l.authReq },
    { kind: 'authReq', reason: 'other key', key: 'Secret', challenge: l.challenge, packet: l.authReq },
    { kind: 'authReq', reason: 'id changed', key: l.key, challenge: l.challenge, packet: flip(l.authReq, 1) },
    { kind: 'authRes', reason: 'proof bit flipped', sessionOf: 0, packet: flip(l.authRes, 16) },
    { kind: 'authRes', reason: 'client proof echoed', sessionOf: 0, packet: '' + hex([ref.TYPE.AUTH_RES]) + l.clientProof }
  ]

  return {
    format: 'boho-vectors',
    version: 1,
    design: 'docs/PROTOCOL.md',
    notes: 'All byte strings are lowercase hex. Integers are little-endian on the wire. Ascon is NIST SP 800-232.',
    constants: {
      types: Object.fromEntries(Object.entries(ref.TYPE).map(([k, v]) => [k, v])),
      dir: ref.DIR,
      custom: ref.CUSTOM,
      sizes: ref.SIZE
    },
    keys, logins, messages, packs, invalid
  }
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href
if (isMain) {
  const file = new URL('../test/fixtures/boho-vectors.json', import.meta.url)
  const text = JSON.stringify(makeVectors(), null, 2) + '\n'
  if (process.argv.includes('--check')) {
    if (readFileSync(file, 'utf8') !== text) { console.error('boho-vectors.json is out of date'); process.exit(1) }
    console.log('boho-vectors.json is up to date')
  } else {
    writeFileSync(file, text)
    console.log('wrote', file.pathname)
  }
}
