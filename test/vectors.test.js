// The independent reference (test/reference.js) against the shared vectors (fixtures/boho-vectors.json).
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as ref from './reference.js'
import { makeVectors } from '../tools/make-vectors.mjs'

const hex = b => Buffer.from(b).toString('hex')
const unhex = h => new Uint8Array(Buffer.from(h, 'hex'))
const vectors = JSON.parse(readFileSync(new URL('./fixtures/boho-vectors.json', import.meta.url), 'utf8'))

describe('Boho vectors', () => {
  it('the file matches the reference (run tools/make-vectors.mjs after a change)', () => {
    assert.deepEqual(vectors, JSON.parse(JSON.stringify(makeVectors())))
  })

  it('keys', () => {
    for (const k of vectors.keys) assert.equal(hex(ref.deriveKey(k.key)), k.derived)
  })

  it('logins: both sides agree and check each other', () => {
    for (const l of vectors.logins) {
      const key = ref.deriveKey(l.key), challenge = unhex(l.challenge)
      const req = ref.authReq(key, challenge, ref.id8(l.id), unhex(l.clientNonce))
      assert.equal(hex(req.packet), l.authReq)
      assert.equal(hex(req.session.sessionKey), l.sessionKey)
      const res = ref.verifyAuthReq(key, challenge, unhex(l.authReq))
      assert.equal(hex(res.packet), l.authRes)
      assert.ok(ref.verifyAuthRes(req.session, unhex(l.authRes)))
    }
  })

  it('messages open to their plaintext, clock and E2E body', () => {
    for (const m of vectors.messages) {
      const opened = ref.open(unhex(m.sessionKey), m.dir, unhex(m.packet))
      assert.ok(opened, m.packet)
      assert.equal(opened.type, ref.TYPE[m.type])
      assert.deepEqual([opened.sec, opened.ms, opened.counter], [m.sec, m.ms, m.counter])
      assert.equal(hex(opened.data), m.plaintext)
      assert.equal(hex(opened.e2eBody), m.e2eBody)
    }
    // Same clock, other direction: different bytes.
    assert.notEqual(vectors.messages[1].packet, vectors.messages[2].packet)
  })

  it('packs open to their plaintext and sender', () => {
    for (const p of vectors.packs) {
      const opened = ref.openPack(ref.deriveKey(p.key), unhex(p.packet))
      assert.ok(opened, p.packet)
      assert.equal(hex(opened.data), p.plaintext)
      assert.equal(hex(opened.sender), p.sender)
    }
  })

  it('invalid packets are rejected', () => {
    const sessions = vectors.logins.map(l => ref.session(ref.deriveKey(l.key), unhex(l.challenge), ref.id8(l.id), unhex(l.clientNonce)))
    for (const c of vectors.invalid) {
      const packet = unhex(c.packet)
      let result
      if (c.kind === 'message') result = ref.open(unhex(c.sessionKey), c.dir, packet)
      else if (c.kind === 'pack') result = ref.openPack(ref.deriveKey(c.key), packet)
      else if (c.kind === 'authReq') result = ref.verifyAuthReq(ref.deriveKey(c.key), unhex(c.challenge), packet)
      else if (c.kind === 'authRes') result = ref.verifyAuthRes(sessions[c.sessionOf], packet) || null
      assert.equal(result, null, `${c.kind}: ${c.reason}`)
    }
  })

  it('sizes follow the design', () => {
    const l = vectors.logins[0]
    assert.equal(l.authReq.length / 2, 33)
    assert.equal(l.authRes.length / 2, 17)
    for (const m of vectors.messages) assert.equal(m.packet.length / 2, 21 + (m.plaintext.length + m.e2eBody.length) / 2)
    for (const p of vectors.packs) assert.equal(p.packet.length / 2, 29 + p.plaintext.length / 2)
  })
})
