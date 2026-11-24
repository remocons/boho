/*
 * reference.js — independent byte-level reference of the Boho message formats on Ascon
 *
 * Written apart from src/boho.js (functions, no state). Used to
 * make the shared test vectors (boho-vectors.json); not the production API.
 *
 * Author: Taeo Lee <sixgen@gmail.com>
 */

import { encrypt, decrypt, cxof128 } from '../src/ascon.js'

export const TYPE = {
  SERVER_TIME_NONCE: 0xB0,
  AUTH_FAIL: 0xB3,
  AUTH_REQ: 0xB4,
  AUTH_RES: 0xB5,
  ENC_PACK: 0xB9,
  ENC_E2E: 0xBA,
  ENC: 0xBB
}
export const DIR = { CLIENT_TO_SERVER: 1, SERVER_TO_CLIENT: 2 }
export const CUSTOM = { KEY: 'boho/v2/key', SESSION: 'boho/v2/session' }
export const SIZE = {
  SERVER_TIME_NONCE: 13, AUTH_REQ: 33, AUTH_RES: 17, TRANSCRIPT: 29,
  TAG: 8, PROOF: 16, ENC_HEADER: 21, ENC_AD: 13, ENC_PACK_HEADER: 29, ENC_PACK_AD: 5
}

const encoder = new TextEncoder()
const bytes = v => (typeof v === 'string' ? encoder.encode(v) : new Uint8Array(v))
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) { out.set(p, o); o += p.length }
  return out
}
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0
const u16 = (b, o) => b[o] | (b[o + 1] << 8)
const put32 = (b, o, v) => { b[o] = v; b[o + 1] = v >>> 8; b[o + 2] = v >>> 16; b[o + 3] = v >>> 24 }
const put16 = (b, o, v) => { b[o] = v; b[o + 1] = v >>> 8 }
const equal = (a, b) => {
  if (a.length !== b.length) return false
  let d = 0
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]
  return d === 0
}

function clockOk (c) {
  return Number.isInteger(c.sec) && c.sec >= 0 && c.sec <= 0xffffffff &&
    Number.isInteger(c.ms) && c.ms >= 0 && c.ms < 1000 &&
    Number.isInteger(c.counter) && c.counter >= 0 && c.counter <= 0xffff
}

/** Key string (the part after "id." in id.key) or E2E key string → 16-byte key. */
export function deriveKey (keyString) {
  const k = bytes(keyString)
  if (!k.length) throw new RangeError('key must not be empty')
  return cxof128(k, 16, CUSTOM.KEY)
}

/** ID string → id8 (first 8 bytes, zero padded), as v1 set_id8. */
export function id8 (id) {
  const b = bytes(id)
  if (!b.length || b.length > 8) throw new RangeError('id must be 1..8 bytes')
  const out = new Uint8Array(8)
  out.set(b)
  return out
}

/** Transcript, session key and both proofs of one login. */
export function session (key, challenge, id, clientNonce) {
  if (challenge.length !== SIZE.SERVER_TIME_NONCE || challenge[0] !== TYPE.SERVER_TIME_NONCE) throw new RangeError('bad challenge')
  if (id.length !== 8 || clientNonce.length !== 8) throw new RangeError('id8 and clientNonce must be 8 bytes')
  const transcript = concat(challenge, id, clientNonce)
  const out = cxof128(concat(key, transcript), 48, CUSTOM.SESSION)
  return {
    transcript,
    sessionKey: out.subarray(0, 16),
    clientProof: out.subarray(16, 32),
    serverProof: out.subarray(32, 48)
  }
}

/** Client: AUTH_REQ = type | id8 | clientNonce8 | clientProof16. */
export function authReq (key, challenge, id, clientNonce) {
  const s = session(key, challenge, id, clientNonce)
  return { packet: concat([TYPE.AUTH_REQ], id, clientNonce, s.clientProof), session: s }
}

/** Server: check AUTH_REQ with the key of its id8. Returns AUTH_RES and the session, or null. */
export function verifyAuthReq (key, challenge, packet) {
  if (packet.length !== SIZE.AUTH_REQ || packet[0] !== TYPE.AUTH_REQ) return null
  const s = session(key, challenge, packet.subarray(1, 9), packet.subarray(9, 17))
  if (!equal(packet.subarray(17, 33), s.clientProof)) return null
  return { packet: concat([TYPE.AUTH_RES], s.serverProof), session: s }
}

/** Client: check AUTH_RES = type | serverProof16. */
export function verifyAuthRes (s, packet) {
  return packet.length === SIZE.AUTH_RES && packet[0] === TYPE.AUTH_RES && equal(packet.subarray(1), s.serverProof)
}

function header (type, length, clock) {
  const h = new Uint8Array(SIZE.ENC_AD)
  h[0] = type
  put32(h, 1, length)
  put32(h, 5, clock.sec)
  put16(h, 9, clock.ms)
  put16(h, 11, clock.counter)
  return h
}

function sessionNonce (h, dir) {
  const n = new Uint8Array(16)
  n.set(h.subarray(5, 13))
  n[8] = dir
  return n
}

/**
 * ENC / ENC_E2E = type | len4 | sec4 | ms2 | counter2 | tag8 | ciphertext [| e2eBody].
 * For ENC_E2E the plaintext is the routing header and e2eBody (an ENC_PACK) follows unchanged.
 */
export function seal (type, sessionKey, dir, clock, plaintext, e2eBody = new Uint8Array(0)) {
  if (type !== TYPE.ENC && type !== TYPE.ENC_E2E) throw new RangeError('type must be ENC or ENC_E2E')
  if (type === TYPE.ENC && e2eBody.length) throw new RangeError('ENC has no E2E body')
  if (!clockOk(clock)) throw new RangeError('bad clock')
  const h = header(type, plaintext.length, clock)
  const sealed = encrypt(sessionKey, sessionNonce(h, dir), plaintext, h, SIZE.TAG)
  const ct = sealed.subarray(0, plaintext.length), tag = sealed.subarray(plaintext.length)
  return concat(h, tag, ct, e2eBody)
}

/** Opens ENC / ENC_E2E. Returns { type, sec, ms, counter, data, e2eBody } or null. */
export function open (sessionKey, dir, packet) {
  if (packet.length < SIZE.ENC_HEADER) return null
  const type = packet[0]
  if (type !== TYPE.ENC && type !== TYPE.ENC_E2E) return null
  const length = u32(packet, 1)
  const room = packet.length - SIZE.ENC_HEADER
  if (length > room || (type === TYPE.ENC && length !== room)) return null
  const clock = { sec: u32(packet, 5), ms: u16(packet, 9), counter: u16(packet, 11) }
  if (clock.ms >= 1000) return null
  const h = packet.subarray(0, SIZE.ENC_AD)
  const sealed = concat(packet.subarray(SIZE.ENC_HEADER, SIZE.ENC_HEADER + length), packet.subarray(13, 21))
  const data = decrypt(sessionKey, sessionNonce(h, dir), sealed, h, SIZE.TAG)
  if (!data) return null
  return { type, ...clock, data, e2eBody: packet.slice(SIZE.ENC_HEADER + length) }
}

/** ENC_PACK = type | len4 | nonce16 (sec4 | ms2 | counter2 | sender8) | tag8 | ciphertext. */
export function sealPack (key, clock, sender, plaintext) {
  if (!clockOk(clock)) throw new RangeError('bad clock')
  if (sender.length !== 8) throw new RangeError('sender must be 8 bytes')
  const ad = new Uint8Array(SIZE.ENC_PACK_AD)
  ad[0] = TYPE.ENC_PACK
  put32(ad, 1, plaintext.length)
  const nonce = new Uint8Array(16)
  put32(nonce, 0, clock.sec); put16(nonce, 4, clock.ms); put16(nonce, 6, clock.counter)
  nonce.set(sender, 8)
  const sealed = encrypt(key, nonce, plaintext, ad, SIZE.TAG)
  return concat(ad, nonce, sealed.subarray(plaintext.length), sealed.subarray(0, plaintext.length))
}

/** Opens ENC_PACK. Returns { sec, ms, counter, sender, data } or null. */
export function openPack (key, packet) {
  if (packet.length < SIZE.ENC_PACK_HEADER || packet[0] !== TYPE.ENC_PACK) return null
  const length = u32(packet, 1)
  if (length !== packet.length - SIZE.ENC_PACK_HEADER) return null
  const nonce = packet.subarray(5, 21)
  if (u16(nonce, 4) >= 1000) return null
  const sealed = concat(packet.subarray(SIZE.ENC_PACK_HEADER), packet.subarray(21, 29))
  const data = decrypt(key, nonce, sealed, packet.subarray(0, 5), SIZE.TAG)
  if (!data) return null
  return { sec: u32(nonce, 0), ms: u16(nonce, 4), counter: u16(nonce, 6), sender: nonce.slice(8), data }
}
