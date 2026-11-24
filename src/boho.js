// Copyright (c) 2024-2026 Taeo Lee (sixgen@gmail.com)
// MIT License
//
// https://github.com/remocons/boho
//
// Boho 3: shared-key authentication and encrypted messages on Ascon (NIST SP 800-232).
//
//   login     SERVER_TIME_NONCE (13 B) → AUTH_REQ (33 B) → AUTH_RES (17 B)
//   session   ENC / ENC_E2E: 21-byte header, Ascon-AEAD128 with an 8-byte tag
//   pack/E2E  ENC_PACK: 29-byte header (16-byte nonce with an 8-byte sender value)
//
// Keys: Ascon-CXOF128(Z = "boho/v2/key") of the key string, 16 bytes (deriveKey). A server
// stores this derived key, never the key string. Each login makes a new session key.
// Boho 2.x (SHA-256 based, classic/) is not supported: its message codes are not reused.
import MBP from 'meta-buffer-pack'
import { Buffer } from 'buffer/index.js'
import { encrypt, decrypt, cxof128 } from './ascon.js'
import { BohoMsg, MetaSize } from './constants.js'

export { MBP, Buffer, BohoMsg, MetaSize }

const KEY_CUSTOM = 'boho/v2/key'
const SESSION_CUSTOM = 'boho/v2/session'
const TAG = 8
const KEY_SIZE = 16
const DIR = { client: 1, server: 2 }  // the direction byte of what that side sends
const encoder = new TextEncoder()

/**
 * Random bytes from the platform's cryptographic generator.
 * @param {number} size
 * @returns {Buffer}
 */
export function RAND (size) {
  const out = Buffer.alloc(size)
  globalThis.crypto.getRandomValues(out)
  return out
}

function bytes (data) {
  if (typeof data === 'string') return encoder.encode(data)
  return MBP.B8(data)
}

function equal (a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false
  let difference = 0
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i]
  return difference === 0
}

function wipe (b) { if (b) b.fill(0) }

/**
 * Key string (the part after "id." in id.key, or an E2E key) → the 16-byte key.
 * Servers store it (for example base64) as the key of an ID.
 * @param {string|Uint8Array} key
 * @returns {Buffer}
 */
export function deriveKey (key) {
  const k = bytes(key)
  if (!k.length) throw new RangeError('key must not be empty')
  return Buffer.from(cxof128(k, KEY_SIZE, KEY_CUSTOM))
}

function readHeader (packet) {
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength)
  return {
    length: view.getUint32(1, true),
    sec: view.getUint32(5, true),
    ms: view.getUint16(9, true),
    counter: view.getUint16(11, true)
  }
}

function sessionNonce (header, dir) {
  const nonce = new Uint8Array(16)
  nonce.set(header.subarray(5, 13))
  nonce[8] = dir
  return nonce
}

function validChallenge (c) {
  return c instanceof Uint8Array && c.length === MetaSize.SERVER_TIME_NONCE &&
    c[0] === BohoMsg.SERVER_TIME_NONCE && (c[5] | (c[6] << 8)) < 1000
}

export class Boho {
  constructor () {
    /** True after a verified login (AUTH_RES on a client, AUTH_REQ on a server). */
    this.isAuthorized = false
    this._id8 = new Uint8Array(8)
    this._key = null
    this._sessionKey = null
    this._serverProof = null
    this._challenge = null
    this._role = null          // 'client' or 'server': which direction byte this side sends
    this._lastMs = -1
    this._lastCounter = 0
    this._sender = null
  }

  clearAuth () {
    wipe(this._id8); wipe(this._key); wipe(this._sessionKey); wipe(this._serverProof)
    this._key = this._sessionKey = this._serverProof = this._role = null
    this.isAuthorized = false
  }

  /** The login ID: at most 8 bytes are used. */
  set_id8 (id) {
    this._id8 = new Uint8Array(8)
    this._id8.set(bytes(id).subarray(0, 8))
  }

  copy_id8 (id8) {
    this._id8 = Uint8Array.from(id8.subarray(0, 8))
  }

  /** Key string → key. A new key ends the session. */
  set_key (key) {
    this.isAuthorized = false
    wipe(this._sessionKey); this._sessionKey = null
    this._key = key ? deriveKey(key) : null
  }

  /** A stored 16-byte key (deriveKey), on a server. */
  copy_key (key16) {
    if (!(key16 instanceof Uint8Array) || key16.length !== KEY_SIZE) throw new RangeError('key must be 16 bytes')
    this.isAuthorized = false
    wipe(this._sessionKey); this._sessionKey = null
    this._key = Uint8Array.from(key16)
  }

  /** 'id.key' */
  set_id_key (idKey) {
    const dot = typeof idKey === 'string' ? idKey.indexOf('.') : -1
    if (dot < 1 || dot === idKey.length - 1) { this.clearAuth(); return }
    this.set_id8(idKey.slice(0, dot))
    this.set_key(idKey.slice(dot + 1))
  }

  _session (challenge, id8, clientNonce) {
    const input = new Uint8Array(KEY_SIZE + 13 + 8 + 8)
    input.set(this._key, 0)
    input.set(challenge, 16)
    input.set(id8, 29)
    input.set(clientNonce, 37)
    const out = cxof128(input, 48, SESSION_CUSTOM)
    wipe(input)
    return out
  }

  // ---- server ----

  /**
   * The server's challenge: type | unixTime4 | ms2 | random2 | random4 (13 bytes).
   * Kept for verify_auth_req.
   * @returns {Buffer}
   */
  server_time_nonce () {
    const now = Date.now()
    const packet = Buffer.alloc(MetaSize.SERVER_TIME_NONCE)
    packet[0] = BohoMsg.SERVER_TIME_NONCE
    packet.writeUInt32LE(Math.floor(now / 1000), 1)
    packet.writeUInt16LE(now % 1000, 5)
    globalThis.crypto.getRandomValues(packet.subarray(7, 13))
    this._challenge = Buffer.from(packet)
    return packet
  }

  /**
   * Checks a client's AUTH_REQ against the challenge this side sent (server_time_nonce, or the
   * one given), with the ID's stored key (copy_key). On success the session is ready and
   * AUTH_RES is returned.
   * @returns {Buffer|false}
   */
  verify_auth_req (packet, challenge = this._challenge) {
    if (!this._key || !validChallenge(challenge) || !(packet instanceof Uint8Array) ||
        packet.length !== MetaSize.AUTH_REQ || packet[0] !== BohoMsg.AUTH_REQ) return false
    const id8 = packet.subarray(1, 9)
    const out = this._session(challenge, id8, packet.subarray(9, 17))
    if (!equal(packet.subarray(17, 33), out.subarray(16, 32))) { wipe(out); return false }
    this._id8 = Uint8Array.from(id8)
    this._sessionKey = out.slice(0, 16)
    this._role = 'server'
    this.isAuthorized = true
    const res = Buffer.alloc(MetaSize.AUTH_RES)
    res[0] = BohoMsg.AUTH_RES
    res.set(out.subarray(32, 48), 1)
    wipe(out)
    return res
  }

  // ---- client ----

  /**
   * AUTH_REQ for the server's SERVER_TIME_NONCE.
   * @returns {Buffer|false}
   */
  auth_req (serverTimeNonce, clientNonce = RAND(8)) {
    if (!this._key || !validChallenge(serverTimeNonce)) return false
    const out = this._session(serverTimeNonce, this._id8, clientNonce)
    this._sessionKey = out.slice(0, 16)
    this._serverProof = out.slice(32, 48)
    this._role = 'client'
    this.isAuthorized = false
    const packet = Buffer.alloc(MetaSize.AUTH_REQ)
    packet[0] = BohoMsg.AUTH_REQ
    packet.set(this._id8, 1)
    packet.set(clientNonce, 9)
    packet.set(out.subarray(16, 32), 17)
    wipe(out)
    return packet
  }

  /** Checks the server's AUTH_RES. */
  verify_auth_res (packet) {
    if (!this._serverProof || !(packet instanceof Uint8Array) || packet.length !== MetaSize.AUTH_RES ||
        packet[0] !== BohoMsg.AUTH_RES || !equal(packet.subarray(1), this._serverProof)) return
    wipe(this._serverProof); this._serverProof = null
    this.isAuthorized = true
    return true
  }

  // ---- messages ----

  // The next outgoing (time, counter): strictly increasing, from the wall clock.
  _nextClock () {
    let ms = Date.now()
    let counter
    if (ms > this._lastMs) {
      counter = (this._lastCounter + 1) & 0xffff
    } else {
      ms = this._lastMs
      counter = this._lastCounter + 1
      if (counter > 0xffff) { ms++; counter = 0 }
    }
    this._lastMs = ms
    this._lastCounter = counter
    return { sec: Math.floor(ms / 1000), ms: ms % 1000, counter }
  }

  _header (type, length) {
    const clock = this._nextClock()
    const h = new Uint8Array(13)
    const view = new DataView(h.buffer)
    h[0] = type
    view.setUint32(1, length, true)
    view.setUint32(5, clock.sec, true)
    view.setUint16(9, clock.ms, true)
    view.setUint16(11, clock.counter, true)
    return h
  }

  /**
   * ENC (the whole message) or ENC_E2E (a routing header; the caller appends the E2E body).
   * Only after a verified login.
   * @returns {Buffer|undefined}
   */
  encrypt_session (data, type = BohoMsg.ENC) {
    if (!this.isAuthorized || !this._sessionKey) return
    if (type !== BohoMsg.ENC && type !== BohoMsg.ENC_E2E) return
    const plain = bytes(data)
    const header = this._header(type, plain.length)
    const sealed = encrypt(this._sessionKey, sessionNonce(header, DIR[this._role]), plain, header, TAG)
    const packet = Buffer.alloc(MetaSize.ENC + plain.length)
    packet.set(header, 0)
    packet.set(sealed.subarray(plain.length), 13)
    packet.set(sealed.subarray(0, plain.length), 21)
    return packet
  }

  /**
   * Opens ENC (exact length) or the routing header of ENC_E2E (the body after it is not read).
   * @returns {Buffer|undefined} the plaintext
   */
  decrypt_session (packet) {
    if (!this.isAuthorized || !this._sessionKey || !(packet instanceof Uint8Array) || packet.length < MetaSize.ENC) return
    const type = packet[0]
    if (type !== BohoMsg.ENC && type !== BohoMsg.ENC_E2E) return
    const h = readHeader(packet)
    const room = packet.length - MetaSize.ENC
    if (h.length > room || (type === BohoMsg.ENC && h.length !== room) || h.ms >= 1000) return
    const header = packet.subarray(0, 13)
    const sealed = new Uint8Array(h.length + TAG)
    sealed.set(packet.subarray(21, 21 + h.length))
    sealed.set(packet.subarray(13, 21), h.length)
    const other = this._role === 'client' ? DIR.server : DIR.client
    const plain = decrypt(this._sessionKey, sessionNonce(header, other), sealed, header, TAG)
    return plain ? Buffer.from(plain.buffer, plain.byteOffset, plain.byteLength) : undefined
  }

  _seal (key, data) {
    const plain = bytes(data)
    this._sender ??= RAND(8)
    const clock = this._nextClock()
    const head = new Uint8Array(21)
    const view = new DataView(head.buffer)
    head[0] = BohoMsg.ENC_PACK
    view.setUint32(1, plain.length, true)
    view.setUint32(5, clock.sec, true)
    view.setUint16(9, clock.ms, true)
    view.setUint16(11, clock.counter, true)
    head.set(this._sender, 13)
    const sealed = encrypt(key, head.subarray(5, 21), plain, head.subarray(0, 5), TAG)
    const packet = Buffer.alloc(MetaSize.ENC_PACK + plain.length)
    packet.set(head, 0)
    packet.set(sealed.subarray(plain.length), 21)
    packet.set(sealed.subarray(0, plain.length), 29)
    return packet
  }

  _open (key, packet) {
    if (!(packet instanceof Uint8Array) || packet.length < MetaSize.ENC_PACK || packet[0] !== BohoMsg.ENC_PACK) return
    const h = readHeader(packet)
    if (h.length !== packet.length - MetaSize.ENC_PACK || h.ms >= 1000) return
    const sealed = new Uint8Array(h.length + TAG)
    sealed.set(packet.subarray(29))
    sealed.set(packet.subarray(21, 29), h.length)
    const plain = decrypt(key, packet.subarray(5, 21), sealed, packet.subarray(0, 5), TAG)
    if (!plain) return
    return {
      type: BohoMsg.ENC_PACK, len: h.length, sec: h.sec, ms: h.ms, counter: h.counter,
      sender: Buffer.from(packet.subarray(13, 21)),
      data: Buffer.from(plain.buffer, plain.byteOffset, plain.byteLength)
    }
  }

  /** ENC_PACK with this side's key. */
  encryptPack (data) { if (this._key) return this._seal(this._key, data) }

  /** Opens ENC_PACK with this side's key: { data, sec, ms, counter, sender, ... } or undefined. */
  decryptPack (packet) { if (this._key) return this._open(this._key, packet) }

  /** ENC_PACK with an E2E key string. */
  encrypt_e2e (data, key) {
    if (!key) return
    const k = deriveKey(key)
    try { return this._seal(k, data) } finally { wipe(k) }
  }

  /** Opens ENC_PACK with an E2E key string: { data, ... } or undefined. */
  decrypt_e2e (packet, key) {
    if (!key) return
    const k = deriveKey(key)
    try { return this._open(k, packet) } finally { wipe(k) }
  }
}

Boho.deriveKey = deriveKey
