/*
 * ascon.js — Ascon (NIST SP 800-232) for Boho v2
 *
 * Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 on one 320-bit permutation.
 * JS partner of the Arduino BohoAscon.cpp. Used by BohoV2 (src/boho-v2.js).
 *
 * Each 64-bit state word is kept as two 32-bit halves (lo, hi) so that plain
 * 32-bit integer operations work in every JS engine without BigInt. A byte view
 * of the same buffer gives the little-endian byte order SP 800-232 uses.
 *
 * Author: Taeo Lee <sixgen@gmail.com>
 */

if (new Uint8Array(new Uint32Array([1]).buffer)[0] !== 1) {
  throw new Error('ascon.js needs a little-endian platform')
}

export const KEY_SIZE = 16
export const NONCE_SIZE = 16
export const TAG_SIZE = 16
export const HASH_SIZE = 32

const encoder = new TextEncoder()

function bytes (value, name) {
  if (value === undefined || value === null) return new Uint8Array(0)
  if (typeof value === 'string') return encoder.encode(value)
  if (value instanceof Uint8Array) return value
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  throw new TypeError(`${name} must be a string, Uint8Array, ArrayBuffer or typed array`)
}

function fixed (value, size, name) {
  const b = bytes(value, name)
  if (b.length !== size) throw new RangeError(`${name} must be ${size} bytes`)
  return b
}

function tagSize (value) {
  if (!Number.isInteger(value) || value < 4 || value > 16) throw new RangeError('tagLength must be 4..16')
  return value
}

class State {
  constructor () {
    this.w = new Uint32Array(10)  // word i: lo = w[2i], hi = w[2i+1]
    this.b = new Uint8Array(this.w.buffer)
  }

  setWord (i, hi, lo) { this.w[2 * i] = lo; this.w[2 * i + 1] = hi }

  xor (offset, data, start, length) {
    const b = this.b
    for (let i = 0; i < length; i++) b[offset + i] ^= data[start + i]
  }

  // The last `rounds` of 12 rounds (12 or 8).
  permute (rounds) {
    const w = this.w
    let x0l = w[0], x0h = w[1], x1l = w[2], x1h = w[3], x2l = w[4], x2h = w[5]
    let x3l = w[6], x3h = w[7], x4l = w[8], x4h = w[9]
    let tl, th, al, ah, bl, bh, cl, ch, dl, dh, el, eh
    for (let i = 12 - rounds; i < 12; i++) {
      x2l ^= ((0x0f - i) << 4) | i
      // Substitution layer
      x0l ^= x4l; x0h ^= x4h
      x4l ^= x3l; x4h ^= x3h
      x2l ^= x1l; x2h ^= x1h
      al = ~x0l & x1l; ah = ~x0h & x1h
      bl = ~x1l & x2l; bh = ~x1h & x2h
      cl = ~x2l & x3l; ch = ~x2h & x3h
      dl = ~x3l & x4l; dh = ~x3h & x4h
      el = ~x4l & x0l; eh = ~x4h & x0h
      x0l ^= bl; x0h ^= bh
      x1l ^= cl; x1h ^= ch
      x2l ^= dl; x2h ^= dh
      x3l ^= el; x3h ^= eh
      x4l ^= al; x4h ^= ah
      x1l ^= x0l; x1h ^= x0h
      x0l ^= x4l; x0h ^= x4h
      x3l ^= x2l; x3h ^= x2h
      x2l = ~x2l; x2h = ~x2h
      // Linear layer: x ^= ror(x, a) ^ ror(x, b)
      // x0: 19, 28
      tl = x0l; th = x0h
      x0l = tl ^ ((tl >>> 19) | (th << 13)) ^ ((tl >>> 28) | (th << 4))
      x0h = th ^ ((th >>> 19) | (tl << 13)) ^ ((th >>> 28) | (tl << 4))
      // x1: 61, 39 (rotations over 32 swap halves: 29, 7)
      tl = x1l; th = x1h
      x1l = tl ^ ((th >>> 29) | (tl << 3)) ^ ((th >>> 7) | (tl << 25))
      x1h = th ^ ((tl >>> 29) | (th << 3)) ^ ((tl >>> 7) | (th << 25))
      // x2: 1, 6
      tl = x2l; th = x2h
      x2l = tl ^ ((tl >>> 1) | (th << 31)) ^ ((tl >>> 6) | (th << 26))
      x2h = th ^ ((th >>> 1) | (tl << 31)) ^ ((th >>> 6) | (tl << 26))
      // x3: 10, 17
      tl = x3l; th = x3h
      x3l = tl ^ ((tl >>> 10) | (th << 22)) ^ ((tl >>> 17) | (th << 15))
      x3h = th ^ ((th >>> 10) | (tl << 22)) ^ ((th >>> 17) | (tl << 15))
      // x4: 7, 41 (41 swaps halves: 9)
      tl = x4l; th = x4h
      x4l = tl ^ ((tl >>> 7) | (th << 25)) ^ ((th >>> 9) | (tl << 23))
      x4h = th ^ ((th >>> 7) | (tl << 25)) ^ ((tl >>> 9) | (th << 23))
    }
    w[0] = x0l; w[1] = x0h; w[2] = x1l; w[3] = x1h; w[4] = x2l; w[5] = x2h
    w[6] = x3l; w[7] = x3h; w[8] = x4l; w[9] = x4h
  }

  wipe () { this.w.fill(0) }
}

function start (key, nonce, ad) {
  const s = new State()
  s.setWord(0, 0x00001000, 0x808c0001)
  s.b.set(key, 8)
  s.b.set(nonce, 24)
  s.permute(12)
  s.xor(24, key, 0, 16)
  if (ad.length) {
    let i = 0
    for (; ad.length - i >= 16; i += 16) {
      s.xor(0, ad, i, 16)
      s.permute(8)
    }
    s.xor(0, ad, i, ad.length - i)
    s.b[ad.length - i] ^= 0x01
    s.permute(8)
  }
  s.b[39] ^= 0x80
  return s
}

function finish (s, key) {
  s.xor(16, key, 0, 16)
  s.permute(12)
  s.xor(24, key, 0, 16)  // tag = s.b[24..39]
}

/**
 * Ascon-AEAD128 encryption.
 * @returns {Uint8Array} ciphertext followed by the tag (tagLength bytes, default 16).
 * The (key, nonce) pair must never be used for two different messages.
 */
export function encrypt (key, nonce, plaintext, ad, tagLength = TAG_SIZE) {
  key = fixed(key, KEY_SIZE, 'key')
  nonce = fixed(nonce, NONCE_SIZE, 'nonce')
  const m = bytes(plaintext, 'plaintext')
  const t = tagSize(tagLength)
  const s = start(key, nonce, bytes(ad, 'ad'))
  const out = new Uint8Array(m.length + t)
  let i = 0
  for (; m.length - i >= 16; i += 16) {
    s.xor(0, m, i, 16)
    out.set(s.b.subarray(0, 16), i)
    s.permute(8)
  }
  const rest = m.length - i
  s.xor(0, m, i, rest)
  out.set(s.b.subarray(0, rest), i)
  s.b[rest] ^= 0x01
  finish(s, key)
  out.set(s.b.subarray(24, 24 + t), m.length)
  s.wipe()
  return out
}

/**
 * Ascon-AEAD128 decryption of ciphertext followed by a tagLength-byte tag.
 * @returns {Uint8Array|null} plaintext, or null when the tag does not match.
 */
export function decrypt (key, nonce, sealed, ad, tagLength = TAG_SIZE) {
  key = fixed(key, KEY_SIZE, 'key')
  nonce = fixed(nonce, NONCE_SIZE, 'nonce')
  const c = bytes(sealed, 'ciphertext')
  const t = tagSize(tagLength)
  if (c.length < t) return null
  const length = c.length - t
  const s = start(key, nonce, bytes(ad, 'ad'))
  const out = new Uint8Array(length)
  const b = s.b
  let i = 0
  while (true) {
    const n = Math.min(16, length - i)
    for (let j = 0; j < n; j++) {
      const v = c[i + j]
      out[i + j] = b[j] ^ v
      b[j] = v
    }
    i += n
    if (n < 16) {
      b[n] ^= 0x01
      break
    }
    s.permute(8)
  }
  finish(s, key)
  let diff = 0
  for (let j = 0; j < t; j++) diff |= b[24 + j] ^ c[length + j]
  s.wipe()
  if (diff) {
    out.fill(0)
    return null
  }
  return out
}

// Absorb one padded string in 8-byte blocks, 12 rounds after each block.
function absorb8 (s, data) {
  let i = 0
  for (; data.length - i >= 8; i += 8) {
    s.xor(0, data, i, 8)
    s.permute(12)
  }
  s.xor(0, data, i, data.length - i)
  s.b[data.length - i] ^= 0x01
  s.permute(12)
}

// One hash/XOF/CXOF run. A customization string (CXOF) goes in after its bit length.
function hashRun (ivHi, ivLo, data, outLength, custom) {
  const s = new State()
  s.setWord(0, ivHi, ivLo)
  s.permute(12)
  if (custom) {
    const bits = custom.length * 8  // at most 2048: fits the low half
    s.w[0] ^= bits
    s.permute(12)
    absorb8(s, custom)
  }
  absorb8(s, data)
  const out = new Uint8Array(outLength)
  for (let o = 0; o < outLength; o += 8) {
    if (o) s.permute(12)
    out.set(s.b.subarray(0, Math.min(8, outLength - o)), o)
  }
  s.wipe()
  return out
}

/** Ascon-Hash256: 32-byte digest. */
export function hash256 (data) {
  return hashRun(0x00000801, 0x00cc0002, bytes(data, 'data'), HASH_SIZE)
}

/** Ascon-XOF128: outLength bytes. */
export function xof128 (data, outLength) {
  if (!Number.isInteger(outLength) || outLength < 0) throw new RangeError('outLength must be a non-negative integer')
  return hashRun(0x00000800, 0x00cc0003, bytes(data, 'data'), outLength)
}

export const CXOF_MAX_CUSTOM = 256

/** Ascon-CXOF128: outLength bytes, with a customization string of at most 256 bytes. */
export function cxof128 (data, outLength, custom) {
  if (!Number.isInteger(outLength) || outLength < 0) throw new RangeError('outLength must be a non-negative integer')
  const z = bytes(custom, 'custom')
  if (z.length > CXOF_MAX_CUSTOM) throw new RangeError(`custom must be at most ${CXOF_MAX_CUSTOM} bytes`)
  return hashRun(0x00000800, 0x00cc0004, bytes(data, 'data'), outLength, z)
}

export default { encrypt, decrypt, hash256, xof128, cxof128, CXOF_MAX_CUSTOM, KEY_SIZE, NONCE_SIZE, TAG_SIZE, HASH_SIZE }
