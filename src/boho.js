// Copyright (c) 2024 Taeo Lee (sixgen@gmail.com)
// MIT License
//
// https://github.com/remocons/boho
//
//
//
import { sha256 } from './sha256-mbp.js'
import MBP from 'meta-buffer-pack'
export { MBP }
import { BohoMsg, Meta, MetaSize } from './constants.js'
export { BohoMsg, Meta, MetaSize, sha256 }
import { Buffer } from 'buffer/index.js'
export { Buffer }

// Avoid data-dependent early exits when comparing fixed-length tags.
// JavaScript engines do not guarantee constant-time execution.
function equalTag(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false
  let difference = 0
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i]
  return difference === 0
}

function readPacket(data, type, size, meta, variable = false) {
  if (!(data instanceof Uint8Array)) return
  const buffer = Buffer.from(data)
  if (buffer.length < size || buffer[0] !== type) return
  if (variable ? buffer.readUInt32LE(1) !== buffer.length - size : buffer.length !== size) return
  return MBP.unpack(buffer, meta)
}

function validClock(clock) {
  return clock.readUInt16LE(4) < 1000
}


/**
 * Generates a random byte buffer.
 * @param {number} size - Number of bytes to generate
 * @returns {Buffer}
 */
export function RAND(size) {
  return globalThis.crypto.getRandomValues(Buffer.alloc(size))
}

/**
 * Boho security protocol class
 */
export class Boho {
  /**
   * @constructor
   */
  constructor() {

    this._id8 = Buffer.alloc(8)
    this._otpSrc44 = Buffer.alloc(44)
    this._otp36 = Buffer.alloc(36)
    this._hmac = Buffer.alloc(32)

    this.auth_salt12 = Buffer.alloc(12)
    this.localNonce = Buffer.alloc(4)
    this.remoteNonce = Buffer.alloc(4)
    this.isAuthorized = false
    this.counter = 0
    this._hasKey = false
    this._lastSendTime = 0
  }

  /**
   * Initializes authentication state.
   */
  clearAuth() {
    this._id8.fill(0)
    this._otpSrc44.fill(0)
    this._otp36.fill(0)
    this._hmac.fill(0)
    this.auth_salt12.fill(0)
    this.localNonce.fill(0)
    this.remoteNonce.fill(0)
    this.isAuthorized = false
    this.counter = 0
    this._hasKey = false
    this._lastSendTime = 0
  }

  /**
   * Sets id8 by hashing the input data.
   * @param {any} data
   */
  set_hash_id8(data) {
    let idSum = MBP.B8(sha256.hash(data))
    idSum.copy(this._id8, 0, 0, 8)
  }

  /**
   * Sets the id8 value.
   * @param {any} data
   */
  set_id8(data) {
    let encStr = MBP.B8(data)
    this._id8.fill(0)
    encStr.copy(this._id8, 0, 0, 8)
  }

  /**
   * Sets the key value by hashing and storing in otpSrc44.
   * @param {any} data
   */
  set_key(data) {
    const bytes = MBP.B8(data)
    if (!bytes || bytes.length === 0) throw new TypeError('Key must not be empty')
    this.copy_key(MBP.B8(sha256.hash(bytes)))
  }

  /**
   * Splits 'id.key' string and sets id8 and key.
   * @param {string} id_key
   */
  set_id_key(id_key) {
    let delimiterPosition = id_key.indexOf('.')
    if (delimiterPosition == -1) return
    let id = id_key.substring(0, delimiterPosition)
    let key = id_key.substring(delimiterPosition + 1)
    this.set_id8(id)
    this.set_key(key)
  }

  /**
   * Copies id8 value from external buffer.
   * @param {Buffer} data
   */
  copy_id8(data) {
    data.copy(this._id8, 0, 0, 8)
  }

  /**
   * Copies key value from external buffer.
   * @param {Buffer} data
   */
  copy_key(data) {
    if (!(data instanceof Uint8Array) || data.length !== 32) {
      throw new TypeError('copy_key requires exactly 32 bytes')
    }
    this._otpSrc44.set(data, 0)
    this._hasKey = true

  }

  /**
   * Applies sha256 hash n times.
   * @param {any} srcData
   * @param {number} n
   * @returns {Uint8Array}
   */
  sha256_n(srcData, n) {
    let hashSum = sha256.hash(srcData)
    for (let i = 0; i < n; i++) hashSum = sha256.hash(hashSum)
    return hashSum
  }


  /**
   * Sets random clock value (salt12) in otpSrc44.
   */
  set_clock_rand() {
    this.set_clock_nonce(RAND(4))
  }

  /** Sets a monotonic clock/counter and a 4-byte nonce. */
  set_clock_nonce(nonce) {
    if (!(nonce instanceof Uint8Array) || nonce.length !== 4) {
      throw new TypeError('Nonce must be 4 bytes')
    }
    let now = Math.max(Date.now(), this._lastSendTime)
    this.counter = (this.counter + 1) & 0xffff
    if (this.counter === 0 && now === this._lastSendTime) now++
    if (!Number.isSafeInteger(now) || now < 0 || Math.floor(now / 1000) > 0xffffffff) {
      throw new RangeError('Clock is outside the protocol range')
    }
    this._lastSendTime = now
    const salt12 = Buffer.concat([
      MBP.NB('32L', Math.floor(now / 1000)),
      MBP.NB('16L', now % 1000),
      MBP.NB('16L', this.counter),
      Buffer.from(nonce)
    ])
    salt12.copy(this._otpSrc44, 32)
  }

  _requireKey() {
    if (!this._hasKey) throw new Error('Set a key before encryption or authentication')
  }

  /**
   * Sets salt12 value in otpSrc44.
   * @param {Buffer} salt12
   */
  set_salt12(salt12 , caller) {
    // console.log('boho.set_salt12', salt12  , caller )
    if( salt12.byteLength != 12){
      throw TypeError('set_salt12: Invalid salt12 byteLength.')
    } 
    salt12.copy(this._otpSrc44, 32)
  }

  /**
   * Initializes OTP value.
   */
  resetOTP() {
    this._requireKey()
    let otp32 = MBP.B8(sha256.hash(this._otpSrc44))
    otp32.copy(this._otp36, 0, 0, 32)
  }

  /**
   * Returns OTP value for the given index.
   * @param {number} otpIndex
   * @returns {Uint8Array}
   */
  getIndexOTP(otpIndex) {
    this._otp36.writeUInt32LE(otpIndex, 32)
    return sha256.hash(this._otp36)
  }

  /**
   * Generates the legacy SHA-256 prefix tag (not standard HMAC).
   * @param {Buffer} data
   */
  generateHMAC(data) {
    this._requireKey()
    let hmacSrc = Buffer.concat([this._otpSrc44, data])
    this._hmac = MBP.B8(sha256.hash(hmacSrc))
  }

  /**
   * Returns the truncated 8-byte legacy tag (not standard HMAC).
   * @param {Buffer} data
   * @returns {Buffer}
   */
  getHMAC8(data) {
    this._requireKey()
    let hmacSrc = Buffer.concat([this._otpSrc44, data])
    this._hmac = MBP.B8(sha256.hash(hmacSrc))
    return this._hmac.subarray(0, 8)
  }

  /**
   * OTP-based XOR encryption/decryption
   * @param {Buffer} data
   * @param {number} [otpStartIndex=0]
   * @param {boolean} [shareDataBuffer=false]
   * @returns {Buffer}
   */
  xotp(data, otpStartIndex = 0, shareDataBuffer = false) {

    data = MBP.B8(data, shareDataBuffer)

    let len = data.byteLength
    let otpIndex = otpStartIndex
    let dataOffset = 0
    let xorCalcLen = 0

    while (len > 0) {
      xorCalcLen = len < 32 ? len : 32
      let iotp = this.getIndexOTP(++otpIndex);
      for (let i = 0; i < xorCalcLen; i++) {
        data[dataOffset++] ^= iotp[i]
      }
      len -= 32
    }
    return data
  }

  // B. AUTH process

  /**
   * Generates server time and nonce signal
   * @returns {Buffer}
   */
  server_time_nonce() {
    const now = Date.now()
    const unixTime = Math.floor(now / 1000)
    const milliseconds = now % 1000;

    this.localNonce = RAND(4)
    //keep 
    this.auth_salt12 = Buffer.concat([
      MBP.NB('32L', unixTime),
      MBP.NB('16L', milliseconds),
      RAND(2),  // used for client's counter IV.
      this.localNonce
    ])

    let infoPack = Buffer.concat([
      MBP.NB('8', BohoMsg.SERVER_TIME_NONCE),
      this.auth_salt12
    ])
    return infoPack
  }

  /**
   * Generates AUTH_REQ message
   * @param {Buffer} buffer server's time nonce
   * @returns {Buffer|boolean}
   */
  auth_req(buffer) {
    if (!this._hasKey) return false
    let server_time_nonce = readPacket(buffer, BohoMsg.SERVER_TIME_NONCE, MetaSize.SERVER_TIME_NONCE, Meta.SERVER_TIME_NONCE)
    if (server_time_nonce && server_time_nonce.milTime >= 1000) return false
    if (server_time_nonce) {
      let salt12 = Buffer.concat([
        MBP.NB('32L', server_time_nonce.unixTime),
        MBP.NB('16L', server_time_nonce.milTime),
        MBP.NB('16L', server_time_nonce.counter),
        server_time_nonce.nonce
      ])

      this.set_salt12(salt12, 'auth_req')

      this.localNonce = RAND(4)
      this.generateHMAC(this.localNonce)

      this.remoteNonce = server_time_nonce.nonce

      let auth_hmac_buffer = MBP.pack(
        MBP.MB('#header', '8', BohoMsg.AUTH_REQ),
        MBP.MB('#id8', this._id8),
        MBP.MB('#nonce', this.localNonce),
        MBP.MB('#hmac32', this._hmac),
      )

      return auth_hmac_buffer
    }
    return false
  }

  /*  
      step 4.  for server
   */

  /**
   * Verify client's AUTH_REQ.
   * @param {Buffer|object} data
   * @returns {boolean}
   */
  verify_auth_req(data) {

    if (!this._hasKey) return false
    let infoPack
    if (data instanceof Uint8Array) {
      infoPack = readPacket(data, BohoMsg.AUTH_REQ, MetaSize.AUTH_REQ, Meta.AUTH_REQ)
    } else if (data && typeof data === 'object') {
      infoPack = data
    }
    if (!infoPack || infoPack.header !== BohoMsg.AUTH_REQ ||
        !(infoPack.id8 instanceof Uint8Array) || infoPack.id8.length !== 8 ||
        !(infoPack.nonce instanceof Uint8Array) || infoPack.nonce.length !== 4 ||
        !(infoPack.hmac32 instanceof Uint8Array) || infoPack.hmac32.length !== 32 ||
        (infoPack.$OTHERS && infoPack.$OTHERS.length !== 0)) return false

    this.set_salt12(this.auth_salt12, 'verify_auth_req 1/2')

    this.generateHMAC(infoPack.nonce)
    let hmac32 = this._hmac

    if (equalTag(infoPack.hmac32, hmac32)) {
      this.remoteNonce = Buffer.from(infoPack.nonce)

      let salt12 = Buffer.concat([
        this.localNonce,
        this.remoteNonce,
        this.localNonce
      ])

      this.set_salt12(salt12, 'verify_auth_req 2/2')
      this.generateHMAC(infoPack.nonce)
      let replyHMAC = this._hmac

      let auth_res = MBP.rawPack(
        MBP.MB('header', '8', BohoMsg.AUTH_RES),
        MBP.MB('hmac32', replyHMAC)
      )
      this.isAuthorized = true
      return auth_res
    }
    return false
  }

  /**
   * Verifies server's AUTH_RES HMAC.
   * @param {Buffer} buffer
   * @returns {boolean}
   */
  verify_auth_res(buffer) {
    if (!this._hasKey) return false
    let auth_res = readPacket(buffer, BohoMsg.AUTH_RES, MetaSize.AUTH_RES, Meta.AUTH_RES)
    if (auth_res) {
      let salt12 = Buffer.concat([
        this.remoteNonce,
        this.localNonce,
        this.remoteNonce,
      ])
      this.set_salt12(salt12, 'verify_auth_res')
      this.generateHMAC(this.localNonce)
      let hmac32 = this._hmac
      if (equalTag(hmac32, auth_res.hmac32)) {
        this.isAuthorized = true
        return true
      }
    }
    return
  }

  // C. Secure Communication

  // Must AUTH first.
  /**
   * Generates encrypted 488 packet after authentication
   * @param {Buffer} data
   * @returns {Buffer|undefined}
   */
  encrypt_488(data) {
    if (!this.isAuthorized || !this._hasKey) return

    data = MBP.B8(data)

    this.set_clock_nonce(this.remoteNonce)
    this.resetOTP()

    let hmac8 = this.getHMAC8(data)
    let encData = this.xotp(data)

    let pack = MBP.pack(
      MBP.MB('#type', '8', BohoMsg.ENC_488),
      MBP.MB('#len', '32L', data.byteLength),
      MBP.MB('#otpSrc8', this._otpSrc44.subarray(32, 40)),
      MBP.MB('#hmac8', hmac8),
      MBP.MB('#xdata', encData)
    )
    return pack
  }

  /**
   * Decrypts 488 packet after authentication
   * @param {Buffer} data
   * @returns {Buffer|undefined}
   */
  decrypt_488(data) {
    if (!this.isAuthorized || !this._hasKey) return
    // iosignal ENC_E2E wraps only an encrypted routing header. The remaining
    // bytes are an opaque end-to-end packet and must not enter this decryptor.
    let header = data
    if (data instanceof Uint8Array && data[0] === BohoMsg.ENC_E2E) {
      if (data.length < MetaSize.ENC_488) return
      const packet = Buffer.from(data)
      const headerLength = packet.readUInt32LE(1)
      if (headerLength > packet.length - MetaSize.ENC_488) return
      header = Buffer.from(packet.subarray(0, MetaSize.ENC_488 + headerLength))
      header[0] = BohoMsg.ENC_488
    }
    const pack = readPacket(header, BohoMsg.ENC_488, MetaSize.ENC_488, Meta.ENC_488, true)
    if (!pack || !validClock(pack.otpSrc8)) return
    this.set_salt12(Buffer.concat([pack.otpSrc8, this.localNonce]), 'decrypt_488')
    this.resetOTP()
    const decData = this.xotp(pack.$OTHERS ?? Buffer.alloc(0))
    if (!equalTag(this.getHMAC8(decData), pack.hmac8)) return
    // Session freshness/replay policy belongs to the caller (iosignal).
    return decData
  }

  /**
   * Generates encrypted packet for up to 2^32-1 bytes
   * @param {Buffer} data
   * @returns {Buffer}
   */
  encryptPack(data) {
    this._requireKey()
    data = MBP.B8(data)

    this.set_clock_rand()
    this.resetOTP()

    let hmac8 = this.getHMAC8(data)
    let encData = this.xotp(data)

    let pack = MBP.pack(
      MBP.MB('#type', '8', BohoMsg.ENC_PACK),
      MBP.MB('#len', '32L', data.byteLength),
      MBP.MB('#salt12', this._otpSrc44.subarray(32)),
      MBP.MB('#hmac8', hmac8),
      MBP.MB('#xdata', encData)
    )
    return pack
  }

  /**
   * Decrypts encrypted packet
   * @param {Buffer} data
   * @returns {Buffer}
   */
  decryptPack(data) {
    if (!this._hasKey) return
    const pack = readPacket(data, BohoMsg.ENC_PACK, MetaSize.ENC_PACK, Meta.ENC_PACK, true)
    if (!pack) return
    this.set_salt12(pack.salt12, 'decryptPack')
    this.resetOTP()
    const decData = this.xotp(pack.$OTHERS ?? Buffer.alloc(0))
    if (!equalTag(pack.hmac, this.getHMAC8(decData))) return
    pack.data = decData
    return pack
  }

  /**
   * End-to-end encryption
   * @param {Buffer} data
   * @param {Buffer} key
   * @returns {Buffer}
   */
  encrypt_e2e(data, key) {
    return this._withKey(key, () => this.encryptPack(data))
  }

  /**
   * End-to-end decryption
   * @param {Buffer} data
   * @param {Buffer} key
   * @returns {Buffer}
   */
  decrypt_e2e(data, key) {
    return this._withKey(key, () => this.decryptPack(data))
  }

  _withKey(key, operation) {
    const bytes = MBP.B8(key)
    if (!bytes || bytes.length === 0) throw new TypeError('Key must not be empty')
    const state = [Buffer.from(this._otpSrc44), Buffer.from(this._otp36), Buffer.from(this._hmac)]
    const hadKey = this._hasKey
    try {
      this._otpSrc44.set(sha256.hash(bytes), 0)
      this._hasKey = true
      return operation()
    } finally {
      this._otpSrc44.set(state[0])
      this._otp36.set(state[1])
      this._hmac.set(state[2])
      this._hasKey = hadKey
      for (const buffer of state) buffer.fill(0)
    }
  }

}

