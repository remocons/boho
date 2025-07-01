import { sha256 } from './sha256-mbp.js'
import MBP from 'meta-buffer-pack'
export { MBP }
import { BohoMsg, Meta, MetaSize } from './constants.js'
export { BohoMsg, Meta, MetaSize, sha256 }
import { Buffer } from 'buffer/index.js'
export { Buffer}

/**
 * 랜덤 바이트 버퍼를 생성합니다.
 * @param {number} size - 생성할 바이트 수
 * @returns {Buffer}
 */
export function RAND(size) {
  return globalThis.crypto.getRandomValues(Buffer.alloc(size))
}

/**
 * Boho 보안 프로토콜 클래스
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

  }

  /**
   * 인증 상태를 초기화합니다.
   */
  clearAuth(){
    this._id8.fill(0)
    this._otpSrc44.fill(0)
    this._otp36.fill(0)
    this._hmac.fill(0)
    this.auth_salt12.fill(0)
    this.localNonce.fill(0)
    this.remoteNonce.fill(0)
    this.isAuthorized = false
  }

  /**
   * 입력 데이터를 해시하여 id8에 설정합니다.
   * @param {any} data
   */
  set_hash_id8(data) {
    let idSum = MBP.B8(sha256.hash(data))
    idSum.copy(this._id8, 0, 0, 8)
  }

  /**
   * id8 값을 설정합니다.
   * @param {any} data
   */
  set_id8(data) {
    let encStr = MBP.B8(data)
    this._id8.fill(0)
    encStr.copy(this._id8, 0, 0, 8)
  }

  /**
   * 키 값을 해시하여 otpSrc44에 설정합니다.
   * @param {any} data
   */
  set_key(data) {
    let keySum = MBP.B8(sha256.hash(data))
    keySum.copy(this._otpSrc44, 0, 0, 32)
  }

  /**
   * 'id.key' 문자열을 분리하여 id8과 key를 설정합니다.
   * @param {string} id_key
   */
  set_id_key(id_key) {
    let delimiterPosition = id_key.indexOf('.')
    if( delimiterPosition == -1 ) return
    let id = id_key.substring(0, delimiterPosition)
    let key = id_key.substring(delimiterPosition + 1)
    this.set_id8(id)
    this.set_key(key)
  }

  /**
   * 외부에서 id8 값을 복사합니다.
   * @param {Buffer} data
   */
  copy_id8(data) {
    data.copy(this._id8, 0, 0, 8)
  }

  /**
   * 외부에서 key 값을 복사합니다.
   * @param {Buffer} data
   */
  copy_key(data) {
    data.copy(this._otpSrc44, 0, 0, 32)
  }

  /**
   * sha256 해시를 n번 반복 적용합니다.
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
   * 랜덤 시계값(salt12)을 otpSrc44에 설정합니다.
   */
  set_clock_rand() {

    let milTime = Date.now()
    let secTime = parseInt(milTime / 1000)
    milTime = milTime % 0xffffffff
    const salt12 = Buffer.concat([
     MBP.NB('32L', secTime),
     MBP.NB('32L', milTime),
      RAND(4)
    ])

    salt12.copy(this._otpSrc44, 32)
  }

  /**
   * 주어진 nonce와 시계값을 otpSrc44에 설정합니다.
   * @param {Buffer} nonce
   */
  set_clock_nonce(nonce) {
    let milTime = Date.now()
    let secTime = parseInt(milTime / 1000)
    milTime = milTime % 0xffffffff
    const salt12 = Buffer.concat([
     MBP.NB('32L', secTime),
     MBP.NB('32L', milTime),
      nonce
    ])

    salt12.copy(this._otpSrc44, 32)
  }

  /**
   * salt12 값을 otpSrc44에 설정합니다.
   * @param {Buffer} salt12
   */
  set_salt12(salt12) {
    salt12.copy(this._otpSrc44, 32)
  }

  /**
   * otp 값을 초기화합니다.
   */
  resetOTP() {
    let otp32 = MBP.B8(sha256.hash(this._otpSrc44))
    otp32.copy(this._otp36, 0, 0, 32)
  }

  /**
   * 인덱스에 해당하는 OTP 값을 반환합니다.
   * @param {number} otpIndex
   * @returns {Uint8Array}
   */
  getIndexOTP(otpIndex) {
    this._otp36.writeUInt32LE(otpIndex, 32)
    return sha256.hash(this._otp36)
  }

  /**
   * HMAC 값을 생성합니다.
   * @param {Buffer} data
   */
  generateHMAC(data) {
    let hmacSrc = Buffer.concat([this._otpSrc44, data])
    this._hmac = MBP.B8(sha256.hash(hmacSrc))
  }

  /**
   * 8바이트 HMAC 값을 반환합니다.
   * @param {Buffer} data
   * @returns {Buffer}
   */
  getHMAC8(data) {
    let hmacSrc = Buffer.concat([this._otpSrc44, data])
    this._hmac = MBP.B8(sha256.hash(hmacSrc))
    return this._hmac.subarray(0, 8)
  }

  /**
   * OTP 기반 XOR 암호화/복호화
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
   * AUTH_REQ 메시지 생성
   * @returns {Buffer}
   */
  auth_req() {
    return MBP.pack(
      MBP.MB('#type', '8', BohoMsg.AUTH_REQ),
      MBP.MB('#reserved', '8', 0)
    )
  }

  /**
   * AUTH_NONCE 메시지 생성
   * @returns {Buffer}
   */
  auth_nonce() {
    let now = Date.now()
    let unixTime = Math.floor(now / 1000)
    let milTime = now % 1000
    this.localNonce = RAND(4)
    this.auth_salt12 = Buffer.concat([
     MBP.NB('32L', unixTime),
     MBP.NB('32L', milTime),
      this.localNonce
    ])

    let infoPack = Buffer.concat([
     MBP.NB('8', BohoMsg.AUTH_NONCE),
      this.auth_salt12
    ])
    return infoPack
  }

  /**
   * AUTH_HMAC 메시지 생성
   * @param {Buffer} buffer
   * @returns {Buffer|boolean}
   */
  auth_hmac(buffer) {
    let auth_nonce = MBP.unpack(buffer, Meta.AUTH_NONCE)
    if (auth_nonce) {
      let salt12 = Buffer.concat([
       MBP.NB('32L', auth_nonce.unixTime),
       MBP.NB('32L', auth_nonce.milTime),
        auth_nonce.nonce
      ])

      this.set_salt12(salt12)

      this.localNonce = RAND(4)
      this.generateHMAC(this.localNonce)

      this.remoteNonce = auth_nonce.nonce

      let auth_hmac_buffer = MBP.pack(
       MBP.MB('#header', '8', BohoMsg.AUTH_HMAC),
       MBP.MB('#id8', this._id8),
       MBP.MB('#nonce', this.localNonce),
       MBP.MB('#hmac32', this._hmac ),
      )

      return auth_hmac_buffer
    }
    return false
  }

  /*  
      step 4.  for server
  
      step 4-1. check client's auth_hmac
      step 4-2. reply result
          send AUTH_ACK  with another HMAC for client.
          or send AUTH_FAIL when fail.
   */

  /**
   * 클라이언트의 AUTH_HMAC을 검증합니다.
   * @param {Buffer|object} data
   * @returns {boolean}
   */
  check_auth_hmac(data) {
    let infoPack
    if (data instanceof Uint8Array) {
      infoPack = MBP.unpack(data, Meta.AUTH_HMAC)
      if (!infoPack) {
        return
      }
    } else {
      infoPack = data;

    }

    this.set_salt12(this.auth_salt12)

    this.generateHMAC(infoPack.nonce)
    let hmac32 = this._hmac

    if (MBP.equal(infoPack.hmac32, hmac32)) {
      this.remoteNonce = infoPack.nonce

      let salt12 = Buffer.concat([
        this.localNonce,
        this.remoteNonce,
        this.localNonce
      ])
      this.set_salt12(salt12)
      this.generateHMAC(infoPack.nonce)
      let replyHMAC = this._hmac

      let auth_ack = MBP.rawPack( 
       MBP.MB('header', '8', BohoMsg.AUTH_ACK),
       MBP.MB('hmac32', replyHMAC)
      )
      this.isAuthorized = true
      return auth_ack
    }
    return false
  }

  /**
   * 서버의 AUTH_ACK HMAC을 검증합니다.
   * @param {Buffer} buffer
   * @returns {boolean}
   */
  check_auth_ack_hmac(buffer) {
    let auth_ack = MBP.unpack(buffer, Meta.AUTH_ACK)
    if (auth_ack) {
      let salt12 = Buffer.concat([
        this.remoteNonce,
        this.localNonce,
        this.remoteNonce,
      ])
      this.set_salt12(salt12)
      this.generateHMAC(this.localNonce)
      let hmac32 = this._hmac
      if (MBP.equal(hmac32, auth_ack.hmac32)) {
        this.isAuthorized = true
        return true
      }
    }
    return
  }

  // C. Secure Communication

  // Must AUTH first.
  /**
   * 인증 후 488 암호화 패킷 생성
   * @param {Buffer} data
   * @returns {Buffer|undefined}
   */
  encrypt_488(data) {
    if (!this.isAuthorized) return

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
   * 인증 후 488 암호화 패킷 복호화
   * @param {Buffer} data
   * @returns {Buffer|undefined}
   */
  decrypt_488(data) {
    data = MBP.B8(data)

    let pack = MBP.unpack(data, Meta.ENC_488)

    if (pack) {

      let salt12 = Buffer.concat([
        pack.otpSrc8,
        this.localNonce
      ])

      this.set_salt12(salt12)
      this.resetOTP()

      let xdata = pack.$OTHERS.subarray(0, pack.len)
      let decData = this.xotp(xdata)

      let hmac8 = this.getHMAC8(decData)

      if (MBP.equal(hmac8, pack.hmac8)) return decData

    }
  }

  /**
   * 최대 2^32-1 바이트 데이터 암호화 패킷 생성
   * @param {Buffer} data
   * @returns {Buffer}
   */
  encryptPack(data) {
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
   * 암호화 패킷 복호화
   * @param {Buffer} data
   * @returns {Buffer}
   */
  decryptPack(data) {

    if (data[0] !== BohoMsg.ENC_PACK) {
      return
    }

    let readPackLen = data.readUint32LE(1);
    if (readPackLen != data.byteLength - MetaSize.ENC_PACK) {
      return
    }

    try {
      let pack = MBP.unpack(data, Meta.ENC_PACK)
      if (!pack) return

      this.set_salt12(pack.salt12)
      this.resetOTP()

      let xdata = pack.$OTHERS
      let decData = this.xotp(xdata)
      let hmac8 = this.getHMAC8(decData)

      if (MBP.equal(pack.hmac, hmac8)) {
        pack.data = decData
        return pack
      }

    } catch (error) {

    }
  }

  /**
   * E2E 암호화
   * @param {Buffer} data
   * @param {Buffer} key
   * @returns {Buffer}
   */
  encrypt_e2e(data, key) {
    let baseKey = Buffer.alloc(32)
    baseKey.set(this._otpSrc44.subarray(0, 32))
    this.set_key(key)
    let pack = this.encryptPack(data)
    this._otpSrc44.set(baseKey)
    return pack;
  }

  /**
   * E2E 복호화
   * @param {Buffer} data
   * @param {Buffer} key
   * @returns {Buffer}
   */
  decrypt_e2e(data, key) {
    let baseKey = Buffer.alloc(32)
    baseKey.set(this._otpSrc44.subarray(0, 32))
    this.set_key(key)
    let decPack = this.decryptPack(data)
    this._otpSrc44.set(baseKey)
    return decPack
  }

}

