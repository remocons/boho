import { sha256 } from './sha256-mbp.js'
import MBP from 'meta-buffer-pack'
export { MBP }
import { BohoMsg, Meta, MetaSize } from './constants.js'
export { BohoMsg, Meta, MetaSize, sha256 }
import { Buffer } from 'buffer/index.js'
export { Buffer}

export function RAND(size) {
  return globalThis.crypto.getRandomValues(Buffer.alloc(size))
}

export class Boho {

  // A. Core
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

  // for the self
  set_hash_id8(data) {
    let idSum = MBP.B8(sha256.hash(data))
    idSum.copy(this._id8, 0, 0, 8)
  }

  set_id8(data) {
    let encStr = MBP.B8(data)
    this._id8.fill(0)
    encStr.copy(this._id8, 0, 0, 8)
  }

  set_key(data) {
    let keySum = MBP.B8(sha256.hash(data))
    keySum.copy(this._otpSrc44, 0, 0, 32)
  }

  //  id_key == 'id' + '.' + 'key' 
  set_id_key(id_key) {
    let delimiterPosition = id_key.indexOf('.')
    if( delimiterPosition == -1 ) return
    let id = id_key.substring(0, delimiterPosition)
    let key = id_key.substring(delimiterPosition + 1)
    this.set_id8(id)
    this.set_key(key)
  }

  copy_id8(data) {
    data.copy(this._id8, 0, 0, 8)
  }

  copy_key(data) {
    data.copy(this._otpSrc44, 0, 0, 32)
  }


  sha256_n(srcData, n) {
    let hashSum = sha256.hash(srcData)
    for (let i = 0; i < n; i++) hashSum = sha256.hash(hashSum)
    return hashSum
  }


  // useful general encryption  i.e. enc_pack
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

  // for secure communication sender. 
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


  set_salt12(salt12) {
    salt12.copy(this._otpSrc44, 32)
  }

  resetOTP() {
    let otp32 = MBP.B8(sha256.hash(this._otpSrc44))
    otp32.copy(this._otp36, 0, 0, 32)
  }

  getIndexOTP(otpIndex) {
    this._otp36.writeUInt32LE(otpIndex, 32)
    return sha256.hash(this._otp36)
  }


  generateHMAC(data) {
    let hmacSrc = Buffer.concat([this._otpSrc44, data])
    this._hmac = MBP.B8(sha256.hash(hmacSrc))
  }

  // return 8 bytes of hash
  getHMAC8(data) {
    let hmacSrc = Buffer.concat([this._otpSrc44, data])
    this._hmac = MBP.B8(sha256.hash(hmacSrc))
    return this._hmac.subarray(0, 8)
  }

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

  // step 1
  // client send AUTH_REQ
  auth_req() {
    return MBP.pack(
      MBP.MB('#type', '8', BohoMsg.AUTH_REQ),
      MBP.MB('#reserved', '8', 0)
    )
  }

  // step 2
  // server send AUTH_NONCE
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


  // step 3
  // client send AUTH_HMAC
  // input :  auth_nonce buffer
  auth_hmac(buffer) {
    let auth_nonce = MBP.unpack(buffer, Meta.AUTH_NONCE)
    if (auth_nonce) {
      // console.log(' auth nonce', auth_nonce )

      // let now = Date.now()
      // let localUTC= Math.floor( now/ 1000 )
      // let localMilTime = now % 1000

      // console.log('time server [sec]', auth_nonce.unixTime, auth_nonce.milTime )
      // console.log('time client [sec]', localUTC , localMilTime )
      // console.log('time diff client and server[sec]', auth_nonce.unixTime - localUTC )

      // let serverSecMil = auth_nonce.unixTime * 1000 + auth_nonce.milTime
      // console.log('time diff msec client and server[msec]', serverSecMil - now )

      let salt12 = Buffer.concat([
       MBP.NB('32L', auth_nonce.unixTime),
       MBP.NB('32L', auth_nonce.milTime),
        auth_nonce.nonce
      ])

      this.set_salt12(salt12)

      this.localNonce = RAND(4)
      // hmac( key, sec,mil,serverNonce, localNonce)
      this.generateHMAC(this.localNonce)

      // let hmac8 = this._hmac.subarray(0, 8)

      this.remoteNonce = auth_nonce.nonce

      let auth_hmac_buffer = MBP.pack( // 21 -> 45
       MBP.MB('#header', '8', BohoMsg.AUTH_HMAC),
       MBP.MB('#id8', this._id8),
       MBP.MB('#nonce', this.localNonce),
       MBP.MB('#hmac32', this._hmac ), //full 32bytes hash
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

  // input: unpack object or buffer of auth_hmac
  check_auth_hmac(data) {
    let infoPack
    if (data instanceof Uint8Array) {
      infoPack = MBP.unpack(data, Meta.AUTH_HMAC)
      if (!infoPack) {
        // console.log('auth_hamc unpack fail.')
        return
      }
    } else {
      infoPack = data;

    }
    // console.log('auth_hamc infoObj', infoPack )

    this.set_salt12(this.auth_salt12)

    // hmac( key, sec,mil,serverNonce, clientNonce)
    this.generateHMAC(infoPack.nonce)
    // let hmac8 = this._hmac.subarray(0, 8)
    let hmac32 = this._hmac

    if (MBP.equal(infoPack.hmac32, hmac32)) {
      //Auth success then store client nonce.
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



  // step 5.  cross check
  // client check server's hmac.  
  check_auth_ack_hmac(buffer) {
    // server response has hmac ( key + clientNonce)
    let auth_ack = MBP.unpack(buffer, Meta.AUTH_ACK)
    if (auth_ack) {
      let salt12 = Buffer.concat([
        this.remoteNonce,
        this.localNonce,
        this.remoteNonce,
      ])
      this.set_salt12(salt12)
      this.generateHMAC(this.localNonce)
      // let hmac8 = this._hmac.subarray(0, 8)
      let hmac32 = this._hmac
      //server side hmac using client nonce.
      if (MBP.equal(hmac32, auth_ack.hmac32)) {
        this.isAuthorized = true
        return true
      }
    }
    // server hmac error
    return
  }

  // C. Secure Communication

  // Must AUTH first.
  encrypt_488(data) {  // payload max about 2^32 bytes.
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
    // console.log('enc pack result', pack )
    return pack
  }


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

      // console.log('hmac dismatch', decData )
    } else {
      // console.log('unpack fail')
    }
  }


  // maxium data size is 2**32 -1 bytes.
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


  decryptPack(data) {

    if (data[0] !== BohoMsg.ENC_PACK) {
      // console.log('Boho: Invalid packType')
      return
    }

    // packLength
    let readPackLen = data.readUint32LE(1);
    if (readPackLen != data.byteLength - MetaSize.ENC_PACK) {
      // console.log('Boho: Invalid LEN data_len: data.byteLen' , readPackLen, data.byteLength)
      return
    }

    try {
      let pack = MBP.unpack(data, Meta.ENC_PACK)
      //  console.log('unpack result', pack )
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
      // console.log('Invalid HMAC', pack.hmac, hmac8 )

    } catch (error) {
      // console.log('Boho: unpack err', error )

    }
  }

  encrypt_e2e(data, key) {
    let baseKey = Buffer.alloc(32)
    baseKey.set(this._otpSrc44.subarray(0, 32))
    this.set_key(key)
    let pack = this.encryptPack(data)
    this._otpSrc44.set(baseKey)
    return pack;
  }

  decrypt_e2e(data, key) {
    let baseKey = Buffer.alloc(32)
    baseKey.set(this._otpSrc44.subarray(0, 32))
    this.set_key(key)
    let decPack = this.decryptPack(data)
    this._otpSrc44.set(baseKey)
    return decPack
  }

}

