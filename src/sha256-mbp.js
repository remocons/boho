import { hash as sha256, hmac } from '../lib/fast-sha256.js'
import { MBP } from 'meta-buffer-pack'

sha256.hash = function (data) {
  return sha256(MBP.U8(data))
}

sha256.hex = function (data) {
  return MBP.hex(sha256.hash(data))
}

sha256.hmac = function (key, data) {
  return hmac(MBP.U8(key), MBP.U8(data))
}

export { sha256 }
