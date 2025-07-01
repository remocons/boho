import { hash, hmac } from '../lib/fast-sha256.js'
import MBP from 'meta-buffer-pack'

/*
Tip.
 fast-sha256 use data:8Uint8Array
 sha256-mbp use data:any  ( internal type converter )

 MBP.U8( any ) return Uint8Array
 MBP.B8( any ) reutn Buffer instance

*/
/**
 * sha256 및 hmac 유틸리티 함수 모음
 * @namespace sha256
 */
const sha256 = {};

/**
 * sha256 해시를 반환합니다.
 * @param {any} data
 * @returns {Uint8Array}
 */
sha256.hash = function (data) {
  return hash(MBP.U8(data))
}

/**
 * sha256 해시의 hex 문자열을 반환합니다.
 * @param {any} data
 * @returns {string}
 */
sha256.hex = function (data) {
  return MBP.B8( hash(MBP.U8(data)) ).toString('hex')
}

/**
 * sha256 해시의 base64 문자열을 반환합니다.
 * @param {any} data
 * @returns {string}
 */
sha256.base64= function (data) {
  return MBP.B8(  hash(MBP.U8(data)) ).toString('base64')
}

/**
 * hmac 값을 반환합니다.
 * @param {any} key
 * @param {any} data
 * @returns {Uint8Array}
 */
sha256.hmac = function (key, data) {
  return hmac(MBP.U8(key), MBP.U8(data))
}

export { sha256 }
