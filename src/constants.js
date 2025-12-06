// Copyright (c) 2024 Taeo Lee (sixgen@gmail.com)
// MIT License
//
// https://github.com/remocons/boho
//
//
//
import MBP from "meta-buffer-pack"
import { Buffer } from 'buffer/index.js'

/**
 * Boho message type constants
 * @typedef {Object} BohoMsg
 * @property {number} SERVER_TIME_NONCE
 * @property {number} AUTH_REQ
 * @property {number} AUTH_RES
 * @property {number} AUTH_FAIL
 * @property {number} ENC_PACK
 * @property {number} ENC_E2E
 * @property {number} ENC_488
 */

// One-byte header for remote control message pack.
export let BohoMsg = {
  SERVER_TIME_NONCE : 0xB0,
  AUTH_REQ: 0xB1,
  AUTH_RES: 0xB2,
  AUTH_FAIL: 0xB3,

  ENC_PACK : 0xB6,
  ENC_E2E : 0xB7,
  ENC_488 : 0xB8
}

for (let c in BohoMsg) { BohoMsg[BohoMsg[c]] = c }

/**
 * Boho message meta information
 * @typedef {Object} Meta
 * @property {any} SERVER_TIME_NONCE
 * @property {any} AUTH_REQ
 * @property {any} AUTH_RES
 * @property {any} ENC_PACK
 * @property {any} ENC_488
 */

export const Meta = {

  SERVER_TIME_NONCE: MBP.meta(  // 13
    MBP.MB('header','8', 0),
    MBP.MB('unixTime','32L', 0),
    MBP.MB('milTime','16L', 0 ),
    MBP.MB('counter','16L', 0 ),
    MBP.MB('nonce', Buffer.alloc(4))
  ),

  AUTH_REQ: MBP.meta( // 45
    MBP.MB('header','8', 0),
    MBP.MB('id8',Buffer.alloc(8)),
    MBP.MB('nonce', Buffer.alloc(4)),
    MBP.MB('hmac32', Buffer.alloc(32))
  ),

  AUTH_RES: MBP.meta( // 33
    MBP.MB('header','8', 0),
    MBP.MB('hmac32', Buffer.alloc(32))
  ),


  ENC_PACK: MBP.meta(  //25 + payload
    MBP.MB('type','8',0),
    MBP.MB('len','32L',0),  // pure xdata size.
    MBP.MB('salt12', Buffer.alloc(12)),  // sec,mil,rand
    MBP.MB('hmac',8,0)
    // MBP.MB( 'xdata', encData )
    ),


  ENC_488: MBP.meta(   // 21 + payload
    MBP.MB('type','8', 0 ),
    MBP.MB('len','32L', 0 ),
    MBP.MB('otpSrc8', Buffer.alloc(8) ),
    MBP.MB('hmac8', Buffer.alloc(8) )
    // MBP.MB('xdata', encData )
    )


  }


  function getMetaSize(meta){
    let lastItem = meta[ meta.length - 1]
    return lastItem[2] + lastItem[3]
  }

  /**
   * Byte size information for each meta
   * @typedef {Object} MetaSize
   * @property {number} AUTH_REQ
   * @property {number} SERVER_TIME_NONCE
   * @property {number} AUTH_RES
   * @property {number} ENC_PACK
   * @property {number} ENC_488
   */

  /**
   * Byte size information for each meta
   * @type {MetaSize}
   */
  export const MetaSize = {
    SERVER_TIME_NONCE: getMetaSize( Meta.SERVER_TIME_NONCE ),
    AUTH_REQ: getMetaSize( Meta.AUTH_REQ ),
    AUTH_RES: getMetaSize( Meta.AUTH_RES ),
    ENC_PACK: getMetaSize( Meta.ENC_PACK ),
    ENC_488: getMetaSize( Meta.ENC_488 )
  }

// console.log( 'boho 2.0.0 MetaSize', MetaSize )
// boho MetaSize {
  // SERVER_TIME_NONCE: 13,
  // AUTH_REQ: 45,
  // AUTH_RES: 33,
  // ENC_PACK: 25,
  // ENC_488: 21
// }
