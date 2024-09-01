import MBP from "meta-buffer-pack"
import { Buffer } from 'buffer/index.js'

// remocon message pack one byte header. 
export let BohoMsg = {
  AUTH_REQ : 0xB0,  
  AUTH_NONCE: 0xB1,
  AUTH_HMAC: 0xB2,
  AUTH_ACK: 0xB3,
  AUTH_FAIL: 0xB4,
  AUTH_EXT: 0xB5,
  ENC_PACK : 0xB6,  
  ENC_E2E : 0xB7,  
  ENC_488 : 0xB8
}

for (let c in BohoMsg) { BohoMsg[BohoMsg[c]] = c }

export const Meta = {

  AUTH_REQ: MBP.meta(  // 2
    MBP.MB('header','8', 0),
    MBP.MB('reserved','8', 0)
  ),

  AUTH_NONCE: MBP.meta(  // 13
    MBP.MB('header','8', 0),
    MBP.MB('unixTime','32L', 0),
    MBP.MB('milTime','32L', 0 ),
    MBP.MB('nonce', Buffer.alloc(4))
  ),

  AUTH_HMAC: MBP.meta( // 45
    MBP.MB('header','8', 0),
    MBP.MB('id8',Buffer.alloc(8)),
    MBP.MB('nonce', Buffer.alloc(4)),
    MBP.MB('hmac32', Buffer.alloc(32))
  ),
    
  AUTH_ACK: MBP.meta( // 33
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

  export const MetaSize = {
    AUTH_REQ: getMetaSize( Meta.AUTH_REQ ),
    AUTH_NONCE: getMetaSize( Meta.AUTH_NONCE ),
    AUTH_HMAC: getMetaSize( Meta.AUTH_HMAC ),
    AUTH_ACK: getMetaSize( Meta.AUTH_ACK ),
    ENC_PACK: getMetaSize( Meta.ENC_PACK ),
    ENC_488: getMetaSize( Meta.ENC_488 )
  }

// console.log( 'boho MetaSize', MetaSize )
// boho MetaSize {
//   AUTH_REQ: 2,
//   AUTH_NONCE: 13,
//   AUTH_HMAC: 45,
//   AUTH_ACK: 33,
//   ENC_PACK: 25,
//   ENC_488: 21
// }