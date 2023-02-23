import{ MBP, Buffer} from "meta-buffer-pack"
const MB = MBP.MB


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
    MB('header','8', 0),
    MB('reserved','8', 0)
  ),

  AUTH_NONCE: MBP.meta(  // 13
    MB('header','8', 0),
    MB('unixTime','32L', 0),
    MB('milTime','32L', 0 ),
    MB('nonce', Buffer.alloc(4))
  ),

  AUTH_HMAC: MBP.meta( // 45
    MB('header','8', 0),
    MB('id8',Buffer.alloc(8)),
    MB('nonce', Buffer.alloc(4)),
    MB('hmac32', Buffer.alloc(32))
  ),
    
  AUTH_ACK: MBP.meta( // 33
    MB('header','8', 0),
    MB('hmac32', Buffer.alloc(32))
  ),
    

  ENC_PACK: MBP.meta(  //25 + payload
    MB('type','8',0),
    MB('len','32L',0),  // pure xdata size.  
    MB('salt12', Buffer.alloc(12)),  // sec,mil,rand
    MB('hmac',8,0)
    // MB( 'xdata', encData )
    ),


  ENC_488: MBP.meta(   // 21 + payload
    MB('type','8', 0 ),
    MB('len','32L', 0 ),
    MB('otpSrc8', Buffer.alloc(8) ),
    MB('hmac8', Buffer.alloc(8) )
    // MB('xdata', encData ) 
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