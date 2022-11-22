import assert from 'assert/strict'
import { Boho , MBP , MetaSize, BohoMsg ,Meta } from 'boho'

describe('AUTH process', function () {

  const id = "id"
  const key = "key"


  //client side
  let c = new Boho()  
  c.set_id8( id )
  c.set_key( key )
  
  let s = new Boho() //server side 
  
  let auth_nonce_buffer = s.auth_nonce()
  let auth_hmac_buffer = c.auth_hmac( auth_nonce_buffer )

  let unpack = MBP.unpack( auth_hmac_buffer, Meta.AUTH_HMAC )
  
  // Find hashID8 from DATABASE then set the  id and key.
  s.set_id8( id )

  s.set_key('wrong-key')  // if key is wrong.
  let check_auth_hmack_fail = s.check_auth_hmac( unpack )

  s.set_key( key );  // if correct.
  let auth_ack_buffer = s.check_auth_hmac( unpack )
  // console.log('auth_ack_buffer', auth_ack_buffer )

  let auth_ack_buffer_with_incorrect_hmac = MBP.Buffer.alloc(9)
  let isCorrectSeverHMAC = c.check_auth_ack_hmac( auth_ack_buffer )
  
  auth_ack_buffer.copy( auth_ack_buffer_with_incorrect_hmac)
  auth_ack_buffer_with_incorrect_hmac[2] ^= 0x55 // change hmac
  let wrongSeverHMACResult = c.check_auth_ack_hmac( auth_ack_buffer_with_incorrect_hmac )
  

  // 1. client send AUTH_REQ first

  describe('2. sever reply AUTH_NONCE', function () {

    it('should return static size buffer', function () {
      // console.log( 'auth-req', auth_nonce_buffer )
      assert.equal( auth_nonce_buffer.byteLength , MetaSize.AUTH_NONCE  )
    })

    it('should pack[0] is header type ', function () {
      // console.log( 'auth-req', auth_nonce_buffer )
      assert.ok( auth_nonce_buffer[0] , BohoMsg.AUTH_NONCE  )
    })

  })

  
  describe('3. client reply AUTH_HMAC', function () {

    it('should return static size buffer', function () {
      // console.log( 'auth-hmac', auth_hmac_buffer )
      assert.equal( auth_hmac_buffer.byteLength , MetaSize.AUTH_HMAC  )
    })

    it('should pack[0] is header type ', function () {
      // console.log( 'auth-hmac', auth_hmac_buffer )
      assert.ok( auth_hmac_buffer[0] , BohoMsg.AUTH_HMAC  )
    })

  })

  describe('3. sever check  AUTH_HMACK pack', function () {

    it('3.1. should success unpack', function () {
      // console.log( 'unpack object of auth-hmac', unpack )
      assert.ok( typeof unpack === 'object' )
    })

    describe('3.2. check_auth_hmac(obj) ', function () {

      // wrong key of id.
      it('3.2.1. should return false when wrong key', function () {
        // console.log( 'auth-fail', check_auth_hmack_fail )
        assert.ok( !check_auth_hmack_fail )
      })

      // correct id and key
      it('3-2.2. should return AUTH_ACK buffer pack when correct key', function () {
        // console.log( 'auth-ack', auth_ack_buffer )
        assert.equal( auth_ack_buffer[0] , BohoMsg.AUTH_ACK  )
      })
    })

  })



  describe('4. client process', function () {

    describe('4.1 check_auth_ack_hmac()', function () {

      it('should return true when correct AUTH_ACK ', function () {
        // console.log( 'auth-ack', auth_ack_buffer )
        assert.ok( isCorrectSeverHMAC )
      })

      it('should return false when  AUTH_ACK has wrong hmac', function () {
        // console.log( 'auth-ack with wrong hmac', auth_ack_buffer_with_incorrect_hmac )
        assert.ok( !wrongSeverHMACResult )
      })

    })


  })



})
