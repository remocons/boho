import { describe, it } from 'node:test';
import assert from 'node:assert';
import Boho from 'boho'

const MBP = Boho.MBP
const MetaSize = Boho.MetaSize
const BohoMsg = Boho.BohoMsg
const Meta = Boho.Meta


describe('AUTH process ESM', function () {
  const id = 'id'
  const key = 'key'

  // client side
  const c = new Boho()
  c.set_id8(id)
  c.set_key(key)

  // server side
  const s = new Boho()
  const auth_nonce_buffer = s.server_time_nonce()
  const auth_req_buffer = c.auth_req(auth_nonce_buffer)

  const unpack = MBP.unpack(auth_req_buffer, Meta.AUTH_REQ)

  // Find hashID8 from DATABASE then set the  id and key.
  s.set_id8(id)

  s.set_key('wrong-key') // if key is wrong.
  const verify_auth_req_fail = s.verify_auth_req(unpack)

  s.set_key(key) // if correct.
  const auth_res_buffer = s.verify_auth_req(unpack)

  const auth_res_buffer_with_incorrect_hmac = Boho.Buffer.alloc(9)
  const isCorrectSeverHMAC = c.verify_auth_res(auth_res_buffer)

  auth_res_buffer.copy(auth_res_buffer_with_incorrect_hmac)
  auth_res_buffer_with_incorrect_hmac[2] ^= 0x55 // change hmac
  const wrongSeverHMACResult = c.verify_auth_res(auth_res_buffer_with_incorrect_hmac)


  describe('1. server send SERVER_TIME_NONCE', function () {
    it('should return static size buffer', function () {
      assert.equal(auth_nonce_buffer.byteLength, MetaSize.SERVER_TIME_NONCE)
    })

    it('should pack[0] is header type ', function () {
      assert.ok(auth_nonce_buffer[0], BohoMsg.SERVER_TIME_NONCE)
    })
  })

  describe('2. client send AUTH_REQ', function () {
    it('should return static size buffer', function () {
      assert.equal(auth_req_buffer.byteLength, MetaSize.AUTH_REQ)
    })

    it('should pack[0] is header type ', function () {
      assert.ok(auth_req_buffer[0], BohoMsg.AUTH_REQ)
    })
  })

  describe('3. server verify AUTH_REQ pack', function () {
    it('3.1. should success unpack', function () {
      assert.ok(typeof unpack === 'object')
    })

    describe('3.2. verify_auth_req(obj) ', function () {
      // wrong key of id.
      it('3.2.1. should return false when wrong key', function () {
        assert.ok(!verify_auth_req_fail)
      })

      // correct id and key
      it('3-2.2. should return AUTH_RES buffer pack when correct key', function () {
        assert.equal(auth_res_buffer[0], BohoMsg.AUTH_RES)
      })
    })
  })

  describe('4. client process', function () {
    describe('4.1 verify_auth_res()', function () {
      it('should return true when correct AUTH_RES ', function () {
        assert.ok(isCorrectSeverHMAC)
      })

      it('should return false when  AUTH_RES has wrong hmac', function () {
        assert.ok(!wrongSeverHMACResult)
      })
    })
  })
})
