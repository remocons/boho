import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Boho, MBP } from 'boho'

describe('ENC_PACK ESM', function () {
  describe('encryption and decryption', function () {
    const plainData = 'aaaaa'
    const key = 'key'

    it('should decryptPack.data property has same buffer of origin.', function () {
      const boho = new Boho()
      boho.set_key(key)

      const encData = boho.encryptPack(plainData)
      const decObj = boho.decryptPack(encData)

      const srcBuffer = MBP.B8(plainData)
      const resultBuffer = MBP.B8(decObj.data)

      assert.ok(MBP.equal(srcBuffer, resultBuffer))
    })
  })
})
