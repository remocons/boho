import assert from 'assert/strict'
import { Boho , MBP } from 'boho'

describe('ENC_PACK', function () {
  describe('encryption and decryption', function () {
    const plainData = 'aaaaa'
    const key = 'key'

    it('should decryptPack.data property has same buffer of origin.', function () {
      let boho = new Boho()
      boho.set_key( key )

      let encData = boho.encryptPack( plainData )
      let decObj = boho.decryptPack( encData )
      
      let srcBuffer = MBP.B8( plainData )
      let resultBuffer = MBP.B8( decObj.data )
      // console.log( srcBuffer, resultBuffer  )

      assert.ok( MBP.equal( srcBuffer, resultBuffer) )
    })

  })
})
