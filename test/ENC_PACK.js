import assert from 'assert/strict'
import { SEA , MBP } from 'sea-js'

describe('ENC_PACK', function () {
  describe('encryption and decryption', function () {
    const plainData = 'aaaaa'
    const key = 'key'

    it('should decryptPack.data property has same buffer of origin.', function () {
      let sea = new SEA()
      sea.setStrKey( key )

      let encData = sea.encryptPack( plainData )
      let decObj = sea.decryptPack( encData )
      
      let srcBuffer = MBP.B8( plainData )
      let resultBuffer = MBP.B8( decObj.data )
      // console.log( srcBuffer, resultBuffer  )

      assert.ok( MBP.equal( srcBuffer, resultBuffer) )
    })

  })
})
