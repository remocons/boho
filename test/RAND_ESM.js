import assert from 'assert/strict'
import { RAND } from 'boho'

describe('RAND ESM', function () {
  describe('for number', function () {
    const num = 16
    it('should return Uint8Array', function () {
      assert.ok(RAND(num) instanceof Uint8Array)
    })

    it('should return number-bytes size of Uint8Array', function () {
      assert.ok(RAND(num).byteLength === num)
    })
  })
})
