import { describe, it } from 'node:test';
import assert from 'node:assert';
import Boho from 'boho'

describe('RAND ESM', function () {
  describe('for number', function () {
    const num = 16
    it('should return Uint8Array', function () {
      assert.ok(Boho.RAND(num) instanceof Uint8Array)
    })

    it('should return number-bytes size of Uint8Array', function () {
      assert.ok(Boho.RAND(num).byteLength === num)
    })
  })
})

console.log( 'buffer: hello', Boho.Buffer.from('hello'))
