const { describe, it } = require('node:test');
const assert = require('node:assert');
const Boho = require('boho')

describe('RAND cjs', function () {
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
