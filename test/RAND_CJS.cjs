const { describe, it } = require('node:test');
const assert = require('node:assert');
const RAND = require('boho').RAND

describe('RAND CJS', function () {
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
