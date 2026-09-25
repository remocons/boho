import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import Source from '../src/index.js'
import Distribution from '../dist/boho.js'

const browser = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer }
vm.runInNewContext(readFileSync(new URL('../dist/boho.min.js', import.meta.url), 'utf8'), browser)
const fixture = JSON.parse(readFileSync(new URL('./fixtures/legacy-pack.json', import.meta.url)))

for (const [name, B] of [['source', Source], ['ESM', Distribution], ['browser UMD', browser.Boho]]) {
  const bytes = value => B.Buffer.from(value)
  function pair() {
    const client = new B(), server = new B()
    client.set_id8('test-id'); client.set_key('shared-test-key')
    const request = client.auth_req(server.server_time_nonce())
    server.set_key('shared-test-key')
    assert.equal(client.verify_auth_res(server.verify_auth_req(request)), true)
    return { client, server, request }
  }
  describe(`${name}: security regressions`, () => {
    it('rejects missing, cleared, empty and incorrectly sized keys', () => {
      const b = new B()
      assert.throws(() => b.encryptPack('hello'), /key/i)
      assert.equal(b.auth_req(new B().server_time_nonce()), false)
      assert.throws(() => b.set_key(''), /empty/i)
      assert.throws(() => b.copy_key(bytes([1])), /32/)
      b.set_key('key'); b.clearAuth()
      assert.throws(() => b.encryptPack('hello'), /key/i)
      assert.equal(b.isAuthorized, false)
    })
    it('decrypts legacy 2.1.3 packet bytes', () => {
      const b = new B(); b.set_key(fixture.key)
      assert.equal(b.decryptPack(B.Buffer.from(fixture.packet, 'hex')).data.toString(), fixture.plaintext)
    })
    it('round trips empty and multi-block binary messages', () => {
      const b = new B(); b.set_key('key')
      for (const size of [0, 1, 31, 32, 33, 1024]) {
        const plain = B.Buffer.alloc(size, 0xa5)
        const packet = b.encryptPack(plain)
        assert.equal(packet.length, size + B.MetaSize.ENC_PACK)
        assert.deepEqual(Array.from(b.decryptPack(new Uint8Array(packet)).data), Array.from(plain))
      }
      const {client, server} = pair()
      assert.equal(server.decrypt_488(client.encrypt_488('')).length, 0)
    })
    it('rejects all truncated lengths, bad types, lengths and trailing bytes', () => {
      const b = new B(); b.set_key('key')
      const packet = b.encryptPack('test message')
      for (let length = 0; length < packet.length; length++) {
        assert.equal(b.decryptPack(packet.subarray(0, length)), undefined)
      }
      for (const invalid of [undefined, null, {}, 'text', [], bytes([B.BohoMsg.ENC_PACK])]) {
        assert.equal(b.decryptPack(invalid), undefined)
      }
      const wrongType = bytes(packet); wrongType[0] = B.BohoMsg.ENC_488
      const wrongLength = bytes(packet); wrongLength.writeUInt32LE(0, 1)
      for (const invalid of [wrongType, wrongLength, B.Buffer.concat([packet, bytes([0])])]) {
        assert.equal(b.decryptPack(invalid), undefined)
      }
    })
    it('rejects tampering in every byte of a normal packet', () => {
      const b = new B(); b.set_key('key')
      const packet = b.encryptPack('payload crossing a thirty two byte boundary')
      for (let i = 0; i < packet.length; i++) {
        const modified = bytes(packet); modified[i] ^= 1
        assert.equal(b.decryptPack(modified), undefined, `byte ${i}`)
      }
    })
    it('rejects wrong keys', () => {
      const b = new B(), other = new B(); b.set_key('key'); other.set_key('other')
      assert.equal(other.decryptPack(b.encryptPack('secret')), undefined)
    })
    it('requires authorization on both 488 entry points', () => {
      const {client, server} = pair(), packet = client.encrypt_488('hello')
      server.isAuthorized = false
      assert.equal(server.decrypt_488(packet), undefined)
      assert.equal(server.encrypt_488('hello'), undefined)
    })
    it('rejects malformed 488 packets without consuming replay state', () => {
      const {client, server} = pair(), packet = client.encrypt_488('hello')
      for (let length = 0; length < packet.length; length++) {
        assert.equal(server.decrypt_488(packet.subarray(0, length)), undefined)
      }
      for (let i = 0; i < packet.length; i++) {
        const modified = bytes(packet); modified[i] ^= 1
        assert.equal(server.decrypt_488(modified), undefined)
      }
      assert.equal(server.decrypt_488(B.Buffer.concat([packet, bytes([0])])), undefined)
      assert.equal(server.decrypt_488(packet).toString(), 'hello')
    })
    it('accepts iosignal E2E routing headers without decrypting the opaque tail', () => {
      const {client, server} = pair()
      const routingHeader = bytes([0x42, 1, 120, 0])
      const encryptedHeader = client.encrypt_488(routingHeader)
      encryptedHeader[0] = B.BohoMsg.ENC_E2E
      const opaqueBody = client.encrypt_e2e('body', 'separate-key')
      const wire = B.Buffer.concat([encryptedHeader, opaqueBody])
      const originalWire = bytes(wire)
      const truncated = wire.subarray(0, B.MetaSize.ENC_488 - 1)
      assert.equal(server.decrypt_488(truncated), undefined)
      const badLength = bytes(wire); badLength.writeUInt32LE(wire.length, 1)
      assert.equal(server.decrypt_488(badLength), undefined)
      const badTag = bytes(wire); badTag[13] ^= 1
      assert.equal(server.decrypt_488(badTag), undefined)
      assert.deepEqual(Array.from(server.decrypt_488(wire)), Array.from(routingHeader))
      assert.deepEqual(Array.from(wire), Array.from(originalWire))
      assert.deepEqual(Array.from(server.decrypt_488(wire)), Array.from(routingHeader))
      assert.equal(server.decrypt_e2e(opaqueBody, 'separate-key').data.toString(), 'body')
    })
    it('leaves replay and delivery-order policy to iosignal', () => {
      const {client, server} = pair()
      const first = client.encrypt_488('first'), second = client.encrypt_488('second')
      assert.equal(server.decrypt_488(second).toString(), 'second')
      assert.equal(server.decrypt_488(first).toString(), 'first')
      assert.equal(server.decrypt_488(second).toString(), 'second')
    })
    it('leaves authentication request reuse policy to iosignal', () => {
      const {server, request, client} = pair()
      server.set_key('shared-test-key')
      const response = server.verify_auth_req(request)
      assert.ok(response)
      assert.equal(client.verify_auth_res(response), true)
      assert.equal(server.isAuthorized, true)
    })
    it('rejects malformed auth messages and full-length forged responses', () => {
      const c = new B(), s = new B(); c.set_key('key'); s.set_key('key')
      const challenge = s.server_time_nonce()
      const wrongChallenge = bytes(challenge); wrongChallenge[0] ^= 1
      assert.equal(c.auth_req(wrongChallenge), false)
      assert.equal(c.auth_req(challenge.subarray(0, 12)), false)
      const request = c.auth_req(challenge)
      for (const bad of [null, {}, request.subarray(0, 44), B.Buffer.concat([request, bytes([0])])]) {
        assert.equal(s.verify_auth_req(bad), false)
      }
      const wrongRequest = bytes(request); wrongRequest[0] ^= 1
      assert.equal(s.verify_auth_req(wrongRequest), false)
      const response = s.verify_auth_req(request)
      const wrongResponse = bytes(response); wrongResponse[1] ^= 1
      assert.ok(!c.verify_auth_res(wrongResponse)); assert.equal(c.isAuthorized, false)
      const wrongType = bytes(response); wrongType[0] ^= 1
      assert.ok(!c.verify_auth_res(wrongType))
      assert.equal(c.verify_auth_res(response), true)
    })
    it('preserves authorization when iosignal reloads the connection key', () => {
      const {client, server} = pair()
      client.set_key('shared-test-key')
      assert.equal(client.isAuthorized, true)
      assert.equal(server.decrypt_488(client.encrypt_488('reloaded')).toString(), 'reloaded')
      server.copy_key(B.sha256.hash('shared-test-key'))
      assert.equal(server.isAuthorized, true)
      assert.equal(client.decrypt_488(server.encrypt_488('reply')).toString(), 'reply')
      // Caller starts reauthentication explicitly, just as it does on reconnect.
      client.isAuthorized = false; server.isAuthorized = false
      const request = client.auth_req(server.server_time_nonce())
      assert.equal(client.verify_auth_res(server.verify_auth_req(request)), true)
    })
    it('restores E2E state on success, rejection and thrown errors', () => {
      const {client, server} = pair()
      const before = Array.from(client._otpSrc44)
      const packet = client.encrypt_e2e('e2e payload', 'e2e key')
      assert.equal(client.decrypt_e2e(packet, 'e2e key').data.toString(), 'e2e payload')
      assert.equal(client.decrypt_e2e(bytes([B.BohoMsg.ENC_PACK]), 'e2e key'), undefined)
      const original = client.decryptPack
      client.decryptPack = () => { throw new Error('forced failure') }
      assert.throws(() => client.decrypt_e2e(packet, 'e2e key'), /forced failure/)
      client.decryptPack = original
      assert.deepEqual(Array.from(client._otpSrc44), before)
      assert.equal(client.isAuthorized, true)
      assert.equal(server.decrypt_488(client.encrypt_488('still works')).toString(), 'still works')
      const keyless = new B(); keyless.encrypt_e2e('hello', 'temporary')
      assert.throws(() => keyless.encryptPack('hello'), /key/i)
    })
    it('keeps sending clocks monotonic through rollback and counter wrap', () => {
      const b = new B(); b.set_key('key')
      b._lastSendTime = Date.now() + 10000; b.counter = 65535
      const lastTime = b._lastSendTime
      b.set_clock_nonce(bytes([1, 2, 3, 4]))
      assert.equal(b._lastSendTime, lastTime + 1)
      assert.equal(b.counter, 0)
      const before = b._lastSendTime
      b.set_clock_nonce(bytes([1, 2, 3, 4]))
      assert.equal(b._lastSendTime, before)
      assert.equal(b.counter, 1)
    })
  })
}

it('both distribution source maps include the installed meta-buffer-pack build', () => {
  const installed = readFileSync(new URL('../node_modules/meta-buffer-pack/dist/meta-buffer-pack.js', import.meta.url), 'utf8')
  for (const file of ['boho.js.map', 'boho.min.js.map']) {
    const map = JSON.parse(readFileSync(new URL(`../dist/${file}`, import.meta.url)))
    assert.ok(map.sourcesContent.includes(installed), file)
  }
})
