// The key and authentication buffers are made on first use, as views into one block.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import Boho from '../src/index.js'

const FIELDS = ['_id8', '_otpSrc44', '_otp36', '_hmac', 'auth_salt12', 'localNonce', 'remoteNonce']
const SIZES = [8, 44, 36, 32, 12, 4, 4]

function authorizedPair() {
  const client = new Boho(), server = new Boho()
  client.set_id8('lazy-id'); client.set_key('lazy-key')
  const request = client.auth_req(server.server_time_nonce())
  server.set_key('lazy-key')
  assert.equal(client.verify_auth_res(server.verify_auth_req(request)), true)
  return { client, server }
}

describe('Boho key and authentication state', () => {
  it('holds no buffers until first used', () => {
    const boho = new Boho()
    assert.equal(boho._block, null); assert.equal(boho._state, null)
    boho.clearAuth()
    assert.equal(boho._block, null, 'clearAuth on an unused instance allocates nothing')
    assert.equal(boho.isAuthorized, false)
  })

  it('gives zeroed, separate views of the documented sizes', () => {
    const boho = new Boho()
    FIELDS.forEach((name, i) => {
      assert.equal(boho[name].length, SIZES[i], name)
      assert.ok(boho[name].every(byte => byte === 0), `${name} starts zeroed`)
    })
    FIELDS.forEach(name => boho[name].fill(0xff))
    FIELDS.forEach(name => assert.ok(boho[name].every(byte => byte === 0xff), `${name} not overwritten by a neighbour`))
    boho.clearAuth()
    FIELDS.forEach(name => assert.ok(boho[name].every(byte => byte === 0), `${name} cleared`))
  })

  it('keeps a replaced buffer and clears it', () => {
    const boho = new Boho()
    const nonce = Boho.Buffer.from([1, 2, 3, 4])
    boho.localNonce = nonce
    assert.equal(boho.localNonce, nonce)
    boho.clearAuth()
    assert.deepEqual([...nonce], [0, 0, 0, 0])
  })

  it('a login challenge alone writes the block without field views', () => {
    const server = new Boho(), before = Math.floor(Date.now() / 1000)
    const pack = server.server_time_nonce()
    assert.equal(server._state, null, 'no field views')
    assert.equal(server._block.length, 140)
    assert.equal(pack.length, 13)
    const salt = pack.subarray(1)
    assert.ok(Math.abs(salt.readUInt32LE(0) - before) <= 1, 'unix time')
    assert.ok(salt.readUInt16LE(4) < 1000, 'milliseconds')
    // Reading the fields later sees the same challenge.
    assert.deepEqual([...server.auth_salt12], [...salt])
    assert.deepEqual([...server.localNonce], [...salt.subarray(8, 12)])
    // Two challenges differ in their random bytes.
    const other = new Boho().server_time_nonce()
    assert.notDeepEqual([...other.subarray(7)], [...salt.subarray(6)])
  })

  it('a new challenge after a login replaces the fields', () => {
    const { server } = authorizedPair()
    const pack = server.server_time_nonce()
    assert.deepEqual([...server.auth_salt12], [...pack.subarray(1)])
    assert.deepEqual([...server.localNonce], [...pack.subarray(9, 13)])
    const client = new Boho()
    client.set_id8('lazy-id'); client.set_key('lazy-key')
    assert.equal(client.verify_auth_res(server.verify_auth_req(client.auth_req(pack))), true)
  })

  it('instances do not share state', () => {
    const a = new Boho(), b = new Boho()
    a._id8.fill(7)
    assert.ok(b._id8.every(byte => byte === 0))
  })

  it('authenticates and encrypts both ways, also after clearAuth and a new login', () => {
    for (let round = 0; round < 2; round++) {
      const { client, server } = authorizedPair()
      const fromClient = server.decrypt_488(client.encrypt_488(Boho.Buffer.from('hello server')))
      assert.equal(Boho.Buffer.from(fromClient).toString(), 'hello server')
      const fromServer = client.decrypt_488(server.encrypt_488(Boho.Buffer.from('hello client')))
      assert.equal(Boho.Buffer.from(fromServer).toString(), 'hello client')
      client.clearAuth(); server.clearAuth()
      assert.equal(client.isAuthorized, false)
    }
  })

  it('E2E on an instance that never authenticated', () => {
    const sender = new Boho(), receiver = new Boho()
    const pack = sender.encrypt_e2e(Boho.Buffer.from('payload'), 'e2e-key')
    assert.equal(Boho.Buffer.from(receiver.decrypt_e2e(pack, 'e2e-key').data).toString(), 'payload')
    assert.equal(receiver.decrypt_e2e(pack, 'wrong-key'), undefined)
  })
})
