import { before, after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import readline from 'node:readline'
import vm from 'node:vm'
import Source from '../../src/index.js'
import Distribution from '../../dist/boho.js'

const directory = fileURLToPath(new URL('.', import.meta.url))
const arduino = process.env.BOHO_ARDUINO_PATH || resolve(directory, '../../../boho-arduino')
let build, executable
before(() => {
  build = mkdtempSync(join(tmpdir(), 'boho-arduino-'))
  executable = join(build, 'interop')
  const args = ['-std=c++11', '-Wno-deprecated-declarations', '-I', join(directory, 'shims'), '-I', join(arduino, 'src'),
    join(directory, 'host.cpp'), join(arduino, 'src/Boho.cpp'), '-o', executable]
  if (process.platform !== 'darwin') args.push('-lcrypto')
  const result = spawnSync('c++', args, { encoding: 'utf8', timeout: 30000 })
  assert.equal(result.status, 0, result.stderr || String(result.error))
})
after(() => { if (build) rmSync(build, { recursive: true, force: true }) })

async function withPeer(run) {
  const child = spawn(executable, [], { stdio: ['pipe', 'pipe', 'pipe'] })
  const lines = readline.createInterface({ input: child.stdout })[Symbol.asyncIterator]()
  const ask = async (command, value = '') => {
    const reply = lines.next()
    child.stdin.write(`${command} ${typeof value === 'string' ? value : Buffer.from(value).toString('hex')}\n`)
    const line = await reply
    assert.equal(line.done, false, 'C++ peer closed unexpectedly')
    return line.value
  }
  try { await run(ask) } finally { child.stdin.end(); child.kill(); await lines.return() }
}

const browser = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer }
vm.runInNewContext(readFileSync(new URL('../../dist/boho.min.js', import.meta.url), 'utf8'), browser)
for (const [name, B] of [['source', Source], ['ESM', Distribution], ['UMD', browser.Boho]]) {
  describe(`${name} ↔ unchanged Arduino Boho.cpp`, { timeout: 10000 }, () => {
    it('exchanges normal and E2E packets in both directions', async () => withPeer(async ask => {
      const b = new B(); b.set_key('interop-shared-key')
      for (const size of [1, 31, 32, 33, 257]) {
        const plain = B.Buffer.from(Array.from({length: size}, (_, i) => i & 255))
        const encoded = B.Buffer.from(await ask('PACK', plain), 'hex')
        assert.equal(b.decryptPack(encoded).data.toString('hex'), plain.toString('hex'))
        assert.equal(await ask('UNPACK', b.encryptPack(plain)), plain.toString('hex'))
        const e2e = B.Buffer.from(await ask('E2E', plain), 'hex')
        assert.equal(b.decrypt_e2e(e2e, 'interop-e2e-key').data.toString('hex'), plain.toString('hex'))
        assert.equal(await ask('DE2E', b.encrypt_e2e(plain, 'interop-e2e-key')), plain.toString('hex'))
      }
    }))
    it('authenticates the Arduino client and exchanges 488 packets', async () => withPeer(async ask => {
      const server = new B(); server.set_key('interop-shared-key')
      const request = B.Buffer.from(await ask('AUTH', server.server_time_nonce()), 'hex')
      const response = server.verify_auth_req(request)
      assert.ok(response)
      assert.equal(await ask('VERIFY', response), '1')
      for (const size of [1, 31, 32, 33, 257]) {
        const plain = B.Buffer.alloc(size, 0x5a)
        const packet = B.Buffer.from(await ask('SEND', plain), 'hex')
        assert.equal(server.decrypt_488(packet).toString('hex'), plain.toString('hex'))
        assert.equal(server.decrypt_488(packet).toString('hex'), plain.toString('hex'))
        assert.equal(await ask('RECV', server.encrypt_488(plain)), plain.toString('hex'))
      }
    }))
    it('accepts Arduino counter wrap and clock resynchronization', async () => withPeer(async ask => {
      const server = new B(); server.set_key('interop-shared-key')
      const challenge = server.server_time_nonce()
      // The challenge counter seeds the Arduino sender; force wrap on send 2.
      challenge.writeUInt16LE(65534, 7)
      server.auth_salt12 = B.Buffer.from(challenge.subarray(1))
      const request = B.Buffer.from(await ask('AUTH', challenge), 'hex')
      assert.equal(await ask('VERIFY', server.verify_auth_req(request)), '1')
      const plain = B.Buffer.from('counter wrap')
      for (const expected of [65535, 0, 1]) {
        const packet = B.Buffer.from(await ask('SEND', plain), 'hex')
        assert.equal(packet.readUInt16LE(11), expected)
        assert.equal(server.decrypt_488(packet).toString(), plain.toString())
      }
      await ask('TIME', '100 0')
      const oldClockPacket = B.Buffer.from(await ask('SEND', plain), 'hex')
      assert.equal(server.decrypt_488(oldClockPacket).toString(), plain.toString())
    }))
  })
}
