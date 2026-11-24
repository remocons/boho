// The Boho class (src/boho.js, the package's default export) against the shared vectors,
// JS client ↔ JS server, and the JS server ↔ the Arduino C++ Boho class.
import { before, after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import readline from 'node:readline'
import Default from '../src/index.js'
import Dist from '../dist/boho.js'
import { Boho, BohoMsg, deriveKey } from '../src/boho.js'

const hex = b => Buffer.from(b).toString('hex')
const unhex = h => new Uint8Array(Buffer.from(h, 'hex'))
const vectors = JSON.parse(readFileSync(new URL('./fixtures/boho-vectors.json', import.meta.url), 'utf8'))

function loggedIn (login = vectors.logins[0]) {
  const client = new Boho(); client.set_id8(login.id); client.set_key(login.key)
  const server = new Boho(); server.copy_key(deriveKey(login.key))
  const req = client.auth_req(unhex(login.challenge), unhex(login.clientNonce))
  const res = server.verify_auth_req(req, unhex(login.challenge))
  assert.ok(res && client.verify_auth_res(res))
  return { client, server, req, res }
}

describe('Boho class', () => {
  it('is exported from the package and the build', () => {
    assert.equal(Default, Boho)
    assert.equal(typeof Dist, 'function')
    assert.equal(Dist.deriveKey('x').length, 16)
    assert.equal(Default.BohoMsg.ENC, 0xbb)
    assert.equal(Default.BohoMsg[0xb4], 'AUTH_REQ')
    assert.equal(Default.MetaSize.ENC_PACK, 29)
    assert.equal(typeof Default.ascon.cxof128, 'function')
    assert.equal(Default.RAND(5).length, 5)
  })

  it('keys and logins match the vectors on both sides', () => {
    for (const k of vectors.keys) assert.equal(hex(deriveKey(k.key)), k.derived)
    for (const l of vectors.logins) {
      const { client, server, req, res } = loggedIn(l)
      assert.equal(hex(req), l.authReq)
      assert.equal(hex(res), l.authRes)
      assert.ok(client.isAuthorized && server.isAuthorized)
    }
  })

  it('the client opens server messages of the vectors and refuses the invalid ones', () => {
    const { client, server } = loggedIn()
    for (const m of vectors.messages) {
      const side = m.dir === 2 ? client : server
      const opened = side.decrypt_session(unhex(m.packet))
      assert.equal(hex(opened), m.plaintext)
    }
    for (const c of vectors.invalid.filter(c => c.kind === 'message')) {
      const login = vectors.logins.find(l => l.sessionKey === c.sessionKey)
      const pair = login === vectors.logins[0] ? { client, server } : loggedIn(login)
      const side = c.dir === 2 ? pair.client : pair.server
      assert.equal(side.decrypt_session(unhex(c.packet)), undefined, c.reason)
    }
  })

  it('packs of the vectors open, the invalid ones do not', () => {
    const b = new Boho()
    for (const p of vectors.packs) assert.equal(hex(b.decrypt_e2e(unhex(p.packet), p.key).data), p.plaintext)
    for (const c of vectors.invalid.filter(c => c.kind === 'pack')) assert.equal(b.decrypt_e2e(unhex(c.packet), c.key), undefined, c.reason)
  })

  it('refuses wrong logins', () => {
    const l = vectors.logins[0]
    for (const c of vectors.invalid.filter(c => c.kind === 'authReq')) {
      const server = new Boho(); server.copy_key(deriveKey(c.key))
      assert.equal(server.verify_auth_req(unhex(c.packet), unhex(c.challenge)), false, c.reason)
      assert.equal(server.isAuthorized, false)
    }
    for (const c of vectors.invalid.filter(c => c.kind === 'authRes')) {
      const client = new Boho(); client.set_id8(l.id); client.set_key(l.key)
      client.auth_req(unhex(l.challenge), unhex(l.clientNonce))
      assert.equal(client.verify_auth_res(unhex(c.packet)), undefined, c.reason)
    }
    const bad = unhex(l.challenge); bad[5] = 0xe8; bad[6] = 0x03
    assert.equal(new Boho().auth_req(bad), false)
    const c = new Boho(); c.set_id_key('dev1.secret')
    assert.equal(c.auth_req(bad), false)
    assert.ok(c.auth_req(unhex(l.challenge)))  // random nonce
  })

  it('JS client ↔ JS server: messages both ways, E2E header, strictly increasing clock', () => {
    const { client, server } = loggedIn()
    let last = -1n
    for (let n = 0; n < 50; n++) {
      const data = Buffer.from(Array.from({ length: n }, (_, i) => i))
      const up = client.encrypt_session(data)
      assert.equal(up.length, 21 + n)
      assert.equal(hex(server.decrypt_session(up)), hex(data))
      assert.equal(server.decrypt_session(up.subarray(0, up.length - 1)), undefined)
      const down = server.encrypt_session(data)
      assert.equal(hex(client.decrypt_session(down)), hex(data))
      assert.equal(client.decrypt_session(up), undefined, 'own direction refused')
      const view = new DataView(up.buffer, up.byteOffset)
      const tuple = (BigInt(view.getUint32(5, true)) * 1000n + BigInt(view.getUint16(9, true))) * 65536n + BigInt(view.getUint16(11, true))
      assert.ok(tuple > last); last = tuple
    }
    const head = client.encrypt_session(Buffer.from([0xd2, 1, 0x78]), BohoMsg.ENC_E2E)
    const body = client.encrypt_e2e('hello', 'e2e-key')
    const packet = Buffer.concat([head, body])
    assert.deepEqual([...server.decrypt_session(packet)], [0xd2, 1, 0x78])
    assert.equal(server.decrypt_e2e(packet.subarray(21 + 3), 'e2e-key').data.toString(), 'hello')
    assert.equal(client.encrypt_session('x', 0xb8), undefined)
    client.set_key('other')
    assert.equal(client.encrypt_session('x'), undefined, 'new key ends the session')
  })
})

// JS server ↔ the Arduino C++ Boho class (host build).
const directory = fileURLToPath(new URL('.', import.meta.url))
// The Arduino Boho is part of the IOSignal Arduino library (iosignal-arduino/src) since Boho 3.
const src = process.env.BOHO_ARDUINO_SRC || resolve(directory, '../../iosignal-arduino/src')
const host = String.raw`
#include "Boho.h"
#include <cstdio>
#include <string>
#include <vector>
uint32_t millis() { static uint32_t t = 0; return t += 3; }
uint32_t micros() { static uint32_t t = 0; return t += 17; }
static std::vector<uint8_t> hex(const char *s) { std::vector<uint8_t> v; unsigned x; while (s[0] && s[1] && std::sscanf(s, "%2x", &x) == 1) { v.push_back(x); s += 2; } return v; }
static void put(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; ++i) std::printf("%02x", p[i]); std::printf("\n"); std::fflush(stdout); }
int main() {
  Boho b; char op[16]; static char arg[8192];
  while (std::scanf("%15s %8191s", op, arg) == 2) {
    std::string o(op); auto in = hex(strcmp(arg, "-") ? arg : "");
    std::vector<uint8_t> out(in.size() + 64);
    if (o == "IDKEY") { b.set_id_key(arg); std::printf("ok\n"); std::fflush(stdout); }
    else if (o == "AUTH") { int n = b.auth_req(out.data(), in.data(), in.size()); put(out.data(), n); }
    else if (o == "RES") { std::printf(b.verify_auth_res(in.data(), in.size()) ? "ok\n" : "fail\n"); std::fflush(stdout); }
    else if (o == "SEND" || o == "SENDE2E") { uint32_t n = b.encrypt_session(out.data(), in.data(), in.size(), o == "SEND" ? Boho::ENC : Boho::ENC_E2E); put(out.data(), n); }
    else if (o == "OPEN") { uint32_t n; if (b.decrypt_session(out.data(), in.data(), in.size(), n)) put(out.data(), n); else { std::printf("fail\n"); std::fflush(stdout); } }
    else if (o == "PACK") { uint32_t n = b.encrypt_e2e(out.data(), in.data(), in.size(), "e2e-key"); put(out.data(), n); }
    else if (o == "UNPACK") { uint32_t n; if (b.decrypt_e2e(out.data(), in.data(), in.size(), "e2e-key", n)) put(out.data(), n); else { std::printf("fail\n"); std::fflush(stdout); } }
  }
}
`

describe('JS server ↔ Arduino C++ Boho', { skip: !existsSync(join(src, 'BohoAscon.cpp')) && 'Arduino Boho (Ascon) not found: set BOHO_ARDUINO_SRC' }, () => {
  let build, executable
  before(() => {
    build = mkdtempSync(join(tmpdir(), 'boho-host-'))
    executable = join(build, 'host')
    writeFileSync(join(build, 'Arduino.h'), '#pragma once\n#include <cstdint>\n#include <cstddef>\n#include <cstring>\nuint32_t millis();\nuint32_t micros();\n')
    writeFileSync(join(build, 'host.cpp'), host)
    const r = spawnSync('c++', ['-std=c++17', '-O1', '-I', build, '-I', src, join(build, 'host.cpp'),
      join(src, 'Boho.cpp'), join(src, 'BohoAscon.cpp'), '-o', executable], { encoding: 'utf8', timeout: 60000 })
    assert.equal(r.status, 0, r.stderr || String(r.error))
  })
  after(() => { if (build) rmSync(build, { recursive: true, force: true }) })

  it('logs in with a random nonce and exchanges ENC, ENC_E2E and ENC_PACK both ways', async () => {
    const child = spawn(executable, [], { stdio: ['pipe', 'pipe', 'inherit'] })
    const lines = readline.createInterface({ input: child.stdout })[Symbol.asyncIterator]()
    const ask = async (op, arg = '-') => { const next = lines.next(); child.stdin.write(`${op} ${arg}\n`); return (await next).value }
    try {
      const server = new Boho(); server.copy_key(deriveKey('shared-secret'))
      const challenge = server.server_time_nonce()
      assert.equal(await ask('IDKEY', 'dev7.shared-secret'), 'ok')
      const req = unhex(await ask('AUTH', hex(challenge)))
      assert.equal(req.length, 33)
      const res = server.verify_auth_req(req)
      assert.ok(res, 'server accepts the Arduino login')
      assert.equal(Buffer.from(req.subarray(1, 9)).toString().replace(/\0+$/, ''), 'dev7')
      assert.equal(await ask('RES', hex(res)), 'ok')
      for (const size of [0, 1, 15, 16, 17, 59, 200]) {
        const data = Buffer.from(Array.from({ length: size }, (_, i) => (i * 7) & 255))
        const up = unhex(await ask('SEND', hex(data) || '-'))
        assert.equal(hex(server.decrypt_session(up)), hex(data))
        const down = server.encrypt_session(data)
        assert.equal(await ask('OPEN', hex(down)), hex(data))
      }
      const head = unhex(await ask('SENDE2E', 'd20178'))
      assert.equal(hex(server.decrypt_session(head)), 'd20178')
      const pack = unhex(await ask('PACK', hex(Buffer.from('on=1'))))
      assert.equal(server.decrypt_e2e(pack, 'e2e-key').data.toString(), 'on=1')
      assert.equal(await ask('UNPACK', hex(server.encrypt_e2e('off', 'e2e-key'))), hex(Buffer.from('off')))
      const forged = server.encrypt_session('x'); forged[14] ^= 1
      assert.equal(await ask('OPEN', hex(forged)), 'fail')
      assert.equal(await ask('RES', hex(res)), 'fail', 'AUTH_RES only once')
    } finally { child.stdin.end(); child.kill(); await lines.return() }
  })
})
