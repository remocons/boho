// Ascon prototype tests: official NIST SP 800-232 KATs and a cross-check with the
// Arduino C++ Ascon (BohoAscon.cpp in the IOSignal Arduino library).
// Run: npm run test:ascon
import { before, after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as ascon from '../src/ascon.js'

const hex = b => Buffer.from(b).toString('hex').toUpperCase()
const unhex = h => new Uint8Array(Buffer.from(h, 'hex'))

// Records copied from the ascon-c reference repository:
// crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt
const KEY = '000102030405060708090A0B0C0D0E0F'
const NONCE = '101112131415161718191A1B1C1D1E1F'
const AEAD = [  // Count, PT, AD, CT||tag
  [1, '', '', '4F9C278211BEC9316BF68F46EE8B2EC6'],
  [2, '', '30', 'CCCB674FE18A09A285D6AB11B35675C0'],
  [17, '', '303132333435363738393A3B3C3D3E3F', 'E4230CDB8330EE9DC0CFD7C7B346E6DC'],
  [33, '', '303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F', 'EFC3E78B02AD9A80A6F0548C5B0BB5BA'],
  [34, '20', '', 'E8DD576ABA1CD3E6FC704DE02AEDB79588'],
  [50, '20', '303132333435363738393A3B3C3D3E3F', '638BBACE2C82A050832E46B3224A9552A0'],
  [100, '202122', '', 'E8C3DEAF8E12816B8EDF39AD1571A9492B7CA2'],
  [290, '2021222324252627', '303132333435363738393A3B3C3D3E3F404142434445464748',
    '16CB13E5853541E2B38396BE456C486F26932ED701D9ADA8'],
  [512, '202122232425262728292A2B2C2D2E', '303132333435363738393A3B3C3D3E3F',
    '6373EBB28BE97C9BAC090CF399C13E646BE0C80B0404770341EB48D6178948'],
  [1089, '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F',
    '303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F',
    'CB34D04660A66DBFBE9C856601F5B8AA51A499B55AC8F7FBEFBC331A613EE9CDFD191750A47F211C0A15ED28173D7CAA']
]
// crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt
const HASH = [
  [1, '', '0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2'],
  [2, '00', '0728621035AF3ED2BCA03BF6FDE900F9456F5330E4B5EE23E7F6A1E70291BC80'],
  [9, '0001020304050607', 'B88E497AE8E6FB641B87EF622EB8F2FCA0ED95383F7FFEBE167ACF1099BA764F'],
  [17, '000102030405060708090A0B0C0D0E0F', '3158C1940A2FBADBD68AB661777859B94A689E4EFC375911467ADDD641835C38'],
  [33, '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    'BD9D3D60A66B53868EAB2A5C74539A518A1F60F01EB176C60E43DEE81680B33E'],
  [65, '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F' +
    '202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F',
    'A6F241BEA5D16405812C06019D9F72D60132BD7C089C60549B2E56BB01C64F48']
]
// crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt
const XOF = [
  [1, '', '473D5E6164F58B39DFD84AACDB8AE42EC2D91FED33388EE0D960D9B3993295C6' +
    'AD77855A5D3B13FE6AD9E6098988373AF7D0956D05A8F1665D2C67D1A3AD10FF'],
  [2, '00', '51430E0438ECDF642B393630D977625F5F337656BA58AB1E960784AC32A16E0D' +
    '446405551F5469384F8EA283CF12E64FA72C426BFEBAEA3AA1529E2C4AB23A2F'],
  [9, '0001020304050607', '8D1886F5D3EC4AF8D15B44BC62B74DA6EA91BC28FB82F9C34079B5ED6E38B6C9' +
    '51803D7DFB3C5E512A0EF5E4060062A6FD067F9C73EF9BEE527411BDA67FC896'],
  [17, '000102030405060708090A0B0C0D0E0F', '10BFEDC5F6442D3E1D8C324878CE1DDF73B01CAFC365589283AC4CBB98E48DE3' +
    'CEDA8A41BB0983D539E4D90F6458C5C781724FAD641ED3CDB4779931097440B3'],
  [33, '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    '2E5F3403F4171471CC7934B51982CECE8D6628435DB70E89880F3BE4E0B7B052' +
    '32DFE63C44A836D771337C9C5A2688D1B71ECABE0D5C2006FEF36EF3186138AD']
]

// crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt: Count, Msg, Z, MD
const CXOF = [
  [1, '', '', '4F50159EF70BB3DAD8807E034EAEBD44C4FA2CBBC8CF1F05511AB66CDCC52990' +
    '5CA12083FC186AD899B270B1473DC5F7EC88D1052082DCDFE69FB75D269E7B74'],
  [2, '', '10', '0C93A483E7D574D49FE52CCE03EE646117977D57A8AA57704AB4DAF44B501430' +
    'FF6AC11A5D1FD6F2154B5C65728268270C8BB578508487B8965718ADA6272FD6'],
  [3, '', '1011', 'D1106C7622E79FE955BD9D79E03B918E770FE0E0CDDDE28BEB924B02C5FC936B' +
    '33ACCA299C89ECA5D71886CBBFA4D54A21C55FDE2B679F5E2488063A1719DC32'],
  [18, '', '101112131415161718191A1B1C1D1E1F20', 'F74D02F0215E2C5E71A89E2315A533F64843223A368DF68B0F2D3603BDBA664F' +
    '2297ABD5EA4EDF25004D7C7E1093C53212EB7C231A6142AA9FBE3A74CFF7A378'],
  [34, '00', '', '7F0C0DDD4BC9603DEED19510CDB954D65CF254F59234BFBF5A730D03D2712DAA' +
    'B9161C6553F65FA72A25B3174AC13A33218C393577A85B6D6F4319D1EF8A7541'],
  [232, '00010203040506', '', 'AA04B2E280D626F649EBC9E6E09BDCB1ED4B4669647FA727064ECE4C913E2D62' +
    'F380F31B1B4EB19AB61C77BB49F533DF1E4FDDBA97CDE8315411A85A178E940B'],
  [307, '000102030405060708', '101112131415161718', '75BA4455E500E37946C81FDDF6A5E168A94F18D1B31C7927D109736A8A33887E' +
    '3D7E189E569ACD8508F075E06E89C72877AFB39133EFE2A518DF33BD6D2499CA']
]

describe('Ascon KAT (NIST SP 800-232)', () => {
  for (const [count, pt, ad, ct] of AEAD) {
    it(`AEAD128 Count ${count}`, () => {
      const key = unhex(KEY); const nonce = unhex(NONCE)
      assert.equal(hex(ascon.encrypt(key, nonce, unhex(pt), unhex(ad))), ct)
      assert.equal(hex(ascon.decrypt(key, nonce, unhex(ct), unhex(ad))), pt)
    })
  }
  for (const [count, msg, md] of HASH) {
    it(`Hash256 Count ${count}`, () => assert.equal(hex(ascon.hash256(unhex(msg))), md))
  }
  for (const [count, msg, md] of XOF) {
    it(`XOF128 Count ${count}`, () => {
      assert.equal(hex(ascon.xof128(unhex(msg), 64)), md)
      for (const n of [0, 1, 7, 8, 9, 31, 33]) assert.equal(hex(ascon.xof128(unhex(msg), n)), md.slice(0, 2 * n))
    })
  }
})

describe('Ascon CXOF128', () => {
  for (const [count, msg, z, md] of CXOF) {
    it(`KAT Count ${count}`, () => {
      assert.equal(hex(ascon.cxof128(unhex(msg), 64, unhex(z))), md)
      for (const n of [0, 1, 8, 9, 33]) assert.equal(hex(ascon.cxof128(unhex(msg), n, unhex(z))), md.slice(0, 2 * n))
    })
  }
  it('differs from XOF128 and refuses a customization string over 256 bytes', () => {
    assert.notEqual(hex(ascon.cxof128('', 32, '')), hex(ascon.xof128('', 32)))
    assert.equal(ascon.cxof128('a', 16, new Uint8Array(256)).length, 16)
    assert.throws(() => ascon.cxof128('a', 16, new Uint8Array(257)), RangeError)
  })
})

describe('Ascon AEAD128 behaviour', () => {
  const key = unhex(KEY); const nonce = unhex(NONCE)
  const [, pt, ad, ct] = AEAD.at(-1)

  it('rejects changed tag, ciphertext, AD, nonce and key', () => {
    const sealed = unhex(ct)
    const flip = (b, i) => { const c = b.slice(); c[i] ^= 1; return c }
    assert.equal(ascon.decrypt(key, nonce, flip(sealed, sealed.length - 1), unhex(ad)), null)
    assert.equal(ascon.decrypt(key, nonce, flip(sealed, 0), unhex(ad)), null)
    assert.equal(ascon.decrypt(key, nonce, sealed, flip(unhex(ad), 3)), null)
    assert.equal(ascon.decrypt(key, flip(nonce, 15), sealed, unhex(ad)), null)
    assert.equal(ascon.decrypt(flip(key, 0), nonce, sealed, unhex(ad)), null)
    assert.equal(ascon.decrypt(key, nonce, sealed.subarray(0, 15), unhex(ad)), null)
  })

  it('truncated tags are prefixes of the full tag', () => {
    const sealed8 = ascon.encrypt(key, nonce, unhex(pt), unhex(ad), 8)
    assert.equal(hex(sealed8), ct.slice(0, 2 * (32 + 8)))
    assert.equal(hex(ascon.decrypt(key, nonce, sealed8, unhex(ad), 8)), pt)
    assert.throws(() => ascon.encrypt(key, nonce, '', '', 3), RangeError)
    assert.throws(() => ascon.decrypt(key, nonce, sealed8, '', 17), RangeError)
  })

  it('accepts strings and typed arrays, checks key and nonce sizes', () => {
    const a = ascon.encrypt(key, nonce, 'hello', 'hdr')
    const b = ascon.encrypt(key.buffer, new Uint16Array(nonce.buffer), Buffer.from('hello'), Buffer.from('hdr'))
    assert.deepEqual(a, b)
    assert.equal(new TextDecoder().decode(ascon.decrypt(key, nonce, a, 'hdr')), 'hello')
    assert.throws(() => ascon.encrypt(key.subarray(1), nonce, ''), RangeError)
    assert.throws(() => ascon.encrypt(key, nonce.subarray(1), ''), RangeError)
    assert.throws(() => ascon.encrypt(key, nonce, 12), TypeError)
  })

  it('round-trips every length 0..80 with AD lengths 0..40', () => {
    const data = randomBytes(80)
    for (let n = 0; n <= 80; n++) {
      for (let a = 0; a <= 40; a += 5) {
        const sealed = ascon.encrypt(key, nonce, data.subarray(0, n), data.subarray(0, a))
        assert.deepEqual(ascon.decrypt(key, nonce, sealed, data.subarray(0, a)), new Uint8Array(data.subarray(0, n)))
      }
    }
  })
})

// Cross-check with the Arduino C++ prototype on random inputs.
const directory = fileURLToPath(new URL('.', import.meta.url))
const prototype = process.env.BOHO_ARDUINO_SRC || resolve(directory, '../../iosignal-arduino/src')
const cppHost = String.raw`
#include "BohoAscon.h"
#include <cstdio>
#include <cstring>
#include <vector>
static std::vector<uint8_t> readHex() {
  char text[4096]; if (std::scanf("%4095s", text) != 1) return {};
  std::vector<uint8_t> v; if (!std::strcmp(text, "-")) return v;
  for (size_t i = 0; text[i] && text[i + 1]; i += 2) { unsigned x; std::sscanf(text + i, "%2x", &x); v.push_back((uint8_t)x); }
  return v;
}
static void printHex(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; ++i) std::printf("%02X", p[i]); std::printf("\n"); }
int main() {
  char op[8];
  while (std::scanf("%7s", op) == 1) {
    if (op[0] == 'E') {  // E key nonce ad pt -> ct||tag
      auto k = readHex(), n = readHex(), a = readHex(), p = readHex();
      std::vector<uint8_t> out(p.size() + 16);
      ascon_aead128_encrypt(out.data(), out.data() + p.size(), p.data(), p.size(), a.data(), a.size(), k.data(), n.data());
      printHex(out.data(), out.size());
    } else if (op[0] == 'D') {  // D key nonce ad ct||tag -> pt or FAIL
      auto k = readHex(), n = readHex(), a = readHex(), c = readHex();
      size_t len = c.size() - 16; std::vector<uint8_t> out(len + 1);
      if (ascon_aead128_decrypt(out.data(), c.data(), len, a.data(), a.size(), c.data() + len, 16, k.data(), n.data())) printHex(out.data(), len);
      else std::printf("FAIL\n");
    } else if (op[0] == 'H') { auto m = readHex(); uint8_t d[32]; ascon_hash256(d, m.data(), m.size()); printHex(d, 32); }
    else if (op[0] == 'C') { unsigned len; auto m = readHex(); auto z = readHex(); std::scanf("%u", &len); std::vector<uint8_t> o(len + 1); ascon_cxof128(o.data(), len, m.data(), m.size(), z.data(), z.size()); printHex(o.data(), len); }
    else if (op[0] == 'X') { unsigned len; auto m = readHex(); std::scanf("%u", &len); std::vector<uint8_t> o(len + 1); ascon_xof128(o.data(), len, m.data(), m.size()); printHex(o.data(), len); }
  }
}
`

describe('JS ↔ Arduino C++ Ascon', { skip: !existsSync(join(prototype, 'BohoAscon.cpp')) && 'Arduino BohoAscon.cpp not found: set BOHO_ARDUINO_SRC' }, () => {
  let build, executable
  before(() => {
    build = mkdtempSync(join(tmpdir(), 'boho-ascon-'))
    executable = join(build, 'ascon-host')
    writeFileSync(join(build, 'host.cpp'), cppHost)
    const result = spawnSync('c++', ['-std=c++17', '-O1', '-I', prototype, join(build, 'host.cpp'),
      join(prototype, 'BohoAscon.cpp'), '-o', executable], { encoding: 'utf8', timeout: 60000 })
    assert.equal(result.status, 0, result.stderr || String(result.error))
  })
  after(() => { if (build) rmSync(build, { recursive: true, force: true }) })

  it('agrees on 300 random AEAD, hash, XOF and CXOF cases in both directions', () => {
    const arg = b => (b.length ? hex(b) : '-')
    const lines = []; const expected = []
    for (let i = 0; i < 300; i++) {
      const key = randomBytes(16); const nonce = randomBytes(16)
      const ad = randomBytes(i % 37); const pt = randomBytes((i * 7) % 101)
      const sealed = ascon.encrypt(key, nonce, pt, ad)
      lines.push(`E ${arg(key)} ${arg(nonce)} ${arg(ad)} ${arg(pt)}`); expected.push(hex(sealed))
      lines.push(`D ${arg(key)} ${arg(nonce)} ${arg(ad)} ${arg(sealed)}`); expected.push(pt.length ? hex(pt) : '')
      const bad = Uint8Array.from(sealed); bad[i % bad.length] ^= 0x40
      lines.push(`D ${arg(key)} ${arg(nonce)} ${arg(ad)} ${arg(bad)}`); expected.push('FAIL')
      lines.push(`H ${arg(pt)}`); expected.push(hex(ascon.hash256(pt)))
      lines.push(`X ${arg(ad)} ${i % 70}`); expected.push(hex(ascon.xof128(ad, i % 70)))
      lines.push(`C ${arg(pt)} ${arg(ad)} ${i % 50}`); expected.push(hex(ascon.cxof128(pt, i % 50, ad)))
    }
    const run = spawnSync(executable, [], { input: lines.join('\n') + '\n', encoding: 'utf8', timeout: 60000 })
    assert.equal(run.status, 0, run.stderr)
    assert.deepEqual(run.stdout.split('\n').slice(0, expected.length), expected)
  })
})
