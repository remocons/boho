# Boho

[English](README.md) | [한국어](README.ko.md)

**Shared-key authentication and encrypted messages on standard Ascon, for Node.js, browsers and Arduino**

Boho is a JavaScript library for shared-key login and binary encrypted messages. It runs in Node.js and
browsers. Since **3.0.0** it is built on **Ascon** (NIST SP 800-232), the lightweight cryptography standard,
instead of the earlier custom SHA-256 construction (2.x). The Arduino implementation is part of
[IOSignal Arduino](https://github.com/remocons/iosignal-arduino) 10.0.0; Kotlin and Python implementations
exist for the IOSignal clients. All of them produce the same bytes (`test/fixtures/boho-vectors.json`).

- `boho` means **protection** in Korean.

> **3.0.0 is not compatible with 2.x.** The message codes and keys changed. A server that stored 2.x key
> hashes must register the keys again (it stores `Boho.deriveKey(key)` instead). IOSignal 10.0.0 uses boho 3.

---

## Why Boho?

Boho is for environments where **you control the code and key provisioning at both endpoints**: an Arduino
device, your own web app, a personal server. A key installed over USB, entered by the user or delivered
through an existing SSH/TLS channel is enough to authenticate the peer and protect messages, without
certificates.

Boho does not invent cryptography. It puts a login handshake, session keys and compact binary packets on
Ascon, with compatible implementations for Arduino, JavaScript, Kotlin and Python.

## Algorithms

| Purpose | Algorithm |
| --- | --- |
| Message encryption and tamper check | Ascon-AEAD128 (8-byte tag) |
| Key string → 16-byte key | Ascon-CXOF128 (customization `boho/v2/key`) |
| Login → session key and both proofs | Ascon-CXOF128 (customization `boho/v2/session`) |

Ascon is small and fast on 8-bit microcontrollers (one 320-bit state and one permutation do everything) and
uses no lookup tables, so it has no timing side channel. `Boho.ascon` exposes the primitives
(AEAD128, Hash256, XOF128, CXOF128).

## Messages

| Type | Code | Size | Use |
| --- | --- | --- | --- |
| `SERVER_TIME_NONCE` | 0xB0 | 13 B | Server challenge (time and random bytes) |
| `AUTH_REQ` | 0xB4 | 33 B | Client: ID, client nonce, client proof |
| `AUTH_RES` | 0xB5 | 17 B | Server proof |
| `AUTH_FAIL` | 0xB3 | 1 B | Login refused |
| `ENC` | 0xBB | 21 B + data | Message of a logged-in session |
| `ENC_E2E` | 0xBA | 21 B + header + body | Encrypted routing header followed by an E2E body |
| `ENC_PACK` | 0xB9 | 29 B + data | Standalone or E2E data with its own key |

Details: [docs/PROTOCOL.md](docs/PROTOCOL.md) (Korean).

## Install

```sh
npm install boho
```

Browsers: `dist/boho.min.js` (UMD, global `Boho`) or `dist/boho.js` (ES module).

## Usage

### Encrypt and decrypt data with a key

```js
import Boho from 'boho'

const boho = new Boho()
boho.set_key('a long random key')
const packet = boho.encryptPack('hello')        // ENC_PACK
console.log(boho.decryptPack(packet).data.toString())   // 'hello'

// E2E: a separate data key shared only by the final endpoints
const sealed = boho.encrypt_e2e('secret', 'e2e-key')
console.log(boho.decrypt_e2e(sealed, 'e2e-key').data.toString())
```

`decryptPack` and `decrypt_e2e` return `{ data, ... }`, or `undefined` for a wrong key or a damaged packet.

### Login and session messages

```js
// Server: stores Boho.deriveKey(key) for the ID, never the key string
const server = new Boho()
server.copy_key(Boho.deriveKey('a long random key'))
const challenge = server.server_time_nonce()        // send to the client

// Client
const client = new Boho()
client.set_id_key('dev1.a long random key')
const authReq = client.auth_req(challenge)          // send to the server

// Server
const authRes = server.verify_auth_req(authReq)     // false when the proof is wrong
// Client
client.verify_auth_res(authRes)                     // true: both sides are logged in

const up = client.encrypt_session('to server')      // ENC
server.decrypt_session(up)                          // Buffer 'to server'
```

## Main APIs

| API | Description |
| --- | --- |
| `Boho.deriveKey(key)` | Key string → 16-byte key (what a server stores) |
| `set_id8(id)`, `set_key(key)`, `set_id_key('id.key')`, `copy_key(key16)` | ID and key |
| `server_time_nonce()`, `verify_auth_req(packet[, challenge])` | Server side of the login |
| `auth_req(challenge)`, `verify_auth_res(packet)` | Client side of the login |
| `encrypt_session(data[, type])`, `decrypt_session(packet)` | `ENC` / `ENC_E2E` after login |
| `encryptPack(data)`, `decryptPack(packet)` | `ENC_PACK` with this side's key |
| `encrypt_e2e(data, key)`, `decrypt_e2e(packet, key)` | `ENC_PACK` with an E2E key |
| `Boho.BohoMsg`, `Boho.MetaSize` | Message codes and sizes |
| `Boho.ascon`, `Boho.sha256`, `Boho.RAND`, `Boho.MBP` | Primitives and helpers |

TypeScript definitions are in `dist/boho.d.ts`.

## Security scope

- Use sufficiently random keys. Key derivation is not a slow password KDF.
- Every login makes a new session key; senders keep increasing the clock and counter so nonces never repeat.
- Boho does not reject replays or expire challenges by itself; the application (the IOSignal server) does.
- There is no forward secrecy: a leaked long-term key exposes the traffic it protected.
- Boho does not replace HTTPS for delivering browser code that handles keys.

## Development checks

```sh
npm test                 # Ascon KATs, shared vectors, class tests, types
BOHO_ARDUINO_SRC=../iosignal-arduino/src npm test   # also JS ↔ Arduino C++ (host build)
```

The earlier 2.x source is not part of the package; see the 2.x releases.

## License

MIT
