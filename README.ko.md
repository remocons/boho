# Boho

[English](README.md) | [한국어](README.ko.md)

**Node.js, 브라우저, Arduino를 위한 표준 Ascon 기반 공유 키 인증과 암호 메시지**

Boho는 공유 키 로그인과 바이너리 암호 메시지를 제공하는 JavaScript 라이브러리입니다. Node.js와 브라우저에서
동작합니다. **3.0.0**부터 예전의 SHA-256 자체 구성(2.x) 대신 경량 암호 표준 **Ascon**(NIST SP 800-232)을
씁니다. Arduino 구현은 [IOSignal Arduino](https://github.com/remocons/iosignal-arduino) 10.0.0에 들어 있고,
IOSignal 클라이언트용 Kotlin·Python 구현도 있습니다. 모두 같은 바이트를 냅니다(`test/fixtures/boho-vectors.json`).

- `boho`는 **보호**를 의미합니다.

> **3.0.0은 2.x와 호환되지 않습니다.** 메시지 번호와 키가 바뀌었습니다. 2.x 키 해시를 저장한 서버는 키를 다시
> 등록해야 합니다(이제 `Boho.deriveKey(key)`를 저장). IOSignal 10.0.0이 boho 3을 씁니다.

---

## 왜 boho인가요?

boho는 **통신할 양쪽의 코드와 키 설정을 직접 관리할 수 있는 환경**을 위한 것입니다. Arduino 장치, 직접 만든
웹앱, 개인 서버처럼요. USB로 넣거나 사용자가 입력하거나 기존 SSH·TLS 경로로 받은 키만으로 인증서 없이 상대를
확인하고 메시지를 보호합니다.

boho는 새 암호를 만들지 않습니다. Ascon 위에 로그인 절차, 세션 키, 작은 바이너리 패킷을 올리고, Arduino·
JavaScript·Kotlin·Python 구현을 서로 맞춥니다.

## 알고리즘

| 용도 | 알고리즘 |
| --- | --- |
| 메시지 암호화와 변조 검사 | Ascon-AEAD128 (태그 8바이트) |
| 키 문자열 → 16바이트 키 | Ascon-CXOF128 (용도 문자열 `boho/v2/key`) |
| 로그인 → 세션 키와 양쪽 증명 | Ascon-CXOF128 (용도 문자열 `boho/v2/session`) |

Ascon은 320비트 상태 하나와 순열 하나로 모든 일을 해서 8비트 마이크로컨트롤러에서도 작고 빠르며, 표를 쓰지
않아 타이밍 부채널이 없습니다. `Boho.ascon`으로 기본 함수(AEAD128, Hash256, XOF128, CXOF128)를 쓸 수 있습니다.

## 메시지

| 형식 | 번호 | 크기 | 용도 |
| --- | --- | --- | --- |
| `SERVER_TIME_NONCE` | 0xB0 | 13B | 서버 challenge(시각과 무작위 바이트) |
| `AUTH_REQ` | 0xB4 | 33B | 클라이언트: ID, 클라이언트 nonce, 클라이언트 증명 |
| `AUTH_RES` | 0xB5 | 17B | 서버 증명 |
| `AUTH_FAIL` | 0xB3 | 1B | 로그인 거부 |
| `ENC` | 0xBB | 21B + 데이터 | 로그인한 세션의 메시지 |
| `ENC_E2E` | 0xBA | 21B + 헤더 + 본문 | 암호화한 라우팅 헤더 뒤에 E2E 본문 |
| `ENC_PACK` | 0xB9 | 29B + 데이터 | 자기 키로 봉한 독립 데이터나 E2E 본문 |

자세한 내용: [docs/PROTOCOL.md](docs/PROTOCOL.md)

## 설치

```sh
npm install boho
```

브라우저: `dist/boho.min.js`(UMD, 전역 `Boho`) 또는 `dist/boho.js`(ES 모듈).

## 사용 예제

### 키로 데이터 암호화·복호화

```js
import Boho from 'boho'

const boho = new Boho()
boho.set_key('충분히 긴 무작위 키')
const packet = boho.encryptPack('hello')        // ENC_PACK
console.log(boho.decryptPack(packet).data.toString())   // 'hello'

// E2E: 최종 송수신자만 나눠 가진 별도 데이터 키
const sealed = boho.encrypt_e2e('secret', 'e2e-key')
console.log(boho.decrypt_e2e(sealed, 'e2e-key').data.toString())
```

`decryptPack`, `decrypt_e2e`는 `{ data, ... }`를 돌려주고, 키가 틀리거나 패킷이 망가졌으면 `undefined`입니다.

### 로그인과 세션 메시지

```js
// 서버: ID의 키로 Boho.deriveKey(key)를 저장합니다. 키 문자열은 저장하지 않습니다.
const server = new Boho()
server.copy_key(Boho.deriveKey('충분히 긴 무작위 키'))
const challenge = server.server_time_nonce()        // 클라이언트에 보냄

// 클라이언트
const client = new Boho()
client.set_id_key('dev1.충분히 긴 무작위 키')
const authReq = client.auth_req(challenge)          // 서버에 보냄

// 서버
const authRes = server.verify_auth_req(authReq)     // 증명이 틀리면 false
// 클라이언트
client.verify_auth_res(authRes)                     // true: 양쪽이 로그인 상태

const up = client.encrypt_session('to server')      // ENC
server.decrypt_session(up)                          // Buffer 'to server'
```

## 주요 API

| API | 설명 |
| --- | --- |
| `Boho.deriveKey(key)` | 키 문자열 → 16바이트 키(서버가 저장하는 값) |
| `set_id8(id)`, `set_key(key)`, `set_id_key('id.key')`, `copy_key(key16)` | ID와 키 |
| `server_time_nonce()`, `verify_auth_req(packet[, challenge])` | 로그인의 서버 쪽 |
| `auth_req(challenge)`, `verify_auth_res(packet)` | 로그인의 클라이언트 쪽 |
| `encrypt_session(data[, type])`, `decrypt_session(packet)` | 로그인 뒤 `ENC` / `ENC_E2E` |
| `encryptPack(data)`, `decryptPack(packet)` | 자기 키로 `ENC_PACK` |
| `encrypt_e2e(data, key)`, `decrypt_e2e(packet, key)` | E2E 키로 `ENC_PACK` |
| `Boho.BohoMsg`, `Boho.MetaSize` | 메시지 번호와 크기 |
| `Boho.ascon`, `Boho.sha256`, `Boho.RAND`, `Boho.MBP` | 기본 함수와 도우미 |

TypeScript 정의는 `dist/boho.d.ts`에 있습니다.

## 보안 범위

- 충분히 무작위인 키를 쓰세요. 키 유도는 비밀번호용 느린 KDF가 아닙니다.
- 로그인마다 새 세션 키를 만들고, 보내는 쪽은 시계와 카운터를 계속 늘려 nonce가 겹치지 않게 합니다.
- boho는 재전송 거부나 challenge 만료를 스스로 하지 않습니다. 응용(IOSignal 서버)이 합니다.
- 순방향 비밀성이 없습니다. 장기 키가 유출되면 그 키로 보호한 통신이 드러납니다.
- 키를 다루는 브라우저 코드를 전달하는 HTTPS를 대신하지 않습니다.

## 개발 검증

```sh
npm test                 # Ascon KAT, 공용 시험 자료, 클래스 시험, 타입
BOHO_ARDUINO_SRC=../iosignal-arduino/src npm test   # JS ↔ Arduino C++(호스트 빌드)까지
```

예전 2.x 소스는 패키지에 들어 있지 않습니다. 2.x 릴리스를 보세요.

## 라이선스

MIT
