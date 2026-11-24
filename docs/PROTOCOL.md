# 프로토콜과 사용 범위 (Boho 3)

Boho 3.0.0부터 인증과 암호화는 표준 **Ascon**(NIST SP 800-232)을 씁니다. Boho 2.x의 SHA-256 기반
자체 구성은 지원하지 않으며, 그 메시지 번호(0xB1, 0xB2, 0xB6, 0xB7, 0xB8)도 다시 쓰지 않습니다.
Arduino 구현은 IOSignal Arduino 라이브러리(iosignal-arduino, 10.0.0부터)에 들어 있습니다.

## 알고리즘

| 용도 | 알고리즘 |
|---|---|
| 데이터 암호화·인증 | Ascon-AEAD128 (태그 8바이트) |
| 키 문자열 → 키 | Ascon-CXOF128, 용도 문자열 `boho/v2/key`, 16바이트 |
| 로그인 → 세션 키·증명 | Ascon-CXOF128, 용도 문자열 `boho/v2/session`, 48바이트 |

용도 문자열의 `v2`는 바이트를 정하는 프로토콜 상수입니다.

서버는 키 문자열이 아니라 `deriveKey(키 문자열)`로 만든 16바이트 키를 저장합니다.

## 접속 인증

```
서버 → SERVER_TIME_NONCE 0xB0 (13B)  type | unixTime4 | ms2 | random2 | random4
클라이언트 → AUTH_REQ 0xB4 (33B)      type | id8 | clientNonce8 | clientProof16
서버 → AUTH_RES 0xB5 (17B)           type | serverProof16      (실패면 AUTH_FAIL 0xB3)
```

- 대본 `T = SERVER_TIME_NONCE ‖ id8 ‖ clientNonce8`
- `CXOF128(Z="boho/v2/session", K ‖ T)` 48바이트 = 세션 키 16 ‖ 클라이언트 증명 16 ‖ 서버 증명 16
- 서버는 클라이언트 증명을 상수 시간으로 비교한 뒤 AUTH_RES를 보내고, 클라이언트는 서버 증명을 확인한 뒤에야 세션을 씁니다.

Boho는 키 소유 증명과 암호 처리를 제공합니다. 키 조회, 최종 접속 승인, 인증 시도 제한, challenge 만료와
1회 사용, 연결 종료와 재접속 정책은 상위 애플리케이션(IOSignal 서버)이 관리합니다.

## 메시지

| 형식 | 배치 | 키 | 서버의 역할 |
|---|---|---|---|
| `ENC` 0xBB | type1 len4 sec4 ms2 counter2 tag8 암호문 (헤더 21B) | 세션 키 | 복호화 후 처리·라우팅, 받는 연결에 맞춰 재암호화 |
| `ENC_E2E` 0xBA | ENC와 같고, len은 라우팅 헤더 길이. 그 뒤 E2E 본문 | 세션 키 | 헤더만 풀고 본문은 그대로 중계 |
| `ENC_PACK` 0xB9 | type1 len4 nonce16(sec4 ms2 counter2 sender8) tag8 암호문 (헤더 29B) | 연결 키 또는 E2E 키 | E2E 본문 |

- ENC·ENC_E2E의 nonce는 헤더의 시계 8바이트와 방향(클라이언트→서버 1, 서버→클라이언트 2), 연관데이터는 헤더 앞 13바이트입니다.
- ENC_PACK의 연관데이터는 앞 5바이트(type, len)이고, `sender8`은 보내는 쪽마다 부팅할 때 한 번 정하는 값입니다.
- 보내는 쪽은 (sec, ms, counter)를 계속 늘려 같은 세션·같은 방향에서 nonce가 겹치지 않게 합니다.
- 태그 8바이트의 위조 확률은 한 번에 2⁻⁶⁴입니다. 로그인 증명은 16바이트입니다.

CongPacket은 TCP 데이터에서 메시지 경계를 구분하는 외부 프레이밍입니다. 자체 암호 인증이나 재전송 검사를 제공하지 않습니다.

## 보안 범위

Boho는 수신 이력·재전송·시간 신선도 정책을 강제하지 않습니다. IOSignal 서버는 시계와 카운터로 재전송을 거부합니다.
사람이 정한 비밀번호를 위한 느린 KDF, 순방향 비밀성, E2E 키 배포는 제공하지 않습니다. 실제 공유 키에는 충분한 엔트로피가 필요합니다.

## 작은 장치의 메시지 크기

최종 수신 태그(토픽)의 바이트 길이를 `t`, 이진 본문 크기를 `p`라고 하면 일반 암호화 SIGNAL은 `24+t+p`,
E2E SIGNAL은 `53+t+p`바이트입니다(CongPacket 외부 헤더 제외). 장치 수신 버퍼가 80바이트라면 각각 `p <= 56-t`, `p <= 27-t`입니다.

## 시험 자료

`test/fixtures/boho-vectors.json`은 고정 입력으로 만든 키, 로그인, ENC·ENC_E2E, ENC_PACK의 바이트와 거부해야 하는 패킷입니다.
JS, C++(Arduino), Kotlin, Python 구현이 같은 바이트를 내야 합니다. `node tools/make-vectors.mjs`가 만들고 `--check`로 확인합니다.
