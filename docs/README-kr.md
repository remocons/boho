[ [en](../README.md) | kr ]

# Boho

**Node.js, 브라우저, Arduino를 위한 안전하고 가벼운 암호화 및 인증 라이브러리**

Boho는 강력한 암호화, 인증 및 보안 통신을 위한 경량 JavaScript 라이브러리입니다. Node.js, 브라우저, 그리고 Arduino와 같은 임베디드 시스템을 위해 설계되었으며, 최소한의 오버헤드로 강력한 보안이 필요한 IoT, 임베디드 및 웹 애플리케이션에 이상적입니다.

- `boho`는 **보호**를 의미합니다.

---

## 주요 기능
- 범용 암호화 및 복호화
- 상호 인증 프로토콜 (아래 참조)
- 인증 후 보안 통신
- 종단간(End-to-End) 대칭 암호화
- TypeScript 타입 정의 포함
- JavaScript (Node.js, 브라우저) 및 C/C++ (Arduino) 지원

---

## 라이브러리
- **JavaScript:** Node.js, 웹 브라우저 ([GitHub](https://github.com/remocons/boho))
- **C/C++:** Arduino ([GitHub](https://github.com/remocons/boho-arduino))

---

## 대표적인 사용 사례
- WebSocket 인증 및 보안 메시징
- 보안 TCP/직렬/스트림 통신
- 보안 MQTT 페이로드
- 로컬 파일 암호화

---

## 핵심 개념
- **SHA256**: 해싱
- **xotp**: XOR 기반 일회용 패드
- **generateOTP**: OTP 생성
- **generateHMAC**: 인증을 위한 HMAC

---

## 주요 API
- `encryptPack`, `decryptPack`: 범용 암호화/복호화
- `encrypt_488`, `decrypt_488`: 인증 후 보안 통신
- `encrypt_e2e`, `decrypt_e2e`: 종단간 암호화
- `RAND(size)`: 안전한 랜덤 버퍼 생성
- `sha256.hash`, `sha256.hex`, `sha256.base64`, `sha256.hmac`: 해싱 유틸리티

---

## 인증 프로토콜 (요약)
Boho는 랜덤 nonce와 HMAC을 기반으로 한 상호 인증 프로토콜을 사용합니다:

1. **AUTH_REQ**: 클라이언트가 인증 시작
2. **AUTH_NONCE**: 서버가 시간과 랜덤 nonce로 응답
3. **AUTH_HMAC**: 클라이언트가 서버의 nonce와 자신의 nonce를 사용하여 HMAC 전송
4. **AUTH_ACK**: 서버가 검증 후 자신의 HMAC으로 응답
5. **AUTH_FAIL**: 인증 실패 시 서버가 전송

자세한 프로토콜 설명은 [`AUTH_PROCESS-kr.md`](./AUTH_PROCESS-kr.md)를 참조하세요.

### 인증 메시지 흐름 다이어그램

![Boho Auth Message Flow](auth_process_flow.svg)

---

## 사용 예제

### 일반 데이터 암호화 및 복호화
```js
import Boho from 'boho'

  let boho = new Boho()

  boho.set_key('abc' )

  let data = 'aaaaaaaa'

  let encData = boho.encryptPack( data )
  console.log('encData buffer:', encData )
  let result = boho.decryptPack( encData )
  
  if(result){  
    console.log('result object:', result )
    printMessage(result.data)  // decode to string.
  }else{
    console.log('decryption is fail')
  }

  function printMessage(data){
    let dataStr = new TextDecoder().decode( data )
    console.log('
 result string:',dataStr)
  }

```

### Boho를 사용한 인증 및 보안 통신 예제는 `IOSignal`을 참고하세요.
- `iosignal` ([GitHub](https://github.com/remocons/iosignal))
- test/AUTH_process.js

---

## TypeScript 지원
Boho는 완전한 TypeScript 타입 정의를 제공합니다. 간단히 설치하고 가져오기만 하면 TypeScript 프로젝트에서 자동 완성 및 타입 검사를 받을 수 있습니다.

---

## 라이선스
MIT
