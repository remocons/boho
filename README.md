# Boho

Secure Lightweight Encryption & Authentication Library for Node.js, Browsers and Arduino.

Boho is a lightweight JavaScript library that provides easy-to-use encryption, authentication, and secure communication features. Designed for both Node.js and browser environments, Boho offers simple APIs for generating random values, hashing, HMAC, and secure message packing, making it ideal for IoT, embedded, and web applications that require robust security with minimal overhead.

- ``boho`` means Protection 

## features
- general encryption.
- authentication.
- secure communication.
- End-to-End Encryption with Symmetric.
- support JS & C/C++ for Arduino.

## libraries
- JavaScript: Node.js , Web Browser. [ [github](https://github.com/remocons/boho) ] 
- C/C++: Arduino [ [github](https://github.com/remocons/boho-arduino) ] 

## applications

- Websocket authentication, secure communication.
- secure TCP/Serial/Stream communication, authentication.
- secure MQTT payload.
- local file encryption.

## core
- Using SHA256
- xotp
- generateOTP
- generateHMAC

## general purpose encryption

- encryptPack
- decryptPack


## authentication protocol.

- AUTH_REQ
- AUTH_NONCE
- AUTH_HMAC
- check_auth_hmac
- AUTH_ACK
- check_auth_ack_hamc
- AUTH_FAIL

## secure communication after auth.

- ENC_488
- ENC_E2E


## license
- MIT
