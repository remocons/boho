// Copyright (c) 2024-2026 Taeo Lee (sixgen@gmail.com)
// MIT License
//
// https://github.com/remocons/boho

/**
 * Boho message types (one-byte header). Boho 3 (Ascon). The 2.x codes 0xB1, 0xB2, 0xB6, 0xB7
 * and 0xB8 belong to the classic protocol and are not used.
 * @typedef {Object} BohoMsg
 * @property {number} SERVER_TIME_NONCE
 * @property {number} AUTH_FAIL
 * @property {number} AUTH_REQ
 * @property {number} AUTH_RES
 * @property {number} ENC_PACK
 * @property {number} ENC_E2E
 * @property {number} ENC
 */
export const BohoMsg = {
  SERVER_TIME_NONCE: 0xB0,
  AUTH_FAIL: 0xB3,
  AUTH_REQ: 0xB4,
  AUTH_RES: 0xB5,
  ENC_PACK: 0xB9,
  ENC_E2E: 0xBA,
  ENC: 0xBB
}

for (const c of Object.keys(BohoMsg)) { BohoMsg[BohoMsg[c]] = c }

/**
 * Sizes in bytes: whole packets (SERVER_TIME_NONCE, AUTH_REQ, AUTH_RES) or headers before the
 * payload (ENC and ENC_E2E: 21, ENC_PACK: 29).
 * @typedef {Object} MetaSize
 */
export const MetaSize = {
  SERVER_TIME_NONCE: 13,
  AUTH_REQ: 33,
  AUTH_RES: 17,
  ENC: 21,
  ENC_PACK: 29
}
