// TypeScript type definitions for boho 3
// Project: https://github.com/remocons/boho
// Definitions by: Taeo Lee (sixgen@gmail.com)
//
// Boho 3: shared-key authentication and encrypted messages on Ascon (NIST SP 800-232).
// Boho 2.x (SHA-256 based) is not supported.

import { Buffer } from 'buffer';
import MBP from 'meta-buffer-pack';

declare function RAND(size: number): Buffer;

/** Key string → the 16-byte key a server stores for an ID. */
declare function deriveKey(key: string | Uint8Array): Buffer;

export interface BohoMsgType {
  SERVER_TIME_NONCE: number;
  AUTH_FAIL: number;
  AUTH_REQ: number;
  AUTH_RES: number;
  ENC_PACK: number;
  ENC_E2E: number;
  ENC: number;
  [key: string]: number | string;
}

export interface MetaSizeType {
  SERVER_TIME_NONCE: number;
  AUTH_REQ: number;
  AUTH_RES: number;
  /** Header size of ENC and ENC_E2E. */
  ENC: number;
  /** Header size of ENC_PACK. */
  ENC_PACK: number;
}

export interface Sha256 {
  hash(data: any): Uint8Array;
  hex(data: any): string;
  base64(data: any): string;
  hmac(key: any, data: any): Uint8Array;
}

export interface Ascon {
  KEY_SIZE: number;
  NONCE_SIZE: number;
  TAG_SIZE: number;
  HASH_SIZE: number;
  CXOF_MAX_CUSTOM: number;
  /** Ascon-AEAD128: ciphertext followed by the tag (tagLength 4..16, default 16). */
  encrypt(key: Uint8Array, nonce: Uint8Array, plaintext?: any, ad?: any, tagLength?: number): Uint8Array;
  /** Plaintext, or null when the tag does not match. */
  decrypt(key: Uint8Array, nonce: Uint8Array, sealed: any, ad?: any, tagLength?: number): Uint8Array | null;
  hash256(data: any): Uint8Array;
  xof128(data: any, outLength: number): Uint8Array;
  cxof128(data: any, outLength: number, custom?: any): Uint8Array;
}

/** Result of decryptPack / decrypt_e2e. */
export interface OpenedPack {
  type: number;
  len: number;
  sec: number;
  ms: number;
  counter: number;
  sender: Buffer;
  data: Buffer;
}

declare class Boho {
  static RAND: typeof RAND;
  static deriveKey: typeof deriveKey;
  static BohoMsg: BohoMsgType;
  static MetaSize: MetaSizeType;
  static ascon: Ascon;
  static sha256: Sha256;
  static MBP: typeof MBP;
  static Buffer: typeof Buffer;

  /** True after a verified login (AUTH_RES on a client, AUTH_REQ on a server). */
  isAuthorized: boolean;

  constructor();
  clearAuth(): void;
  /** The login ID: at most 8 bytes are used. */
  set_id8(id: any): void;
  copy_id8(id8: Uint8Array): void;
  /** Key string → key. A new key ends the session. */
  set_key(key: any): void;
  /** A stored 16-byte key (deriveKey), on a server. */
  copy_key(key16: Uint8Array): void;
  /** 'id.key' */
  set_id_key(idKey: string): void;

  /** Server: the challenge (SERVER_TIME_NONCE, 13 bytes), kept for verify_auth_req. */
  server_time_nonce(): Buffer;
  /** Server: checks AUTH_REQ; returns AUTH_RES, or false. */
  verify_auth_req(packet: Uint8Array, challenge?: Uint8Array): Buffer | false;
  /** Client: AUTH_REQ for the server's SERVER_TIME_NONCE, or false. */
  auth_req(serverTimeNonce: Uint8Array, clientNonce?: Uint8Array): Buffer | false;
  /** Client: checks AUTH_RES. */
  verify_auth_res(packet: Uint8Array): true | undefined;

  /** ENC (default) or ENC_E2E after a verified login. */
  encrypt_session(data: any, type?: number): Buffer | undefined;
  /** Opens ENC, or the routing header of ENC_E2E. */
  decrypt_session(packet: Uint8Array): Buffer | undefined;

  /** ENC_PACK with this side's key. */
  encryptPack(data: any): Buffer | undefined;
  decryptPack(packet: Uint8Array): OpenedPack | undefined;
  /** ENC_PACK with an E2E key string. */
  encrypt_e2e(data: any, key: any): Buffer | undefined;
  decrypt_e2e(packet: Uint8Array, key: any): OpenedPack | undefined;
}

export default Boho;
