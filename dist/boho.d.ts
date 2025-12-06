// TypeScript type definitions for boho
// Project: https://github.com/remocons/boho
// Definitions by: Taeo Lee (sixgen@gmail.com)

import { Buffer } from 'buffer';
import MBP from 'meta-buffer-pack';

export function RAND(size: number): Buffer;

// Interfaces based on src/constants.js and usage in boho.js
export interface BohoMsgType {
  SERVER_TIME_NONCE: number;
  AUTH_REQ: number;
  AUTH_RES: number;
  ENC_PACK: number;
  ENC_488: number;
  [key: string]: number | string;
}

export interface MetaType {
  SERVER_TIME_NONCE: any;
  AUTH_REQ: any;
  AUTH_RES: any;
  ENC_PACK: any;
  ENC_488: any;
}

export interface MetaSizeType {
  ENC_PACK: number;
}

export interface Sha256 {
  hash(data: any): Uint8Array;
  hex(data: any): string;
  base64(data: any): string;
  hmac(key: any, data: any): Uint8Array;
}

export class Boho {
  protected _id8: Buffer;
  protected _otpSrc44: Buffer;
  protected _otp36: Buffer;
  protected _hmac: Buffer;

  auth_salt12: Buffer;
  localNonce: Buffer;
  remoteNonce: Buffer;
  isAuthorized: boolean;
  counter: number;

  constructor();

  /**
   * Initializes authentication state.
   */
  clearAuth(): void;

  /**
   * Sets id8 by hashing the input data.
   * @param data
   */
  set_hash_id8(data: any): void;

  /**
   * Sets the id8 value.
   * @param data
   */
  set_id8(data: any): void;

  /**
   * Sets the key value by hashing and storing in otpSrc44.
   * @param data
   */
  set_key(data: any): void;

  /**
   * Splits 'id.key' string and sets id8 and key.
   * @param id_key
   */
  set_id_key(id_key: string): void;

  /**
   * Copies id8 value from external buffer.
   * @param data
   */
  copy_id8(data: Buffer): void;

  /**
   * Copies key value from external buffer.
   * @param data
   */
  copy_key(data: Buffer): void;

  /**
   * Applies sha256 hash n times.
   * @param srcData
   * @param n
   */
  sha256_n(srcData: any, n: number): Uint8Array;

  /**
   * Sets random clock value (salt12) in otpSrc44.
   */
  set_clock_rand(): void;

  /**
   * Sets otpSrc44 with given nonce and clock value.
   * @param nonce
   */
  set_clock_nonce(nonce: Buffer): void;

  /**
   * Sets salt12 value in otpSrc44.
   * @param salt12
   * @param caller - for debug
   */
  set_salt12(salt12: Buffer, caller?: string): void;

  /**
   * Initializes OTP value.
   */
  resetOTP(): void;

  /**
   * Returns OTP value for the given index.
   * @param otpIndex
   */
  getIndexOTP(otpIndex: number): Uint8Array;

  /**
   * Generates HMAC value.
   * @param data
   */
  generateHMAC(data: Buffer): void;

  /**
   * Returns 8-byte HMAC value.
   * @param data
   */
  getHMAC8(data: Buffer): Buffer;

  /**
   * OTP-based XOR encryption/decryption
   * @param data
   * @param otpStartIndex
   * @param shareDataBuffer
   */
  xotp(data: Buffer, otpStartIndex?: number, shareDataBuffer?: boolean): Buffer;

  // B. AUTH process

  /**
   * Generates server time and nonce signal
   */
  server_time_nonce(): Buffer;

  /**
   * Generates AUTH_REQ message
   * @param buffer server's time nonce
   */
  auth_req(buffer: Buffer): Buffer | boolean;

  /**
   * Verify client's AUTH_REQ.
   * @param data
   * @returns auth_res packet or false
   */
  verify_auth_req(data: Buffer | object): Buffer | false;

  /**
   * Verifies server's AUTH_RES HMAC.
   * @param buffer
   */
  verify_auth_res(buffer: Buffer): boolean | undefined;

  // C. Secure Communication

  /**
   * Generates encrypted 488 packet after authentication
   * @param data
   */
  encrypt_488(data: Buffer): Buffer | undefined;

  /**
   * Decrypts 488 packet after authentication
   * @param data
   */
  decrypt_488(data: Buffer): Buffer | undefined;

  /**
   * Generates encrypted packet for up to 2^32-1 bytes
   * @param data
   */
  encryptPack(data: Buffer): Buffer;

  /**
   * Decrypts encrypted packet
   * @param data
   * @returns The decrypted data buffer inside a pack object, or undefined.
   */
  decryptPack(data: Buffer): { data: Buffer, [key: string]: any } | undefined;

  /**
   * End-to-end encryption
   * @param data
   * @param key
   */
  encrypt_e2e(data: Buffer, key: any): Buffer;

  /**
   * End-to-end decryption
   * @param data
   * @param key
   */
  decrypt_e2e(data: Buffer, key: any): { data: Buffer, [key: string]: any } | undefined;
}

export const BohoMsg: BohoMsgType;
export const Meta: MetaType;
export const MetaSize: MetaSizeType;
export const sha256: Sha256;

export { MBP, Buffer };