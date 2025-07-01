// TypeScript type definitions for boho
import { Buffer } from 'buffer';

export function RAND(size: number): Buffer;

export interface BohoMsgType {
  AUTH_REQ: number;
  AUTH_NONCE: number;
  AUTH_HMAC: number;
  AUTH_ACK: number;
  AUTH_FAIL: number;
  AUTH_EXT: number;
  ENC_PACK: number;
  ENC_E2E: number;
  ENC_488: number;
  [key: string]: number | string;
}

export interface MetaType {
  AUTH_REQ: any;
  AUTH_NONCE: any;
  AUTH_HMAC: any;
  AUTH_ACK: any;
  ENC_PACK: any;
  ENC_488: any;
}

export interface MetaSizeType {
  AUTH_REQ: number;
  AUTH_NONCE: number;
  AUTH_HMAC: number;
  AUTH_ACK: number;
  ENC_PACK: number;
  ENC_488: number;
}

export interface Sha256 {
  hash(data: any): Uint8Array;
  hex(data: any): string;
  base64(data: any): string;
  hmac(key: any, data: any): Uint8Array;
}

export class Boho {
  _id8: Buffer;
  _otpSrc44: Buffer;
  _otp36: Buffer;
  _hmac: Buffer;
  auth_salt12: Buffer;
  localNonce: Buffer;
  remoteNonce: Buffer;
  isAuthorized: boolean;

  constructor();
  clearAuth(): void;
  set_hash_id8(data: any): void;
  set_id8(data: any): void;
  set_key(data: any): void;
  set_id_key(id_key: string): void;
  copy_id8(data: Buffer): void;
  copy_key(data: Buffer): void;
  sha256_n(srcData: any, n: number): Uint8Array;
  set_clock_rand(): void;
  set_clock_nonce(nonce: Buffer): void;
  set_salt12(salt12: Buffer): void;
  resetOTP(): void;
  getIndexOTP(otpIndex: number): Uint8Array;
  generateHMAC(data: Buffer): void;
  getHMAC8(data: Buffer): Buffer;
  xotp(data: Buffer, otpStartIndex?: number, shareDataBuffer?: boolean): Buffer;
  auth_req(): Buffer;
  auth_nonce(): Buffer;
  auth_hmac(buffer: Buffer): Buffer | boolean;
  check_auth_hmac(data: Buffer | object): boolean;
  check_auth_ack_hmac(buffer: Buffer): boolean;
  encrypt_488(data: Buffer): Buffer | undefined;
  decrypt_488(data: Buffer): Buffer | undefined;
  encryptPack(data: Buffer): Buffer;
  decryptPack(data: Buffer): Buffer;
  encrypt_e2e(data: Buffer, key: Buffer): Buffer;
  decrypt_e2e(data: Buffer, key: Buffer): Buffer;
}

export const BohoMsg: BohoMsgType;
export const Meta: MetaType;
export const MetaSize: MetaSizeType;
export const sha256: Sha256;
export const MBP: any;
export { Buffer };

declare const _default: typeof Boho & {
  RAND: typeof RAND;
  BohoMsg: typeof BohoMsg;
  Meta: typeof Meta;
  MetaSize: typeof MetaSize;
  sha256: typeof sha256;
  MBP: typeof MBP;
  Buffer: typeof Buffer;
};
export default _default; 