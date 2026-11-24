// Copyright (c) 2024-2026 Taeo Lee (sixgen@gmail.com)
// MIT License
//
// https://github.com/remocons/boho
//
import { Boho, RAND, BohoMsg, MetaSize, deriveKey, MBP, Buffer } from './boho.js'
import { sha256 } from './sha256-mbp.js'
import * as ascon from './ascon.js'

Boho.RAND = RAND;
Boho.BohoMsg = BohoMsg;
Boho.MetaSize = MetaSize;
Boho.deriveKey = deriveKey;
Boho.ascon = ascon;     // Ascon-AEAD128, Hash256, XOF128, CXOF128 (NIST SP 800-232)
Boho.sha256 = sha256;   // SHA-256 and standard HMAC utilities (not used by the protocol)
Boho.MBP = MBP;
Boho.Buffer = Buffer;

/**
 * Main entry point of the boho library
 * @module boho
 */

/**
 * Default export: the Boho class with its helpers.
 * @type {typeof Boho & { RAND: typeof RAND, BohoMsg: typeof BohoMsg, MetaSize: typeof MetaSize,
 *   deriveKey: typeof deriveKey, ascon: typeof ascon, sha256: typeof sha256, MBP: typeof MBP, Buffer: typeof Buffer }}
 */
export default Boho;
