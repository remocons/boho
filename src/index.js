import { Boho, RAND, BohoMsg, Meta, MetaSize, sha256, MBP, Buffer } from './boho.js'

Boho.RAND = RAND;
Boho.BohoMsg = BohoMsg;
Boho.Meta = Meta;
Boho.MetaSize = MetaSize;
Boho.sha256 = sha256;
Boho.MBP = MBP;
Boho.Buffer = Buffer;

/**
 * boho 라이브러리의 메인 엔트리포인트
 * @module boho
 */

/**
 * @typedef {import('./boho.js').Boho} Boho
 * @typedef {import('./boho.js').RAND} RAND
 * @typedef {import('./boho.js').BohoMsg} BohoMsg
 * @typedef {import('./boho.js').Meta} Meta
 * @typedef {import('./boho.js').MetaSize} MetaSize
 * @typedef {import('./boho.js').sha256} sha256
 * @typedef {import('./boho.js').MBP} MBP
 * @typedef {import('./boho.js').Buffer} Buffer
 */

/**
 * boho의 기본 export 객체
 * @type {Boho & { RAND: typeof RAND, BohoMsg: typeof BohoMsg, Meta: typeof Meta, MetaSize: typeof MetaSize, sha256: typeof sha256, MBP: typeof MBP, Buffer: typeof Buffer }}
 */
export default Boho;