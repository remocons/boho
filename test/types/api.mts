import Boho, { type MetaSizeType } from 'boho'
// @ts-expect-error Runtime exports only the default class.
import { RAND } from 'boho'

const boho = new Boho()
boho.set_key(Boho.RAND(32))
const packet = boho.encryptPack('hello')
const clear: Uint8Array | undefined = boho.decryptPack(packet)?.data
const sizes: MetaSizeType = Boho.MetaSize
const challengeSize: number = sizes.SERVER_TIME_NONCE
const request = boho.auth_req(new Uint8Array(challengeSize))
if (request) boho.verify_auth_req(request)
boho.encrypt_e2e('hello', 'key')
Boho.sha256.hmac(Boho.RAND(32), packet)
Boho.Buffer.from('hello')
Boho.MBP.unpack(packet, Boho.Meta.ENC_PACK)
void clear
