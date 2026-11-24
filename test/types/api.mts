import Boho, { type MetaSizeType, type OpenedPack } from 'boho'
// @ts-expect-error Runtime exports only the default class.
import { RAND } from 'boho'

const server = new Boho()
server.copy_key(Boho.deriveKey('secret'))
const challenge = server.server_time_nonce()
const client = new Boho()
client.set_id_key('dev1.secret')
const request = client.auth_req(challenge)
const response = request ? server.verify_auth_req(request) : false
if (response) client.verify_auth_res(response)
const packet = client.encrypt_session('hello')
const plain: Uint8Array | undefined = packet ? server.decrypt_session(packet) : undefined
const header = client.encrypt_session(new Uint8Array([0xd2, 1, 0x78]), Boho.BohoMsg.ENC_E2E)
const body = client.encrypt_e2e('hello', 'e2e-key')
const opened: OpenedPack | undefined = body ? server.decrypt_e2e(body, 'e2e-key') : undefined
const sizes: MetaSizeType = Boho.MetaSize
const tag: Uint8Array = Boho.ascon.encrypt(new Uint8Array(16), new Uint8Array(16), 'x')
Boho.sha256.hmac(Boho.RAND(32), Boho.Buffer.from('hello'))
void plain; void header; void opened; void sizes.ENC; void tag
