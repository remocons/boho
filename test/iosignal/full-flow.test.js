import { it } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import readline from 'node:readline'
import PatchedBoho from '../../dist/boho.js'

const dir = fileURLToPath(new URL('.', import.meta.url))
const iosignal = process.env.IOSIGNAL_PATH || resolve(dir, '../../../iosignal')
const arduino = process.env.IOSIGNAL_ARDUINO_PATH || resolve(dir, '../../../iosignal-arduino')
const load = path => import(pathToFileURL(join(iosignal, path)))
const {Manager} = await load('src/server/Manager.js')
const {BohoAuth} = await load('src/auth/BohoAuth.js')
const {IOCongSocket} = await load('src/client/IOCongSocket.js')
const {CongRx} = await load('src/client/CongPacket.js')
const {STATE} = await load('src/common/constants.js')

it('Arduino IOSignal (80-byte RX) ↔ real iosignal server ↔ JS client: auth, normal, E2EE', {timeout:30000}, async () => {
  const build=mkdtempSync(join(tmpdir(),'iosignal-full-flow-'))
  const executable=join(build,'peer')
  let child, lines, io, manager
  try {
    const args=['-std=c++11','-ffunction-sections','-fdata-sections','-Wno-deprecated-declarations',
      '-I',join(dir,'shims'),'-I',join(dir,'../arduino/shims'),'-I',join(arduino,'src'),
      join(dir,'host.cpp'),...['Boho.cpp','CongPacket.cpp','IOSignal.cpp'].map(f=>join(arduino,'src',f)),
      '-o',executable]
    args.push(process.platform==='darwin'?'-Wl,-dead_strip':'-Wl,--gc-sections')
    if(process.platform!=='darwin')args.push('-lcrypto')
    const compiled=spawnSync('c++',args,{encoding:'utf8',timeout:20000})
    assert.equal(compiled.status,0,compiled.stderr||String(compiled.error))
    child=spawn(executable,[],{stdio:['pipe','pipe','inherit']})
    lines=readline.createInterface({input:child.stdout})[Symbol.asyncIterator]()
    const ask=async command=>{
      const line=lines.next();child.stdin.write(command+'\n');const value=await line
      assert.equal(value.done,false);return value.value
    }
    class Socket extends EventEmitter {
      constructor(){super();this.socketType='cong';this.readyState='open';this.remoteAddress='127.0.0.1';this.pending=[]}
      write(data){this.pending.push(Buffer.from(data))}
      end(){this.readyState='closed'} destroy(){this.end()}
    }
    const server=new EventEmitter();server.serviceNames=new Set()
    const auth=new BohoAuth({getAuth:async id=>id==='arduino'?{key:'arduino-key',cid:'arduino',level:1}:
      id==='jsclient'?{key:'js-key',cid:'js',level:1}:null})
    manager=new Manager(server,auth)
    const aSocket=new Socket(),jsSocket=new Socket(),jsOutbound=[]
    io=new IOCongSocket();io.autoReconnect=false;io.auth('jsclient','js-key')
    io.socket={readyState:'open',write:data=>jsOutbound.push(Buffer.from(data))}
    const jsRx=new CongRx();jsRx.on('data',data=>io.onTCPSocketMessage(data))
    manager.addRemote(aSocket,{});manager.addRemote(jsSocket,{})
    assert.ok(io.boho instanceof PatchedBoho, 'JS client must use the working Boho build')
    for (const remote of manager.remotes) assert.ok(remote.boho instanceof PatchedBoho, 'Server must use the working Boho build')
    const pump=async()=>{
      for(let pass=0;pass<30;pass++) {
        let activity=false
        while(aSocket.pending.length){activity=true;const frame=aSocket.pending.shift()
          // Exercise actual Arduino CongPacket parsing with split headers/body.
          for(const piece of [frame.subarray(0,1),frame.subarray(1,3),frame.subarray(3)]) {
            if(!piece.length)continue
            const returned=await ask('FEED '+piece.toString('hex'))
            if(returned)aSocket.emit('data',Buffer.from(returned,'hex'))
          }
        }
        while(jsSocket.pending.length){activity=true;jsRx.write(jsSocket.pending.shift())}
        while(jsOutbound.length){activity=true;const frame=jsOutbound.shift();jsSocket.emit('data',frame.subarray(0,1));jsSocket.emit('data',frame.subarray(1))}
        await new Promise(r=>setImmediate(r))
        if(!activity&&!aSocket.pending.length&&!jsSocket.pending.length&&!jsOutbound.length)return
      }
      assert.fail('Message pump did not settle')
    }
    await pump()
    assert.equal(await ask('STATE'),'19:1')
    assert.equal(io.state,STATE.READY)
    assert.equal(manager.cid2remote.size,2)
    const received=[];io.on('@',(tag,data)=>received.push({tag,data:Buffer.from(data)}))
    aSocket.emit('data',Buffer.from(await ask('SIGNAL js@t 68656c6c6f'),'hex'));await pump()
    assert.equal(received.pop().data.toString(),'hello')
    io.signal('arduino@t',Buffer.from('world'));await pump()
    assert.equal(await ask('MESSAGES'),'@t:776f726c64;')
    aSocket.emit('data',Buffer.from(await ask('E2E js@t 736563726574'),'hex'));await pump()
    const secret=received.pop();assert.equal(secret.data[0],0xb6)
    assert.equal(io.decrypt_e2e(secret.data,'interop-e2e-key').data.toString(),'secret')
    assert.equal(io.decrypt_e2e(secret.data,'wrong-key'),undefined)
    io.signal_e2e('arduino@t',Buffer.from('reply'),'interop-e2e-key');await pump()
    assert.equal(await ask('MESSAGES'),'@t:7265706c79;')
  } finally {
    if(io){io.socket=null;io.destroy()}
    if(manager){clearInterval(manager.pingIntervalID);clearInterval(manager.monitIntervalID);clearInterval(manager.metrics.tickId)}
    if(child){child.stdin.end();child.kill()}
    if(lines)await lines.return()
    rmSync(build,{recursive:true,force:true})
  }
})
