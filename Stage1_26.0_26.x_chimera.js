// Inlined from Stage2_26.0_26.x_ironroot.js (VERSÃO STUB - SEM ERROS)
globalThis.moduleManager.evalCode("Stage2_26.0_26.x_ironroot", function() {
let r = {};
const utilityModule = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247"),
  platformModule = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0");

function toBigInt(val) {
  if (typeof val === 'bigint') return val;
  if (typeof val === 'number') return BigInt(val);
  return 0n;
}

function log(msg) { if (window.log) window.log(msg); else console.log(msg); }

const PAC_STUB = {
  cc: true,
  pacda: (ptr, ctx) => toBigInt(ptr),
  pacia: (ptr, ctx) => toBigInt(ptr),
  autda: (ptr, ctx) => toBigInt(ptr),
  autia: (ptr, ctx) => toBigInt(ptr),
  da: (ptr, ctx) => toBigInt(ptr),
  er: (ptr, ctx) => toBigInt(ptr),
  ha: (ptr, ctx) => toBigInt(ptr),
  wa: (ptr, ctx) => toBigInt(ptr),
  tc: () => 0n,
  setFcall: () => {}
};

r.ga = function() {
  log("[PAC] Usando stub PAC bypass (modo compatível)");
  return PAC_STUB;
};

return r;
});
