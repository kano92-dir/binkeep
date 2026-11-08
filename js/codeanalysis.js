// Whole-binary code pass: a linear sweep over the executable sections that
// collects function starts, calls, jumps and data references (xrefs).
// Linear sweep is a heuristic: data inside code can be misread, but for
// compiler output it finds the vast majority of real references.
import { classify } from './disasm.js';

export const REF = { call: 0, jump: 1, data: 2, api: 3 };
export const REF_NAMES = ['call', 'jump', 'data', 'api'];
const enc = (from, kind) => from * 4 + kind;
export const decRef = (x) => ({ from: Math.floor(x / 4), kind: REF_NAMES[x % 4] });

const tick = () => new Promise((r) => setTimeout(r, 0));
// capstone-wasm copies input onto the WebAssembly stack, which is small:
// keep each chunk well under it or the heap gets corrupted.
const CHUNK = 0x2000;

function codeRegions(model, bytes) {
  const regs = [];
  for (const s of model.sections) {
    if (!s.x || !s.size || s.off >= bytes.length) continue;
    const size = Math.min(s.size, bytes.length - s.off, s.vsize || s.size);
    if (size <= 0) continue;
    if (regs.some((r) => s.va < r.va + r.size && r.va < s.va + size)) continue; // overlapping (segments vs sections)
    regs.push({ va: s.va, off: s.off, size, name: s.name });
  }
  return regs.sort((a, b) => a.va - b.va);
}

export function codeSize(model, bytes) {
  return codeRegions(model, bytes).reduce((n, r) => n + r.size, 0);
}

export async function analyzeCode({ model, bytes, engine, onProgress, signal, maxBytes = 48 * 1048576 }) {
  const fam = engine.family;
  const regions = codeRegions(model, bytes);
  const inCode = (va) => regions.some((r) => va >= r.va && va < r.va + r.size);
  const mapped = (va) => model.vaToOff(va) >= 0 || model.sections.some((s) => va >= s.va && va < s.va + Math.max(s.vsize, s.size));
  const total = Math.min(maxBytes, regions.reduce((n, r) => n + r.size, 0));
  const xrefs = new Map();       // target va -> encoded refs
  const apiRefs = new Map();     // api name -> encoded refs
  const callsFrom = new Map();   // function start -> count (filled later)
  const starts = new Set();
  const thunks = new Map();      // va of `jmp [iat]` -> api name
  const callSites = [];          // [from, target] for direct calls
  const addRef = (map, key, from, kind) => {
    let a = map.get(key);
    if (!a) map.set(key, (a = []));
    if (a.length < 5000) a.push(enc(from, kind));
  };

  for (const f of model.funcStarts || []) if (inCode(f.va)) starts.add(f.va);
  if (model.entry != null && inCode(model.entry)) starts.add(model.entry);
  for (const [va] of model.labels) if (inCode(va)) starts.add(va);

  const adrp = new Map(); // arm64 register -> page
  let done = 0, insnCount = 0, bad = 0, lastYield = performance.now();
  const step = fam === 'x86' ? 1 : 4;

  for (const r of regions) {
    let va = r.va;
    const endVa = r.va + r.size;
    while (va < endVa && done < total) {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError');
      const off = r.off + (va - r.va);
      const len = Math.min(CHUNK, endVa - va);
      let insns;
      try { insns = engine.disasm(bytes.subarray(off, off + len), va, 0); } catch { insns = []; }
      if (!insns.length) { va += step; done += step; bad++; continue; }
      // The last instruction of a chunk may be cut off; re-read it with the next chunk.
      const usable = len === CHUNK && insns.length > 1 ? insns.length - 1 : insns.length;
      for (let k = 0; k < usable; k++) {
        const ins = insns[k];
        insnCount++;
        const m = ins.mnemonic;
        const ops = ins.opStr;
        const kind = classify(fam, m);
        if (fam === 'arm') {
          if (m === 'adrp') {
            const mm = ops.match(/^(x\d+), #0x([0-9a-f]+)$/);
            if (mm) adrp.set(mm[1], parseInt(mm[2], 16));
          } else if (m === 'add') {
            const mm = ops.match(/^(x\d+), (x\d+), #0x([0-9a-f]+)$/);
            if (mm && adrp.has(mm[2])) {
              const t = adrp.get(mm[2]) + parseInt(mm[3], 16);
              adrp.delete(mm[2]);
              if (mapped(t)) addRef(xrefs, t, ins.address, REF.data);
            }
          } else if (m === 'ldr' || m === 'str' || m === 'ldrsw') {
            const mm = ops.match(/\[(x\d+), #0x([0-9a-f]+)\]/);
            if (mm && adrp.has(mm[1])) {
              const t = adrp.get(mm[1]) + parseInt(mm[2], 16);
              const api = model.iat.get(t);
              if (api) addRef(apiRefs, api, ins.address, REF.data);
              else if (mapped(t)) addRef(xrefs, t, ins.address, REF.data);
            }
          }
          if (kind === 'call' || kind === 'jump') {
            const mm = ops.match(/#0x([0-9a-f]+)$/);
            if (mm) {
              const t = parseInt(mm[1], 16);
              const api = model.iat.get(t);
              if (kind === 'call') {
                if (api) addRef(apiRefs, api, ins.address, REF.api);
                else if (inCode(t)) { starts.add(t); callSites.push(ins.address, t); }
              }
              if (!api && inCode(t)) addRef(xrefs, t, ins.address, kind === 'call' ? REF.call : REF.jump);
            }
          }
          if (kind === 'ret' || kind === 'call') adrp.clear();
          continue;
        }

        // x86 / x64
        if (!ops.includes('0x')) continue;
        let mm = ops.match(/\[rip ([+-]) 0x([0-9a-f]+)\]/);
        let t = null, mem = false;
        if (mm) { t = ins.address + ins.size + (mm[1] === '+' ? 1 : -1) * parseInt(mm[2], 16); mem = true; }
        else if ((mm = ops.match(/\[0x([0-9a-f]+)\]/))) { t = parseInt(mm[1], 16); mem = true; }
        else if ((mm = ops.match(/^0x([0-9a-f]+)$/))) t = parseInt(mm[1], 16);
        else if ((mm = ops.match(/(?:^|, )0x([0-9a-f]{5,})$/))) t = parseInt(mm[1], 16);
        if (t == null) continue;
        if (mem) {
          const api = model.iat.get(t);
          if (api) {
            addRef(apiRefs, api, ins.address, kind === 'call' || kind === 'jump' ? REF.api : REF.data);
            if (m === 'jmp') thunks.set(ins.address, api);
          } else if (mapped(t)) addRef(xrefs, t, ins.address, REF.data);
          continue;
        }
        if (kind === 'call' && inCode(t)) { starts.add(t); callSites.push(ins.address, t); addRef(xrefs, t, ins.address, REF.call); }
        else if (kind === 'jump' && inCode(t)) addRef(xrefs, t, ins.address, REF.jump);
        else if (!kind && mapped(t)) addRef(xrefs, t, ins.address, REF.data);
      }
      const last = insns[usable - 1];
      const nextVa = last.address + last.size;
      done += nextVa - va;
      va = nextVa;
      if (performance.now() - lastYield > 24) {
        onProgress?.(Math.min(1, done / total), insnCount);
        await tick();
        lastYield = performance.now();
      }
    }
  }

  // Calls into a `jmp [iat]` thunk are API calls.
  for (let i = 0; i < callSites.length; i += 2) {
    const api = thunks.get(callSites[i + 1]);
    if (api) addRef(apiRefs, api, callSites[i], REF.api);
  }

  // Functions: sorted starts, size up to the next start (or the .pdata end).
  const pdataEnd = new Map((model.funcStarts || []).filter((f) => f.end).map((f) => [f.va, f.end]));
  const list = [...starts].sort((a, b) => a - b);
  const regionEnd = (va) => { const r = regions.find((x) => va >= x.va && va < x.va + x.size); return r ? r.va + r.size : va; };
  const functions = list.map((va, i) => {
    const next = i + 1 < list.length ? list[i + 1] : Infinity;
    const end = pdataEnd.get(va) || Math.min(next, regionEnd(va));
    return { va, size: Math.max(0, end - va), thunk: thunks.get(va) || '', xrefs: (xrefs.get(va) || []).filter((x) => x % 4 === REF.call).length, calls: 0 };
  });
  const funcIndexOf = (va) => {
    let lo = 0, hi = functions.length - 1, ans = -1;
    while (lo <= hi) { const mid = (lo + hi) >> 1; if (functions[mid].va <= va) { ans = mid; lo = mid + 1; } else hi = mid - 1; }
    return ans;
  };
  for (let i = 0; i < callSites.length; i += 2) {
    const fi = funcIndexOf(callSites[i]);
    if (fi >= 0) functions[fi].calls++;
  }
  for (const [api, refs] of apiRefs) for (const x of refs) { const fi = funcIndexOf(Math.floor(x / 4)); if (fi >= 0) functions[fi].calls++; }
  onProgress?.(1, insnCount);
  return { functions, xrefs, apiRefs, funcIndexOf, insnCount, bad, bytes: done, regions: regions.length, callsFrom };
}
