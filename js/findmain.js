// Find the program's own main function, skipping the compiler's startup code.
//
// The entry point of most programs is C runtime code that sets up the process
// and only then calls the function the author wrote. This module looks for it:
//   1. a symbol named main / wmain / WinMain / main.main,
//   2. Mach-O LC_MAIN, whose entry point already is main,
//   3. glibc / musl _start: the address passed to __libc_start_main
//      (rdi on x86-64, the last push on x86, x0 on ARM64),
//   4. MSVC / MinGW startup: once the CRT has fetched argv or the command line
//      (__p___argv, __wgetmainargs, ...), the next call whose return value is
//      kept is main,
//   5. older msvcrt startup: the call whose result is passed to exit().
// The startup functions are walked in execution order (fall-through first),
// not in address order, because compilers move cold paths around.

import { classify, operandTarget } from './disasm.js';

const MAIN_NAMES = ['main', '_main', 'wmain', '_wmain', 'WinMain', 'wWinMain', '_WinMain@16', '_wWinMain@16', 'main.main', '_main.main'];
const ARGS_API = /(^|!)(?:_o_)?(__p___w?argv|__p___argc|_get_initial_(narrow|wide)_environment|__w?getmainargs|_get_(narrow|wide)_winmain_command_line|__p__acmdln|__p__wcmdln)$/;
const START_MAIN = /(^|!)__libc_start_main(@.*)?$/;
const EXIT_API = /(^|!)(?:_o_)?exit$/; // the CRT's exit(), not ExitProcess (NSIS-style WinMain ends with ExitProcess(cleanup()))
const NORETURN = /(^|!)(?:_o_)?(exit|_exit|_Exit|ExitProcess|abort|_amsg_exit|_invoke_watson|__stack_chk_fail|__fastfail|\?terminate@@YAXXZ|terminate|__report_gsfailure)$/;

export function findMain({ engine, model: m, bytes }) {
  const fam = engine.family;
  const isCode = (va) => {
    if (va == null || m.vaToOff(va) < 0) return false;
    const s = m.sections.find((x) => va >= x.va && va < x.va + Math.max(x.vsize || 0, x.size || 0));
    return !s || s.x;
  };
  const dis = (va, count) => {
    const off = m.vaToOff(va);
    if (off < 0) return [];
    return engine.disasm(bytes.subarray(off, Math.min(bytes.length, off + count * 16)), va, count);
  };

  // 1. symbols
  const byName = new Map();
  for (const [va, name] of m.labels) if (!byName.has(name)) byName.set(name, va);
  for (const n of MAIN_NAMES) {
    const va = byName.get(n);
    if (va != null && isCode(va)) return { va, name: n.replace(/^_/, '').replace(/@16$/, ''), how: 'symbol' };
  }
  if (m.entry == null) return null;

  // Go: main.main from the pclntab function table (present even when stripped)
  const go = goMain(m, bytes);
  if (go && isCode(go)) return { va: go, name: 'main.main', how: 'Go pclntab' };

  // 2. Mach-O LC_MAIN
  if (m.entryIsMain && isCode(m.entry)) return { va: m.entry, name: 'main', how: 'LC_MAIN' };

  // Name of the import a call or jump goes to: directly through the IAT/GOT,
  // or through a jump thunk / PLT stub that loads it.
  const thunkCache = new Map();
  const thunkApi = (va) => {
    if (thunkCache.has(va)) return thunkCache.get(va);
    let api = '', page = null;
    for (const i of dis(va, 4)) {
      if (/^(endbr|nop|bti)/.test(i.mnemonic)) continue;
      if (fam === 'x86') {
        if (/jmp$/.test(i.mnemonic)) { const j = operandTarget(fam, i); if (j?.mem) api = m.iat.get(j.va) || ''; }
        break;
      }
      let r = i.opStr.match(/^x16, #0x([0-9a-f]+)$/i);
      if (i.mnemonic === 'adrp' && r) { page = parseInt(r[1], 16); continue; }
      r = i.opStr.match(/^x17, \[x16(?:, #0x([0-9a-f]+))?\]$/i);
      if (i.mnemonic === 'ldr' && r && page != null) api = m.iat.get(page + parseInt(r[1] || '0', 16)) || '';
      break;
    }
    thunkCache.set(va, api);
    return api;
  };
  const apiOf = (insn) => {
    const t = operandTarget(fam, insn);
    if (!t) return '';
    if (t.mem) return m.iat.get(t.va) || '';
    if (m.iat.has(t.va)) return m.iat.get(t.va);
    return t.direct ? thunkApi(t.va) : '';
  };
  const directTarget = (insn) => {
    const t = operandTarget(fam, insn);
    return t && t.direct && !t.mem ? t.va : null;
  };
  // Does the instruction after a call keep its return value?
  const keepsResult = (list, n) => {
    let nx = list[n + 1];
    if (nx && nx.mnemonic === 'add' && /^[er]sp, /.test(nx.opStr)) nx = list[n + 2];
    if (!nx) return false;
    if (fam === 'x86') return /^mov/.test(nx.mnemonic) && /, [er]?ax$/.test(nx.opStr);
    return /^(mov|str|stur)$/.test(nx.mnemonic) && /^w0|, w0$|^x0|, x0$/.test(nx.opStr);
  };

  // x86: does the value a call returns reach exit()? Follows both sides of
  // branches for a few instructions, tracking registers and memory it is copied to.
  const R = (r) => { const x = r.toLowerCase().match(/^(?:[re]?([abcd])x|[re]?(si|di|bp)|(r(?:8|9|1[0-5]))[dwb]?)$/); return x ? (x[1] || x[2] || x[3]) : null; };
  const VOLATILE = ['a', 'c', 'd', 'r8', 'r9', 'r10', 'r11'];
  const flowsToExit = (start) => {
    if (fam !== 'x86') return false;
    let budget = 60;
    const go = (va, regs, mem, pushed, depth) => {
      for (let k = 0; k < 16 && budget-- > 0; k++) {
        const i = dis(va, 1)[0];
        if (!i) return false;
        const mn = i.mnemonic.toLowerCase();
        const ops = i.opStr.split(', ');
        const kind = classify(fam, mn);
        if (kind === 'ret' || mn === 'int3' || mn === 'hlt') return false;
        if (kind === 'call') {
          const api = apiOf(i);
          if (EXIT_API.test(api)) return regs.has(m.bits === 64 ? 'c' : '') || pushed;
          if (NORETURN.test(api)) return false;
          regs = new Set([...regs].filter((r) => !VOLATILE.includes(r)));
          pushed = false;
        } else if (kind === 'jump') {
          const t = directTarget(i);
          if (mn === 'jmp') { if (t == null) return false; va = t; continue; }
          if (t != null && depth < 4 && go(t, new Set(regs), new Set(mem), pushed, depth + 1)) return true;
        } else if (mn === 'push') {
          pushed = R(ops[0]) != null && regs.has(R(ops[0]));
        } else if (/^(mov|movsxd|movzx|lea|xor|pop)$/.test(mn) && ops.length >= 1) {
          const dst = R(ops[0]);
          const t = operandTarget(fam, i);
          const srcAlive = ops[1] && (R(ops[1]) ? regs.has(R(ops[1])) : t?.mem && mem.has(t.va));
          if (dst) { if (/^mov/.test(mn) && srcAlive) regs.add(dst); else regs.delete(dst); }
          else if (t?.mem && mn === 'mov') { if (srcAlive) mem.add(t.va); else mem.delete(t.va); }
        } else if (ops[0] && R(ops[0]) && !/^(test|cmp|bt)$/.test(mn)) {
          regs.delete(R(ops[0]));
        }
        if (!regs.size && !mem.size && !pushed) return false;
        va = i.address + i.size;
      }
      return false;
    };
    return go(start, new Set(['a']), new Set(), false, 0);
  };

  // Walk one function in rough execution order. Returns the instructions as a
  // list of runs (straight-line code) and the functions it calls or tail-jumps to.
  const walk = (fva) => {
    const runs = [], callees = [], done = new Set();
    const todo = [fva];
    let budget = 3000;
    const near = (t) => t >= fva - 0x4000 && t < fva + 0x8000;
    while (todo.length && budget > 0) {
      let va = todo.pop();
      const run = [];
      while (va != null && !done.has(va) && budget > 0) {
        const insn = dis(va, 1)[0];
        if (!insn) break;
        done.add(va);
        budget--;
        run.push(insn);
        const mn = insn.mnemonic.toLowerCase();
        const kind = classify(fam, mn);
        const next = insn.address + insn.size;
        if (kind === 'ret' || mn === 'int3' || mn === 'hlt' || mn === 'ud2') break;
        if (kind === 'call') {
          const api = apiOf(insn);
          if (NORETURN.test(api)) break;
          const t = directTarget(insn);
          if (!api && isCode(t)) callees.push(t);
          va = next;
          continue;
        }
        if (kind === 'jump') {
          const t = directTarget(insn);
          const uncond = fam === 'x86' ? mn === 'jmp' : (mn === 'b' || mn === 'br' || mn === 'bx');
          if (uncond) {
            if (t != null && isCode(t) && !apiOf(insn)) {
              if (near(t)) { va = t; continue; }
              callees.push(t);
            }
            break;
          }
          if (t != null && isCode(t) && near(t)) todo.unshift(t); // taken branch later, fall through first
          va = next;
          continue;
        }
        va = next;
      }
      if (run.length) runs.push(run);
    }
    return { runs, callees };
  };

  const seen = new Set();
  let fallback = null;
  const queue = [{ va: m.entry, depth: 0 }];
  while (queue.length) {
    const { va: fva, depth } = queue.shift();
    if (seen.has(fva) || seen.size > 30) continue;
    seen.add(fva);
    const { runs, callees } = walk(fva);
    let armed = '';
    for (const run of runs) {
      const reg = {};
      for (let n = 0; n < run.length; n++) {
        const i = run[n];
        const mn = i.mnemonic.toLowerCase();
        // 3. the address of main handed to __libc_start_main
        if (fam === 'x86') {
          let r = i.opStr.match(/^([re]di), (?:qword ptr |dword ptr )?(?:\[rip ([+-]) 0x([0-9a-f]+)\]|0x([0-9a-f]+))$/i);
          if (r && (mn === 'lea' || mn === 'mov')) {
            const v = r[3] ? i.address + i.size + (r[2] === '+' ? 1 : -1) * parseInt(r[3], 16) : parseInt(r[4], 16);
            reg.di = mn === 'mov' && r[3] ? readPtr(m, bytes, v, 8) : v;
          }
          if (mn === 'push') { r = i.opStr.match(/^(?:dword ptr )?0x([0-9a-f]+)$/i); reg.push = r ? parseInt(r[1], 16) : null; }
        } else {
          let r = i.opStr.match(/^x0, #0x([0-9a-f]+)$/i);
          if (r && mn === 'adrp') reg.x0 = parseInt(r[1], 16);
          r = i.opStr.match(/^x0, x0, #0x([0-9a-f]+)$/i);
          if (r && mn === 'add' && reg.x0 != null) reg.x0 += parseInt(r[1], 16);
          r = i.opStr.match(/^x0, \[x0(?:, #0x([0-9a-f]+))?\]$/i);
          if (r && mn === 'ldr' && reg.x0 != null) reg.x0 = readPtr(m, bytes, reg.x0 + parseInt(r[1] || '0', 16), 8);
        }
        if (classify(fam, mn) !== 'call') continue;
        const api = apiOf(i);
        const tgt = directTarget(i);
        if (START_MAIN.test(api) || (fva === m.entry && !api && m.format.startsWith('ELF'))) {
          const cand = fam === 'x86' ? (m.bits === 64 ? reg.di : reg.push) : reg.x0;
          if (isCode(cand) && cand !== m.entry) return { va: cand, name: 'main', how: '__libc_start_main' };
        }
        if (api) {
          // 4. argv / command line fetched: main comes next
          if (ARGS_API.test(api)) armed = /winmain|cmdln/i.test(api) ? (/wide|wcmdln/.test(api) ? 'wWinMain' : 'WinMain') : (/w(argv|getmainargs)|wide/.test(api) ? 'wmain' : 'main');
        } else if (isCode(tgt)) {
          if (armed && keepsResult(run, n)) return { va: tgt, name: armed, how: 'CRT startup' };
          // 5. exit(main(...))
          if (!fallback && flowsToExit(i.address + i.size)) fallback = { va: tgt, name: wideMain(m) ? 'wmain' : 'main', how: 'exit call' };
        }
      }
    }
    if (depth < 3) for (const c of callees) queue.push({ va: c, depth: depth + 1 });
  }
  return fallback;
}

// Go keeps a table of every function and its name (pclntab) for stack traces.
// Find it by section name or by its magic header, then look up main.main.
function goMain(m, bytes) {
  const sec = m.sections.find((s) => /gopclntab/.test(s.name) && s.size);
  const starts = [];
  if (sec) { const off = m.vaToOff(sec.va); if (off >= 0) starts.push(off); }
  if (!starts.length) {
    // Only scan files that look like Go: a Go section, or the build info marker.
    const sig = [0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a]; // "\xff Go buildinf:"
    if (!m.sections.some((s) => /go\.buildinfo|gosymtab/.test(s.name)) && !findBytes(bytes, sig)) return null;
    for (let i = 0; i + 16 < bytes.length && starts.length < 8; i += 4) {
      if (bytes[i + 1] !== 0xff || bytes[i + 2] !== 0xff || bytes[i + 3] !== 0xff) continue;
      if (![0xfb, 0xfa, 0xf0, 0xf1].includes(bytes[i]) || bytes[i + 4] || bytes[i + 5]) continue;
      if (![1, 2, 4].includes(bytes[i + 6]) || ![4, 8].includes(bytes[i + 7])) continue;
      starts.push(i);
    }
  }
  for (const t of starts) {
    try { const va = goTable(m, bytes, t); if (va) return va; } catch { /* not a pclntab */ }
  }
  return null;
}

function goTable(m, bytes, t) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = dv.getUint32(t, true), ps = bytes[t + 7];
  const word = (o) => (ps === 8 ? Number(dv.getBigUint64(o, true)) : dv.getUint32(o, true));
  const cstr = (o) => { let e = o; while (e < bytes.length && bytes[e] && e - o < 64) e++; return String.fromCharCode(...bytes.subarray(o, e)); };
  const hdr = (k) => word(t + 8 + k * ps);
  const nfunc = hdr(0);
  if (!nfunc || nfunc > 2e6) return null;
  if (magic === 0xfffffff0 || magic === 0xfffffff1) { // Go 1.18+
    let text = hdr(2);
    const names = t + hdr(3), pcln = t + hdr(7);
    if (!text) text = (m.sections.find((s) => /^(\.text|__TEXT,__text|__text)$/.test(s.name)) || {}).va || 0;
    for (let k = 0; k < nfunc; k++) {
      const f = pcln + dv.getUint32(pcln + k * 8 + 4, true);
      if (cstr(names + dv.getInt32(f + 4, true)) === 'main.main') return text + dv.getUint32(f, true);
    }
  } else if (magic === 0xfffffffa) { // Go 1.16 / 1.17
    const names = t + hdr(2), pcln = t + hdr(6);
    for (let k = 0; k < nfunc; k++) {
      const f = pcln + word(pcln + (2 * k + 1) * ps);
      if (cstr(names + dv.getInt32(f + ps, true)) === 'main.main') return word(f);
    }
  } else if (magic === 0xfffffffb) { // Go 1.2 - 1.15
    const tab = t + 8 + ps;
    for (let k = 0; k < nfunc; k++) {
      const f = t + word(tab + (2 * k + 1) * ps);
      if (cstr(t + dv.getInt32(f + ps, true)) === 'main.main') return word(f);
    }
  }
  return null;
}

function findBytes(bytes, sig) {
  outer: for (let i = bytes.indexOf(sig[0]); i >= 0 && i + sig.length <= bytes.length; i = bytes.indexOf(sig[0], i + 1)) {
    for (let k = 1; k < sig.length; k++) if (bytes[i + k] !== sig[k]) continue outer;
    return true;
  }
  return false;
}

function wideMain(m) {
  for (const x of m.iat.values()) if (/__wgetmainargs|__p___wargv|_get_initial_wide_environment/.test(x)) return true;
  return false;
}

function readPtr(m, bytes, va, size) {
  const off = m.vaToOff(va);
  if (off < 0 || off + size > bytes.length) return null;
  let v = 0;
  for (let k = size - 1; k >= 0; k--) v = v * 256 + bytes[off + k];
  return v;
}
