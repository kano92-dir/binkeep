// ELF (32/64-bit, little or big endian) parser.
import { hex } from './pe.js';

const MACHINES = {
  3: ['x86', { arch: 'X86', mode: 'MODE_32' }],
  62: ['x86-64', { arch: 'X86', mode: 'MODE_64' }],
  40: ['ARM', { arch: 'ARM', mode: 'MODE_ARM' }],
  183: ['AArch64', { arch: 'ARM64', mode: 'MODE_ARM' }],
  8: ['MIPS', null],
  20: ['PowerPC', null],
  21: ['PowerPC64', null],
  243: ['RISC-V', null],
};

const TYPES = { 1: 'Relocatable (.o)', 2: 'Executable', 3: 'Shared object / PIE', 4: 'Core dump' };

export function isELF(bytes) {
  return bytes.length >= 52 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;
}

export function parseELF(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const is64 = bytes[4] === 2;
  const le = bytes[5] !== 2;
  const warnings = [];
  const u16 = (o) => dv.getUint16(o, le);
  const u32 = (o) => dv.getUint32(o, le);
  const addr = (o) => (is64 ? Number(dv.getBigUint64(o, le)) : u32(o));
  const readCStr = (off, max = 512) => {
    let s = '';
    for (let i = off; i >= 0 && i < bytes.length && i < off + max; i++) {
      if (bytes[i] === 0) break;
      s += String.fromCharCode(bytes[i]);
    }
    return s;
  };

  const type = u16(16);
  const machine = u16(18);
  const entry = addr(24);
  const phoff = addr(is64 ? 32 : 28);
  const shoff = addr(is64 ? 40 : 32);
  const phentsize = u16(is64 ? 54 : 42), phnum = u16(is64 ? 56 : 44);
  const shentsize = u16(is64 ? 58 : 46), shnum = u16(is64 ? 60 : 48), shstrndx = u16(is64 ? 62 : 50);

  const segments = [];
  for (let i = 0; i < phnum && phoff + (i + 1) * phentsize <= bytes.length; i++) {
    const o = phoff + i * phentsize;
    segments.push(is64
      ? { type: u32(o), flags: u32(o + 4), off: addr(o + 8), va: addr(o + 16), filesz: addr(o + 32), memsz: addr(o + 40) }
      : { type: u32(o), off: u32(o + 4), va: u32(o + 8), filesz: u32(o + 16), memsz: u32(o + 20), flags: u32(o + 24) });
  }

  const shdrs = [];
  for (let i = 0; i < shnum && shoff && shoff + (i + 1) * shentsize <= bytes.length; i++) {
    const o = shoff + i * shentsize;
    shdrs.push(is64
      ? { nameOff: u32(o), type: u32(o + 4), flags: addr(o + 8), va: addr(o + 16), off: addr(o + 24), size: addr(o + 32), link: u32(o + 40), entsize: addr(o + 56) }
      : { nameOff: u32(o), type: u32(o + 4), flags: u32(o + 8), va: u32(o + 12), off: u32(o + 16), size: u32(o + 20), link: u32(o + 24), entsize: u32(o + 36) });
  }
  const strtab = shdrs[shstrndx];
  for (const s of shdrs) s.name = strtab ? readCStr(strtab.off + s.nameOff, 128) : '';

  const loads = segments.filter((s) => s.type === 1);
  const vaToOff = (va) => {
    for (const s of loads) if (va >= s.va && va < s.va + s.filesz) return s.off + (va - s.va);
    for (const s of shdrs) if (s.type !== 8 && s.va && va >= s.va && va < s.va + s.size) return s.off + (va - s.va);
    return -1;
  };
  const offToVa = (off) => {
    for (const s of loads) if (off >= s.off && off < s.off + s.filesz) return s.va + (off - s.off);
    return null;
  };

  // Sections shown in the UI: section headers, or PT_LOAD segments if they were stripped.
  const sections = shdrs.length > 1
    ? shdrs.filter((s) => s.type !== 0).map((s) => ({
        name: s.name, va: s.va, vsize: s.size, off: s.off, size: s.type === 8 ? 0 : s.size,
        r: !!(s.flags & 2), w: !!(s.flags & 1), x: !!(s.flags & 4),
      }))
    : loads.map((s, i) => ({
        name: `LOAD${i}`, va: s.va, vsize: s.memsz, off: s.off, size: s.filesz,
        r: !!(s.flags & 4), w: !!(s.flags & 2), x: !!(s.flags & 1),
      }));
  if (shdrs.length <= 1) warnings.push('No section headers: showing PT_LOAD segments instead');

  // Symbols
  const readSyms = (sec) => {
    const out = [];
    const link = shdrs[sec.link];
    if (!link) return out;
    const esz = sec.entsize || (is64 ? 24 : 16);
    const n = Math.min(Math.floor(sec.size / esz), 200000);
    for (let i = 1; i < n; i++) {
      const o = sec.off + i * esz;
      if (o + esz > bytes.length) break;
      const nameOff = u32(o);
      const info = is64 ? bytes[o + 4] : bytes[o + 12];
      const shndx = is64 ? u16(o + 6) : u16(o + 14);
      const value = is64 ? Number(dv.getBigUint64(o + 8, le)) : u32(o + 4);
      const name = readCStr(link.off + nameOff, 256);
      out.push({ idx: i, name, bind: info >> 4, type: info & 0xf, shndx, value });
    }
    return out;
  };
  const dynsymSec = shdrs.find((s) => s.type === 11);
  const symtabSec = shdrs.find((s) => s.type === 2);
  const dynsymsAll = dynsymSec ? readSyms(dynsymSec) : [];
  const dynsyms = dynsymsAll.filter((s) => s.name);
  const symtab = symtabSec ? readSyms(symtabSec).filter((s) => s.name) : [];

  // Relocations against the GOT: map each GOT slot to the symbol it will hold,
  // so `jmp [rip+X]` in a PLT stub and `call [rip+X]` resolve to a name.
  const got = new Map();
  const symByIdx = new Map(dynsymsAll.map((s) => [s.idx, s.name]));
  for (const sec of shdrs) {
    if ((sec.type !== 4 && sec.type !== 9) || !dynsymSec || shdrs[sec.link] !== dynsymSec) continue;
    const rela = sec.type === 4;
    const esz = sec.entsize || (is64 ? (rela ? 24 : 16) : (rela ? 12 : 8));
    const n = Math.min(Math.floor(sec.size / esz), 200000);
    for (let i = 0; i < n; i++) {
      const o = sec.off + i * esz;
      if (o + esz > bytes.length) break;
      const where = addr(o);
      const info = is64 ? Number(dv.getBigUint64(o + 8, le)) : u32(o + 4);
      const symIdx = is64 ? Math.floor(info / 0x100000000) : info >>> 8;
      const name = symByIdx.get(symIdx);
      if (name && !got.has(where)) got.set(where, name);
    }
  }

  const imported = dynsyms.filter((s) => s.shndx === 0);
  const imports = imported.length ? [{ lib: 'Dynamic symbols (undefined)', fns: imported.map((s) => ({ name: s.name })) }] : [];

  const exports = [];
  const seen = new Set();
  for (const [list, src] of [[dynsyms, 'dynsym'], [symtab, 'symtab']]) {
    for (const s of list) {
      if (s.shndx === 0 || !s.value || (s.type !== 2 && s.type !== 1)) continue;
      if (src === 'dynsym' && s.bind !== 1 && s.bind !== 2) continue;
      if (seen.has(s.name)) continue;
      seen.add(s.name);
      exports.push({ name: s.name, va: s.value, forwarder: '', source: src, func: s.type === 2 });
    }
  }
  exports.sort((a, b) => a.va - b.va);

  const labels = new Map();
  for (const e of exports) if (e.func) labels.set(e.va, e.name);
  if (entry) labels.set(entry, labels.get(entry) || 'entry');
  const funcStarts = exports.filter((e) => e.func).map((e) => ({ va: e.va, end: null }));

  // Dynamic section: NEEDED libraries and BIND_NOW flags
  const needed = [];
  let bindNow = false;
  const dynSeg = segments.find((s) => s.type === 2);
  const dynSec = shdrs.find((s) => s.type === 6);
  const dynOff = dynSec ? dynSec.off : dynSeg ? dynSeg.off : -1;
  const dynSize = dynSec ? dynSec.size : dynSeg ? dynSeg.filesz : 0;
  const dynStr = dynSec ? shdrs[dynSec.link] : dynsymSec ? shdrs[dynsymSec.link] : null;
  if (dynOff >= 0) {
    const esz = is64 ? 16 : 8;
    for (let o = dynOff; o + esz <= dynOff + dynSize && o + esz <= bytes.length; o += esz) {
      const tag = is64 ? Number(dv.getBigInt64(o, le)) : dv.getInt32(o, le);
      const val = addr(o + (is64 ? 8 : 4));
      if (tag === 0) break;
      if (tag === 1 && dynStr) needed.push(readCStr(dynStr.off + val, 256));
      if (tag === 24) bindNow = true;
      if (tag === 30 && val & 0x8) bindNow = true;
      if (tag === 0x6ffffffb && val & 0x1) bindNow = true;
    }
  }

  const interpSeg = segments.find((s) => s.type === 3);
  const interp = interpSeg ? readCStr(interpSeg.off, 256) : '';
  const stack = segments.find((s) => s.type === 0x6474e551);
  const relro = segments.some((s) => s.type === 0x6474e552);
  const canary = dynsyms.some((s) => s.name === '__stack_chk_fail') || symtab.some((s) => s.name === '__stack_chk_fail');
  const fortify = dynsyms.some((s) => /_chk$/.test(s.name) && s.name !== '__stack_chk_fail');
  const pie = type === 3 && !!interp;

  const [archName, disasm] = MACHINES[machine] || [`unknown (${machine})`, null];
  const hints = [];
  if (!symtabSec) hints.push({ level: 'info', text: 'Stripped: no .symtab, only dynamic symbols are available' });
  for (const s of sections) if (s.w && s.x) hints.push({ level: 'warn', text: `${s.name} is both writable and executable` });
  if (stack && stack.flags & 1) hints.push({ level: 'warn', text: 'Executable stack (PT_GNU_STACK has X)' });
  if (!le) hints.push({ level: 'info', text: 'Big-endian binary' });

  return {
    format: is64 ? 'ELF64' : 'ELF32',
    arch: archName,
    bits: is64 ? 64 : 32,
    kind: TYPES[type] || `type ${type}`,
    entry: entry || null,
    facts: [
      ['Format', `${is64 ? 'ELF64' : 'ELF32'} ${le ? 'little-endian' : 'big-endian'}`],
      ['Architecture', archName],
      ['Type', pie ? 'PIE executable' : TYPES[type] || String(type)],
      ['Entry point', entry ? hex(entry) : 'none'],
      ['Interpreter', interp || 'none (static or library)'],
      ['Needed libs', needed.length ? needed.join(', ') : 'none'],
      ['Sections', String(sections.length)],
      ['Imported symbols', String(imported.length)],
      ['Defined symbols', String(exports.length)],
    ],
    mitigations: [
      ['PIE', pie],
      ['NX stack', !!stack && !(stack.flags & 1)],
      ['RELRO', relro ? (bindNow ? 'Full' : 'Partial') : false],
      ['Stack canary', canary],
      ['FORTIFY', fortify],
    ],
    sections,
    imports,
    exports,
    labels,
    iat: got,
    funcStarts,
    overlay: null,
    hints,
    warnings,
    disasm,
    vaToOff,
    offToVa,
  };
}
