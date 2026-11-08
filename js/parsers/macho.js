// Mach-O parser: 32/64-bit thin binaries and universal (fat) binaries.
import { hex } from './pe.js';

const CPU = {
  7: ['x86', 32, { arch: 'X86', mode: 'MODE_32' }],
  0x01000007: ['x86-64', 64, { arch: 'X86', mode: 'MODE_64' }],
  12: ['ARM', 32, { arch: 'ARM', mode: 'MODE_ARM' }],
  0x0100000c: ['ARM64', 64, { arch: 'ARM64', mode: 'MODE_ARM' }],
  0x0200000c: ['ARM64_32', 32, { arch: 'ARM64', mode: 'MODE_ARM' }],
  18: ['PowerPC', 32, null],
  0x01000012: ['PowerPC64', 64, null],
};
const FILETYPES = { 1: 'Object file', 2: 'Executable', 6: 'Dynamic library', 7: 'Dynamic linker', 8: 'Bundle', 9: 'Dylib stub', 10: 'dSYM companion', 11: 'Kernel extension' };
const PLATFORMS = { 1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS Simulator', 8: 'tvOS Simulator', 9: 'watchOS Simulator', 10: 'DriverKit', 11: 'visionOS', 12: 'visionOS Simulator' };
const PREFERRED = [0x0100000c, 0x01000007];

const be32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;

function fatArchs(bytes) {
  if (bytes.length < 8) return null;
  const magic = be32(bytes, 0);
  if (magic !== 0xcafebabe && magic !== 0xcafebabf) return null;
  const n = be32(bytes, 4);
  if (n < 1 || n > 32) return null;
  const is64 = magic === 0xcafebabf;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const archs = [];
  for (let i = 0; i < n; i++) {
    const o = 8 + i * (is64 ? 32 : 20);
    if (o + 20 > bytes.length) return null;
    const cpu = be32(bytes, o);
    const offset = is64 ? Number(dv.getBigUint64(o + 8, false)) : be32(bytes, o + 8);
    const size = is64 ? Number(dv.getBigUint64(o + 16, false)) : be32(bytes, o + 12);
    if (!CPU[cpu] || offset + 28 > bytes.length) return null; // also rules out Java .class files
    archs.push({ cpu, offset, size, name: CPU[cpu][0] });
  }
  return archs;
}

function thinMagic(bytes, o) {
  const m = be32(bytes, o);
  if (m === 0xfeedface || m === 0xfeedfacf) return { le: false, is64: m === 0xfeedfacf };
  if (m === 0xcefaedfe || m === 0xcffaedfe) return { le: true, is64: m === 0xcffaedfe };
  return null;
}

export function isMachO(bytes) {
  return bytes.length >= 28 && (!!thinMagic(bytes, 0) || !!fatArchs(bytes));
}

export function parseMachO(bytes) {
  const warnings = [];
  const hints = [];
  let base = 0;
  let slices = null;
  const fat = fatArchs(bytes);
  if (fat) {
    const pick = PREFERRED.map((c) => fat.find((a) => a.cpu === c)).find(Boolean) || fat[0];
    base = pick.offset;
    slices = fat;
    hints.push({ level: 'info', text: `Universal binary with ${fat.map((a) => a.name).join(', ')}. Showing the ${pick.name} slice.` });
  }
  const tm = thinMagic(bytes, base);
  if (!tm) throw new Error('Mach-O header not found');
  const { le, is64 } = tm;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (o) => dv.getUint16(o, le);
  const u32 = (o) => dv.getUint32(o, le);
  const u64 = (o) => Number(dv.getBigUint64(o, le));
  const word = (o) => (is64 ? u64(o) : u32(o));
  const cstr = (o, max = 1024) => {
    let s = '';
    for (let i = o; i >= 0 && i < bytes.length && i < o + max && bytes[i]; i++) s += String.fromCharCode(bytes[i]);
    return s;
  };
  const fixed = (o, n) => cstr(o, n);

  const cpu = u32(base + 4);
  const filetype = u32(base + 12);
  const ncmds = u32(base + 16);
  const flags = u32(base + 24);
  const hdrSize = is64 ? 32 : 28;

  const segments = [];
  const sections = [];
  const dylibs = [];
  const rpaths = [];
  let symtab = null, dysymtab = null, entryOff = null, threadPc = null, uuid = '', build = '', codeSig = null, crypt = null, funcStartsCmd = null, idDylib = '';

  let o = base + hdrSize;
  for (let i = 0; i < Math.min(ncmds, 4096); i++) {
    if (o + 8 > bytes.length) { warnings.push('Load commands are truncated'); break; }
    const cmd = u32(o), size = u32(o + 4);
    if (size < 8) { warnings.push('Malformed load command'); break; }
    switch (cmd >>> 0) {
      case 0x1: case 0x19: {
        const s64 = cmd === 0x19;
        const seg = {
          name: fixed(o + 8, 16),
          vmaddr: s64 ? u64(o + 24) : u32(o + 24),
          vmsize: s64 ? u64(o + 32) : u32(o + 28),
          fileoff: s64 ? u64(o + 40) : u32(o + 32),
          filesize: s64 ? u64(o + 48) : u32(o + 36),
          initprot: u32(o + (s64 ? 60 : 44)),
        };
        segments.push(seg);
        const nsects = u32(o + (s64 ? 64 : 48));
        let so = o + (s64 ? 72 : 56);
        for (let k = 0; k < nsects && k < 512; k++, so += s64 ? 80 : 68) {
          const sflags = u32(so + (s64 ? 64 : 56));
          const type = sflags & 0xff;
          const zerofill = type === 0x1 || type === 0xc || type === 0x12;
          const sec = {
            name: `${fixed(so + 16, 16)},${fixed(so, 16)}`,
            va: s64 ? u64(so + 32) : u32(so + 32),
            vsize: s64 ? u64(so + 40) : u32(so + 36),
            off: base + u32(so + (s64 ? 48 : 40)),
            type,
            reserved1: u32(so + (s64 ? 68 : 60)),
            reserved2: u32(so + (s64 ? 72 : 64)),
            r: !!(seg.initprot & 1), w: !!(seg.initprot & 2),
            x: !!(seg.initprot & 4) && !!(sflags & 0x80000400),
          };
          sec.size = zerofill ? 0 : sec.vsize;
          sections.push(sec);
        }
        break;
      }
      case 0x2: symtab = { symoff: u32(o + 8), nsyms: u32(o + 12), stroff: u32(o + 16), strsize: u32(o + 20) }; break;
      case 0xb: dysymtab = { indirectoff: u32(o + 56), nindirect: u32(o + 60) }; break;
      case 0xc: case 0x80000018: case 0x8000001f: case 0x20: case 0x80000023: {
        const kind = { 0xc: '', 0x80000018: 'weak', 0x8000001f: 'reexport', 0x20: 'lazy', 0x80000023: 'upward' }[cmd >>> 0];
        dylibs.push({ path: cstr(o + u32(o + 8)), kind });
        break;
      }
      case 0xd: idDylib = cstr(o + u32(o + 8)); break;
      case 0x8000001c: rpaths.push(cstr(o + u32(o + 8))); break;
      case 0x80000028: entryOff = u64(o + 8); break;
      case 0x5: {
        const flavor = u32(o + 8);
        if (flavor === 4 && is64) threadPc = u64(o + 16 + 16 * 8);
        else if (flavor === 6 && is64) threadPc = u64(o + 16 + 32 * 8);
        else if (flavor === 1) threadPc = u32(o + 16 + 10 * 4);
        break;
      }
      case 0x1b: uuid = [...bytes.subarray(o + 8, o + 24)].map((b) => b.toString(16).padStart(2, '0')).join('').replace(/^(.{8})(.{4})(.{4})(.{4})/, '$1-$2-$3-$4-').toUpperCase(); break;
      case 0x32: {
        const ver = (v) => `${v >>> 16}.${(v >> 8) & 0xff}${v & 0xff ? '.' + (v & 0xff) : ''}`;
        build = `${PLATFORMS[u32(o + 8)] || 'platform ' + u32(o + 8)} ${ver(u32(o + 12))} (SDK ${ver(u32(o + 16))})`;
        break;
      }
      case 0x24: case 0x25: case 0x2f: case 0x30: {
        const v = u32(o + 8);
        const plat = { 0x24: 'macOS', 0x25: 'iOS', 0x2f: 'tvOS', 0x30: 'watchOS' }[cmd];
        if (!build) build = `${plat} ${v >>> 16}.${(v >> 8) & 0xff}`;
        break;
      }
      case 0x1d: codeSig = { off: base + u32(o + 8), size: u32(o + 12) }; break;
      case 0x21: case 0x2c: crypt = { off: u32(o + 8), size: u32(o + 12), id: u32(o + 16) }; break;
      case 0x26: funcStartsCmd = { off: base + u32(o + 8), size: u32(o + 12) }; break;
      default: break;
    }
    o += size;
  }

  const realSegs = segments.filter((s) => s.filesize > 0);
  const vaToOff = (va) => {
    for (const s of realSegs) if (va >= s.vmaddr && va < s.vmaddr + s.filesize) return base + s.fileoff + (va - s.vmaddr);
    return -1;
  };
  const offToVa = (off) => {
    const r = off - base;
    for (const s of realSegs) if (r >= s.fileoff && r < s.fileoff + s.filesize) return s.vmaddr + (r - s.fileoff);
    return null;
  };
  const textSeg = segments.find((s) => s.name === '__TEXT');

  // Symbols
  const syms = [];
  if (symtab) {
    const esz = is64 ? 16 : 12;
    const n = Math.min(symtab.nsyms, 400000);
    for (let i = 0; i < n; i++) {
      const so = base + symtab.symoff + i * esz;
      if (so + esz > bytes.length) break;
      const strx = u32(so);
      const type = bytes[so + 4];
      syms.push({
        name: strx && strx < symtab.strsize ? cstr(base + symtab.stroff + strx, 512) : '',
        type, sect: bytes[so + 5], desc: u16(so + 6), value: is64 ? u64(so + 8) : u32(so + 8),
      });
    }
  }
  const isStab = (s) => (s.type & 0xe0) !== 0;
  const undef = syms.filter((s) => !isStab(s) && (s.type & 0x0e) === 0 && (s.type & 1) && s.name);
  const defined = syms.filter((s) => !isStab(s) && (s.type & 0x0e) === 0x0e && s.name && s.value);

  // Imports grouped by the library ordinal in n_desc (two-level namespace).
  const libName = (ord) => {
    if (ord > 0 && ord <= dylibs.length) return dylibs[ord - 1].path;
    if (ord === 0xfe) return '(main executable)';
    if (ord === 0xff || ord === 0) return '(flat namespace)';
    return `(library #${ord})`;
  };
  const byLib = new Map();
  for (const s of undef) {
    const lib = libName((s.desc >> 8) & 0xff);
    if (!byLib.has(lib)) byLib.set(lib, []);
    byLib.get(lib).push({ name: s.name });
  }
  const imports = [...byLib].map(([lib, fns]) => ({ lib, fns }));
  for (const d of dylibs) if (!byLib.has(d.path)) imports.push({ lib: d.path, fns: [] });

  const exports = defined.filter((s) => s.type & 1).map((s) => ({ name: s.name, va: s.value, forwarder: '', source: 'symtab', func: true }));
  exports.sort((a, b) => a.va - b.va);
  const labels = new Map();
  for (const s of defined) {
    const sec = sections[s.sect - 1];
    if (sec && sec.x && !labels.has(s.value)) labels.set(s.value, s.name);
  }

  // Stubs and pointer tables -> symbol names, through the indirect symbol table.
  const iat = new Map();
  if (dysymtab && dysymtab.nindirect) {
    for (const sec of sections) {
      const t = sec.type;
      if (t !== 0x6 && t !== 0x7 && t !== 0x8) continue;
      const stride = t === 0x8 ? sec.reserved2 : is64 ? 8 : 4;
      if (!stride) continue;
      const n = Math.floor(sec.vsize / stride);
      for (let k = 0; k < n && k < 200000; k++) {
        const io = base + dysymtab.indirectoff + (sec.reserved1 + k) * 4;
        if (io + 4 > bytes.length) break;
        const idx = u32(io);
        if (idx & 0xc0000000) continue; // INDIRECT_SYMBOL_LOCAL / ABS
        const s = syms[idx];
        if (s?.name) iat.set(sec.va + k * stride, s.name);
      }
    }
  }

  // LC_FUNCTION_STARTS: ULEB128 deltas from the start of __TEXT.
  const funcStarts = [];
  if (funcStartsCmd && textSeg) {
    let p = funcStartsCmd.off, end = Math.min(bytes.length, funcStartsCmd.off + funcStartsCmd.size);
    let addr = textSeg.vmaddr;
    while (p < end) {
      let v = 0, shift = 0, b;
      do { b = bytes[p++]; v += (b & 0x7f) * 2 ** shift; shift += 7; } while (b & 0x80 && p < end);
      if (!v) break;
      addr += v;
      funcStarts.push({ va: addr, end: null });
    }
  }
  for (const e of exports) funcStarts.push({ va: e.va, end: null });

  let entry = null;
  if (entryOff != null && textSeg) entry = textSeg.vmaddr + entryOff - textSeg.fileoff;
  else if (threadPc) entry = threadPc;
  if (entry != null) labels.set(entry, labels.get(entry) || 'entry');

  // Code signature: SuperBlob -> CodeDirectory (identifier, team, flags); CMS blob present?
  let sig = null;
  if (codeSig && codeSig.off + 12 <= bytes.length && be32(bytes, codeSig.off) === 0xfade0cc0) {
    const count = be32(bytes, codeSig.off + 8);
    sig = { identifier: '', team: '', adhoc: false, runtime: false, cms: false };
    for (let k = 0; k < Math.min(count, 64); k++) {
      const type = be32(bytes, codeSig.off + 12 + k * 8);
      const bo = codeSig.off + be32(bytes, codeSig.off + 16 + k * 8);
      if (bo + 52 > bytes.length) continue;
      const magic = be32(bytes, bo);
      if (type === 0 && magic === 0xfade0c02) {
        const version = be32(bytes, bo + 8);
        const cdFlags = be32(bytes, bo + 12);
        sig.identifier = cstr(bo + be32(bytes, bo + 20), 256);
        if (version >= 0x20200 && be32(bytes, bo + 48)) sig.team = cstr(bo + be32(bytes, bo + 48), 64);
        sig.adhoc = !!(cdFlags & 0x2);
        sig.runtime = !!(cdFlags & 0x10000);
      }
      if (type === 0x10000 && magic === 0xfade0b01 && be32(bytes, bo + 4) > 8) sig.cms = true;
    }
  }

  const [archName, bits, disasm] = CPU[cpu] || [`unknown (0x${cpu.toString(16)})`, is64 ? 64 : 32, null];
  const importNames = new Set(undef.map((s) => s.name));
  const pie = !!(flags & 0x200000);
  const mitigations = [
    ['PIE', pie],
    ...(is64 ? [] : [['NX heap', !!(flags & 0x1000000)]]),
    ['NX stack', !(flags & 0x20000)],
    ['Stack canary', importNames.has('___stack_chk_fail') || importNames.has('___stack_chk_guard')],
    ['ARC', importNames.has('_objc_release')],
    ['Code signature', sig ? (sig.adhoc ? 'ad-hoc' : sig.cms ? 'Developer' : true) : false],
    ['Hardened runtime', !!sig?.runtime],
  ];

  if (!symtab || !defined.length) hints.push({ level: 'info', text: 'Stripped: few or no local symbols' });
  if (crypt?.id) hints.push({ level: 'warn', text: 'Encrypted (FairPlay, cryptid=1): the code section is not readable as-is' });
  if (sig?.adhoc) hints.push({ level: 'info', text: 'Ad-hoc code signature: signed without a developer identity' });
  if (!sig) hints.push({ level: 'info', text: cpu === 0x0100000c ? 'No code signature: macOS on Apple silicon refuses to run unsigned arm64 code' : 'No code signature' });
  for (const s of sections) if (s.w && s.x) hints.push({ level: 'warn', text: `${s.name} is both writable and executable` });
  if (flags & 0x20000) hints.push({ level: 'warn', text: 'MH_ALLOW_STACK_EXECUTION is set: the stack is executable' });

  const importCount = undef.length;
  return {
    format: is64 ? 'Mach-O 64' : 'Mach-O',
    arch: archName,
    bits,
    kind: FILETYPES[filetype] || `type ${filetype}`,
    entry,
    facts: [
      ['Format', `${is64 ? 'Mach-O 64-bit' : 'Mach-O 32-bit'}${slices ? ` (universal: ${slices.map((a) => a.name).join(', ')})` : ''}`],
      ['Architecture', archName],
      ['Type', FILETYPES[filetype] || String(filetype)],
      ['Platform', build || 'not stated'],
      ['Entry point', entry != null ? hex(entry) : 'none'],
      ...(idDylib ? [['Install name', idDylib]] : []),
      ['Linked libraries', dylibs.length ? dylibs.map((d) => d.path.split('/').pop() + (d.kind ? ` (${d.kind})` : '')).join(', ') : 'none'],
      ...(rpaths.length ? [['Rpaths', rpaths.join(', ')]] : []),
      ...(uuid ? [['UUID', uuid]] : []),
      ...(sig ? [['Signed as', `${sig.identifier || '?'}${sig.team ? ` (team ${sig.team})` : ''}`]] : []),
      ['Sections', String(sections.length)],
      ['Imported symbols', String(importCount)],
    ],
    mitigations,
    sections,
    imports,
    exports,
    labels,
    iat,
    funcStarts,
    overlay: null,
    hints,
    warnings,
    disasm,
    vaToOff,
    offToVa,
    macho: { codeSig: sig, slices, base },
  };
}
