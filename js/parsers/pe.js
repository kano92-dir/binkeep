// Portable Executable (PE32 / PE32+) parser.

const MACHINES = {
  0x14c: ['x86', 32, { arch: 'X86', mode: 'MODE_32' }],
  0x8664: ['x86-64', 64, { arch: 'X86', mode: 'MODE_64' }],
  0xaa64: ['ARM64', 64, { arch: 'ARM64', mode: 'MODE_ARM' }],
  0x1c0: ['ARM', 32, { arch: 'ARM', mode: 'MODE_ARM' }],
  0x1c4: ['ARM Thumb-2', 32, { arch: 'ARM', mode: 'MODE_THUMB' }],
};

const SUBSYSTEMS = {
  1: 'Native', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2 console', 7: 'POSIX console',
  9: 'Windows CE', 10: 'EFI application', 11: 'EFI boot driver', 12: 'EFI runtime driver',
  13: 'EFI ROM', 14: 'Xbox', 16: 'Windows boot application',
};

export function isPE(bytes) {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return false;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const e = dv.getUint32(0x3c, true);
  return e + 24 <= bytes.length && dv.getUint32(e, true) === 0x00004550;
}

export function parsePE(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (o) => dv.getUint16(o, true);
  const u32 = (o) => dv.getUint32(o, true);
  const warnings = [];

  const readCStr = (off, max = 512) => {
    if (off < 0 || off >= bytes.length) return '';
    let s = '';
    for (let i = off; i < bytes.length && i < off + max; i++) {
      if (bytes[i] === 0) break;
      s += String.fromCharCode(bytes[i]);
    }
    return s;
  };

  const peOff = u32(0x3c);
  const coff = peOff + 4;
  const machine = u16(coff);
  const numSections = u16(coff + 2);
  const timestamp = u32(coff + 4);
  const optSize = u16(coff + 16);
  const characteristics = u16(coff + 18);
  const opt = coff + 20;
  const magic = u16(opt);
  const is64 = magic === 0x20b;
  if (magic !== 0x10b && magic !== 0x20b) warnings.push(`Unknown optional header magic 0x${magic.toString(16)}`);

  const entryRva = u32(opt + 16);
  const imageBase = is64 ? Number(dv.getBigUint64(opt + 24, true)) : u32(opt + 28);
  const subsystem = u16(opt + 68);
  const dllChars = u16(opt + 70);
  const numDirs = Math.min(16, u32(opt + (is64 ? 108 : 92)));
  const dirBase = opt + (is64 ? 112 : 96);
  const dirs = [];
  for (let i = 0; i < 16; i++) {
    dirs.push(i < numDirs ? { rva: u32(dirBase + i * 8), size: u32(dirBase + i * 8 + 4) } : { rva: 0, size: 0 });
  }

  const sections = [];
  const secBase = opt + optSize;
  for (let i = 0; i < numSections && secBase + (i + 1) * 40 <= bytes.length; i++) {
    const o = secBase + i * 40;
    let name = '';
    for (let j = 0; j < 8 && bytes[o + j]; j++) name += String.fromCharCode(bytes[o + j]);
    const flags = u32(o + 36);
    sections.push({
      name,
      rva: u32(o + 12),
      vsize: u32(o + 8),
      size: u32(o + 16),
      off: u32(o + 20),
      r: !!(flags & 0x40000000),
      w: !!(flags & 0x80000000),
      x: !!(flags & 0x20000000) || !!(flags & 0x20),
    });
  }
  for (const s of sections) s.va = imageBase + s.rva;

  const firstRva = sections.length ? Math.min(...sections.map((s) => s.rva)) : Infinity;
  const rvaToOff = (rva) => {
    for (const s of sections) {
      const span = Math.max(s.vsize, s.size);
      if (rva >= s.rva && rva < s.rva + span) {
        const d = rva - s.rva;
        return d < s.size ? s.off + d : -1;
      }
    }
    return rva < firstRva && rva < bytes.length ? rva : -1;
  };
  const vaToOff = (va) => rvaToOff(va - imageBase);
  const offToVa = (off) => {
    for (const s of sections) if (off >= s.off && off < s.off + s.size) return imageBase + s.rva + (off - s.off);
    return off < firstRva ? imageBase + off : null;
  };

  // Imports
  const imports = [];
  const iat = new Map();
  const ptr = is64 ? 8 : 4;
  try {
    let d = dirs[1].rva ? rvaToOff(dirs[1].rva) : -1;
    for (let k = 0; d >= 0 && k < 4096; k++, d += 20) {
      const oft = u32(d), nameRva = u32(d + 12), ft = u32(d + 16);
      if (!oft && !nameRva && !ft) break;
      const lib = readCStr(rvaToOff(nameRva));
      let t = rvaToOff(oft || ft);
      const fns = [];
      for (let j = 0; t >= 0 && j < 20000; j++, t += ptr) {
        let fn;
        if (is64) {
          const v = dv.getBigUint64(t, true);
          if (v === 0n) break;
          fn = v & (1n << 63n) ? { ordinal: Number(v & 0xffffn) } : hintName(Number(v & 0x7fffffffn));
        } else {
          const v = u32(t);
          if (v === 0) break;
          fn = v & 0x80000000 ? { ordinal: v & 0xffff } : hintName(v & 0x7fffffff);
        }
        fn.iat = imageBase + ft + j * ptr;
        fns.push(fn);
        iat.set(fn.iat, `${lib.replace(/\.dll$/i, '')}!${fn.name || '#' + fn.ordinal}`);
      }
      imports.push({ lib, fns });
    }
  } catch (e) {
    warnings.push('Import table is truncated or malformed');
  }
  function hintName(rva) {
    const o = rvaToOff(rva);
    return o >= 0 ? { name: readCStr(o + 2) } : { name: '?' };
  }

  // Exports
  const exports = [];
  try {
    const ed = dirs[0];
    const o = ed.rva ? rvaToOff(ed.rva) : -1;
    if (o >= 0) {
      const base = u32(o + 16), nFn = u32(o + 20), nNames = u32(o + 24);
      const aFn = rvaToOff(u32(o + 28)), aNames = rvaToOff(u32(o + 32)), aOrd = rvaToOff(u32(o + 36));
      const names = new Map();
      for (let i = 0; aNames >= 0 && i < Math.min(nNames, 65536); i++) {
        names.set(u16(aOrd + i * 2), readCStr(rvaToOff(u32(aNames + i * 4))));
      }
      for (let i = 0; aFn >= 0 && i < Math.min(nFn, 65536); i++) {
        const rva = u32(aFn + i * 4);
        if (!rva) continue;
        const fwd = rva >= ed.rva && rva < ed.rva + ed.size;
        exports.push({
          name: names.get(i) || '',
          ordinal: base + i,
          va: fwd ? null : imageBase + rva,
          forwarder: fwd ? readCStr(rvaToOff(rva)) : '',
        });
      }
    }
  } catch (e) {
    warnings.push('Export table is truncated or malformed');
  }

  const [archName, bits, disasm] = MACHINES[machine] || [`unknown (0x${machine.toString(16)})`, is64 ? 64 : 32, null];
  const isDll = !!(characteristics & 0x2000);
  const isDotNet = dirs[14].rva !== 0;
  const signed = dirs[4].rva !== 0 && dirs[4].size > 0;

  // Overlay = data after the last section, minus the Authenticode blob
  // (whose directory entry holds a file offset, not an RVA).
  const rawEnd = sections.reduce((m, s) => Math.max(m, s.off + s.size), 0);
  let overlayEnd = bytes.length;
  if (signed && dirs[4].rva >= rawEnd && dirs[4].rva + dirs[4].size >= bytes.length - 8) overlayEnd = dirs[4].rva;
  const overlay = rawEnd > 0 && overlayEnd - rawEnd > 16 ? { off: rawEnd, size: overlayEnd - rawEnd } : null;

  const date = new Date(timestamp * 1000);
  let tsText = timestamp ? date.toISOString().replace('T', ' ').replace('.000Z', ' UTC') : '0 (not set)';
  if (timestamp && date > new Date()) tsText += ' (in the future, likely a reproducible-build hash)';

  const labels = new Map();
  for (const e of exports) if (e.va != null) labels.set(e.va, e.name || `ord_${e.ordinal}`);
  const entryVa = imageBase + entryRva;
  if (entryRva) labels.set(entryVa, labels.get(entryVa) || 'entry');

  // Exception directory (.pdata): exact function ranges on x64 and ARM64.
  const funcStarts = [];
  try {
    const ex = dirs[3];
    const o = ex.rva ? rvaToOff(ex.rva) : -1;
    if (o >= 0 && (machine === 0x8664 || machine === 0xaa64)) {
      const esz = machine === 0x8664 ? 12 : 8;
      const n = Math.min(Math.floor(ex.size / esz), 500000);
      for (let i = 0; i < n && o + (i + 1) * esz <= bytes.length; i++) {
        const begin = u32(o + i * esz);
        if (!begin) continue;
        funcStarts.push({ va: imageBase + begin, end: esz === 12 ? imageBase + u32(o + i * esz + 4) : null });
      }
    }
  } catch { /* malformed .pdata is not fatal */ }

  const hints = [];
  if (isDotNet) hints.push({ level: 'info', text: '.NET assembly: native disassembly shows only the loader stub. Use a .NET decompiler for the IL.' });
  if (overlay) hints.push({ level: overlay.size > bytes.length * 0.3 ? 'warn' : 'info', text: `Overlay: ${overlay.size.toLocaleString()} bytes appended after the last section (installers and self-extractors do this)` });
  for (const s of sections) {
    if (s.w && s.x) hints.push({ level: 'warn', text: `Section ${s.name || '(unnamed)'} is both writable and executable` });
    if (s.size === 0 && s.vsize > 0x1000 && s.x) hints.push({ level: 'warn', text: `Section ${s.name || '(unnamed)'} is executable but empty on disk (unpacked at runtime?)` });
  }
  const entrySec = sections.find((s) => entryRva >= s.rva && entryRva < s.rva + Math.max(s.vsize, s.size));
  if (entryRva && entrySec && !entrySec.x) hints.push({ level: 'warn', text: `Entry point is in non-executable section ${entrySec.name}` });
  if (entryRva && entrySec && entrySec !== sections.find((s) => s.x)) hints.push({ level: 'info', text: `Entry point is in ${entrySec.name}, not the first code section` });
  const importCount = imports.reduce((n, i) => n + i.fns.length, 0);
  if (!isDotNet && importCount > 0 && importCount < 10) hints.push({ level: 'warn', text: `Only ${importCount} imported functions: common for packed binaries` });

  return {
    format: is64 ? 'PE32+' : 'PE32',
    arch: archName,
    bits,
    kind: isDll ? 'DLL' : subsystem === 1 ? 'Driver / native' : 'Executable',
    entry: entryRva ? entryVa : null,
    facts: [
      ['Format', `${is64 ? 'PE32+' : 'PE32'}${isDotNet ? ' (.NET)' : ''}`],
      ['Architecture', archName],
      ['Type', isDll ? 'DLL' : 'Executable'],
      ['Subsystem', SUBSYSTEMS[subsystem] || `0x${subsystem.toString(16)}`],
      ['Image base', hex(imageBase)],
      ['Entry point', entryRva ? `${hex(entryVa)} (RVA ${hex(entryRva)})` : 'none'],
      ['Compiled', tsText],
      ['Sections', String(sections.length)],
      ['Imports', `${importCount} functions from ${imports.length} libraries`],
      ['Exports', String(exports.length)],
    ],
    mitigations: [
      ['ASLR', !!(dllChars & 0x40)],
      ['High-entropy VA', !!(dllChars & 0x20)],
      ['DEP / NX', !!(dllChars & 0x100)],
      ['Control Flow Guard', !!(dllChars & 0x4000)],
    ],
    sections,
    imports,
    exports,
    labels,
    iat,
    overlay,
    hints,
    warnings,
    disasm,
    vaToOff,
    offToVa,
    funcStarts,
    pe: { dirs, rvaToOff, imageBase, is64, machine, checksumOff: opt + 64, secDirOff: dirBase + 4 * 8, sizeOfHeaders: u32(opt + 60) },
  };
}

export const hex = (n) => '0x' + Number(n).toString(16).toUpperCase().padStart(8, '0').replace(/^0+(?=\w{8})/, '');
