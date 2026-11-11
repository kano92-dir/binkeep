// .NET metadata reader (ECMA-335 partition II): the CLI header, metadata
// streams and tables. Gives the assembly identity, referenced assemblies,
// every type with its methods, the framework members the code calls
// (MemberRef), P/Invoke imports, embedded resources and the user strings heap.

const CODED = {
  TypeDefOrRef: [2, [0x02, 0x01, 0x1b]],
  HasConstant: [2, [0x04, 0x08, 0x17]],
  HasCustomAttribute: [5, [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b]],
  HasFieldMarshal: [1, [0x04, 0x08]],
  HasDeclSecurity: [2, [0x02, 0x06, 0x20]],
  MemberRefParent: [3, [0x02, 0x01, 0x1a, 0x06, 0x1b]],
  HasSemantics: [1, [0x14, 0x17]],
  MethodDefOrRef: [1, [0x06, 0x0a]],
  MemberForwarded: [1, [0x04, 0x06]],
  Implementation: [2, [0x26, 0x23, 0x27]],
  CustomAttributeType: [3, [-1, -1, 0x06, 0x0a, -1]],
  ResolutionScope: [2, [0x00, 0x1a, 0x23, 0x01]],
  TypeOrMethodDef: [1, [0x02, 0x06]],
};

// Column kinds: 2 / 4 fixed bytes, 's' string, 'g' guid, 'b' blob,
// '@xx' = index into table xx, any other string = coded index.
const TABLES = {
  0x00: ['Module', [2, 's', 'g', 'g', 'g']],
  0x01: ['TypeRef', ['ResolutionScope', 's', 's']],
  0x02: ['TypeDef', [4, 's', 's', 'TypeDefOrRef', '@04', '@06']],
  0x03: ['FieldPtr', ['@04']],
  0x04: ['Field', [2, 's', 'b']],
  0x05: ['MethodPtr', ['@06']],
  0x06: ['MethodDef', [4, 2, 2, 's', 'b', '@08']],
  0x07: ['ParamPtr', ['@08']],
  0x08: ['Param', [2, 2, 's']],
  0x09: ['InterfaceImpl', ['@02', 'TypeDefOrRef']],
  0x0a: ['MemberRef', ['MemberRefParent', 's', 'b']],
  0x0b: ['Constant', [2, 'HasConstant', 'b']],
  0x0c: ['CustomAttribute', ['HasCustomAttribute', 'CustomAttributeType', 'b']],
  0x0d: ['FieldMarshal', ['HasFieldMarshal', 'b']],
  0x0e: ['DeclSecurity', [2, 'HasDeclSecurity', 'b']],
  0x0f: ['ClassLayout', [2, 4, '@02']],
  0x10: ['FieldLayout', [4, '@04']],
  0x11: ['StandAloneSig', ['b']],
  0x12: ['EventMap', ['@02', '@14']],
  0x13: ['EventPtr', ['@14']],
  0x14: ['Event', [2, 's', 'TypeDefOrRef']],
  0x15: ['PropertyMap', ['@02', '@17']],
  0x16: ['PropertyPtr', ['@17']],
  0x17: ['Property', [2, 's', 'b']],
  0x18: ['MethodSemantics', [2, '@06', 'HasSemantics']],
  0x19: ['MethodImpl', ['@02', 'MethodDefOrRef', 'MethodDefOrRef']],
  0x1a: ['ModuleRef', ['s']],
  0x1b: ['TypeSpec', ['b']],
  0x1c: ['ImplMap', [2, 'MemberForwarded', 's', '@1a']],
  0x1d: ['FieldRVA', [4, '@04']],
  0x1e: ['EncLog', [4, 4]],
  0x1f: ['EncMap', [4]],
  0x20: ['Assembly', [4, 2, 2, 2, 2, 4, 'b', 's', 's']],
  0x21: ['AssemblyProcessor', [4]],
  0x22: ['AssemblyOS', [4, 4, 4]],
  0x23: ['AssemblyRef', [2, 2, 2, 2, 4, 'b', 's', 's', 'b']],
  0x24: ['AssemblyRefProcessor', [4, '@23']],
  0x25: ['AssemblyRefOS', [4, 4, 4, '@23']],
  0x26: ['File', [4, 's', 'b']],
  0x27: ['ExportedType', [4, 4, 's', 's', 'Implementation']],
  0x28: ['ManifestResource', [4, 4, 's', 'Implementation']],
  0x29: ['NestedClass', ['@02', '@02']],
  0x2a: ['GenericParam', [2, 2, 'TypeOrMethodDef', 's']],
  0x2b: ['MethodSpec', ['MethodDefOrRef', 'b']],
  0x2c: ['GenericParamConstraint', ['@2a', 'TypeDefOrRef']],
};

const SUSPICIOUS = [
  [/Assembly::Load(File|From)?$|AppDomain::Load$/, 'Loads code from bytes at runtime'],
  [/Process::Start$/, 'Starts processes'],
  [/(WebClient|HttpClient|WebRequest|HttpWebRequest)::/, 'Network requests'],
  [/(TcpClient|Socket|UdpClient)::/, 'Raw sockets'],
  [/RegistryKey::(SetValue|CreateSubKey|DeleteValue)$/, 'Writes the registry'],
  [/Convert::FromBase64String$/, 'Decodes Base64'],
  [/(CryptoStream|RijndaelManaged|AesManaged|Aes|TripleDES|DESCryptoServiceProvider|RSACryptoServiceProvider)::/, 'Encryption'],
  [/ProtectedData::Unprotect$/, 'DPAPI decryption'],
  [/Graphics::CopyFromScreen$/, 'Screenshots'],
  [/Clipboard::/, 'Clipboard'],
  [/Marshal::(GetDelegateForFunctionPointer|Copy|AllocHGlobal)$/, 'Raw memory and function pointers'],
  [/MethodBase::Invoke$|MethodInfo::Invoke$|Type::InvokeMember$|Activator::CreateInstance$/, 'Reflection calls'],
  [/Debugger::(get_)?IsAttached$|Debugger::Launch$/, 'Debugger checks'],
  [/ManagementObjectSearcher::/, 'WMI queries'],
  [/Environment::(get_MachineName|get_UserName|get_OSVersion|GetFolderPath)$/, 'System information'],
];

export function parseDotNet(bytes, model) {
  const pe = model.pe;
  if (!pe || !pe.dirs[14] || !pe.dirs[14].rva) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (o) => dv.getUint16(o, true), u32 = (o) => dv.getUint32(o, true);
  const cli = pe.rvaToOff(pe.dirs[14].rva);
  if (cli < 0 || cli + 72 > bytes.length) return null;
  const flags = u32(cli + 16), entryToken = u32(cli + 20);
  const resRva = u32(cli + 24), resSize = u32(cli + 28);
  const md = pe.rvaToOff(u32(cli + 8));
  if (md < 0 || u32(md) !== 0x424a5342) return null; // BSJB
  const verLen = u32(md + 12);
  const runtime = ascii(bytes, md + 16, md + 16 + verLen).replace(/\0+$/, '');
  let o = md + 16 + verLen;
  const nStreams = u16(o + 2);
  o += 4;
  const streams = {};
  for (let i = 0; i < nStreams; i++) {
    const off = u32(o), size = u32(o + 4);
    let e = o + 8;
    while (bytes[e]) e++;
    const name = ascii(bytes, o + 8, e);
    streams[name] = { off: md + off, size };
    o = (e + 4) & ~3;
  }
  const tbl = streams['#~'] || streams['#-'];
  const strs = streams['#Strings'], blob = streams['#Blob'], us = streams['#US'];
  if (!tbl) return null;

  const heap = bytes[tbl.off + 6];
  const valid = dv.getBigUint64(tbl.off + 8, true);
  let p = tbl.off + 24;
  const rows = new Array(64).fill(0);
  for (let i = 0; i < 64; i++) if ((valid >> BigInt(i)) & 1n) { rows[i] = u32(p); p += 4; }
  if (heap & 0x40) p += 4;
  const strSize = heap & 1 ? 4 : 2, guidSize = heap & 2 ? 4 : 2, blobSize = heap & 4 ? 4 : 2;
  const idxSize = (t) => (rows[t] > 0xffff ? 4 : 2);
  const codedSize = (name) => {
    const [bits, tabs] = CODED[name];
    const max = Math.max(...tabs.map((t) => (t < 0 ? 0 : rows[t])));
    return max < (1 << (16 - bits)) ? 2 : 4;
  };
  const colSize = (c) => (c === 2 || c === 4 ? c : c === 's' ? strSize : c === 'g' ? guidSize : c === 'b' ? blobSize : c[0] === '@' ? idxSize(parseInt(c.slice(1), 16)) : codedSize(c));
  const T = {};
  for (let t = 0; t < 64; t++) {
    if (!rows[t]) continue;
    const def = TABLES[t];
    if (!def) return null; // unknown table: cannot compute the layout
    const sizes = def[1].map(colSize);
    const rowSize = sizes.reduce((a, b) => a + b, 0);
    T[def[0]] = { off: p, n: rows[t], cols: def[1], sizes, rowSize };
    p += rowSize * rows[t];
  }
  const cell = (name, row, col) => { // row is 1-based
    const t = T[name];
    if (!t || row < 1 || row > t.n) return 0;
    let at = t.off + (row - 1) * t.rowSize;
    for (let i = 0; i < col; i++) at += t.sizes[i];
    return t.sizes[col] === 4 ? u32(at) : u16(at);
  };
  const str = (i) => {
    if (!strs || !i) return '';
    let e = strs.off + i;
    const start = e;
    while (e < strs.off + strs.size && bytes[e]) e++;
    return new TextDecoder().decode(bytes.subarray(start, e));
  };
  const blobAt = (i) => {
    if (!blob || !i) return null;
    let q = blob.off + i;
    const [len, n] = compressed(bytes, q);
    return bytes.subarray(q + n, q + n + len);
  };
  const decode = (name, v) => {
    const [bits, tabs] = CODED[name];
    return [tabs[v & ((1 << bits) - 1)], v >>> bits];
  };
  const N = (t) => T[t]?.n || 0;

  const typeRefName = (row, depth = 0) => {
    const ns = str(cell('TypeRef', row, 2)), name = str(cell('TypeRef', row, 1));
    const [scopeT, scopeRow] = decode('ResolutionScope', cell('TypeRef', row, 0));
    if (scopeT === 0x01 && depth < 4) return `${typeRefName(scopeRow, depth + 1)}+${name}`; // nested
    return ns ? `${ns}.${name}` : name;
  };
  const typeDefName = (row) => {
    const ns = str(cell('TypeDef', row, 2)), name = str(cell('TypeDef', row, 1));
    return ns ? `${ns}.${name}` : name;
  };

  // types and their methods
  const types = [];
  const methodOwner = new Map();
  for (let r = 1; r <= N('TypeDef'); r++) {
    const first = cell('TypeDef', r, 5), next = r < N('TypeDef') ? cell('TypeDef', r + 1, 5) : N('MethodDef') + 1;
    const methods = [];
    for (let mrow = first; mrow < next && mrow <= N('MethodDef'); mrow++) {
      const name = str(cell('MethodDef', mrow, 3));
      methods.push({ name, rva: cell('MethodDef', mrow, 0), row: mrow });
      methodOwner.set(mrow, r);
    }
    const [extT, extRow] = decode('TypeDefOrRef', cell('TypeDef', r, 3));
    const ext = extT === 0x01 ? typeRefName(extRow) : extT === 0x02 ? typeDefName(extRow) : '';
    types.push({ name: typeDefName(r), flags: cell('TypeDef', r, 0), extends: ext, methods });
  }
  const methodName = (mrow) => { const t = methodOwner.get(mrow); return `${t ? typeDefName(t) : '?'}::${str(cell('MethodDef', mrow, 3))}`; };

  // members this code references from other assemblies
  const memberRefs = [];
  for (let r = 1; r <= N('MemberRef'); r++) {
    const [pt, prow] = decode('MemberRefParent', cell('MemberRef', r, 0));
    const owner = pt === 0x01 ? typeRefName(prow) : pt === 0x02 ? typeDefName(prow) : pt === 0x1a ? str(cell('ModuleRef', prow, 0)) : pt === 0x06 ? methodName(prow) : '';
    if (!owner) continue;
    memberRefs.push(`${owner}::${str(cell('MemberRef', r, 1))}`);
  }
  const memberSet = [...new Set(memberRefs)];

  // P/Invoke: native functions the managed code calls directly
  const pinvoke = [];
  for (let r = 1; r <= N('ImplMap'); r++) {
    const mod = str(cell('ModuleRef', cell('ImplMap', r, 3), 0));
    const fn = str(cell('ImplMap', r, 2));
    pinvoke.push({ lib: mod, name: fn });
  }

  const refs = [];
  for (let r = 1; r <= N('AssemblyRef'); r++) {
    refs.push({ name: str(cell('AssemblyRef', r, 6)), version: [0, 1, 2, 3].map((c) => cell('AssemblyRef', r, c)).join('.') });
  }
  let assembly = null;
  if (N('Assembly')) assembly = { name: str(cell('Assembly', 1, 7)), version: [1, 2, 3, 4].map((c) => cell('Assembly', 1, c)).join('.'), culture: str(cell('Assembly', 1, 8)) };
  const moduleName = N('Module') ? str(cell('Module', 1, 1)) : '';

  // embedded resources
  const resources = [];
  const resBase = resRva ? pe.rvaToOff(resRva) : -1;
  for (let r = 1; r <= N('ManifestResource'); r++) {
    const name = str(cell('ManifestResource', r, 2));
    const impl = cell('ManifestResource', r, 3);
    let size = null;
    if (!impl && resBase >= 0) {
      const at = resBase + cell('ManifestResource', r, 0);
      if (at + 4 <= bytes.length && at < resBase + resSize) size = u32(at);
    }
    resources.push({ name, size, embedded: !impl });
  }

  // user strings (#US): length-prefixed UTF-16
  const userStrings = [];
  if (us) {
    let q = us.off + 1;
    const end = us.off + us.size;
    while (q < end && userStrings.length < 20000) {
      const [len, n] = compressed(bytes, q);
      q += n;
      if (len > 1) {
        const s = utf16(bytes, q, q + len - 1);
        if (s.trim().length >= 2) userStrings.push(s);
      }
      q += len;
      if (!len) break;
    }
  }

  // entry point
  let entry = '';
  if ((entryToken >>> 24) === 0x06) entry = methodName(entryToken & 0xffffff);

  // obfuscation hints
  const named = types.filter((t) => t.name !== '<Module>');
  const odd = named.filter((t) => /[^\x20-\x7e]|^[a-zA-Z]{1,2}$|^[^A-Za-z_<]/.test(t.name.split('.').pop())).length;
  const obfuscated = named.length >= 10 && odd / named.length > 0.4;
  const tr = new Set(Array.from({ length: N('TypeRef') }, (_, i) => typeRefName(i + 1)));
  const obfuscator = [...tr].map((n) => n.split('.').pop()).find((n) => /ConfusedBy|Dotfuscator|SmartAssembly|Babel|ObfuscatedBy|Xenocode|Eazfuscator|DotNetPatcher|Agile/i.test(n)) || '';

  const suspicious = [];
  for (const [re, label] of SUSPICIOUS) {
    const hits = memberSet.filter((x) => re.test(x));
    if (hits.length) suspicious.push({ label, hits: hits.slice(0, 12) });
  }

  return {
    runtime,
    flags: { ilOnly: !!(flags & 1), x86Only: !!(flags & 2), strongName: !!(flags & 8), nativeEntry: !!(flags & 0x10), prefer32: !!(flags & 0x20000) },
    assembly, moduleName, refs, types: named, memberRefs: memberSet, pinvoke, resources, userStrings, entry,
    obfuscated, obfuscator, suspicious,
    counts: { types: named.length, methods: N('MethodDef'), memberRefs: memberSet.length },
  };
}

function compressed(b, o) {
  const x = b[o];
  if ((x & 0x80) === 0) return [x, 1];
  if ((x & 0xc0) === 0x80) return [((x & 0x3f) << 8) | b[o + 1], 2];
  return [((x & 0x1f) << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3], 4];
}

function ascii(b, s, e) {
  let out = '';
  for (let i = s; i < e && i < b.length; i++) out += String.fromCharCode(b[i]);
  return out;
}

function utf16(b, s, e) {
  let out = '';
  for (let i = s; i + 1 < e && i + 1 < b.length; i += 2) out += String.fromCharCode(b[i] | (b[i + 1] << 8));
  return out;
}
