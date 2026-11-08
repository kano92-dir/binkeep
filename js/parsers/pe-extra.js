// PE resources (with version info, manifest, icon) and the Authenticode signature.
import { entropy } from '../analysis.js';

const RT = {
  1: 'Cursor', 2: 'Bitmap', 3: 'Icon', 4: 'Menu', 5: 'Dialog', 6: 'String table', 7: 'Font directory', 8: 'Font',
  9: 'Accelerators', 10: 'RCDATA', 11: 'Message table', 12: 'Cursor group', 14: 'Icon group', 16: 'Version info',
  17: 'Dialog include', 19: 'Plug and Play', 20: 'VxD', 21: 'Animated cursor', 22: 'Animated icon', 23: 'HTML', 24: 'Manifest',
};

const MAGICS = [
  [[0x4d, 0x5a], 'PE / DOS executable', 'bad'],
  [[0x7f, 0x45, 0x4c, 0x46], 'ELF executable', 'bad'],
  [[0x50, 0x4b, 0x03, 0x04], 'ZIP archive', 'warn'],
  [[0x52, 0x61, 0x72, 0x21], 'RAR archive', 'warn'],
  [[0x37, 0x7a, 0xbc, 0xaf], '7-Zip archive', 'warn'],
  [[0x4d, 0x53, 0x43, 0x46], 'CAB archive', 'warn'],
  [[0x1f, 0x8b], 'gzip data', 'warn'],
  [[0x25, 0x50, 0x44, 0x46], 'PDF document', 'warn'],
  [[0xd0, 0xcf, 0x11, 0xe0], 'OLE / Office document', 'warn'],
  [[0x89, 0x50, 0x4e, 0x47], 'PNG image', ''],
  [[0xff, 0xd8, 0xff], 'JPEG image', ''],
  [[0x47, 0x49, 0x46, 0x38], 'GIF image', ''],
  [[0x3c, 0x3f, 0x78, 0x6d], 'XML', ''],
];

function sniff(bytes, off, size) {
  for (const [sig, name, level] of MAGICS) {
    if (size >= sig.length && sig.every((b, i) => bytes[off + i] === b)) return { name, level };
  }
  return null;
}

export function parseResources(bytes, model) {
  const { dirs, rvaToOff } = model.pe;
  const rd = dirs[2];
  const root = rd.rva ? rvaToOff(rd.rva) : -1;
  if (root < 0) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (o) => dv.getUint16(o, true);
  const u32 = (o) => dv.getUint32(o, true);
  const items = [];
  let budget = 20000;

  const readName = (o) => {
    const p = root + o;
    if (p + 2 > bytes.length) return '?';
    const n = Math.min(u16(p), 256);
    let s = '';
    for (let i = 0; i < n && p + 2 + i * 2 + 1 < bytes.length; i++) s += String.fromCharCode(u16(p + 2 + i * 2));
    return s;
  };
  const walk = (dirOff, depth, path, seen) => {
    const d = root + dirOff;
    if (d + 16 > bytes.length || seen.has(d) || depth > 3) return;
    seen.add(d);
    const count = u16(d + 12) + u16(d + 14);
    for (let i = 0; i < count && budget-- > 0; i++) {
      const e = d + 16 + i * 8;
      if (e + 8 > bytes.length) return;
      const nameField = u32(e), target = u32(e + 4);
      const id = nameField & 0x80000000 ? readName(nameField & 0x7fffffff) : nameField;
      const next = [...path, id];
      if (target & 0x80000000) walk(target & 0x7fffffff, depth + 1, next, seen);
      else {
        const de = root + target;
        if (de + 16 > bytes.length) continue;
        const rva = u32(de), size = u32(de + 4);
        const off = rvaToOff(rva);
        const [type, name, lang] = next;
        items.push({ type, typeName: typeof type === 'number' ? RT[type] || `type ${type}` : String(type), name, lang: lang ?? 0, rva, size, off });
      }
    }
  };
  walk(0, 0, [], new Set());

  for (const it of items) {
    const ok = it.off >= 0 && it.off + it.size <= bytes.length && it.size > 0;
    it.valid = ok;
    if (!ok) continue;
    it.entropy = entropy(bytes, it.off, it.off + it.size);
    it.magic = sniff(bytes, it.off, it.size);
  }

  const version = parseVersion(bytes, items.find((r) => r.type === 16 && r.valid));
  const manifest = parseManifest(bytes, items.find((r) => r.type === 24 && r.valid));
  const icon = buildIcon(bytes, items);
  return { items, version, manifest, icon };
}

// ---------- VS_VERSIONINFO ----------

function parseVersion(bytes, res) {
  if (!res) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = (o) => dv.getUint16(o, true);
  const u32 = (o) => dv.getUint32(o, true);
  const start = res.off, end = res.off + res.size;
  const align = (p) => start + ((p - start + 3) & ~3);
  const wstr = (p, lim) => {
    let s = '';
    while (p + 1 < lim) { const c = u16(p); p += 2; if (!c) break; s += String.fromCharCode(c); }
    return [s, p];
  };
  const out = { strings: [], fileVersion: '', productVersion: '' };
  const block = (o, lim, depth) => {
    if (depth > 4 || o + 6 > lim) return;
    const len = u16(o), vlen = u16(o + 2), type = u16(o + 4);
    if (len < 6) return;
    const bEnd = Math.min(lim, o + len);
    const [key, afterKey] = wstr(o + 6, bEnd);
    const valOff = align(afterKey);
    const valBytes = type === 1 ? vlen * 2 : vlen;
    if (key === 'VS_VERSION_INFO' && vlen >= 52 && u32(valOff) === 0xfeef04bd) {
      const v = (ms, ls) => `${u32(valOff + ms) >>> 16}.${u32(valOff + ms) & 0xffff}.${u32(valOff + ls) >>> 16}.${u32(valOff + ls) & 0xffff}`;
      out.fileVersion = v(8, 12);
      out.productVersion = v(16, 20);
    }
    if (depth === 3 && type === 1 && vlen) {
      const [val] = wstr(valOff, Math.min(bEnd, valOff + valBytes + 2));
      out.strings.push([key, val]);
    }
    let c = align(valOff + valBytes);
    let guard = 0;
    while (c + 6 <= bEnd && guard++ < 200) {
      const clen = u16(c);
      if (clen < 6) break;
      block(c, bEnd, depth + 1);
      c = align(c + clen);
    }
  };
  try { block(start, end, 0); } catch { /* truncated */ }
  return out.strings.length || out.fileVersion ? out : null;
}

function parseManifest(bytes, res) {
  if (!res) return null;
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(res.off, res.off + Math.min(res.size, 65536)));
  const level = text.match(/requestedExecutionLevel[^>]*level\s*=\s*["']([^"']+)/i)?.[1] || '';
  const uiAccess = /uiAccess\s*=\s*["']true/i.test(text);
  const dpi = text.match(/<dpiAware[^>]*>([^<]+)/i)?.[1]?.trim() || '';
  const os = (text.match(/supportedOS\s+Id=/gi) || []).length;
  return { text, level, uiAccess, dpi, os };
}

// Build a displayable icon from the first icon group. PNG images are used
// directly; classic DIB icons are wrapped in a one-image .ico container.
function buildIcon(bytes, items) {
  const group = items.find((r) => r.type === 14 && r.valid);
  if (!group || group.size < 6) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = Math.min(dv.getUint16(group.off + 4, true), 64);
  let best = null;
  for (let i = 0; i < count; i++) {
    const e = group.off + 6 + i * 14;
    if (e + 14 > group.off + group.size) break;
    const w = bytes[e] || 256, h = bytes[e + 1] || 256;
    const bitCount = dv.getUint16(e + 6, true);
    const id = dv.getUint16(e + 12, true);
    const img = items.find((r) => r.type === 3 && r.name === id && r.valid);
    if (!img) continue;
    const score = w * 1000 + bitCount;
    if (w <= 256 && (!best || score > best.score)) best = { w, h, bitCount, img, entry: e, score };
  }
  if (!best) return null;
  const data = bytes.subarray(best.img.off, best.img.off + best.img.size);
  if (data[0] === 0x89 && data[1] === 0x50) return { mime: 'image/png', data: data.slice(), size: `${best.w}x${best.h}` };
  const ico = new Uint8Array(6 + 16 + data.length);
  const iv = new DataView(ico.buffer);
  iv.setUint16(2, 1, true); iv.setUint16(4, 1, true);
  ico.set(bytes.subarray(best.entry, best.entry + 8), 6); // width, height, colors, reserved, planes, bitcount
  iv.setUint32(14, data.length, true);
  iv.setUint32(18, 22, true);
  ico.set(data, 22);
  return { mime: 'image/x-icon', data: ico, size: `${best.w}x${best.h}` };
}

// ---------- Minimal DER reader ----------

function der(bytes, o, end) {
  if (o + 2 > end) return null;
  const tag = bytes[o];
  let len = bytes[o + 1], hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || o + 2 + n > end) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[o + 2 + i];
    hdr = 2 + n;
  }
  const start = o + hdr;
  if (start + len > end) return null;
  return { tag, start, end: start + len, next: start + len, constructed: !!(tag & 0x20) };
}
function children(bytes, node) {
  const out = [];
  let o = node.start;
  while (o < node.end) {
    const c = der(bytes, o, node.end);
    if (!c) break;
    out.push(c);
    o = c.next;
  }
  return out;
}
function oid(bytes, n) {
  const b = bytes.subarray(n.start, n.end);
  if (!b.length) return '';
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) {
    v = v * 128 + (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}
function str(bytes, n) {
  const b = bytes.subarray(n.start, n.end);
  if (n.tag === 0x1e) { let s = ''; for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]); return s; }
  if (n.tag === 0x0c) return new TextDecoder().decode(b);
  return String.fromCharCode(...b);
}
function time(bytes, n) {
  const s = str(bytes, n);
  const m = n.tag === 0x17 ? s.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/) : s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/);
  if (!m) return s;
  let y = Number(m[1]);
  if (n.tag === 0x17) y += y < 50 ? 2000 : 1900;
  return `${y}-${m[2]}-${m[3]} ${m[4]}:${m[5]} UTC`;
}
const NAME_OIDS = { '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST' };
function name(bytes, n) {
  const out = {};
  for (const rdn of children(bytes, n)) {
    for (const atv of children(bytes, rdn)) {
      const [k, v] = children(bytes, atv);
      if (k && v && k.tag === 0x06) {
        const key = NAME_OIDS[oid(bytes, k)];
        if (key && !out[key]) out[key] = str(bytes, v);
      }
    }
  }
  return out;
}
const hexOf = (bytes, n) => [...bytes.subarray(n.start, n.end)].map((b) => b.toString(16).padStart(2, '0')).join('');

const DIGESTS = {
  '1.3.14.3.2.26': ['SHA-1', 'SHA-1'], '2.16.840.1.101.3.4.2.1': ['SHA-256', 'SHA-256'],
  '2.16.840.1.101.3.4.2.2': ['SHA-384', 'SHA-384'], '2.16.840.1.101.3.4.2.3': ['SHA-512', 'SHA-512'],
  '1.2.840.113549.2.5': ['MD5', null],
};

function parseCert(bytes, node) {
  const [tbs] = children(bytes, node);
  if (!tbs) return null;
  let f = children(bytes, tbs);
  if (f[0]?.tag === 0xa0) f = f.slice(1);
  const [serial, , issuer, validity, subject] = f;
  if (!serial || !issuer || !validity || !subject) return null;
  const [nb, na] = children(bytes, validity);
  return {
    serial: hexOf(bytes, serial).replace(/^00/, ''),
    issuer: name(bytes, issuer),
    subject: name(bytes, subject),
    notBefore: nb ? time(bytes, nb) : '',
    notAfter: na ? time(bytes, na) : '',
    issuerRaw: hexOf(bytes, issuer),
    subjectRaw: hexOf(bytes, subject),
  };
}

// Depth-first search for the first time value under OIDs that carry a signing time.
function findTimestamp(bytes, node, depth = 0) {
  if (depth > 14) return '';
  const kids = node.constructed ? children(bytes, node) : node.tag === 0x04 ? children(bytes, node) : [];
  for (let i = 0; i < kids.length; i++) {
    const k = kids[i];
    if (k.tag === 0x06) {
      const id = oid(bytes, k);
      if (id === '1.2.840.113549.1.9.5') {
        const set = kids[i + 1];
        const t = set && children(bytes, set)[0];
        if (t && (t.tag === 0x17 || t.tag === 0x18)) return time(bytes, t);
      }
      if (id === '1.2.840.113549.1.9.16.1.4') { // TSTInfo content type: genTime follows inside the eContent
        const content = kids[i + 1];
        if (content) {
          const g = firstTime(bytes, content, 0);
          if (g) return g;
        }
      }
    }
    if (k.constructed || k.tag === 0x04) {
      const r = findTimestamp(bytes, k, depth + 1);
      if (r) return r;
    }
  }
  return '';
}
function firstTime(bytes, node, depth) {
  if (depth > 8) return '';
  if (node.tag === 0x18) return time(bytes, node);
  if (!node.constructed && node.tag !== 0x04) return '';
  for (const k of children(bytes, node)) {
    const r = firstTime(bytes, k, depth + 1);
    if (r) return r;
  }
  return '';
}

export function parseAuthenticode(bytes, model) {
  const sd = model.pe.dirs[4];
  if (!sd.rva || !sd.size) return null;
  if (sd.rva + 8 > bytes.length) {
    return { offset: sd.rva, size: sd.size, certs: [], signer: null, digestAlg: '', digest: '', timestamp: '', nested: 0,
      error: `The certificate table points to offset 0x${sd.rva.toString(16)}, past the end of the ${bytes.length.toLocaleString()} byte file. The signature was cut off, so the file cannot be verified as signed.` };
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const certType = dv.getUint16(sd.rva + 6, true);
  const out = { offset: sd.rva, size: sd.size, certType, certs: [], signer: null, digestAlg: '', digest: '', timestamp: '', nested: 0, error: '' };
  if (certType !== 2) { out.error = `Certificate type ${certType} is not PKCS#7`; return out; }
  const end = Math.min(bytes.length, sd.rva + sd.size);
  try {
    const ci = der(bytes, sd.rva + 8, end);
    const [ctype, wrapped] = children(bytes, ci);
    if (!ctype || oid(bytes, ctype) !== '1.2.840.113549.1.7.2') throw new Error('not SignedData');
    const signed = children(bytes, wrapped)[0];
    const parts = children(bytes, signed);
    const encap = parts[2];
    // SpcIndirectDataContent -> DigestInfo (algorithm + file digest)
    const [, encapContent] = children(bytes, encap);
    const spc = encapContent && children(bytes, encapContent)[0];
    const digestInfo = spc && children(bytes, spc)[1];
    if (digestInfo) {
      const [alg, dig] = children(bytes, digestInfo);
      const algOid = alg && children(bytes, alg)[0];
      out.digestAlg = algOid ? (DIGESTS[oid(bytes, algOid)]?.[0] || oid(bytes, algOid)) : '';
      out.subtle = algOid ? DIGESTS[oid(bytes, algOid)]?.[1] || null : null;
      if (dig) out.digest = hexOf(bytes, dig);
    }
    const certSet = parts.find((p) => p.tag === 0xa0);
    if (certSet) for (const c of children(bytes, certSet)) { const pc = parseCert(bytes, c); if (pc) out.certs.push(pc); }
    const signerInfos = parts[parts.length - 1];
    const si = signerInfos && children(bytes, signerInfos)[0];
    if (si) {
      const sic = children(bytes, si);
      const ias = sic[1];
      const [iss, ser] = ias ? children(bytes, ias) : [];
      if (iss && ser) {
        const serial = hexOf(bytes, ser).replace(/^00/, '');
        out.signer = out.certs.find((c) => c.serial === serial && c.issuerRaw === hexOf(bytes, iss)) || null;
      }
      const unsigned = sic.find((p) => p.tag === 0xa1);
      if (unsigned) {
        out.timestamp = findTimestamp(bytes, unsigned);
        for (const attr of children(bytes, unsigned)) {
          const t = children(bytes, attr)[0];
          if (t && oid(bytes, t) === '1.3.6.1.4.1.311.2.4.1') out.nested += children(bytes, children(bytes, attr)[1] || attr).length;
        }
      }
    }
    if (!out.signer && out.certs.length) {
      const issuers = new Set(out.certs.map((c) => c.issuerRaw));
      out.signer = out.certs.find((c) => !issuers.has(c.subjectRaw)) || out.certs[0];
    }
  } catch (err) {
    out.error = `Could not parse the signature (${err.message})`;
  }
  return out;
}

// Recompute the Authenticode image digest and compare it to the signed one.
// This proves the file was not modified after signing. It does not check
// the certificate chain or the signature itself.
export async function verifyDigest(bytes, model, sig) {
  if (!sig?.subtle || !sig.digest || !crypto?.subtle) return null;
  const { checksumOff, secDirOff } = model.pe;
  const certStart = sig.offset, certEnd = sig.offset + sig.size;
  const ranges = [[0, checksumOff], [checksumOff + 4, secDirOff], [secDirOff + 8, certStart]];
  if (certEnd < bytes.length) ranges.push([certEnd, bytes.length]);
  const total = ranges.reduce((n, [a, b]) => n + Math.max(0, b - a), 0);
  const buf = new Uint8Array(total);
  let p = 0;
  for (const [a, b] of ranges) { if (b > a) { buf.set(bytes.subarray(a, b), p); p += b - a; } }
  const h = new Uint8Array(await crypto.subtle.digest(sig.subtle, buf));
  const hexH = [...h].map((b) => b.toString(16).padStart(2, '0')).join('');
  return hexH === sig.digest;
}
