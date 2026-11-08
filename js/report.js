// Report snapshot: used for share links (compressed into the URL fragment,
// which browsers never send to a server) and for JSON / Markdown export.

const hx = (n) => (n == null ? null : '0x' + Number(n).toString(16));

export function buildReport(s, { full = false } = {}) {
  const m = s.model;
  const cap = (arr, n) => (full ? arr : arr.slice(0, n));
  const blocks = s.blocks?.values || [];
  const step = Math.max(1, Math.ceil(blocks.length / 240));
  const ent = [];
  for (let i = 0; i < blocks.length; i += step) {
    let mx = 0;
    for (let j = i; j < Math.min(blocks.length, i + step); j++) mx = Math.max(mx, blocks[j]);
    ent.push(Math.round((mx / 8) * 255));
  }
  const fnName = (va) => s.notes?.name(va) || m.labels.get(va) || '';
  const r = {
    v: 1,
    app: 'binkeep',
    name: s.name,
    size: s.bytes.length,
    sha256: s.hashes?.['SHA-256'] || '',
    sha1: s.hashes?.['SHA-1'] || '',
    format: m.format,
    arch: m.arch,
    kind: m.kind,
    entry: hx(m.entry),
    facts: m.facts,
    mitigations: m.mitigations,
    hints: [...m.warnings.map((t) => ({ level: 'warn', text: t })), ...m.hints],
    sections: m.sections.map((x) => ({ name: x.name, va: hx(x.va), vsize: x.vsize, off: x.off, size: x.size, flags: `${x.r ? 'R' : '-'}${x.w ? 'W' : '-'}${x.x ? 'X' : '-'}`, entropy: x.entropy == null ? null : +x.entropy.toFixed(2) })),
    imports: m.imports.map((l) => ({ lib: l.lib, fns: cap(l.fns.map((f) => f.name || `#${f.ordinal}`), 400) })),
    exportCount: m.exports.length,
    exports: cap(m.exports.map((e) => e.name).filter(Boolean), full ? Infinity : 200),
    strings: cap(s.strings.filter((x) => x.cat).map((x) => ({ off: x.off, cat: x.cat, text: x.text.slice(0, 200) })), 250),
    stringCount: s.strings.length,
    entropy: { total: s.totalEntropy != null ? +s.totalEntropy.toFixed(2) : null, blocks: ent },
    packing: s.packing ? { verdict: s.packing.verdict, packers: s.packing.packers.map((p) => p.name), reasons: s.packing.reasons } : null,
    signature: s.signature ? {
      signer: s.signature.signer ? { subject: s.signature.signer.subject, issuer: s.signature.signer.issuer, notBefore: s.signature.signer.notBefore, notAfter: s.signature.signer.notAfter } : null,
      digestAlg: s.signature.digestAlg, timestamp: s.signature.timestamp, intact: s.signature.intact ?? null, certs: s.signature.certs.length,
    } : null,
    version: s.resources?.version || null,
    manifest: s.resources?.manifest ? { level: s.resources.manifest.level, uiAccess: s.resources.manifest.uiAccess } : null,
    resources: s.resources ? s.resources.items.filter((x) => x.magic?.level).map((x) => ({ type: x.typeName, name: String(x.name), size: x.size, magic: x.magic.name })) : [],
    functions: s.code ? { count: s.code.functions.length, list: full ? s.code.functions.map((f) => ({ va: hx(f.va), name: fnName(f.va), size: f.size })) : undefined } : null,
    yara: s.yara ? s.yara.rules.map((x) => ({ rule: x.name, matches: x.matches.length })) : null,
    notes: s.notes ? s.notes.all() : null,
    created: new Date().toISOString(),
  };
  return r;
}

const b64url = (u8) => {
  let bin = '';
  for (let i = 0; i < u8.length; i += 0x8000) bin += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64url = (s) => {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
};
async function pipe(u8, stream) {
  const res = new Response(new Blob([u8]).stream().pipeThrough(stream));
  return new Uint8Array(await res.arrayBuffer());
}

export async function encodeReport(report) {
  const json = new TextEncoder().encode(JSON.stringify(report));
  return b64url(await pipe(json, new CompressionStream('deflate-raw')));
}

// A share link can be crafted by anyone, so decoding is strict: the inflated
// size is capped (no zip bombs) and every field is rebuilt with the type the
// viewer expects. Anything else in the payload is dropped.
const MAX_REPORT = 4 * 1024 * 1024;

async function inflateCapped(u8) {
  const reader = new Blob([u8]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_REPORT) { reader.cancel(); throw new Error('Report is too large'); }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let p = 0;
  for (const x of parts) { out.set(x, p); p += x.length; }
  return out;
}

const str = (v, max = 2000) => (typeof v === 'string' ? v : v == null ? '' : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '').slice(0, max);
const num = (v, d = 0) => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const numOrNull = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const arr = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);
const obj = (v) => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const hexStr = (v) => (typeof v === 'string' && /^0x[0-9a-f]{1,16}$/i.test(v) ? v : null);
const hash = (v, len) => (typeof v === 'string' && new RegExp(`^[0-9a-f]{${len}}$`).test(v) ? v : '');
const strMap = (v, max) => {
  const out = {};
  for (const [k, val] of Object.entries(obj(v)).slice(0, max)) if (/^\d{1,20}$/.test(k)) out[k] = str(val, 500);
  return out;
};
const pair = (p) => (Array.isArray(p) ? [str(p[0], 200), typeof p[1] === 'boolean' ? p[1] : str(p[1], 500)] : ['', '']);

export function normalizeReport(r) {
  r = obj(r);
  if (r.app !== 'binkeep' || r.v !== 1) throw new Error('Not a binkeep report');
  const sig = r.signature && typeof r.signature === 'object' ? r.signature : null;
  const pack = r.packing && typeof r.packing === 'object' ? r.packing : null;
  const fns = r.functions && typeof r.functions === 'object' ? r.functions : null;
  const notes = obj(r.notes);
  return {
    v: 1,
    app: 'binkeep',
    name: str(r.name, 300) || 'unknown',
    created: /^\d{4}-\d{2}-\d{2}/.test(str(r.created)) ? str(r.created, 40) : '',
    size: Math.max(0, num(r.size)),
    sha256: hash(r.sha256, 64),
    sha1: hash(r.sha1, 40),
    format: str(r.format, 100),
    arch: str(r.arch, 100),
    kind: str(r.kind, 100),
    entry: hexStr(r.entry),
    facts: arr(r.facts, 200).map(pair).map(([k, v]) => [k, str(v, 500)]),
    mitigations: arr(r.mitigations, 50).map(pair),
    hints: arr(r.hints, 100).map((h) => ({ level: obj(h).level === 'warn' ? 'warn' : 'info', text: str(obj(h).text, 500) })),
    sections: arr(r.sections, 500).map((s) => {
      s = obj(s);
      return {
        name: str(s.name, 100), va: hexStr(s.va) || '0x0', vsize: Math.max(0, num(s.vsize)), off: Math.max(0, num(s.off)), size: Math.max(0, num(s.size)),
        flags: /^[R-][W-][X-]$/.test(str(s.flags)) ? s.flags : '---', entropy: numOrNull(s.entropy) == null ? null : Math.min(8, Math.max(0, s.entropy)),
      };
    }),
    imports: arr(r.imports, 1000).map((l) => ({ lib: str(obj(l).lib, 300), fns: arr(obj(l).fns, 5000).map((f) => str(f, 300)) })),
    exportCount: Math.max(0, num(r.exportCount)),
    exports: arr(r.exports, 100000).map((e) => str(e, 300)),
    strings: arr(r.strings, 1000).map((s) => ({ off: Math.max(0, num(obj(s).off)), cat: /^[a-z]{1,20}$/.test(str(obj(s).cat)) ? obj(s).cat : '', text: str(obj(s).text, 200) })),
    stringCount: Math.max(0, num(r.stringCount)),
    entropy: {
      total: numOrNull(obj(r.entropy).total),
      blocks: arr(obj(r.entropy).blocks, 4096).map((b) => Math.min(255, Math.max(0, num(b)))),
    },
    packing: pack ? {
      verdict: ['signature', 'likely', 'maybe', 'none'].includes(pack.verdict) ? pack.verdict : 'none',
      packers: arr(pack.packers, 50).map((p) => str(p, 100)),
      reasons: arr(pack.reasons, 50).map((p) => str(p, 300)),
    } : null,
    signature: sig ? {
      signer: sig.signer && typeof sig.signer === 'object' ? {
        subject: { CN: str(obj(sig.signer.subject).CN, 300), O: str(obj(sig.signer.subject).O, 300), C: str(obj(sig.signer.subject).C, 10) },
        issuer: { CN: str(obj(sig.signer.issuer).CN, 300), O: str(obj(sig.signer.issuer).O, 300) },
        notBefore: str(sig.signer.notBefore, 40), notAfter: str(sig.signer.notAfter, 40),
      } : null,
      digestAlg: str(sig.digestAlg, 40), timestamp: str(sig.timestamp, 40),
      intact: typeof sig.intact === 'boolean' ? sig.intact : null, certs: Math.max(0, num(sig.certs)),
    } : null,
    functions: fns ? {
      count: Math.max(0, num(fns.count)),
      list: Array.isArray(fns.list) ? arr(fns.list, 200000).map((f) => ({ va: hexStr(obj(f).va) || '0x0', name: str(obj(f).name, 300), size: Math.max(0, num(obj(f).size)) })) : undefined,
    } : null,
    yara: Array.isArray(r.yara) ? arr(r.yara, 500).map((y) => ({ rule: str(obj(y).rule, 200), matches: Math.max(0, num(obj(y).matches)) })) : null,
    notes: r.notes ? { names: strMap(notes.names, 5000), comments: strMap(notes.comments, 5000) } : null,
  };
}

export async function decodeReport(token) {
  if (typeof token !== 'string' || token.length > 2 * 1024 * 1024 || !/^[A-Za-z0-9_-]+$/.test(token)) throw new Error('Bad share token');
  const raw = await inflateCapped(unb64url(token));
  return normalizeReport(JSON.parse(new TextDecoder().decode(raw)));
}

const mdEsc = (t) => String(t).replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function reportMarkdown(r) {
  const L = [];
  L.push(`# ${r.name}`, '');
  L.push(`${r.format}, ${r.arch}, ${r.kind}, ${r.size.toLocaleString('en-US')} bytes`, '');
  if (r.sha256) L.push(`- SHA-256: \`${r.sha256}\``);
  if (r.sha1) L.push(`- SHA-1: \`${r.sha1}\``);
  if (r.entry) L.push(`- Entry point: \`${r.entry}\``);
  if (r.entropy?.total != null) L.push(`- Entropy: ${r.entropy.total} / 8`);
  L.push('');
  L.push('## Headers', '', '| Field | Value |', '| --- | --- |', ...r.facts.map(([k, v]) => `| ${mdEsc(k)} | ${mdEsc(v)} |`), '');
  if (r.mitigations.length) L.push('## Mitigations', '', ...r.mitigations.map(([k, v]) => `- ${v ? '[x]' : '[ ]'} ${k}${typeof v === 'string' ? `: ${v}` : ''}`), '');
  if (r.packing) {
    L.push('## Packing', '');
    if (r.packing.packers.length) L.push(`Detected: ${r.packing.packers.join(', ')}`);
    else L.push(`Verdict: ${r.packing.verdict === 'none' ? 'no packer detected' : r.packing.verdict}`);
    for (const why of r.packing.reasons) L.push(`- ${why}`);
    L.push('');
  }
  if (r.signature) {
    const s = r.signature;
    L.push('## Signature', '');
    if (s.signer) L.push(`- Signer: ${mdEsc(s.signer.subject.CN || s.signer.subject.O || '?')}`, `- Issuer: ${mdEsc(s.signer.issuer.CN || '?')}`, `- Valid: ${s.signer.notBefore} to ${s.signer.notAfter}`);
    if (s.timestamp) L.push(`- Timestamp: ${s.timestamp}`);
    if (s.intact != null) L.push(`- File digest (${s.digestAlg}): ${s.intact ? 'matches, file unchanged since signing' : 'DOES NOT MATCH, file was modified after signing'}`);
    L.push('- Certificate chain was not verified.', '');
  }
  if (r.version?.strings?.length) L.push('## Version info', '', ...r.version.strings.map(([k, v]) => `- ${k}: ${mdEsc(v)}`), '');
  if (r.hints.length) L.push('## Notes', '', ...r.hints.map((h) => `- ${h.level === 'warn' ? '**check:** ' : ''}${mdEsc(h.text)}`), '');
  L.push('## Sections', '', '| Name | VA | Raw size | Flags | Entropy |', '| --- | --- | --- | --- | --- |',
    ...r.sections.map((s) => `| ${mdEsc(s.name)} | ${s.va} | ${s.size} | ${s.flags} | ${s.entropy ?? ''} |`), '');
  if (r.imports.length) {
    L.push('## Imports', '');
    for (const l of r.imports) L.push(`- **${mdEsc(l.lib)}**: ${l.fns.map(mdEsc).join(', ')}`);
    L.push('');
  }
  if (r.functions?.count) L.push(`## Code`, '', `${r.functions.count.toLocaleString('en-US')} functions found.`, '');
  if (r.yara?.length) L.push('## YARA matches', '', ...r.yara.map((y) => `- ${y.rule} (${y.matches} hits)`), '');
  if (r.strings.length) L.push('## Interesting strings', '', ...r.strings.slice(0, 120).map((s) => `- \`${s.cat}\` ${mdEsc(s.text)}`), '');
  const notes = r.notes;
  if (notes && (Object.keys(notes.names).length || Object.keys(notes.comments).length)) {
    L.push('## Analyst notes', '');
    for (const [va, n] of Object.entries(notes.names)) L.push(`- \`0x${Number(va).toString(16)}\` renamed to **${mdEsc(n)}**`);
    for (const [va, c] of Object.entries(notes.comments)) L.push(`- \`0x${Number(va).toString(16)}\`: ${mdEsc(c)}`);
    L.push('');
  }
  L.push('---', `Generated by binkeep on ${r.created.slice(0, 10)}. The file was analyzed locally and never uploaded.`);
  return L.join('\n');
}
