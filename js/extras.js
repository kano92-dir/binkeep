// Report pieces for capabilities, .NET assemblies, Android apps and archives.

import { listZip, readEntry } from './zip.js';
import { parseAxml, manifestInfo, parseDex, packageSummary, dexFlags, javaName } from './android.js';
import { TACTIC_ORDER, attackUrl } from './capabilities.js';
import { categorize } from './analysis.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtSize = (n) => (n == null ? '' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const list = (arr, max, fmt) => arr.slice(0, max).map(fmt).join('') + (arr.length > max ? `<li class="muted small">and ${(arr.length - max).toLocaleString()} more</li>` : '');

/* ---------- hash lookups ---------- */

export function hashLinks(sha256) {
  if (!sha256) return '';
  return `<div class="hash-links"><span class="muted small">Look it up by hash</span>
    <a class="btn" href="https://www.virustotal.com/gui/file/${sha256}" target="_blank" rel="noopener noreferrer">VirusTotal</a>
    <a class="btn" href="https://bazaar.abuse.ch/sample/${sha256}/" target="_blank" rel="noopener noreferrer">MalwareBazaar</a>
    <a class="btn" href="https://www.hybrid-analysis.com/search?query=${sha256}" target="_blank" rel="noopener noreferrer">Hybrid Analysis</a>
    <span class="muted small">Only the SHA-256 is sent, and only when you click. The file stays here.</span></div>`;
}

/* ---------- capabilities ---------- */

const EV_LABEL = { api: 'calls', str: 'string', net: '.NET call', perm: 'permission', dex: 'Java call' };

export function capsCard(caps) {
  if (!caps) return '';
  const strong = caps.filter((c) => !c.weak), weak = caps.filter((c) => c.weak);
  const order = (c) => TACTIC_ORDER.indexOf(c.tactic);
  strong.sort((a, b) => order(a) - order(b));
  const ev = (e) => `<span class="cap-ev"><span class="muted">${EV_LABEL[e.kind]}</span> <code>${esc(e.value.length > 70 ? e.value.slice(0, 70) + '...' : e.value)}</code></span>`;
  const row = (c) => `<li class="cap"><div class="cap-main"><b>${esc(c.name)}</b><a class="chip info attack" href="${attackUrl(c.attack)}" target="_blank" rel="noopener noreferrer" title="MITRE ATT&CK technique">${c.attack}</a><span class="muted small">${esc(c.tactic)}</span></div><div class="cap-evs">${c.evidence.map(ev).join('')}</div></li>`;
  const body = strong.length
    ? `<ul class="caps">${strong.map(row).join('')}</ul>`
    : '<p class="muted small">No notable behaviour found in the imports, strings or code references.</p>';
  const weakHtml = weak.length ? `<details class="caps-weak"><summary class="muted small">Also common in ordinary software (${weak.length})</summary><ul class="caps">${weak.map(row).join('')}</ul></details>` : '';
  return `<div class="card-head"><h2>What it can do</h2><span class="muted small">${strong.length} behaviour${strong.length === 1 ? '' : 's'}, mapped to MITRE ATT&amp;CK</span></div>${body}${weakHtml}
    <p class="muted small">Found from what the file imports, references and contains. It shows what the code is able to do, not proof that it does it.</p>`;
}

/* ---------- .NET ---------- */

export function dotnetCard(d) {
  if (!d) return '';
  const f = d.flags;
  const facts = [
    ['Assembly', d.assembly ? `${d.assembly.name} ${d.assembly.version}` : d.moduleName],
    ['Runtime', d.runtime],
    ['Entry point', d.entry || 'none (library)'],
    ['Code', f.ilOnly ? 'IL only (managed)' : 'Mixed managed and native'],
    ['Strong name', f.strongName ? 'signed' : 'no'],
    ['Size', `${d.counts.types.toLocaleString()} types, ${d.counts.methods.toLocaleString()} methods`],
  ];
  const obf = d.obfuscator ? `<div class="verdict bad"><b>Obfuscated with ${esc(d.obfuscator)}</b><span>Names and strings may be scrambled.</span></div>`
    : d.obfuscated ? '<div class="verdict warn"><b>Names look obfuscated</b><span>Many type names are random or unreadable.</span></div>' : '';
  return `<div class="card-head"><h2>.NET assembly</h2><button class="link small" data-tab-link="dotnet">Open .NET view</button></div>${obf}
    <dl class="facts">${facts.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
}

export function dotnetPanel(d) {
  if (!d) return '';
  const refs = d.refs.map((r) => `<li><span class="mono">${esc(r.name)}</span><span class="muted small">${esc(r.version)}</span></li>`).join('');
  const susp = d.suspicious.length
    ? `<ul class="hints">${d.suspicious.map((s) => `<li><span class="chip warn">${esc(s.label)}</span><span class="mono small">${s.hits.map(esc).join(', ')}</span></li>`).join('')}</ul>`
    : '<p class="muted small">None of the watched framework calls are used.</p>';
  const pinv = d.pinvoke.length ? `<div class="card"><div class="card-head"><h2>Native calls (P/Invoke)</h2><span class="muted small">${d.pinvoke.length}</span></div><ul class="plain-list">${list(d.pinvoke, 200, (p) => `<li><span class="mono">${esc(p.lib)}!${esc(p.name)}</span></li>`)}</ul></div>` : '';
  const res = d.resources.length ? `<div class="card"><div class="card-head"><h2>Embedded resources</h2><span class="muted small">${d.resources.length}</span></div><ul class="plain-list">${list(d.resources, 200, (r) => `<li><span class="mono">${esc(r.name)}</span><span class="muted small">${r.size != null ? fmtSize(r.size) : r.embedded ? '' : 'linked'}</span></li>`)}</ul></div>` : '';
  const types = d.types.map((t) => `<details class="dn-type"><summary><span class="mono">${esc(t.name)}</span><span class="muted small">${t.methods.length} method${t.methods.length === 1 ? '' : 's'}${t.extends ? ` · extends ${esc(t.extends)}` : ''}</span></summary><ul class="plain-list mono small">${t.methods.map((m) => `<li>${esc(m.name)}</li>`).join('')}</ul></details>`).join('');
  return `
    <div class="grid-2">
      <div class="card"><div class="card-head"><h2>Framework calls to look at</h2><span class="muted small">from MemberRef</span></div>${susp}</div>
      <div class="card"><div class="card-head"><h2>Referenced assemblies</h2><span class="muted small">${d.refs.length}</span></div><ul class="plain-list">${refs}</ul></div>
    </div>
    <div class="grid-2">${pinv}${res}</div>
    <div class="card"><div class="card-head"><h2>Types and methods</h2><span class="muted small">${d.types.length.toLocaleString()} types</span></div><div class="dn-types">${types}</div></div>
    <div class="card"><div class="card-head"><h2>Framework members used</h2><span class="muted small">${d.memberRefs.length.toLocaleString()}</span></div><ul class="plain-list mono small cols">${list(d.memberRefs, 1500, (m) => `<li>${esc(m)}</li>`)}</ul></div>`;
}

/* ---------- Android ---------- */

export async function loadApk(bytes, entries) {
  const get = (n) => entries.find((e) => e.name === n);
  const man = get('AndroidManifest.xml');
  const manifest = man ? manifestInfo(parseAxml(await readEntry(bytes, man))) : null;
  const dexEntries = entries.filter((e) => /^classes\d*\.dex$/.test(e.name));
  const dexes = [];
  let classes = [], methodRefs = [];
  const strSet = new Set();
  for (const e of dexEntries) {
    const d = parseDex(await readEntry(bytes, e));
    dexes.push({ name: e.name, version: d.version, classes: d.classes.length, methods: d.methodRefs.length });
    classes = classes.concat(d.classes);
    methodRefs = methodRefs.concat(d.methodRefs);
    for (const s of d.strings) if (s.length >= 4 && !/^[LV\[][\w/$]*;?$/.test(s)) strSet.add(s);
  }
  const certs = entries.filter((e) => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
  let debugKey = certs.some((e) => /debug/i.test(e.name));
  for (const c of certs) {
    try { if (new TextDecoder('latin1').decode(await readEntry(bytes, c)).includes('Android Debug')) debugKey = true; } catch { /* unreadable */ }
  }
  const v2 = findAscii(bytes, 'APK Sig Block 42', Math.max(0, (entries.cdOff || bytes.length) - 64), (entries.cdOff || bytes.length));
  return {
    manifest,
    dexes,
    classes,
    methodRefs: [...new Set(methodRefs)],
    strings: [...strSet],
    entries,
    nativeLibs: entries.filter((e) => /^lib\/[^/]+\/[^/]+\.so$/.test(e.name)).map((e) => e.name),
    sig: { v1: certs.map((e) => e.name), v2, debugKey },
    permissions: manifest?.permissions || [],
  };
}

function findAscii(b, text, from, to) {
  const t = [...text].map((c) => c.charCodeAt(0));
  for (let i = Math.max(0, from); i + t.length <= Math.min(b.length, to); i++) {
    let ok = true;
    for (let k = 0; k < t.length; k++) if (b[i + k] !== t[k]) { ok = false; break; }
    if (ok) return true;
  }
  return false;
}

export function apkModel(apk, base) {
  const m = apk.manifest || {};
  const sig = apk.sig;
  base.format = 'Android APK';
  base.kind = 'Android app';
  base.arch = apk.nativeLibs.length ? [...new Set(apk.nativeLibs.map((n) => n.split('/')[1]))].join(', ') : 'Dalvik bytecode';
  base.facts = [
    ['Format', 'Android APK'],
    ['Package', m.package || 'unknown'],
    ['Version', `${m.versionName || '?'} (code ${m.versionCode ?? '?'})`],
    ['SDK', `min ${m.minSdk || '?'} · target ${m.targetSdk || '?'}`],
    ['Launch activity', m.launcher || 'none'],
    ['Code', `${apk.dexes.length} DEX file${apk.dexes.length === 1 ? '' : 's'}, ${apk.classes.length.toLocaleString()} classes`],
    ['Native libraries', apk.nativeLibs.length ? String(apk.nativeLibs.length) : 'none'],
    ['Signature', [sig.v1.length ? 'v1 (JAR)' : '', sig.v2 ? 'v2/v3 block' : ''].filter(Boolean).join(' + ') || 'not signed'],
  ];
  base.hints = [];
  if (sig.debugKey) base.hints.push({ level: 'warn', text: 'Signed with the Android debug key: a development build, not from a store' });
  if (!sig.v1.length && !sig.v2) base.hints.push({ level: 'warn', text: 'Not signed: Android will refuse to install it' });
  if (m.app?.debuggable) base.hints.push({ level: 'warn', text: 'android:debuggable is on: anyone can attach a debugger' });
  if (m.app?.cleartext) base.hints.push({ level: 'warn', text: 'Allows unencrypted HTTP traffic (usesCleartextTraffic)' });
  if (m.app?.allowBackup) base.hints.push({ level: 'info', text: 'App data can be copied with adb backup (allowBackup)' });
  const exported = (m.components || []).filter((c) => c.exported && c.kind !== 'activity-alias' && !c.actions.includes('android.intent.action.MAIN'));
  if (exported.length) base.hints.push({ level: 'info', text: `${exported.length} component${exported.length > 1 ? 's are' : ' is'} exported (other apps can start ${exported.length > 1 ? 'them' : 'it'})` });
  return base;
}

export function apkStrings(apk) {
  return apk.strings.map((text) => ({ text, off: -1, len: 0, enc: 'DEX', cat: categorize(text) }));
}

export function androidCard(apk) {
  const m = apk.manifest || {};
  const perms = m.permissions || [];
  const dangerous = new Set(m.dangerous || []);
  const short = (p) => p.replace(/^android\.permission\./, '');
  return `<div class="card-head"><h2>Permissions</h2><span class="muted small">${perms.length} requested, ${dangerous.size} sensitive</span></div>
    ${perms.length ? `<div class="chips">${perms.map((p) => `<span class="chip ${dangerous.has(p) ? 'warn' : ''}" title="${esc(p)}">${esc(short(p))}</span>`).join('')}</div>` : '<p class="muted small">No permissions requested.</p>'}
    <p class="muted small">Highlighted ones give access to personal data, the screen, or other apps.</p>`;
}

export function androidPanel(apk) {
  const m = apk.manifest || {};
  const comps = m.components || [];
  const flags = dexFlags(apk.methodRefs);
  const pkgs = packageSummary(apk.classes);
  const comp = (c) => `<li><span class="chip ${c.exported ? 'warn' : ''}">${esc(c.kind)}${c.exported ? ' · exported' : ''}</span><span class="mono small">${esc(c.name)}</span>${c.actions.length ? `<span class="muted small">${[...new Set(c.actions)].map((a) => esc(a.replace(/^android\.intent\.action\./, ''))).join(', ')}</span>` : ''}</li>`;
  return `
    <div class="grid-2">
      <div class="card"><div class="card-head"><h2>Code to look at</h2><span class="muted small">from DEX method references</span></div>
        ${flags.length ? `<ul class="hints">${flags.map((f) => `<li><span class="chip warn">${esc(f.label)}</span><span class="mono small">${f.hits.slice(0, 4).map((h) => esc(h.replace(/^L/, '').replace(/;->/, '.'))).join(', ')}</span></li>`).join('')}</ul>` : '<p class="muted small">None of the watched Android APIs are referenced.</p>'}
        <p class="muted small">Bundled libraries (AndroidX, Google Play services, game engines) reference many of these too.</p></div>
      <div class="card"><div class="card-head"><h2>Components</h2><span class="muted small">${comps.length}</span></div><ul class="hints comps">${comps.map(comp).join('') || '<li class="muted small">None declared.</li>'}</ul></div>
    </div>
    <div class="grid-2">
      <div class="card"><div class="card-head"><h2>Packages</h2><span class="muted small">classes per package</span></div><ul class="plain-list">${list(pkgs, 60, ([p, n]) => `<li><span class="mono">${esc(p)}</span><span class="muted small">${n}</span></li>`)}</ul></div>
      <div class="card"><div class="card-head"><h2>DEX files</h2></div><ul class="plain-list">${apk.dexes.map((d) => `<li><span class="mono">${esc(d.name)}</span><span class="muted small">v${esc(d.version)} · ${d.classes.toLocaleString()} classes · ${d.methods.toLocaleString()} methods</span></li>`).join('')}</ul>
        ${apk.nativeLibs.length ? `<div class="card-head" style="margin-top:16px"><h2>Native libraries</h2><button class="link small" data-tab-link="files">Open in Files</button></div><ul class="plain-list">${list(apk.nativeLibs, 40, (n) => `<li><span class="mono small">${esc(n)}</span></li>`)}</ul>` : ''}</div>
    </div>
    <div class="card"><div class="card-head"><h2>Classes</h2><span class="muted small">${apk.classes.length.toLocaleString()}</span></div><ul class="plain-list mono small cols">${list(apk.classes.map(javaName), 3000, (c) => `<li>${esc(c)}</li>`)}</ul></div>`;
}

/* ---------- archive file list ---------- */

export function filesTable(entries, { openable = true } = {}) {
  const icon = (n) => /\.(exe|dll|sys|so|dylib|elf|bin|o|dex|apk|scr|cpl|ocx|node)$/i.test(n) || !/\.[a-z0-9]{1,5}$/i.test(n.split('/').pop());
  const rows = entries.map((e, i) => `<tr${icon(e.name) ? ' class="bin"' : ''}>
    <td class="mono">${esc(e.name)}${e.encrypted ? ' <span class="chip warn">locked</span>' : ''}</td>
    <td class="num">${fmtSize(e.usize)}</td>
    <td>${openable ? `<button class="btn" type="button" data-zip-open="${i}">Open</button>` : ''}</td></tr>`).join('');
  return `<table class="data"><thead><tr><th>File</th><th class="num">Size</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
}

export { listZip, readEntry };
