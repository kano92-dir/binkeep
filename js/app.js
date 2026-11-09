import { isPE, parsePE } from './parsers/pe.js';
import { isELF, parseELF } from './parsers/elf.js';
import { isMachO, parseMachO } from './parsers/macho.js';
import { parseResources, parseAuthenticode, verifyDigest } from './parsers/pe-extra.js';
import { entropy, entropyBlocks, extractStrings, hashes, flagApi } from './analysis.js';
import { createDisassembler, classify, isUnconditionalEnd, operandTarget } from './disasm.js';
import { detectPackers } from './packers.js';
import { analyzeCode, codeSize, decRef } from './codeanalysis.js';
import { createNotes } from './notes.js';
import { runYara, SAMPLE_RULES } from './yara.js';
import { buildReport, encodeReport, decodeReport, reportMarkdown } from './report.js';
import { profileOf, diffProfiles } from './diff.js';
import { createPalette, fuzzy } from './palette.js';
import { buildCfg, layoutCfg } from './cfg.js';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hx = (n) => '0x' + Number(n).toString(16);
const hxPad = (n, w = 8) => Number(n).toString(16).padStart(w, '0');
const fmtSize = (n) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`;
const tick = () => new Promise((r) => setTimeout(r, 16));
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage blocked */ } },
};
const ICON_SEARCH = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';

const SECTION_COLORS = ['#e4e4e8', '#a9a9b2', '#cfcfd6', '#8c8c95', '#d9d9df', '#b7b7bf', '#9e9ea7', '#c3c3ca'];
const HIGH_ENTROPY = 7.2;
const AUTO_CODE_LIMIT = 8 * 1048576;
const YARA_KEY = 'binkeep.yaraRules';

const state = {
  name: '',
  bytes: null,
  model: null,
  strings: [],
  stringByOff: new Map(),
  blocks: null,
  totalEntropy: null,
  hashes: null,
  packing: null,
  resources: null,
  signature: null,
  code: null,
  codeRun: { ctrl: null, running: false },
  yara: null,
  notes: createNotes(),
  compare: null,
  hexSel: null,
  hexList: null,
  strList: null,
  fnList: null,
  iconUrl: null,
  tab: 'overview',
  dis: { engine: null, enginePromise: null, history: [], start: null, next: null, items: [], sel: null },
  cfg: { graph: null, layout: null, sel: null, busy: 0, history: [], view: { x: 0, y: 0, k: 1 } },
};

/* ---------- File loading ---------- */

const fileInput = $('#fileInput');
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) loadFile(fileInput.files[0]);
  fileInput.value = '';
});

let dragDepth = 0;
window.addEventListener('dragenter', (e) => {
  if (![...e.dataTransfer.types].includes('Files')) return;
  dragDepth++;
  $('#dragOverlay').hidden = false;
  $('#dropzone').classList.add('over');
});
window.addEventListener('dragleave', () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) { $('#dragOverlay').hidden = true; $('#dropzone').classList.remove('over'); }
});
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => {
  e.preventDefault();
  dragDepth = 0;
  $('#dragOverlay').hidden = true;
  $('#dropzone').classList.remove('over');
  const f = e.dataTransfer.files[0];
  if (f) loadFile(f);
});

async function loadFile(file) {
  if (file.size > 512 * 1048576) {
    toast('Files over 512 MB are not supported in the browser.');
    return;
  }
  showLoading(`Reading ${file.name}...`);
  const buf = await file.arrayBuffer();
  await analyze(file.name, buf);
}

function showLoading(text) {
  $('#emptyState').hidden = true;
  $('#report').hidden = true;
  $('#shared').hidden = true;
  $('#loadingState').hidden = false;
  $('#loadingText').textContent = text;
}

/* ---------- Analysis ---------- */

function genericModel(bytes, reason) {
  const magic = [...bytes.subarray(0, 4)].map((b) => hxPad(b, 2)).join(' ');
  let format = 'Unknown';
  const m32 = bytes.length >= 4 ? new DataView(bytes.buffer, bytes.byteOffset).getUint32(0, false) : 0;
  if (m32 === 0xcafebabe) format = 'Java class';
  else if (bytes[0] === 0x50 && bytes[1] === 0x4b) format = 'ZIP (or APK / JAR / Office)';
  else if (bytes[0] === 0x4d && bytes[1] === 0x5a) format = 'MZ (DOS stub, no PE header)';
  else if (bytes[0] === 0x00 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d) format = 'WebAssembly module';
  return {
    format, arch: 'n/a', bits: 0, kind: 'n/a', entry: null,
    facts: [['Format', format], ['Magic bytes', magic]],
    mitigations: [], sections: [], imports: [], exports: [], labels: new Map(), iat: new Map(), funcStarts: [], overlay: null,
    hints: [{ level: 'info', text: reason || 'Not a PE, ELF or Mach-O file. Hex, strings, entropy and YARA still work.' }],
    warnings: [], disasm: null, vaToOff: () => -1, offToVa: () => null,
  };
}

function parseAny(bytes) {
  try {
    if (isPE(bytes)) return parsePE(bytes);
    if (isELF(bytes)) return parseELF(bytes);
    if (isMachO(bytes)) return parseMachO(bytes);
    return genericModel(bytes);
  } catch (err) {
    console.error(err);
    return genericModel(bytes, `Header parsing failed (${err.message}). The file may be truncated or malformed.`);
  }
}

function sectionEntropies(model, bytes) {
  for (const s of model.sections) {
    const end = Math.min(bytes.length, s.off + s.size);
    s.entropy = s.size > 0 && s.off < bytes.length ? entropy(bytes, s.off, end) : null;
  }
}

async function analyze(name, buf) {
  const bytes = new Uint8Array(buf);
  state.codeRun.ctrl?.abort();
  Object.assign(state, {
    name, bytes, hexSel: null, hashes: null, code: null, yara: null, compare: null,
    packing: null, resources: null, signature: null,
  });
  state.codeRun = { ctrl: null, running: false };
  state.notes.reset();
  if (state.iconUrl) { URL.revokeObjectURL(state.iconUrl); state.iconUrl = null; }
  resetDisasm();
  resetCfg();

  showLoading('Parsing headers...');
  await tick();
  const model = parseAny(bytes);
  sectionEntropies(model, bytes);
  state.model = model;

  showLoading('Measuring entropy and extracting strings...');
  await tick();
  state.blocks = entropyBlocks(bytes, 1200);
  state.totalEntropy = entropy(bytes);
  state.strings = extractStrings(bytes);
  state.stringByOff = new Map(state.strings.map((s) => [s.off, s]));
  const lang = detectToolchain(model, state.strings);
  if (lang) model.hints.unshift({ level: 'info', text: lang });
  state.packing = detectPackers(bytes, model, state.strings);
  if (model.pe) {
    try { state.resources = parseResources(bytes, model); } catch (err) { console.error(err); }
    try { state.signature = parseAuthenticode(bytes, model); } catch (err) { console.error(err); }
  }

  $('#loadingState').hidden = true;
  $('#report').hidden = false;
  $('#fileMeta').hidden = false;
  $$('.report-only').forEach((el) => { el.hidden = false; });
  $('#fileName').textContent = name;
  $('#fileName').title = name;
  $('#fileFormat').textContent = `${model.format}${model.arch !== 'n/a' ? ' · ' + model.arch : ''}`;
  document.title = `${name} · binkeep`;
  renderFileIcon();

  $('[data-tab="resources"]').hidden = !state.resources?.items.length;
  $('[data-tab="diff"]').hidden = true;
  $('[data-panel="diff"]').innerHTML = '';

  renderSummary();
  drawEntropy();
  renderOverview();
  renderSections();
  renderImports();
  renderExports();
  setupStrings();
  setupHex();
  renderFunctions();
  renderResources();
  renderYaraIdle();
  updateTabCounts();
  const want = location.hash.slice(1);
  selectTab(want && !want.startsWith('r=') ? want : 'overview');

  hashes(bytes).then((h) => {
    if (state.bytes !== bytes) return;
    state.hashes = h;
    state.notes.load(h['SHA-256']);
    renderHashes();
    renderNotesCard();
    refreshNames();
  }).catch(() => {});
  if (state.signature?.digest) {
    verifyDigest(bytes, model, state.signature).then((ok) => {
      if (state.bytes !== bytes) return;
      state.signature.intact = ok;
      renderSignatureCard();
    }).catch(() => {});
  }
  maybeAutoAnalyze();
  if (store.get(YARA_KEY)?.trim()) runYaraNow(true);
}

function detectToolchain(model, strings) {
  const names = new Set(model.sections.map((s) => s.name));
  const has = (re) => strings.some((s) => re.test(s.text));
  if (names.has('.gopclntab') || names.has('.go.buildinfo') || names.has('__DATA_CONST,__go_buildinfo') || has(/^\s*Go build(inf| ID)/) || has(/^go1\.\d+/)) {
    const v = strings.find((s) => /^go1\.\d+(\.\d+)?$/.test(s.text));
    return `Built with Go${v ? ' (' + v.text + ')' : ''}. Function names live in .gopclntab even when stripped.`;
  }
  if (has(/\/rustc\/[0-9a-f]{40}/) || has(/rust_panic|core::panicking/)) return 'Built with Rust (rustc paths found in strings)';
  if (has(/^Nim(Main|_\w+)/) || has(/@m\.\.@s/)) return 'Built with Nim';
  if (has(/^PyInstaller|_MEIPASS|pyi-runtime-tmpdir/)) return 'PyInstaller bundle: Python bytecode is packed in the overlay';
  if (has(/^Electron\/|electron\.asar/)) return 'Electron app';
  if (has(/AU3!EA06/)) return 'Compiled AutoIt script';
  if (has(/NullsoftInst/) && has(/NSIS Error/)) return 'NSIS installer';
  if (has(/^Inno Setup Setup Data/)) return 'Inno Setup installer';
  if (has(/^GCC: \(/)) return `Compiled with ${strings.find((s) => /^GCC: \(/.test(s.text)).text}`;
  return '';
}

/* ---------- Names (labels, user renames, analysis) ---------- */

function fnAt(va) { return state.code?.funcByVa.get(va) || null; }

function funcName(va) {
  const n = state.notes.name(va) || state.model.labels.get(va);
  if (n) return n;
  const f = fnAt(va);
  if (f?.thunk) return `j_${f.thunk.replace(/^.*!/, '')}`;
  return `sub_${va.toString(16)}`;
}

// Label shown above an instruction in the disassembly, if any.
function labelAt(va) {
  const n = state.notes.name(va) || state.model.labels.get(va);
  if (n) return n;
  if (fnAt(va)) return funcName(va);
  if (state.code?.jumpTargets.has(va)) return `loc_${va.toString(16)}`;
  return '';
}

function containingFunc(va) {
  const c = state.code;
  if (!c) return null;
  const i = c.funcIndexOf(va);
  if (i < 0) return null;
  const f = c.functions[i];
  return va < f.va + Math.max(f.size, 1) || va - f.va < 0x4000 ? f : null;
}

function whereIs(va) {
  const f = containingFunc(va);
  if (!f) return hx(va);
  const d = va - f.va;
  return d ? `${funcName(f.va)}+${hx(d)}` : funcName(f.va);
}

function apiKey(lib, fn) {
  const m = state.model;
  if (m.format.startsWith('PE')) return `${lib.replace(/\.dll$/i, '')}!${fn.name || '#' + fn.ordinal}`;
  return fn.name;
}

function refreshNames() {
  if (state.fnList) drawFunctions();
  if (state.dis.items.length) rerenderDisasm();
}

/* ---------- Summary + overview ---------- */

function flaggedImports() {
  const out = [];
  for (const lib of state.model.imports) {
    for (const fn of lib.fns) {
      const cat = flagApi(fn.name);
      if (cat) out.push({ lib: lib.lib, name: fn.name, cat });
    }
  }
  return out;
}

function renderSummary() {
  const m = state.model;
  const total = state.totalEntropy;
  const flagged = flaggedImports().length;
  const fnCount = state.code ? state.code.functions.length.toLocaleString() : state.codeRun.running ? '...' : m.disasm ? '-' : 'n/a';
  const stats = [
    ['Format', m.format],
    ['Architecture', m.arch],
    ['Size', fmtSize(state.bytes.length)],
    ['Entropy', `${total.toFixed(2)} / 8`, total > HIGH_ENTROPY ? 'warn' : ''],
    ['Flagged APIs', String(flagged), flagged > 10 ? 'warn' : ''],
    ['Functions', fnCount],
  ];
  $('#summary').innerHTML = stats.map(([k, v, cls]) => `<dl class="stat"><dt>${k}</dt><dd class="${cls || ''}">${esc(v)}</dd></dl>`).join('');
}

function renderFileIcon() {
  const icon = state.resources?.icon;
  const el = $('#fileIcon');
  if (!icon) { el.hidden = true; el.innerHTML = ''; return; }
  state.iconUrl = URL.createObjectURL(new Blob([icon.data], { type: icon.mime }));
  el.innerHTML = `<img src="${state.iconUrl}" alt="">`;
  el.hidden = false;
}

function renderOverview() {
  const m = state.model;
  const facts = m.facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
  const mit = m.mitigations.length
    ? m.mitigations.map(([k, v]) => {
        const on = !!v;
        const label = typeof v === 'string' ? `${k}: ${v}` : k;
        return `<span class="chip ${on ? 'ok' : 'bad'}">${on ? 'on' : 'off'} · ${esc(label)}</span>`;
      }).join('')
    : '<span class="muted small">Not applicable for this format.</span>';
  const allHints = [...m.warnings.map((t) => ({ level: 'warn', text: t })), ...m.hints];
  const hints = allHints.length
    ? `<ul class="hints">${allHints.map((h) => `<li><span class="chip ${h.level === 'warn' ? 'warn' : 'info'}">${h.level === 'warn' ? 'check' : 'note'}</span><span>${esc(h.text)}</span></li>`).join('')}</ul>`
    : '<p class="muted small">Nothing unusual in the headers.</p>';

  const flagged = flaggedImports();
  const byCat = {};
  for (const f of flagged) (byCat[f.cat] ||= []).push(f.name);
  const flagHtml = flagged.length
    ? `<div class="chips">${Object.entries(byCat).map(([c, names]) => `<span class="chip warn" title="${esc(names.join(', '))}">${esc(c)} · ${names.length}</span>`).join('')}</div>`
    : '<p class="muted small">No imports from the watch list.</p>';

  const ver = state.resources?.version;
  const verStr = (k) => ver?.strings.find(([key]) => key === k)?.[1] || '';
  const ident = ver && (verStr('FileDescription') || verStr('ProductName'))
    ? `<div class="ident">${state.iconUrl ? `<img src="${state.iconUrl}" alt="">` : ''}<div><b>${esc(verStr('FileDescription') || verStr('ProductName'))}</b><span class="muted small">${esc([verStr('CompanyName'), ver.fileVersion || verStr('FileVersion')].filter(Boolean).join(' · '))}</span></div></div>`
    : '';

  $('[data-panel="overview"]').innerHTML = `
    <div class="grid-2">
      <div class="card">${ident}<div class="card-head"><h2>Headers</h2></div><dl class="facts">${facts}</dl></div>
      <div class="card" style="display:grid;gap:16px;align-content:start">
        <div><div class="card-head"><h2>Things to check</h2></div>${hints}</div>
        <div><div class="card-head"><h2>Security mitigations</h2></div><div class="chips">${mit}</div></div>
        <div><div class="card-head"><h2>API categories</h2><button class="link small" data-tab-link="imports">See imports</button></div>${flagHtml}
          <p class="muted small">Heuristic hints only. Legit software uses these APIs too.</p></div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card" id="packCard"></div>
      <div class="card" id="sigCard"></div>
    </div>
    <div class="card" id="notesCard" hidden></div>
    <div class="card"><div class="card-head"><h2>Hashes</h2><span class="muted small">computed locally</span></div><div id="hashes" class="muted small">Computing...</div></div>`;
  renderPackingCard();
  renderSignatureCard();
}

function renderPackingCard() {
  const el = $('#packCard');
  const p = state.packing;
  if (!el || !p) return;
  let body;
  if (p.packers.length) {
    body = `<div class="verdict bad"><b>${esc(p.packers.map((x) => x.name).join(', '))}</b><span>Packed or protected. Static analysis will mostly see the unpacking stub.</span></div>
      <ul class="hints">${p.packers.flatMap((x) => x.evidence.map((e) => `<li><span class="chip warn">${esc(x.name)}</span><span>${esc(e)}</span></li>`)).join('')}</ul>`;
  } else if (p.verdict === 'likely' || p.verdict === 'maybe') {
    body = `<div class="verdict ${p.verdict === 'likely' ? 'bad' : 'warn'}"><b>${p.verdict === 'likely' ? 'Likely packed' : 'Possibly packed'}</b><span>No known packer signature, but the layout looks unusual.</span></div>
      <ul class="hints">${p.reasons.map((r) => `<li><span class="chip warn">why</span><span>${esc(r)}</span></li>`).join('')}</ul>`;
  } else {
    body = `<div class="verdict ok"><b>No packer detected</b><span>${p.codeEntropy != null ? `Code entropy ${p.codeEntropy.toFixed(2)} looks like normal compiled code.` : 'No code sections to measure.'}</span></div>`;
  }
  el.innerHTML = `<div class="card-head"><h2>Packing</h2><span class="muted small">signatures and heuristics</span></div>${body}`;
}

function renderSignatureCard() {
  const el = $('#sigCard');
  if (!el) return;
  const m = state.model;
  const head = (right = '') => `<div class="card-head"><h2>Signature</h2>${right}</div>`;
  if (m.macho) {
    const s = m.macho.codeSig;
    el.innerHTML = head('<span class="muted small">Mach-O code signature</span>') + (s
      ? `<div class="verdict ${s.adhoc ? 'warn' : 'ok'}"><b>${s.adhoc ? 'Ad-hoc signed' : s.cms ? 'Signed with a developer certificate' : 'Signed'}</b><span>${esc(s.identifier || '')}${s.team ? ` · team ${esc(s.team)}` : ''}</span></div>
         <div class="chips"><span class="chip ${s.runtime ? 'ok' : 'bad'}">${s.runtime ? 'on' : 'off'} · Hardened runtime</span></div>
         <p class="muted small">Parsed, not verified against Apple's chain.</p>`
      : '<div class="verdict warn"><b>Not signed</b><span>No LC_CODE_SIGNATURE load command.</span></div>');
    return;
  }
  if (!m.pe) {
    el.innerHTML = head() + `<p class="muted small">${m.format.startsWith('ELF') ? 'ELF files are not signed in a standard way.' : 'No signature format for this file type.'}</p>`;
    return;
  }
  const s = state.signature;
  if (!s) {
    el.innerHTML = head('<span class="muted small">Authenticode</span>') + '<div class="verdict warn"><b>No embedded signature</b><span>Windows system files are often catalog-signed instead, which is not stored in the file.</span></div>';
    return;
  }
  if (s.error && !s.certs.length) {
    el.innerHTML = head('<span class="muted small">Authenticode</span>') + `<div class="verdict warn"><b>Signature block present</b><span>${esc(s.error)}</span></div>`;
    return;
  }
  const sub = s.signer?.subject || {};
  const iss = s.signer?.issuer || {};
  const asDate = (t) => new Date(t.replace(' UTC', ':00Z').replace(' ', 'T'));
  const expiredNow = s.signer?.notAfter && asDate(s.signer.notAfter) < new Date();
  const signedInTime = s.timestamp && s.signer?.notAfter && asDate(s.timestamp) <= asDate(s.signer.notAfter);
  const expired = expiredNow ? (signedInTime ? '<span class="chip ok">expired, but timestamped while valid</span>' : '<span class="chip warn">expired</span>') : '';
  const integrity = s.intact == null
    ? (s.subtle ? '<span class="chip">checking digest...</span>' : `<span class="chip">${esc(s.digestAlg || 'unknown')} digest not checked</span>`)
    : s.intact ? '<span class="chip ok">file unchanged since signing</span>' : '<span class="chip bad">modified after signing</span>';
  el.innerHTML = head('<span class="muted small">Authenticode</span>') + `
    <div class="verdict ${s.intact === false ? 'bad' : 'ok'}"><b>${esc(sub.CN || sub.O || 'Unknown signer')}</b><span>${esc([sub.O && sub.O !== sub.CN ? sub.O : '', sub.C].filter(Boolean).join(', '))}</span></div>
    <dl class="facts">
      <dt>Issued by</dt><dd>${esc(iss.CN || iss.O || '?')}</dd>
      <dt>Valid</dt><dd>${esc(s.signer?.notBefore || '?')} to ${esc(s.signer?.notAfter || '?')}${expired ? ` ${expired}` : ''}</dd>
      ${s.timestamp ? `<dt>Timestamp</dt><dd>${esc(s.timestamp)}</dd>` : ''}
      <dt>Digest</dt><dd>${esc(s.digestAlg || '?')}</dd>
      <dt>Certificates</dt><dd>${s.certs.length}${s.nested ? `, plus ${s.nested} nested signature${s.nested > 1 ? 's' : ''}` : ''}</dd>
    </dl>
    <div class="chips">${integrity}</div>
    <p class="muted small">The file digest is recomputed here. The certificate chain and trust are not verified.</p>`;
}

function renderHashes() {
  const el = $('#hashes');
  if (!el || !state.hashes) return;
  el.classList.remove('muted', 'small');
  el.style.display = 'grid';
  el.style.gap = '8px';
  el.innerHTML = Object.entries(state.hashes).map(([k, v]) => `
    <div class="hash-row"><span class="muted">${k}</span><code>${v}</code><button class="btn copy" data-copy="${v}">Copy</button></div>`).join('');
}

function renderNotesCard() {
  const el = $('#notesCard');
  if (!el) return;
  const n = state.notes.all();
  const names = Object.entries(n.names), comments = Object.entries(n.comments);
  el.hidden = !names.length && !comments.length;
  if (el.hidden) return;
  const row = (va, text, kind) => `<li><button class="link mono" data-dis="${va}">${hx(va)}</button><span class="chip">${kind}</span><span>${esc(text)}</span></li>`;
  el.innerHTML = `<div class="card-head"><h2>Your notes</h2><span class="muted small">saved in this browser for this file</span></div>
    <ul class="hints notes-list">${names.map(([va, t]) => row(va, t, 'name')).join('')}${comments.map(([va, t]) => row(va, t, 'comment')).join('')}</ul>`;
}

/* ---------- Entropy chart ---------- */

const canvas = $('#entropyCanvas');
const tip = $('#entropyTip');

function sectionAt(off) {
  return state.model?.sections.find((s) => s.size > 0 && off >= s.off && off < s.off + s.size);
}

function drawEntropyChart(cv, values, sections, len, legendEl, blockLabel) {
  if (!values.length || !cv.clientWidth) return;
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = cv.clientHeight;
  cv.width = Math.round(w * dpr);
  cv.height = Math.round(h * dpr);
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const css = getComputedStyle(document.documentElement);
  const v = (n) => css.getPropertyValue(n).trim();
  const bandH = 16, gap = 6, chartH = h - bandH - gap;

  ctx.font = '11px ' + v('--mono');
  ctx.strokeStyle = v('--line');
  ctx.lineWidth = 1;
  for (const bits of [2, 4, 6, 8]) {
    const y = Math.round(chartH - (bits / 8) * (chartH - 4)) + 0.5;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  const ty = chartH - (HIGH_ENTROPY / 8) * (chartH - 4);
  ctx.setLineDash([4, 4]);
  ctx.strokeStyle = v('--warn');
  ctx.beginPath(); ctx.moveTo(0, ty); ctx.lineTo(w, ty); ctx.stroke();
  ctx.setLineDash([]);

  const n = values.length;
  const xAt = (i) => (i / n) * w;
  const yAt = (e) => chartH - (e / 8) * (chartH - 4);
  const grad = ctx.createLinearGradient(0, 0, 0, chartH);
  grad.addColorStop(0, 'rgba(255,255,255,0.26)');
  grad.addColorStop(0.6, 'rgba(255,255,255,0.06)');
  grad.addColorStop(1, 'rgba(255,255,255,0)');
  ctx.beginPath();
  ctx.moveTo(xAt(0), chartH);
  for (let i = 0; i < n; i++) { ctx.lineTo(xAt(i), yAt(values[i])); ctx.lineTo(xAt(i + 1), yAt(values[i])); }
  ctx.lineTo(xAt(n), chartH);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.beginPath();
  for (let i = 0; i < n; i++) { const y = yAt(values[i]); i ? ctx.lineTo(xAt(i), y) : ctx.moveTo(xAt(i), y); ctx.lineTo(xAt(i + 1), y); }
  const lineGrad = ctx.createLinearGradient(0, 0, w, 0);
  lineGrad.addColorStop(0, '#ffffff');
  lineGrad.addColorStop(1, '#b8b8c0');
  ctx.strokeStyle = lineGrad;
  ctx.lineWidth = 1.6;
  ctx.shadowColor = 'rgba(255,255,255,0.45)';
  ctx.shadowBlur = 8;
  ctx.stroke();
  ctx.shadowBlur = 0;

  ctx.fillStyle = v('--muted');
  ctx.fillText('8', 4, yAt(8) + 12);
  ctx.fillText(`${HIGH_ENTROPY}`, w - 28, ty - 4);

  const by = chartH + gap;
  const pill = (x, y, ww, hh, r) => { ctx.beginPath(); ctx.roundRect ? ctx.roundRect(x, y, ww, hh, r) : ctx.rect(x, y, ww, hh); };
  ctx.fillStyle = 'rgba(255,255,255,0.05)';
  pill(0, by, w, bandH, bandH / 2); ctx.fill();
  sections.forEach((s, i) => {
    if (!s.size || s.off >= len) return;
    const x0 = (s.off / len) * w, x1 = (Math.min(len, s.off + s.size) / len) * w;
    const bw = Math.max(2, x1 - x0 - 2);
    const g = ctx.createLinearGradient(0, by, 0, by + bandH);
    g.addColorStop(0, '#ffffff');
    g.addColorStop(0.35, SECTION_COLORS[i % SECTION_COLORS.length]);
    g.addColorStop(1, SECTION_COLORS[i % SECTION_COLORS.length]);
    ctx.fillStyle = g;
    ctx.globalAlpha = 0.9;
    pill(x0 + 1, by, bw, bandH, Math.min(bandH / 2, bw / 2)); ctx.fill();
    ctx.globalAlpha = 1;
    const label = s.name || `#${i}`;
    if (bw > ctx.measureText(label).width + 12) {
      ctx.fillStyle = '#000';
      ctx.fillText(label, x0 + 7, by + 12);
    }
  });
  if (legendEl) legendEl.innerHTML = `<span class="legend-dot" style="background:#fff"></span>bits per byte${blockLabel ? `, ${blockLabel}` : ''}<span class="legend-dot" style="background:var(--warn)"></span>${HIGH_ENTROPY} threshold<span class="legend-dot" style="background:${SECTION_COLORS[0]}"></span>sections`;
}

function drawEntropy() {
  if (!state.blocks || $('#report').hidden) return;
  drawEntropyChart(canvas, state.blocks.values, state.model.sections, state.bytes.length, $('#entropyLegend'), `${fmtSize(state.blocks.blockSize)} blocks`);
}

function offsetFromEvent(e) {
  const r = canvas.getBoundingClientRect();
  const x = Math.min(Math.max(0, e.clientX - r.left), r.width - 1);
  const idx = Math.floor((x / r.width) * state.blocks.values.length);
  return { x, idx, off: idx * state.blocks.blockSize };
}

canvas.addEventListener('mousemove', (e) => {
  if (!state.blocks) return;
  const { x, idx, off } = offsetFromEvent(e);
  const sec = sectionAt(off);
  const val = state.blocks.values[idx] ?? 0;
  tip.hidden = false;
  tip.style.left = `${Math.min(Math.max(x, 90), canvas.clientWidth - 90)}px`;
  tip.style.top = '0px';
  tip.textContent = `${hx(off)}  ${val.toFixed(2)} bits${sec ? '  ' + (sec.name || 'section') : ''}`;
});
canvas.addEventListener('mouseleave', () => { tip.hidden = true; });
canvas.addEventListener('click', (e) => {
  if (!state.blocks) return;
  gotoHex(offsetFromEvent(e).off, 16);
});
new ResizeObserver(() => drawEntropy()).observe(canvas);

/* ---------- Sections ---------- */

function entropyBar(e) {
  if (e == null) return '<span class="muted">n/a</span>';
  const pct = (e / 8) * 100;
  const color = e > HIGH_ENTROPY ? 'var(--danger)' : e > 6.5 ? 'var(--warn)' : 'rgba(255,255,255,0.75)';
  return `<span class="ebar"><i style="width:${pct}%;background:${color}"></i></span>${e.toFixed(2)}`;
}

function renderSections() {
  const m = state.model;
  const panel = $('[data-panel="sections"]');
  if (!m.sections.length) {
    panel.innerHTML = '<div class="card empty-note">No sections for this file type.</div>';
    return;
  }
  const rows = m.sections.map((s, i) => `
    <tr>
      <td><span class="legend-dot" style="margin:0 8px 0 0;background:${SECTION_COLORS[i % SECTION_COLORS.length]}"></span><span class="mono">${esc(s.name || '(unnamed)')}</span></td>
      <td class="num">${hx(s.va)}</td>
      <td class="num">${hx(s.vsize)}</td>
      <td class="num">${hx(s.off)}</td>
      <td class="num">${hx(s.size)}</td>
      <td><span class="flag ${s.r ? 'on' : ''}" title="Readable">R</span><span class="flag w ${s.w ? 'on' : ''}" title="Writable">W</span><span class="flag x ${s.x ? 'on' : ''}" title="Executable">X</span></td>
      <td class="num">${entropyBar(s.entropy)}</td>
      <td>${s.size ? `<button class="link" data-hex="${s.off}" data-len="16">Hex</button>` : ''}
          ${s.x && m.disasm && s.size ? ` · <button class="link" data-dis="${s.va}">Disassemble</button>` : ''}</td>
    </tr>`).join('');
  panel.innerHTML = `
    <div class="table-wrap"><table>
      <thead><tr><th>Name</th><th>Virtual address</th><th>Virtual size</th><th>File offset</th><th>File size</th><th>Flags</th><th>Entropy</th><th><span class="visually-hidden">Actions</span></th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    ${m.overlay ? `<div class="card small">Overlay at <button class="link" data-hex="${m.overlay.off}" data-len="16">${hx(m.overlay.off)}</button>, ${fmtSize(m.overlay.size)}, entropy ${entropy(state.bytes, m.overlay.off).toFixed(2)}</div>` : ''}`;
}

/* ---------- Imports ---------- */

function renderImports() {
  const m = state.model;
  const panel = $('[data-panel="imports"]');
  if (!m.imports.length) {
    panel.innerHTML = '<div class="card empty-note">No imports found. Static binaries, packed files and non-executables often have none.</div>';
    return;
  }
  panel.innerHTML = `
    <div class="toolbar">
      <label class="search">${ICON_SEARCH}
        <span class="visually-hidden">Filter imports</span><input type="search" id="impFilter" placeholder="Filter by function or library" autocomplete="off"></label>
      <label class="select"><input type="checkbox" id="impFlagged"> Flagged only</label>
      <label class="select"><input type="checkbox" id="impUsed"> Called by code</label>
      <span class="muted small" id="impCount"></span>
    </div>
    <div class="libs" id="impLibs"></div>`;
  $('#impFilter').addEventListener('input', drawImports);
  $('#impFlagged').addEventListener('change', drawImports);
  $('#impUsed').addEventListener('change', drawImports);
  drawImports();
}

function drawImports() {
  const m = state.model;
  if (!$('#impLibs')) return;
  const q = $('#impFilter').value.trim().toLowerCase();
  const onlyFlagged = $('#impFlagged').checked;
  const onlyUsed = $('#impUsed').checked;
  const refs = state.code?.apiRefs;
  let shown = 0;
  const html = m.imports.map((lib) => {
    const libMatch = lib.lib.toLowerCase().includes(q);
    const fns = lib.fns.filter((f) => {
      const label = f.name || `#${f.ordinal}`;
      if (onlyFlagged && !flagApi(f.name)) return false;
      if (onlyUsed && !(refs?.get(apiKey(lib.lib, f))?.length)) return false;
      return !q || libMatch || label.toLowerCase().includes(q);
    });
    if (!fns.length) return '';
    shown += fns.length;
    const flaggedN = fns.filter((f) => flagApi(f.name)).length;
    const items = fns.map((f) => {
      const cat = flagApi(f.name);
      const key = apiKey(lib.lib, f);
      const n = refs?.get(key)?.length || 0;
      return `<li><span title="${esc(f.name || '')}">${f.name ? esc(f.name) : `<span class="muted">ordinal ${f.ordinal}</span>`}</span>${cat ? `<span class="chip warn">${cat}</span>` : ''}${n ? `<button class="refs" type="button" data-api="${esc(key)}">${n} ref${n > 1 ? 's' : ''}</button>` : ''}</li>`;
    }).join('');
    return `<details class="lib" open><summary>${esc(lib.lib)}${flaggedN ? ` <span class="chip warn">${flaggedN} flagged</span>` : ''}<span class="muted">${fns.length} functions</span></summary><ul class="fn-list">${items}</ul></details>`;
  }).join('');
  $('#impLibs').innerHTML = html || '<div class="card empty-note">No imports match this filter.</div>';
  $('#impCount').textContent = `${shown.toLocaleString()} shown`;
}

/* ---------- Exports / symbols ---------- */

function renderExports() {
  const m = state.model;
  const panel = $('[data-panel="exports"]');
  if (!m.exports.length) {
    panel.innerHTML = '<div class="card empty-note">No exported or defined symbols. Most .exe files export nothing, and stripped binaries keep only dynamic symbols.</div>';
    return;
  }
  const isElf = !m.format.startsWith('PE');
  panel.innerHTML = `
    <div class="toolbar">
      <label class="search">${ICON_SEARCH}
        <span class="visually-hidden">Filter symbols</span><input type="search" id="expFilter" placeholder="Filter symbols" autocomplete="off"></label>
      <span class="muted small" id="expCount"></span>
    </div>
    <div class="table-wrap" style="max-height:70vh;overflow:auto"><table>
      <thead><tr><th>Name</th><th>Address</th><th>${isElf ? 'Source' : 'Ordinal'}</th></tr></thead>
      <tbody id="expBody"></tbody></table></div>`;
  const LIMIT = 3000;
  const draw = () => {
    const q = $('#expFilter').value.trim().toLowerCase();
    const list = q ? m.exports.filter((e) => e.name.toLowerCase().includes(q)) : m.exports;
    $('#expBody').innerHTML = list.slice(0, LIMIT).map((e) => `
      <tr>
        <td class="mono">${e.name ? esc(e.name) : '<span class="muted">(no name)</span>'}</td>
        <td class="num">${e.forwarder ? `<span class="muted">forwarded to ${esc(e.forwarder)}</span>` : m.disasm && (isElf ? e.func : true) ? `<button class="link" data-dis="${e.va}">${hx(e.va)}</button>` : hx(e.va)}</td>
        <td class="num">${isElf ? e.source : e.ordinal}</td>
      </tr>`).join('');
    $('#expCount').textContent = list.length > LIMIT ? `showing ${LIMIT.toLocaleString()} of ${list.length.toLocaleString()}` : `${list.length.toLocaleString()} symbols`;
  };
  $('#expFilter').addEventListener('input', draw);
  draw();
}

/* ---------- Virtual list ---------- */

function virtualList(container, { count, rowHeight, render }) {
  container.innerHTML = '';
  const MAX_H = 1.2e7;
  const total = count * rowHeight;
  const H = Math.min(total, MAX_H);
  const spacer = document.createElement('div');
  spacer.style.height = `${H}px`;
  spacer.style.position = 'relative';
  container.append(spacer);
  let raf = 0;
  let flashIndex = -1;

  const virtTop = () => {
    const st = container.scrollTop, ch = container.clientHeight;
    return total > H ? (st / Math.max(1, H - ch)) * (total - ch) : st;
  };
  const update = () => {
    raf = 0;
    const st = container.scrollTop, ch = container.clientHeight || 600;
    const vt = virtTop();
    const first = Math.max(0, Math.floor(vt / rowHeight) - 8);
    const last = Math.min(count, Math.ceil((vt + ch) / rowHeight) + 8);
    const frag = document.createDocumentFragment();
    for (let i = first; i < last; i++) {
      const row = render(i);
      row.classList.add('vrow');
      row.style.top = `${st + (i * rowHeight - vt)}px`;
      row.style.height = `${rowHeight}px`;
      if (i === flashIndex) row.classList.add('flash');
      frag.append(row);
    }
    spacer.replaceChildren(frag);
  };
  container.onscroll = () => { if (!raf) raf = requestAnimationFrame(update); };
  if (!count) container.innerHTML = '<div class="empty-note">Nothing to show.</div>';
  else update();

  return {
    refresh: update,
    scrollToIndex(i, flash = false) {
      const ch = container.clientHeight || 600;
      const vt = Math.max(0, i * rowHeight - ch / 3);
      container.scrollTop = total > H ? (vt / Math.max(1, total - ch)) * (H - ch) : vt;
      flashIndex = flash ? i : -1;
      update();
      setTimeout(() => { flashIndex = -1; }, 1200);
    },
  };
}

/* ---------- Strings ---------- */

let strCat = '';
function setupStrings() {
  const cats = ['', 'url', 'ip', 'path', 'registry', 'module'];
  const counts = {};
  for (const s of state.strings) if (s.cat) counts[s.cat] = (counts[s.cat] || 0) + 1;
  strCat = '';
  $('#strCats').innerHTML = cats.map((c) => `<button class="chip" type="button" data-cat="${c}" aria-pressed="${c === ''}">${c || 'all'}${c ? ` · ${counts[c] || 0}` : ''}</button>`).join('');
  $('#strRefOnly').checked = false;
  $('#strRefOnly').disabled = !state.code;
  drawStrings();
}

function strRefs(s) {
  const c = state.code;
  if (!c) return null;
  const va = state.model.offToVa(s.off);
  return va == null ? null : c.xrefs.get(va) || null;
}

function drawStrings() {
  const qRaw = $('#strFilter').value.trim();
  const enc = $('#strEnc').value;
  const refOnly = $('#strRefOnly').checked && !!state.code;
  let re = null;
  if (qRaw) {
    try { re = new RegExp(qRaw, 'i'); } catch { re = new RegExp(qRaw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i'); }
  }
  const list = state.strings.filter((s) => (!enc || s.enc === enc) && (!strCat || s.cat === strCat) && (!re || re.test(s.text)) && (!refOnly || strRefs(s)));
  $('#strCount').textContent = `${list.length.toLocaleString()} of ${state.strings.length.toLocaleString()}`;
  state.strList = virtualList($('#strList'), {
    count: list.length,
    rowHeight: 26,
    render(i) {
      const s = list[i];
      const row = document.createElement('div');
      row.dataset.hex = s.off;
      row.dataset.len = s.len;
      const refs = strRefs(s);
      row.innerHTML = `<span class="s-off">${hxPad(s.off)}</span><span class="s-enc">${s.enc}</span><span class="s-cat">${s.cat ? `<span class="chip info">${s.cat}</span>` : ''}</span><span class="s-refs">${refs ? `<button class="refs" type="button" data-strref="${s.off}">${refs.length} ref${refs.length > 1 ? 's' : ''}</button>` : ''}</span><span class="s-text">${esc(s.text)}</span>`;
      return row;
    },
  });
}

let strTimer = 0;
$('#strFilter').addEventListener('input', () => { clearTimeout(strTimer); strTimer = setTimeout(drawStrings, 150); });
$('#strEnc').addEventListener('change', drawStrings);
$('#strRefOnly').addEventListener('change', drawStrings);
$('#strCats').addEventListener('click', (e) => {
  const b = e.target.closest('[data-cat]');
  if (!b) return;
  strCat = b.dataset.cat;
  $$('#strCats [data-cat]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  drawStrings();
});

/* ---------- Hex ---------- */

function setupHex() {
  const bytes = state.bytes;
  const rows = Math.ceil(bytes.length / 16);
  state.hexList = virtualList($('#hexList'), {
    count: rows,
    rowHeight: 22,
    render(i) {
      const off = i * 16;
      const sel = state.hexSel;
      let hexStr = '', asc = '';
      for (let j = 0; j < 16; j++) {
        if (j === 8) hexStr += ' ';
        const p = off + j;
        if (p >= bytes.length) { hexStr += '   '; continue; }
        const b = bytes[p];
        const t = hxPad(b, 2);
        const ch = b >= 0x20 && b < 0x7f ? esc(String.fromCharCode(b)) : '.';
        const inSel = sel && p >= sel.off && p < sel.off + sel.len;
        hexStr += (inSel ? `<mark>${t}</mark>` : b === 0 ? `<span class="z">${t}</span>` : t) + ' ';
        asc += inSel ? `<mark>${ch}</mark>` : ch;
      }
      const row = document.createElement('div');
      row.innerHTML = `<span class="h-off">${hxPad(off)}</span><span class="h-bytes">${hexStr}</span><span class="h-ascii">${asc}</span>`;
      return row;
    },
  });
  $('#hexInfo').textContent = `${fmtSize(bytes.length)}, ${rows.toLocaleString()} rows`;
}

function gotoHex(off, len = 1) {
  off = Math.max(0, Math.min(state.bytes.length - 1, off));
  state.hexSel = { off, len: Math.max(1, len) };
  selectTab('hex');
  scrollToPanel('hex');
  state.hexList.scrollToIndex(Math.floor(off / 16), true);
  const va = state.model.offToVa(off);
  const sec = sectionAt(off);
  $('#hexInfo').textContent = `Offset ${hx(off)}${va != null ? `, VA ${hx(va)}` : ''}${sec ? `, in ${sec.name || 'section'}` : ''}`;
}

function parseNum(str) {
  const s = str.trim().toLowerCase().replace(/^0x/, '').replace(/[`'_\s]/g, '');
  if (!/^[0-9a-f]+$/.test(s)) return NaN;
  return parseInt(s, 16);
}

$('#hexGoto').addEventListener('submit', (e) => {
  e.preventDefault();
  const n = parseNum($('#hexGotoInput').value);
  if (Number.isNaN(n)) { $('#hexInfo').textContent = 'Enter a hex offset like 0x400'; return; }
  gotoHex(n, 1);
});

/* ---------- Code analysis + Functions ---------- */

function maybeAutoAnalyze() {
  const m = state.model;
  if (!m.disasm) { renderFunctionsStatus(); return; }
  const size = codeSize(m, state.bytes);
  if (size && size <= AUTO_CODE_LIMIT) runCodeAnalysis();
  else renderFunctionsStatus();
}

async function runCodeAnalysis() {
  const m = state.model;
  if (!m.disasm || state.codeRun.running) return;
  const bytes = state.bytes;
  const ctrl = new AbortController();
  state.codeRun = { ctrl, running: true };
  renderFunctionsStatus();
  renderSummary();
  let eng;
  try {
    eng = await createDisassembler(m.disasm);
  } catch (err) {
    state.codeRun = { ctrl: null, running: false };
    $('#fnInfo').textContent = `Could not load the disassembler: ${err.message}`;
    return;
  }
  const t0 = performance.now();
  try {
    const res = await analyzeCode({
      model: m, bytes, engine: eng, signal: ctrl.signal,
      onProgress: (p, n) => {
        if (state.bytes !== bytes) return;
        $('#codeProgress i').style.width = `${(p * 100).toFixed(1)}%`;
        $('#fnInfo').textContent = `Analyzing code... ${Math.round(p * 100)}%, ${n.toLocaleString()} instructions`;
      },
    });
    if (state.bytes !== bytes) return;
    res.funcByVa = new Map(res.functions.map((f) => [f.va, f]));
    res.jumpTargets = new Set();
    for (const [va, refs] of res.xrefs) if (refs.some((x) => x % 4 === 1)) res.jumpTargets.add(va);
    res.ms = Math.round(performance.now() - t0);
    state.code = res;
  } catch (err) {
    if (err.name !== 'AbortError') { console.error(err); $('#fnInfo').textContent = `Code analysis failed: ${err.message}`; }
    return;
  } finally {
    try { eng.close(); } catch { /* already closed */ }
    if (state.codeRun.ctrl === ctrl) state.codeRun = { ctrl: null, running: false };
  }
  renderFunctionsStatus();
  drawFunctions();
  renderSummary();
  updateTabCounts();
  $('#strRefOnly').disabled = false;
  state.strList?.refresh();
  drawImports();
  if (state.dis.items.length) rerenderDisasm();
}

function renderFunctionsStatus() {
  const m = state.model;
  const info = $('#fnInfo'), btn = $('#codeRun'), prog = $('#codeProgress');
  prog.hidden = !state.codeRun.running;
  btn.hidden = true;
  if (!m.disasm) { info.textContent = `Function analysis needs x86, x64, ARM or ARM64 code. This file is ${m.format} / ${m.arch}.`; return; }
  if (state.codeRun.running) { info.textContent = 'Analyzing code...'; return; }
  if (state.code) {
    const c = state.code;
    info.textContent = `${c.functions.length.toLocaleString()} functions, ${c.insnCount.toLocaleString()} instructions in ${(c.ms / 1000).toFixed(1)}s (linear sweep)`;
    return;
  }
  btn.hidden = false;
  btn.textContent = `Analyze code (${fmtSize(codeSize(m, state.bytes))})`;
  info.textContent = 'Large binary: analysis runs on demand.';
}

function renderFunctions() {
  $('#fnFilter').value = '';
  renderFunctionsStatus();
  drawFunctions();
}

function drawFunctions() {
  const c = state.code;
  const box = $('#fnList');
  if (!c) {
    state.fnList = null;
    box.innerHTML = `<div class="empty-note">${state.model.disasm ? 'Functions appear here once the code is analyzed.' : 'No supported code in this file.'}</div>`;
    return;
  }
  const q = $('#fnFilter').value.trim().toLowerCase();
  const sort = $('#fnSort').value;
  let list = c.functions;
  if (q) list = list.filter((f) => funcName(f.va).toLowerCase().includes(q) || f.va.toString(16).includes(q.replace(/^0x/, '')));
  list = [...list];
  if (sort === 'xrefs') list.sort((a, b) => b.xrefs - a.xrefs || a.va - b.va);
  else if (sort === 'size') list.sort((a, b) => b.size - a.size);
  else if (sort === 'name') list.sort((a, b) => funcName(a.va).localeCompare(funcName(b.va)));
  const w = state.model.bits === 64 ? 12 : 8;
  state.fnList = virtualList(box, {
    count: list.length + 1,
    rowHeight: 30,
    render(i) {
      const row = document.createElement('div');
      if (i === 0) {
        row.className = 'fn-head';
        row.innerHTML = '<span class="f-addr">Address</span><span class="f-name">Name</span><span class="f-size">Size</span><span class="f-x">Called by</span><span class="f-c">Calls</span>';
        return row;
      }
      const f = list[i - 1];
      const user = !!state.notes.name(f.va);
      row.dataset.dis = f.va;
      row.innerHTML = `<span class="f-addr">${hxPad(f.va, w)}</span><span class="f-name${user ? ' user' : ''}${f.thunk ? ' thunk' : ''}">${esc(funcName(f.va))}</span><span class="f-size">${f.size ? f.size.toLocaleString() : ''}</span><span class="f-x">${f.xrefs ? `<button class="refs" type="button" data-xref="${f.va}">${f.xrefs}</button>` : '<span class="muted">0</span>'}</span><span class="f-c">${f.calls || ''}</span>`;
      return row;
    },
  });
}

let fnTimer = 0;
$('#fnFilter').addEventListener('input', () => { clearTimeout(fnTimer); fnTimer = setTimeout(drawFunctions, 120); });
$('#fnSort').addEventListener('change', drawFunctions);
$('#codeRun').addEventListener('click', runCodeAnalysis);

/* ---------- Resources ---------- */

function renderResources() {
  const panel = $('[data-panel="resources"]');
  const r = state.resources;
  if (!r?.items.length) { panel.innerHTML = ''; return; }
  const v = r.version, mf = r.manifest;
  const verCard = v ? `<div class="card"><div class="card-head"><h2>Version info</h2>${state.iconUrl ? `<img class="res-icon" src="${state.iconUrl}" alt="Application icon">` : ''}</div>
    <dl class="facts">${v.fileVersion ? `<dt>File version</dt><dd>${esc(v.fileVersion)}</dd>` : ''}${v.productVersion ? `<dt>Product version</dt><dd>${esc(v.productVersion)}</dd>` : ''}
    ${v.strings.map(([k, val]) => `<dt>${esc(k)}</dt><dd>${esc(val)}</dd>`).join('')}</dl></div>` : '';
  const mfCard = mf ? `<div class="card"><div class="card-head"><h2>Manifest</h2></div>
    <div class="chips">${mf.level ? `<span class="chip ${mf.level === 'requireAdministrator' ? 'warn' : ''}">runs as ${esc(mf.level)}</span>` : ''}${mf.uiAccess ? '<span class="chip warn">uiAccess</span>' : ''}${mf.dpi ? `<span class="chip">DPI aware: ${esc(mf.dpi)}</span>` : ''}${mf.os ? `<span class="chip">${mf.os} supported OS ids</span>` : ''}</div>
    <details class="mf"><summary class="link small">Show XML</summary><pre>${esc(mf.text)}</pre></details></div>` : '';
  const embedded = r.items.filter((x) => x.magic?.level === 'bad');
  const rows = r.items.map((x, i) => `<tr>
      <td>${esc(x.typeName)}</td><td class="mono">${esc(String(x.name))}</td><td class="num">${x.lang}</td>
      <td class="num">${x.size.toLocaleString()}</td>
      <td class="num">${x.valid ? entropyBar(x.entropy) : '<span class="muted">outside file</span>'}</td>
      <td>${x.magic ? `<span class="chip ${x.magic.level}">${esc(x.magic.name)}</span>` : ''}</td>
      <td>${x.valid ? `<button class="link" data-hex="${x.off}" data-len="${Math.min(x.size, 256)}">Hex</button> · <button class="link" data-res="${i}">Save</button>` : ''}</td></tr>`).join('');
  panel.innerHTML = `
    ${embedded.length ? `<div class="card"><div class="verdict bad"><b>Embedded executable in resources</b><span>${embedded.length} resource${embedded.length > 1 ? 's start' : ' starts'} with an executable header. Droppers often hide a second payload this way.</span></div></div>` : ''}
    ${verCard || mfCard ? `<div class="grid-2">${verCard}${mfCard}</div>` : ''}
    <div class="table-wrap"><table>
      <thead><tr><th>Type</th><th>Name</th><th>Lang</th><th>Size</th><th>Entropy</th><th>Content</th><th><span class="visually-hidden">Actions</span></th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
}

function saveResource(i) {
  const x = state.resources.items[i];
  const ext = x.magic?.name.startsWith('PNG') ? 'png' : x.magic?.name.startsWith('PE') ? 'bin' : x.type === 24 ? 'xml' : 'bin';
  download(`${state.name}_${x.typeName}_${x.name}.${ext}`.replace(/[^\w.-]+/g, '_'), state.bytes.slice(x.off, x.off + x.size), 'application/octet-stream');
}

/* ---------- Disassembly ---------- */

function resetDisasm() {
  const d = state.dis;
  if (d.engine) { try { d.engine.close(); } catch { /* closed */ } }
  Object.assign(d, { engine: null, enginePromise: null, history: [], start: null, next: null, items: [], sel: null });
  $('#disList').innerHTML = '';
  $('#disMore').hidden = true;
  $('#disBack').disabled = true;
}

async function getEngine() {
  const d = state.dis;
  if (d.engine) return d.engine;
  if (!d.enginePromise) d.enginePromise = createDisassembler(state.model.disasm);
  try {
    d.engine = await d.enginePromise;
  } catch (err) {
    d.enginePromise = null;
    throw err;
  }
  return d.engine;
}

function defaultDisasmVa() {
  const m = state.model;
  if (m.entry != null && m.vaToOff(m.entry) >= 0) return m.entry;
  const code = m.sections.find((s) => s.x && s.size);
  return code ? code.va : null;
}

async function openDisasm(va, push = true, focus = null) {
  const m = state.model;
  const list = $('#disList');
  if (state.tab !== 'disasm') selectTab('disasm', false);
  if (!m.disasm) {
    list.innerHTML = `<div class="empty-note">Disassembly is available for x86, x64, ARM and ARM64 code. This file is ${esc(m.format)} / ${esc(m.arch)}.</div>`;
    $('#disInfo').textContent = '';
    return;
  }
  if (va == null) {
    list.innerHTML = '<div class="empty-note">No entry point or code section found.</div>';
    return;
  }
  if (m.vaToOff(va) < 0) {
    $('#disInfo').textContent = `${hx(va)} is not backed by file data`;
    return;
  }
  const d = state.dis;
  if (push && d.start != null && d.start !== va) d.history.push(d.start);
  $('#disBack').disabled = !d.history.length;
  d.start = va;
  d.items = [];
  d.sel = focus ?? null;
  if (!d.engine) list.innerHTML = '<div class="empty-note"><span class="spinner" style="display:inline-block;vertical-align:middle;margin-right:8px"></span>Loading Capstone...</div>';
  $('#disGotoInput').value = hx(va);
  try {
    await getEngine();
  } catch (err) {
    console.error(err);
    list.innerHTML = `<div class="error-box">Could not load the disassembler: ${esc(err.message)}</div>`;
    return;
  }
  list.innerHTML = '';
  appendDisasm(va, 300);
  for (let guard = 0; focus != null && d.next != null && d.next <= focus && guard < 40; guard++) appendDisasm(d.next, 300);
  if (focus != null) {
    const row = list.querySelector(`.d-row[data-va="${focus}"]`);
    if (row) { row.scrollIntoView({ block: 'center', behavior: 'instant' }); return; }
  }
  scrollToPanel('disasm');
}

function appendDisasm(va, count) {
  const m = state.model;
  const d = state.dis;
  const eng = d.engine;
  const step = eng.family === 'x86' ? 1 : 4;
  const out = [];
  let cur = va, badRun = 0;
  // Capstone stops at the first undecodable bytes: show them as (bad), step
  // over them and keep going, so data inside code does not end the listing.
  while (out.length < count && badRun < 16) {
    const off = m.vaToOff(cur);
    if (off < 0) break;
    const slice = state.bytes.subarray(off, Math.min(state.bytes.length, off + Math.min(0x1800, (count - out.length) * 16)));
    if (!slice.length) break;
    let insns = [];
    try { insns = eng.disasm(slice, cur, count - out.length); } catch { insns = []; }
    if (!insns.length) {
      out.push({ address: cur, size: step, bytes: [...state.bytes.subarray(off, off + step)], bad: true });
      cur += step;
      badRun++;
      continue;
    }
    badRun = 0;
    out.push(...insns);
    const last = insns[insns.length - 1];
    cur = last.address + last.size;
  }
  if (!out.length) return;
  d.items.push(...out);
  $('#disList').insertAdjacentHTML('beforeend', renderItems(out));
  d.next = cur;
  $('#disMore').hidden = m.vaToOff(d.next) < 0;
  updateDisInfo();
}

function updateDisInfo() {
  const m = state.model, d = state.dis;
  const sec = m.sections.find((s) => d.start >= s.va && d.start < s.va + Math.max(s.vsize, s.size));
  const f = containingFunc(d.start);
  $('#disInfo').textContent = `${m.arch}${sec ? `, ${sec.name}` : ''}${f ? `, in ${funcName(f.va)}` : ''}, ${d.items.length} instructions`;
}

function rerenderDisasm() {
  const list = $('#disList');
  if (!state.dis.items.length) return;
  list.innerHTML = renderItems(state.dis.items);
  updateDisInfo();
}

function renderItems(insns) {
  const m = state.model;
  const eng = state.dis.engine;
  const w = m.bits === 64 ? 12 : 8;
  const html = [];
  const isPad = (i) => !i.bad && (i.mnemonic === 'int3' || (i.mnemonic === 'nop' && eng.family === 'x86'));
  for (let k = 0; k < insns.length; k++) {
    const insn = insns[k];
    if (insn.bad) {
      html.push(`<div class="d-row" data-va="${insn.address}"><span class="d-addr">${hxPad(insn.address, w)}</span><span class="d-bytes">${insn.bytes.map((b) => hxPad(b, 2)).join(' ')}</span><span class="d-mnem ret">(bad)</span><span class="d-cmt">; not a valid instruction, probably data</span></div>`);
      continue;
    }
    const label = labelAt(insn.address);
    if (label) {
      const nrefs = state.code?.xrefs.get(insn.address)?.length || 0;
      const isFn = !!fnAt(insn.address) || m.labels.has(insn.address) || !!state.notes.name(insn.address);
      html.push(`<div class="d-label${isFn ? ' fn' : ''}${state.notes.name(insn.address) ? ' user' : ''}" data-va="${insn.address}"><span>${esc(label)}</span>${nrefs ? `<button class="refs" type="button" data-xref="${insn.address}">${nrefs} xref${nrefs > 1 ? 's' : ''}</button>` : ''}</div>`);
    }
    if (isPad(insn) && !label) {
      let j = k;
      while (j + 1 < insns.length && insns[j + 1].mnemonic === insn.mnemonic && !insns[j + 1].bad && !labelAt(insns[j + 1].address)) j++;
      if (j - k >= 2) {
        html.push(`<div class="d-row d-pad" data-va="${insn.address}"><span class="d-addr">${hxPad(insn.address, w)}</span><span class="d-bytes"></span><span class="d-mnem">${insn.mnemonic}</span><span class="d-cmt">; ${j - k + 1} bytes of alignment padding</span></div>`);
        k = j;
        continue;
      }
    }
    html.push(renderInsn(insn));
    if (isUnconditionalEnd(eng.family, insn.mnemonic)) html.push('<div class="d-sep"></div>');
  }
  return html.join('');
}

// Comment and link for an instruction's operand: API name, label or string.
function insnNote(insn) {
  const m = state.model;
  const fam = state.dis.engine.family;
  const kind = classify(fam, insn.mnemonic);
  const target = operandTarget(fam, insn);
  let comment = '', cmtClass = '';
  let linkVa = null;

  if (target) {
    const api = m.iat.get(target.va) || fnAt(target.va)?.thunk;
    const lbl = labelAt(target.va);
    const auto = lbl === `sub_${target.va.toString(16)}` || lbl === `loc_${target.va.toString(16)}`;
    if (api) { comment = api; cmtClass = 'api'; }
    else if (lbl && !auto) comment = lbl;
    const toff = m.vaToOff(target.va);
    // Branch targets are code: bytes like "push r15; push r14" read as ASCII and
    // would show up as a bogus string, so only data references get string hints.
    if (!comment && toff >= 0 && kind !== 'call' && kind !== 'jump') {
      const s = state.stringByOff.get(toff);
      if (s) comment = `"${s.text.length > 60 ? s.text.slice(0, 60) + '...' : s.text}"`;
    }
    if ((kind === 'call' || kind === 'jump') && target.direct && toff >= 0) linkVa = target.va;
  }
  return { kind, comment, cmtClass, linkVa };
}

function renderInsn(insn) {
  const m = state.model;
  const { kind, comment, cmtClass, linkVa } = insnNote(insn);
  const ops = esc(insn.opStr).replace(/(#?)0x([0-9a-f]+)/gi, (all, hash, digits) => {
    const n = parseInt(digits, 16);
    if (linkVa != null && n === linkVa) return `${hash}<button class="link" data-dis="${n}">0x${digits}</button>`;
    return `<span class="num">${all}</span>`;
  });
  const bytesHex = [...insn.bytes].slice(0, 10).map((b) => hxPad(b, 2)).join(' ') + (insn.bytes.length > 10 ? ' ..' : '');
  const cls = `${insn.address === state.dis.start ? ' current' : ''}${insn.address === state.dis.sel ? ' sel' : ''}`;
  const user = state.notes.comment(insn.address);
  return `<div class="d-row${cls}" data-va="${insn.address}"><span class="d-addr">${hxPad(insn.address, m.bits === 64 ? 12 : 8)}</span><span class="d-bytes">${bytesHex}</span><span class="d-mnem ${kind}">${esc(insn.mnemonic)}</span><span class="d-ops">${ops}${comment ? `  <span class="d-cmt ${cmtClass}">; ${esc(comment)}</span>` : ''}${user ? `  <span class="d-cmt user">; ${esc(user)}</span>` : ''}</span></div>`;
}

function selectDisRow(va) {
  state.dis.sel = va;
  $$('#disList .d-row.sel').forEach((r) => r.classList.remove('sel'));
  $(`#disList .d-row[data-va="${va}"]`)?.classList.add('sel');
}

async function disGoto(text) {
  const t = text.trim();
  let n = parseNum(t);
  if (Number.isNaN(n) || (!/^0x/i.test(t) && /[g-z_]/i.test(t))) {
    const q = t.toLowerCase();
    const hit = state.code?.functions.find((f) => funcName(f.va).toLowerCase() === q)
      || [...state.model.labels].find(([, name]) => name.toLowerCase() === q);
    n = hit ? (Array.isArray(hit) ? hit[0] : hit.va) : NaN;
  }
  if (Number.isNaN(n)) { $('#disInfo').textContent = 'Enter a hex address or a function name'; return; }
  openDisasm(n);
}

$('#disList').addEventListener('click', (e) => {
  if (e.target.closest('button')) return;
  const row = e.target.closest('.d-row[data-va], .d-label[data-va]');
  if (row) selectDisRow(Number(row.dataset.va));
  highlightToken($('#disList'), wordAt(e));
});
$('#disList').addEventListener('dblclick', (e) => {
  const lbl = e.target.closest('.d-label[data-va]');
  if (lbl) editName(Number(lbl.dataset.va), lbl);
});
$('#disGoto').addEventListener('submit', (e) => { e.preventDefault(); disGoto($('#disGotoInput').value); });
$('#disBack').addEventListener('click', () => {
  const prev = state.dis.history.pop();
  if (prev != null) openDisasm(prev, false);
});
$('#disEntry').addEventListener('click', () => openDisasm(defaultDisasmVa()));
$('#disMore').addEventListener('click', () => { if (state.dis.next != null) appendDisasm(state.dis.next, 300); });
$('#disGraph').addEventListener('click', () => openGraph(defaultGraphVa()));

/* ---------- Token highlight (click a register or name to see every use) ---------- */

function wordAt(e) {
  let node, off;
  if (document.caretPositionFromPoint) { const p = document.caretPositionFromPoint(e.clientX, e.clientY); node = p?.offsetNode; off = p?.offset; }
  else if (document.caretRangeFromPoint) { const r = document.caretRangeFromPoint(e.clientX, e.clientY); node = r?.startContainer; off = r?.startOffset; }
  if (!node || node.nodeType !== 3 || !node.parentElement?.closest('.d-mnem, .d-ops, .d-label')) return '';
  const t = node.data, w = /[A-Za-z0-9_.$@?]/;
  let a = off, b = off;
  while (a > 0 && w.test(t[a - 1])) a--;
  while (b < t.length && w.test(t[b])) b++;
  return t.slice(a, b);
}

function highlightToken(root, word) {
  if (!window.Highlight || !CSS.highlights) return;
  if (!word || word.length < 2) { CSS.highlights.delete('binkeep-tok'); return; }
  const ranges = [];
  const isW = (c) => c != null && /[A-Za-z0-9_.$@?]/.test(c);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n && ranges.length < 3000; n = walker.nextNode()) {
    if (!n.parentElement.closest('.d-mnem, .d-ops, .d-label')) continue;
    const t = n.data;
    for (let i = t.indexOf(word); i >= 0; i = t.indexOf(word, i + word.length)) {
      if (isW(t[i - 1]) || isW(t[i + word.length])) continue;
      const r = new Range();
      r.setStart(n, i);
      r.setEnd(n, i + word.length);
      ranges.push(r);
    }
  }
  CSS.highlights.set('binkeep-tok', new Highlight(...ranges));
}

/* ---------- Control flow graph ---------- */

const CFG_MIN_K = 0.08, CFG_MAX_K = 2.5;

function resetCfg() {
  const g = state.cfg;
  Object.assign(g, { graph: null, layout: null, sel: null, busy: 0, history: [] });
  $('#cfgCanvas').innerHTML = '';
  $('#cfgInfo').textContent = '';
  $('#cfgBack').disabled = true;
}

function defaultGraphVa() {
  const d = state.dis;
  return d.sel ?? d.start ?? defaultDisasmVa();
}

function cfgNote(html) {
  state.cfg.graph = null;
  state.cfg.layout = null;
  $('#cfgCanvas').innerHTML = '';
  $('#cfgInfo').innerHTML = html;
}

async function openGraph(va, push = true) {
  const m = state.model;
  const g = state.cfg;
  if (state.tab !== 'graph') selectTab('graph', false);
  if (!m.disasm) { cfgNote(`The graph view needs x86, x64, ARM or ARM64 code. This file is ${esc(m.format)} / ${esc(m.arch)}.`); return; }
  if (va == null || m.vaToOff(va) < 0) { $('#cfgInfo').textContent = va == null ? 'No code found.' : `${hx(va)} is not backed by file data`; return; }
  const f = containingFunc(va);
  const start = f ? f.va : va;
  const end = f && f.size ? f.va + f.size : null;
  const token = ++g.busy;
  $('#cfgInfo').textContent = 'Building graph...';
  let eng;
  try {
    eng = await getEngine();
  } catch (err) {
    console.error(err);
    cfgNote(`Could not load the disassembler: ${esc(err.message)}`);
    return;
  }
  if (token !== g.busy) return;
  const cfg = buildCfg({
    engine: eng, model: m, bytes: state.bytes, start, end,
    isFuncStart: (t) => !!fnAt(t) || m.labels.has(t),
  });
  if (push && g.graph && g.graph.start !== start) g.history.push(g.graph.start);
  $('#cfgBack').disabled = !g.history.length;
  g.graph = { start, cfg, bounded: !!f };
  g.sel = va !== start ? va : null;
  $('#cfgGotoInput').value = hx(start);
  renderCfg(va);
  g.busy = 0;
  scrollToPanel('graph');
}

function cfgRow(insn, blockOf) {
  const m = state.model;
  const { kind, comment, cmtClass, linkVa } = insnNote(insn);
  const ops = esc(insn.opStr).replace(/(#?)0x([0-9a-f]+)/gi, (all, hash, digits) => {
    const n = parseInt(digits, 16);
    if (linkVa != null && n === linkVa) {
      if (kind === 'jump' && blockOf.has(n)) return `${hash}<button class="link" data-cfgblock="${blockOf.get(n)}">${esc(labelAt(n) || `loc_${digits}`)}</button>`;
      return `${hash}<button class="link" data-cfg="${n}">${esc(funcName(n))}</button>`;
    }
    return `<span class="num">${all}</span>`;
  });
  const cmt = comment.length > 56 ? comment.slice(0, 56) + '...' : comment;
  const user = state.notes.comment(insn.address);
  const sel = insn.address === state.cfg.sel ? ' sel' : '';
  return `<div class="cfg-row${sel}" data-va="${insn.address}"><span class="d-addr">${insn.address.toString(16).padStart(m.bits === 64 ? 9 : 8, '0')}</span>  <span class="d-mnem ${kind}">${esc(insn.mnemonic.padEnd(7))}</span> <span class="d-ops">${ops}${cmt ? `  <span class="d-cmt ${cmtClass}">; ${esc(cmt)}</span>` : ''}${user ? `  <span class="d-cmt user">; ${esc(user)}</span>` : ''}</span></div>`;
}

function renderCfg(focusVa, keepView = false) {
  const g = state.cfg;
  const { cfg, start, bounded } = g.graph;
  const canvas = $('#cfgCanvas');
  const blockOf = new Map(cfg.blocks.map((b) => [b.start, b.id]));
  const nodes = cfg.blocks.map((b) => {
    const label = b.id === 0 ? funcName(b.start) : (labelAt(b.start) || `loc_${b.start.toString(16)}`);
    const tag = b.id === 0 ? 'entry' : !b.succ.length ? (b.exit != null ? 'tail' : 'exit') : `${b.insns.length}`;
    return `<div class="cfg-node${b.id === 0 ? ' entry' : ''}${!b.succ.length ? ' leaf' : ''}" data-block="${b.id}" style="--d:${Math.min(b.id, 40)}"><div class="cfg-head"><span class="cfg-name">${esc(label)}</span><span class="cfg-tag">${tag}</span></div><div class="cfg-body">${b.insns.map((i) => cfgRow(i, blockOf)).join('')}</div></div>`;
  });
  canvas.innerHTML = nodes.join('');
  const els = $$('.cfg-node', canvas);
  const layout = layoutCfg(cfg.blocks, els.map((el) => ({ w: el.offsetWidth, h: el.offsetHeight })));
  g.layout = layout;
  els.forEach((el, i) => { el.style.left = `${layout.nodes[i].x}px`; el.style.top = `${layout.nodes[i].y}px`; });
  const marker = (k) => `<marker id="cfg-arrow-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,1 L9,5 L0,9 z" class="e-${k}"/></marker>`;
  canvas.insertAdjacentHTML('afterbegin', `<svg class="cfg-edges" style="width:${layout.width}px;height:${layout.height}px" viewBox="0 0 ${layout.width} ${layout.height}" aria-hidden="true"><defs>${['true', 'false', 'jmp'].map(marker).join('')}</defs>${layout.edges.map((e) => `<path class="e-${e.kind}${e.back ? ' back' : ''}" data-from="${e.from}" data-to="${e.to}" d="${e.d}" marker-end="url(#cfg-arrow-${e.kind})"/>`).join('')}</svg>`);
  canvas.style.width = `${layout.width}px`;
  canvas.style.height = `${layout.height}px`;
  const loops = layout.edges.filter((e) => e.back).length;
  $('#cfgInfo').textContent = `${funcName(start)}: ${cfg.blocks.length} block${cfg.blocks.length === 1 ? '' : 's'}, ${cfg.insnCount.toLocaleString()} instructions${loops ? `, ${loops} loop${loops > 1 ? 's' : ''}` : ''}${cfg.truncated ? ', truncated (very large function)' : ''}${!bounded && state.model.disasm ? '. Function bounds are a guess until code analysis runs.' : ''}`;
  canvas.classList.toggle('enter', !keepView);
  if (keepView) { applyCfgView(); return; }
  const focus = focusVa != null ? cfg.blocks.find((b) => b.insns.some((i) => i.address === focusVa)) : null;
  initialCfgView(focus ? focus.id : 0);
}

function applyCfgView() {
  const v = state.cfg.view;
  $('#cfgCanvas').style.transform = `translate(${v.x}px, ${v.y}px) scale(${v.k})`;
  $('#cfgZoom').textContent = `${Math.round(v.k * 100)}%`;
  // The dot grid moves and scales with the graph.
  let gs = 22 * v.k;
  while (gs < 11) gs *= 2;
  const box = $('#cfgView');
  box.style.setProperty('--gs', `${gs}px`);
  box.style.setProperty('--gx', `${v.x % gs}px`);
  box.style.setProperty('--gy', `${v.y % gs}px`);
  drawMinimap();
}

const MINI_W = 168, MINI_H = 120;
function miniScale() {
  const L = state.cfg.layout;
  return Math.min((MINI_W - 16) / L.width, (MINI_H - 16) / L.height);
}

function drawMinimap() {
  const cv = $('#cfgMini'), L = state.cfg.layout;
  cv.hidden = !L || L.nodes.length < 2;
  if (cv.hidden) return;
  const dpr = window.devicePixelRatio || 1;
  if (cv.width !== MINI_W * dpr) { cv.width = MINI_W * dpr; cv.height = MINI_H * dpr; }
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, MINI_W, MINI_H);
  const s = miniScale();
  const ox = (MINI_W - L.width * s) / 2, oy = (MINI_H - L.height * s) / 2;
  L.nodes.forEach((n, i) => {
    ctx.fillStyle = i === 0 ? 'rgba(255,255,255,0.85)' : 'rgba(255,255,255,0.32)';
    ctx.fillRect(ox + n.x * s, oy + n.y * s, Math.max(1.5, n.w * s), Math.max(1.5, n.h * s));
  });
  const v = state.cfg.view, box = $('#cfgView');
  const rx = ox + (-v.x / v.k) * s, ry = oy + (-v.y / v.k) * s;
  const rw = (box.clientWidth / v.k) * s, rh = (box.clientHeight / v.k) * s;
  ctx.fillStyle = 'rgba(255,255,255,0.06)';
  ctx.fillRect(rx, ry, rw, rh);
  ctx.strokeStyle = 'rgba(255,255,255,0.9)';
  ctx.lineWidth = 1;
  ctx.strokeRect(Math.round(rx) + 0.5, Math.round(ry) + 0.5, Math.round(rw), Math.round(rh));
}

// Center the main view on a point picked in the minimap.
function miniJump(e) {
  const cv = $('#cfgMini'), L = state.cfg.layout, box = $('#cfgView');
  const r = cv.getBoundingClientRect(), s = miniScale();
  const gx = (e.clientX - r.left - (MINI_W - L.width * s) / 2) / s;
  const gy = (e.clientY - r.top - (MINI_H - L.height * s) / 2) / s;
  const v = state.cfg.view;
  v.x = box.clientWidth / 2 - gx * v.k;
  v.y = box.clientHeight / 2 - gy * v.k;
  applyCfgView();
}

// Hovering a block lights up its edges and neighbours and dims the rest.
function hotBlock(id) {
  const canvas = $('#cfgCanvas');
  $$('.hot', canvas).forEach((el) => el.classList.remove('hot', 'near'));
  canvas.classList.toggle('focus', id != null);
  if (id == null) return;
  $(`.cfg-node[data-block="${id}"]`, canvas)?.classList.add('hot');
  $$(`path[data-from="${id}"], path[data-to="${id}"]`, canvas).forEach((p) => {
    p.classList.add('hot');
    const other = p.dataset.from === String(id) ? p.dataset.to : p.dataset.from;
    $(`.cfg-node[data-block="${other}"]`, canvas)?.classList.add('hot', 'near');
  });
}

function initialCfgView(blockId) {
  const g = state.cfg, L = g.layout, box = $('#cfgView');
  const vw = box.clientWidth, vh = box.clientHeight;
  const k = Math.max(0.55, Math.min(1, (vw - 40) / L.width));
  const n = L.nodes[blockId];
  const x = L.width * k <= vw ? (vw - L.width * k) / 2 : vw / 2 - (n.x + n.w / 2) * k;
  const y = blockId === 0 ? 24 - n.y * k : vh / 2 - (n.y + Math.min(n.h, vh / k / 2) / 2) * k;
  g.view = { x, y, k };
  applyCfgView();
  if (blockId) flashBlock(blockId);
}

function fitCfg() {
  const g = state.cfg, L = g.layout, box = $('#cfgView');
  if (!L) return;
  const vw = box.clientWidth, vh = box.clientHeight;
  const k = Math.max(CFG_MIN_K, Math.min(1.2, (vw - 32) / L.width, (vh - 32) / L.height));
  g.view = { x: (vw - L.width * k) / 2, y: Math.max(16, (vh - L.height * k) / 2), k };
  applyCfgView();
}

function zoomCfg(factor, cx, cy) {
  const v = state.cfg.view, box = $('#cfgView');
  if (cx == null) { cx = box.clientWidth / 2; cy = box.clientHeight / 2; }
  const k = Math.max(CFG_MIN_K, Math.min(CFG_MAX_K, v.k * factor));
  v.x = cx - (cx - v.x) * (k / v.k);
  v.y = cy - (cy - v.y) * (k / v.k);
  v.k = k;
  applyCfgView();
}

function flashBlock(id) {
  const el = $(`#cfgCanvas .cfg-node[data-block="${id}"]`);
  if (!el) return;
  el.classList.remove('flash');
  void el.offsetWidth;
  el.classList.add('flash');
}

function centerBlock(id) {
  const g = state.cfg, n = g.layout?.nodes[id], box = $('#cfgView');
  if (!n) return;
  const v = g.view;
  v.x = box.clientWidth / 2 - (n.x + n.w / 2) * v.k;
  v.y = Math.min(box.clientHeight / 2 - (n.y + n.h / 2) * v.k, 40 - n.y * v.k);
  $('#cfgCanvas').classList.add('glide');
  applyCfgView();
  setTimeout(() => $('#cfgCanvas').classList.remove('glide'), 420);
  flashBlock(id);
}

function selectCfgRow(va) {
  state.cfg.sel = va;
  $$('#cfgCanvas .cfg-row.sel').forEach((r) => r.classList.remove('sel'));
  $(`#cfgCanvas .cfg-row[data-va="${va}"]`)?.classList.add('sel');
}

function graphToListing() {
  const g = state.cfg;
  if (!g.graph) { selectTab('disasm'); return; }
  openDisasm(g.graph.start, true, g.sel ?? g.graph.start);
}

{
  const box = $('#cfgView');
  let drag = null, justDragged = false;
  box.addEventListener('pointerdown', (e) => {
    if (e.button !== 0 || e.target.closest('button, .cfg-mini')) return;
    drag = { id: e.pointerId, sx: e.clientX, sy: e.clientY, x: state.cfg.view.x, y: state.cfg.view.y, moved: false };
  });
  box.addEventListener('pointermove', (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
    if (!drag.moved && Math.hypot(dx, dy) < 4) return;
    if (!drag.moved) { drag.moved = true; box.setPointerCapture(e.pointerId); box.classList.add('dragging'); }
    state.cfg.view.x = drag.x + dx;
    state.cfg.view.y = drag.y + dy;
    applyCfgView();
  });
  const end = (e) => {
    if (!drag || e.pointerId !== drag.id) return;
    if (drag.moved) {
      box.classList.remove('dragging');
      // The click that ends a drag should not select a row.
      justDragged = true;
      setTimeout(() => { justDragged = false; }, 0);
    }
    drag = null;
  };
  box.addEventListener('pointerup', end);
  box.addEventListener('pointercancel', end);
  box.addEventListener('wheel', (e) => {
    if (!state.cfg.layout) return;
    e.preventDefault();
    const r = box.getBoundingClientRect();
    if (e.ctrlKey || e.metaKey) { zoomCfg(Math.exp(-e.deltaY * (e.deltaMode ? 0.05 : 0.0025)), e.clientX - r.left, e.clientY - r.top); return; }
    const mult = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? box.clientHeight : 1;
    const v = state.cfg.view;
    if (e.shiftKey && !e.deltaX) v.x -= e.deltaY * mult;
    else { v.x -= e.deltaX * mult; v.y -= e.deltaY * mult; }
    applyCfgView();
  }, { passive: false });
  box.addEventListener('click', (e) => {
    if (justDragged) return;
    const jb = e.target.closest('[data-cfgblock]');
    if (jb) { e.stopPropagation(); centerBlock(Number(jb.dataset.cfgblock)); return; }
    const fn = e.target.closest('[data-cfg]');
    if (fn) { e.stopPropagation(); openGraph(Number(fn.dataset.cfg)); return; }
    if (e.target.closest('button')) return;
    const row = e.target.closest('.cfg-row[data-va]');
    if (row) selectCfgRow(Number(row.dataset.va));
    highlightToken($('#cfgCanvas'), wordAt(e));
  });
  box.addEventListener('pointerover', (e) => {
    if (drag?.moved) return;
    const n = e.target.closest('.cfg-node');
    hotBlock(n ? Number(n.dataset.block) : null);
  });
  box.addEventListener('pointerleave', () => hotBlock(null));
  const mini = $('#cfgMini');
  mini.addEventListener('pointerdown', (e) => {
    e.stopPropagation();
    mini.setPointerCapture(e.pointerId);
    miniJump(e);
    const move = (ev) => miniJump(ev);
    mini.addEventListener('pointermove', move);
    mini.addEventListener('pointerup', () => mini.removeEventListener('pointermove', move), { once: true });
  });
  mini.addEventListener('click', (e) => e.stopPropagation());
  mini.addEventListener('wheel', (e) => e.stopPropagation());
  box.addEventListener('dblclick', (e) => {
    const row = e.target.closest('.cfg-row[data-va]');
    if (!row || e.target.closest('button')) return;
    state.cfg.sel = Number(row.dataset.va);
    graphToListing();
  });
  box.addEventListener('keydown', (e) => {
    if (e.key === '+' || e.key === '=') { e.preventDefault(); zoomCfg(1.2); }
    else if (e.key === '-') { e.preventDefault(); zoomCfg(1 / 1.2); }
    else if (e.key === '0') { e.preventDefault(); fitCfg(); }
  });
  $('#cfgGoto').addEventListener('submit', (e) => {
    e.preventDefault();
    const t = $('#cfgGotoInput').value.trim();
    let n = parseNum(t);
    if (Number.isNaN(n) || (!/^0x/i.test(t) && /[g-z_]/i.test(t))) {
      const q = t.toLowerCase();
      const hit = state.code?.functions.find((f) => funcName(f.va).toLowerCase() === q)
        || [...state.model.labels].find(([, name]) => name.toLowerCase() === q);
      n = hit ? (Array.isArray(hit) ? hit[0] : hit.va) : NaN;
    }
    if (Number.isNaN(n)) { $('#cfgInfo').textContent = 'Enter a hex address or a function name'; return; }
    openGraph(n);
  });
  $('#cfgFit').addEventListener('click', fitCfg);
  $('#cfgIn').addEventListener('click', () => zoomCfg(1.25));
  $('#cfgOut').addEventListener('click', () => zoomCfg(1 / 1.25));
  $('#cfgZoom').addEventListener('click', () => { if (state.cfg.layout) { const v = state.cfg.view; zoomCfg(1 / v.k); } });
  $('#cfgListing').addEventListener('click', graphToListing);
  $('#cfgBack').addEventListener('click', () => {
    const prev = state.cfg.history.pop();
    if (prev != null) openGraph(prev, false);
  });
}

/* ---------- Inline editing (rename, comment) ---------- */

let editing = null;
function openEditor(label, value, anchor, onSave) {
  const pop = $('#editPop');
  $('#editLabel').textContent = label;
  const input = $('#editInput');
  input.value = value;
  pop.hidden = false;
  const r = anchor.getBoundingClientRect();
  const left = Math.min(Math.max(12, r.left + 40), window.innerWidth - pop.offsetWidth - 12);
  const top = r.bottom + 6 + pop.offsetHeight > window.innerHeight ? r.top - pop.offsetHeight - 6 : r.bottom + 6;
  pop.style.left = `${left}px`;
  pop.style.top = `${Math.max(8, top)}px`;
  editing = onSave;
  input.focus();
  input.select();
}
function closeEditor(save) {
  const pop = $('#editPop');
  if (pop.hidden) return;
  pop.hidden = true;
  const fn = editing;
  editing = null;
  if (save && fn) fn($('#editInput').value);
}
$('#editInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); closeEditor(true); }
  if (e.key === 'Escape') { e.preventDefault(); closeEditor(false); }
});
$('#editInput').addEventListener('blur', () => setTimeout(() => closeEditor(false), 120));

function afterNotesChange() {
  refreshNames();
  renderNotesCard();
  if (state.cfg.graph) renderCfg(null, true);
}

function editName(va, anchor) {
  if (!state.hashes) { toast('Still hashing the file, try again in a moment.'); return; }
  openEditor(`Rename ${funcName(va)}`, state.notes.name(va) || '', anchor, (v) => {
    state.notes.setName(va, v);
    afterNotesChange();
  });
}
function editComment(va, anchor) {
  if (!state.hashes) { toast('Still hashing the file, try again in a moment.'); return; }
  openEditor(`Comment at ${hx(va)}`, state.notes.comment(va), anchor, (v) => {
    state.notes.setComment(va, v);
    afterNotesChange();
  });
}

/* ---------- Cross-references dialog ---------- */

const xrefDlg = $('#xrefDlg');
xrefDlg.addEventListener('click', (e) => {
  if (e.target === xrefDlg || e.target.closest('[data-close]')) xrefDlg.close();
  const go = e.target.closest('[data-goto]');
  if (go) {
    xrefDlg.close();
    const from = Number(go.dataset.goto);
    const f = containingFunc(from);
    openDisasm(f && from - f.va < 0x8000 ? f.va : from, true, from);
  }
});

async function showRefs(title, encoded) {
  const refs = (encoded || []).map(decRef);
  let eng = null;
  if (state.model.disasm) { try { eng = await getEngine(); } catch { /* preview optional */ } }
  const rows = refs.slice(0, 400).map(({ from, kind }) => {
    let preview = '';
    if (eng) {
      const off = state.model.vaToOff(from);
      if (off >= 0) {
        const [ins] = eng.disasm(state.bytes.subarray(off, off + 16), from, 1);
        if (ins) preview = `${ins.mnemonic} ${ins.opStr}`;
      }
    }
    return `<button type="button" class="xref-row" data-goto="${from}"><span class="chip ${kind === 'call' || kind === 'api' ? 'ok' : kind === 'jump' ? 'warn' : 'info'}">${kind}</span><span class="mono">${hxPad(from, state.model.bits === 64 ? 12 : 8)}</span><span class="mono xr-where">${esc(whereIs(from))}</span><span class="mono muted xr-ins">${esc(preview)}</span></button>`;
  }).join('');
  $('#xrefTitle').textContent = title;
  $('#xrefBody').innerHTML = refs.length
    ? `<p class="muted small">${refs.length.toLocaleString()} reference${refs.length > 1 ? 's' : ''}${refs.length > 400 ? ', first 400 shown' : ''}. Click one to open it in the disassembly.</p><div class="xref-list">${rows}</div>`
    : '<p class="muted">No references found by the code pass.</p>';
  if (!xrefDlg.open) xrefDlg.showModal();
}

function xrefsForVa(va) {
  const name = labelAt(va) || hx(va);
  showRefs(`References to ${name}`, state.code?.xrefs.get(va));
}

/* ---------- YARA ---------- */

const yaraBox = $('#yaraRules');
yaraBox.value = store.get(YARA_KEY) || SAMPLE_RULES;
yaraBox.addEventListener('input', () => store.set(YARA_KEY, yaraBox.value));
yaraBox.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runYaraNow(); }
  if (e.key === 'Tab') {
    e.preventDefault();
    const s = yaraBox.selectionStart;
    yaraBox.setRangeText('  ', s, yaraBox.selectionEnd, 'end');
  }
});
$('#yaraRun').addEventListener('click', () => runYaraNow());
$('#yaraSample').addEventListener('click', () => { yaraBox.value = SAMPLE_RULES; store.set(YARA_KEY, SAMPLE_RULES); });
$('#yaraFile').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  e.target.value = '';
  if (!f) return;
  yaraBox.value = await f.text();
  store.set(YARA_KEY, yaraBox.value);
  runYaraNow();
});

function renderYaraIdle() {
  $('#yaraStatus').textContent = 'Ctrl+Enter runs';
  $('#yaraResults').innerHTML = '<div class="card-head"><h2>Matches</h2></div><p class="muted small">Run your rules to see matches here. Rules are kept in this browser and run automatically on every file you open.</p>';
}

async function runYaraNow(quiet = false) {
  if (!state.bytes) return;
  const bytes = state.bytes;
  $('#yaraStatus').textContent = 'Running...';
  let res;
  const t0 = performance.now();
  try {
    res = await runYara(bytes, yaraBox.value);
  } catch (err) {
    console.error(err);
    $('#yaraStatus').textContent = `YARA failed: ${err.message}`;
    return;
  }
  if (state.bytes !== bytes) return;
  state.yara = res;
  const ms = Math.round(performance.now() - t0);
  const fatal = res.errors.filter((e) => !e.warning);
  $('#yaraStatus').textContent = fatal.length ? `${fatal.length} error${fatal.length > 1 ? 's' : ''}` : `${res.rules.length} rule${res.rules.length === 1 ? '' : 's'} matched in ${ms} ms`;
  const errs = res.errors.length
    ? `<ul class="hints">${res.errors.map((e) => `<li><span class="chip ${e.warning ? 'warn' : 'bad'}">line ${e.line}</span><span>${esc(e.message)}</span></li>`).join('')}</ul>` : '';
  const printable = (s) => /^[\x20-\x7e]*$/.test(s) ? s : [...s].map((c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
  const rules = res.rules.map((r) => `
    <details class="lib" open><summary>${esc(r.name)}<span class="muted">${r.matches.length} hit${r.matches.length === 1 ? '' : 's'}</span></summary>
      ${r.meta.length ? `<div class="chips yr-meta">${r.meta.map(([k, v]) => `<span class="chip">${esc(k)}: ${esc(v)}</span>`).join('')}</div>` : ''}
      ${r.matches.length ? `<ul class="yr-hits">${r.matches.slice(0, 200).map((x) => `<li><button class="link mono" data-hex="${x.off}" data-len="${x.len}">${hxPad(x.off)}</button><span class="mono muted">${esc(x.id)}</span><span class="mono">${esc(printable(x.data).slice(0, 80))}</span></li>`).join('')}</ul>` : '<p class="muted small yr-cond">Matched by condition only.</p>'}
    </details>`).join('');
  $('#yaraResults').innerHTML = `<div class="card-head"><h2>Matches</h2><span class="muted small">${ms} ms</span></div>${errs}${rules || (fatal.length ? '' : '<div class="verdict ok"><b>No rules matched</b><span>None of your rules fire on this file.</span></div>')}`;
  updateTabCounts();
  if (!quiet && state.tab !== 'yara') selectTab('yara');
}

/* ---------- Compare ---------- */

$('#compareBtn').addEventListener('click', () => $('#compareInput').click());
$('#compareInput').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  e.target.value = '';
  if (f) await compareWith(f);
});

async function compareWith(file) {
  if (!state.bytes) return;
  toast(`Analyzing ${file.name}...`);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const model = parseAny(bytes);
  sectionEntropies(model, bytes);
  const strings = extractStrings(bytes);
  const h = await hashes(bytes);
  if (!state.hashes) state.hashes = await hashes(state.bytes);
  const A = profileOf(state.name, state.bytes, state.model, state.strings, state.hashes);
  const B = profileOf(file.name, bytes, model, strings, h);
  state.compare = { A, B };
  renderDiff();
  $('[data-tab="diff"]').hidden = false;
  updateTabCounts();
  selectTab('diff');
  toast(`Compared with ${file.name}`);
}

function renderDiff() {
  const panel = $('[data-panel="diff"]');
  const c = state.compare;
  if (!c) { panel.innerHTML = ''; return; }
  const { A, B } = c;
  const d = diffProfiles(A, B);
  const head = (p, tag) => `<div class="card diff-file"><span class="chip">${tag}</span><b class="mono">${esc(p.name)}</b><span class="muted small">${esc(p.model.format)} · ${esc(p.model.arch)} · ${fmtSize(p.size)}</span><code class="small">${esc(p.hashes?.['SHA-256'] || '')}</code></div>`;
  const list = (items, cls, empty) => items.length
    ? `<ul class="diff-list ${cls}">${items.slice(0, 400).map((x) => `<li>${esc(x)}</li>`).join('')}${items.length > 400 ? `<li class="muted">+${(items.length - 400).toLocaleString()} more</li>` : ''}</ul>`
    : `<p class="muted small">${empty}</p>`;
  const changedFacts = d.facts.filter((f) => f.changed);
  const secRows = d.sections.map((s) => `<tr class="st-${s.status}"><td class="mono">${esc(s.name || '(unnamed)')}</td><td><span class="chip ${s.status === 'added' ? 'ok' : s.status === 'removed' ? 'bad' : s.status === 'changed' ? 'warn' : ''}">${s.status}</span></td>
    <td class="num">${s.sizeA == null ? '' : s.sizeA.toLocaleString()}</td><td class="num">${s.sizeB == null ? '' : s.sizeB.toLocaleString()}</td>
    <td class="num">${s.sizeA != null && s.sizeB != null && s.sizeA !== s.sizeB ? `${s.sizeB > s.sizeA ? '+' : ''}${(s.sizeB - s.sizeA).toLocaleString()}` : ''}</td>
    <td class="num">${s.entA == null ? '' : s.entA.toFixed(2)}</td><td class="num">${s.entB == null ? '' : s.entB.toFixed(2)}</td></tr>`).join('');
  panel.innerHTML = `
    <div class="diff-head">${head(A, 'A')}<div class="diff-vs">${d.identical ? '<span class="chip ok">identical</span>' : 'vs'}</div>${head(B, 'B')}</div>
    <div class="toolbar"><button class="btn" type="button" id="diffSwap">Swap A and B</button><button class="btn" type="button" id="diffOther">Compare with another file</button><button class="btn" type="button" id="diffClose">Close comparison</button></div>
    <div class="summary diff-sum">
      <dl class="stat"><dt>Imports added</dt><dd class="${d.importsAdded.length ? 'ok' : ''}">${d.importsAdded.length}</dd></dl>
      <dl class="stat"><dt>Imports removed</dt><dd class="${d.importsRemoved.length ? 'bad' : ''}">${d.importsRemoved.length}</dd></dl>
      <dl class="stat"><dt>Sections changed</dt><dd>${d.sections.filter((s) => s.status !== 'same').length}</dd></dl>
      <dl class="stat"><dt>Exports changed</dt><dd>${d.exportsAdded.length + d.exportsRemoved.length}</dd></dl>
      <dl class="stat"><dt>Strings added</dt><dd>${d.stringsAdded.length.toLocaleString()}</dd></dl>
      <dl class="stat"><dt>Strings removed</dt><dd>${d.stringsRemoved.length.toLocaleString()}</dd></dl>
    </div>
    <div class="card"><div class="card-head"><h2>Headers that changed</h2></div>
      ${changedFacts.length || d.mit.length ? `<div class="table-wrap flat"><table><thead><tr><th>Field</th><th>A</th><th>B</th></tr></thead><tbody>
        ${changedFacts.map((f) => `<tr><td>${esc(f.key)}</td><td class="mono">${esc(f.a)}</td><td class="mono">${esc(f.b)}</td></tr>`).join('')}
        ${d.mit.map((x) => `<tr><td>${esc(x.key)}</td><td>${x.a ? 'on' : 'off'}${typeof x.a === 'string' ? ` (${esc(x.a)})` : ''}</td><td>${x.b ? 'on' : 'off'}${typeof x.b === 'string' ? ` (${esc(x.b)})` : ''}</td></tr>`).join('')}
      </tbody></table></div>` : '<p class="muted small">Same headers and mitigations.</p>'}</div>
    <div class="table-wrap"><table><thead><tr><th>Section</th><th>Status</th><th>Size A</th><th>Size B</th><th>Change</th><th>Entropy A</th><th>Entropy B</th></tr></thead><tbody>${secRows}</tbody></table></div>
    <div class="grid-2">
      <div class="card"><div class="card-head"><h2>Imports added in B</h2></div>${list(d.importsAdded, 'add', 'None')}</div>
      <div class="card"><div class="card-head"><h2>Imports removed in B</h2></div>${list(d.importsRemoved, 'del', 'None')}</div>
    </div>
    ${d.exportsAdded.length || d.exportsRemoved.length ? `<div class="grid-2">
      <div class="card"><div class="card-head"><h2>Exports added</h2></div>${list(d.exportsAdded, 'add', 'None')}</div>
      <div class="card"><div class="card-head"><h2>Exports removed</h2></div>${list(d.exportsRemoved, 'del', 'None')}</div></div>` : ''}
    <div class="grid-2">
      <div class="card"><div class="card-head"><h2>Strings only in B</h2></div>${list(d.stringsAdded, 'add', 'None')}</div>
      <div class="card"><div class="card-head"><h2>Strings only in A</h2></div>${list(d.stringsRemoved, 'del', 'None')}</div>
    </div>`;
  $('#diffSwap').onclick = () => { state.compare = { A: c.B, B: c.A }; renderDiff(); };
  $('#diffOther').onclick = () => $('#compareInput').click();
  $('#diffClose').onclick = () => { state.compare = null; $('[data-tab="diff"]').hidden = true; panel.innerHTML = ''; selectTab('overview'); updateTabCounts(); };
}

/* ---------- Share + export ---------- */

function download(filename, data, type) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}

async function shareLink() {
  if (!state.bytes) return;
  if (!state.hashes) state.hashes = await hashes(state.bytes);
  const token = await encodeReport(buildReport(state));
  const url = `${location.origin}${location.pathname}#r=${token}`;
  try {
    await navigator.clipboard.writeText(url);
    toast(`Share link copied (${fmtSize(url.length)}). It holds the report only, never the file.`);
  } catch {
    prompt('Copy this link:', url);
  }
}

async function exportReport(kind) {
  if (!state.bytes) return;
  if (!state.hashes) state.hashes = await hashes(state.bytes);
  const r = buildReport(state, { full: kind === 'json' });
  const base = state.name.replace(/[^\w.-]+/g, '_');
  if (kind === 'json') download(`${base}.binkeep.json`, JSON.stringify(r, null, 2), 'application/json');
  else download(`${base}.binkeep.md`, reportMarkdown(r), 'text/markdown');
}

$('#shareBtn').addEventListener('click', shareLink);
$('#exportBtn').addEventListener('click', (e) => {
  e.stopPropagation();
  const menu = $('#exportMenu');
  menu.hidden = !menu.hidden;
  $('#exportBtn').setAttribute('aria-expanded', String(!menu.hidden));
  if (!menu.hidden) menu.querySelector('button').focus();
});
$('#exportMenu').addEventListener('click', (e) => {
  const b = e.target.closest('[data-export]');
  if (!b) return;
  $('#exportMenu').hidden = true;
  exportReport(b.dataset.export);
});
document.addEventListener('click', (e) => {
  if (!e.target.closest('.menu-wrap')) { $('#exportMenu').hidden = true; $('#exportBtn').setAttribute('aria-expanded', 'false'); }
});

let toastTimer = 0;
function toast(text) {
  const t = $('#toast');
  t.textContent = text;
  t.hidden = false;
  t.classList.remove('out');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.classList.add('out'); setTimeout(() => { t.hidden = true; }, 300); }, 3200);
}

/* ---------- Shared report view (no file, just the report from the URL) ---------- */

async function openShared(token) {
  let r;
  try {
    r = await decodeReport(token);
  } catch (err) {
    console.error(err);
    toast('This share link is damaged or incomplete.');
    return;
  }
  $('#emptyState').hidden = true;
  $('#report').hidden = true;
  const el = $('#shared');
  el.hidden = false;
  $('#fileMeta').hidden = false;
  $('#fileName').textContent = r.name;
  $('#fileFormat').textContent = 'shared report';
  document.title = `${r.name} · shared · binkeep`;
  const mit = r.mitigations.map(([k, v]) => `<span class="chip ${v ? 'ok' : 'bad'}">${v ? 'on' : 'off'} · ${esc(typeof v === 'string' ? `${k}: ${v}` : k)}</span>`).join('');
  const hints = r.hints.map((h) => `<li><span class="chip ${h.level === 'warn' ? 'warn' : 'info'}">${h.level === 'warn' ? 'check' : 'note'}</span><span>${esc(h.text)}</span></li>`).join('');
  const sig = r.signature;
  const pack = r.packing;
  const notes = r.notes && (Object.keys(r.notes.names).length + Object.keys(r.notes.comments).length);
  el.innerHTML = `
    <div class="card shared-banner">
      <div><b>Shared report</b><span class="muted small">Created ${esc(r.created.slice(0, 10))} with binkeep. The file itself is not included, only what was found in it.</span></div>
      <label class="btn btn-primary" for="fileInput">Analyze your own file</label>
    </div>
    <div class="summary">
      <dl class="stat"><dt>Format</dt><dd>${esc(r.format)}</dd></dl>
      <dl class="stat"><dt>Architecture</dt><dd>${esc(r.arch)}</dd></dl>
      <dl class="stat"><dt>Size</dt><dd>${fmtSize(r.size)}</dd></dl>
      <dl class="stat"><dt>Entropy</dt><dd class="${r.entropy.total > HIGH_ENTROPY ? 'warn' : ''}">${esc(r.entropy.total ?? '?')} / 8</dd></dl>
      <dl class="stat"><dt>Imports</dt><dd>${r.imports.reduce((n, l) => n + l.fns.length, 0)}</dd></dl>
      <dl class="stat"><dt>Functions</dt><dd>${r.functions ? r.functions.count.toLocaleString() : 'n/a'}</dd></dl>
    </div>
    <div class="card entropy-card"><div class="card-head"><h2>Entropy</h2><span class="muted" id="sharedLegend"></span></div><div class="entropy-wrap"><canvas id="sharedCanvas" class="entropy-canvas" role="img" aria-label="Entropy across the file"></canvas></div></div>
    <div class="grid-2">
      <div class="card"><div class="card-head"><h2>Headers</h2></div><dl class="facts">${r.facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></div>
      <div class="card" style="display:grid;gap:16px;align-content:start">
        <div><div class="card-head"><h2>Things to check</h2></div>${hints ? `<ul class="hints">${hints}</ul>` : '<p class="muted small">Nothing unusual.</p>'}</div>
        <div><div class="card-head"><h2>Security mitigations</h2></div><div class="chips">${mit || '<span class="muted small">n/a</span>'}</div></div>
        ${pack ? `<div><div class="card-head"><h2>Packing</h2></div><p class="small">${pack.packers.length ? esc(pack.packers.join(', ')) : pack.verdict === 'none' ? 'No packer detected' : `${pack.verdict === 'likely' ? 'Likely' : 'Possibly'} packed: ${esc(pack.reasons.join('; '))}`}</p></div>` : ''}
        ${sig ? `<div><div class="card-head"><h2>Signature</h2></div><p class="small">${esc(sig.signer?.subject?.CN || 'Unknown signer')}${sig.intact == null ? '' : sig.intact ? ' <span class="chip ok">unchanged since signing</span>' : ' <span class="chip bad">modified after signing</span>'}</p></div>` : ''}
      </div>
    </div>
    ${r.sha256 ? `<div class="card"><div class="card-head"><h2>Hashes</h2></div><div style="display:grid;gap:8px"><div class="hash-row"><span class="muted">SHA-256</span><code>${esc(r.sha256)}</code><button class="btn copy" data-copy="${esc(r.sha256)}">Copy</button></div><div class="hash-row"><span class="muted">SHA-1</span><code>${esc(r.sha1)}</code><button class="btn copy" data-copy="${esc(r.sha1)}">Copy</button></div></div></div>` : ''}
    <div class="table-wrap"><table><thead><tr><th>Section</th><th>Virtual address</th><th>File size</th><th>Flags</th><th>Entropy</th></tr></thead>
      <tbody>${r.sections.map((s) => `<tr><td class="mono">${esc(s.name)}</td><td class="num">${esc(s.va)}</td><td class="num">${hx(s.size)}</td><td class="mono">${esc(s.flags)}</td><td class="num">${entropyBar(s.entropy)}</td></tr>`).join('')}</tbody></table></div>
    ${r.imports.length ? `<div class="libs">${r.imports.map((l) => `<details class="lib"><summary>${esc(l.lib)}<span class="muted">${l.fns.length} functions</span></summary><ul class="fn-list">${l.fns.map((f) => `<li><span>${esc(f)}</span>${flagApi(f) ? `<span class="chip warn">${flagApi(f)}</span>` : ''}</li>`).join('')}</ul></details>`).join('')}</div>` : ''}
    ${r.strings.length ? `<div class="card"><div class="card-head"><h2>Interesting strings</h2><span class="muted small">${r.strings.length} of ${r.stringCount.toLocaleString()}</span></div><ul class="yr-hits">${r.strings.map((s) => `<li><span class="mono muted">${hxPad(s.off)}</span><span class="chip info">${esc(s.cat)}</span><span class="mono">${esc(s.text)}</span></li>`).join('')}</ul></div>` : ''}
    ${r.yara?.length ? `<div class="card"><div class="card-head"><h2>YARA matches</h2></div><div class="chips">${r.yara.map((y) => `<span class="chip warn">${esc(y.rule)} · ${y.matches}</span>`).join('')}</div></div>` : ''}
    ${notes ? `<div class="card"><div class="card-head"><h2>Analyst notes</h2></div><ul class="hints notes-list">${Object.entries(r.notes.names).map(([va, n]) => `<li><span class="mono">${hx(va)}</span><span class="chip">name</span><span>${esc(n)}</span></li>`).join('')}${Object.entries(r.notes.comments).map(([va, n]) => `<li><span class="mono">${hx(va)}</span><span class="chip">comment</span><span>${esc(n)}</span></li>`).join('')}</ul></div>` : ''}`;
  const draw = () => drawEntropyChart($('#sharedCanvas'), r.entropy.blocks.map((b) => (b / 255) * 8), r.sections, r.size, $('#sharedLegend'), '');
  requestAnimationFrame(draw);
  new ResizeObserver(draw).observe($('#sharedCanvas'));
}

/* ---------- Command palette ---------- */

const TAB_NAMES = { overview: 'Overview', sections: 'Sections', imports: 'Imports', exports: 'Symbols', strings: 'Strings', functions: 'Functions', resources: 'Resources', hex: 'Hex', disasm: 'Disassembly', graph: 'Graph', decompiler: 'Decompiler', yara: 'YARA', diff: 'Compare' };

function paletteItems(q) {
  const items = [];
  const loaded = !!state.bytes && !$('#report').hidden;
  const m = state.model;
  const take = (arr, n) => arr.sort((a, b) => b.score - a.score).slice(0, n);
  if (loaded && q && /^(0x)?[0-9a-f]{2,}$/i.test(q)) {
    const n = parseInt(q.replace(/^0x/i, ''), 16);
    if (m.disasm && m.vaToOff(n) >= 0) items.push({ group: 'Address', label: `Disassemble at ${hx(n)}`, hint: whereIs(n), run: () => openDisasm(n) });
    if (n < state.bytes.length) items.push({ group: 'Address', label: `Show file offset ${hx(n)} in hex`, run: () => gotoHex(n, 1) });
  }
  const actions = [
    { label: 'Open a file', run: () => fileInput.click() },
    ...(loaded ? [
      { label: 'Compare with another file', run: () => $('#compareInput').click() },
      { label: 'Copy share link', run: shareLink },
      { label: 'Export report as Markdown', run: () => exportReport('md') },
      { label: 'Export report as JSON', run: () => exportReport('json') },
      ...(state.hashes ? [{ label: 'Copy SHA-256', run: () => navigator.clipboard?.writeText(state.hashes['SHA-256']).then(() => toast('SHA-256 copied')) }] : []),
      ...(m.disasm && !state.code && !state.codeRun.running ? [{ label: 'Analyze code (find functions and xrefs)', run: () => { selectTab('functions'); runCodeAnalysis(); } }] : []),
      { label: 'Run YARA rules', run: () => { selectTab('yara'); runYaraNow(); } },
      { label: 'Go to entry point', run: () => openDisasm(defaultDisasmVa()) },
      ...$$('#tabs [data-tab]').filter((b) => !b.hidden).map((b) => ({ label: `Go to ${TAB_NAMES[b.dataset.tab]}`, run: () => selectTab(b.dataset.tab) })),
    ] : []),
  ];
  const act = actions.map((a) => ({ ...a, group: 'Actions', score: fuzzy(a.label, q) })).filter((a) => a.score > 0);
  items.push(...take(act, q ? 6 : 14));
  if (!loaded || !q) return items;

  if (state.code) {
    const fns = [];
    for (const f of state.code.functions) {
      const name = funcName(f.va);
      const s = fuzzy(name, q);
      if (s > 0) fns.push({ group: 'Functions', label: name, hint: hx(f.va), score: s + Math.min(f.xrefs, 50) * 0.2, run: () => openDisasm(f.va) });
    }
    items.push(...take(fns, 12));
  }
  const imps = [];
  for (const lib of m.imports) for (const f of lib.fns) {
    if (!f.name) continue;
    const s = fuzzy(f.name, q);
    if (s > 0) {
      const key = apiKey(lib.lib, f);
      imps.push({ group: 'Imports', label: f.name, hint: lib.lib.split('/').pop(), score: s, run: () => {
        const refs = state.code?.apiRefs.get(key);
        if (refs?.length) showRefs(`Calls to ${f.name}`, refs);
        else { selectTab('imports'); const inp = $('#impFilter'); if (inp) { inp.value = f.name; drawImports(); } }
      } });
    }
  }
  items.push(...take(imps, 8));
  const syms = [];
  for (const e of m.exports) {
    if (!e.name || e.va == null) continue;
    const s = fuzzy(e.name, q);
    if (s > 0) syms.push({ group: 'Symbols', label: e.name, hint: hx(e.va), score: s, run: () => openDisasm(e.va) });
    if (syms.length > 3000) break;
  }
  items.push(...take(syms, 6));
  if (q.length >= 3) {
    const strs = [];
    for (const s of state.strings) {
      const i = s.text.toLowerCase().indexOf(q);
      if (i >= 0) strs.push({ group: 'Strings', label: s.text.slice(0, 90), hint: hxPad(s.off), score: 100 - i, run: () => gotoHex(s.off, s.len) });
      if (strs.length > 400) break;
    }
    items.push(...take(strs, 8));
  }
  return items;
}

const palette = createPalette(paletteItems);
const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
$$('.kbd').forEach((k) => { if (k.textContent === 'Ctrl K' && isMac) k.textContent = '⌘K'; });
$('#paletteBtn').addEventListener('click', () => palette.open());

/* ---------- Tabs ---------- */

function updateTabCounts() {
  const m = state.model;
  const counts = {
    sections: m.sections.length,
    imports: m.imports.reduce((n, l) => n + l.fns.length, 0),
    exports: m.exports.length,
    strings: state.strings.length,
    functions: state.code?.functions.length,
    resources: state.resources?.items.length,
    yara: state.yara ? state.yara.rules.length : undefined,
  };
  $$('#tabs [data-tab]').forEach((b) => {
    const c = counts[b.dataset.tab];
    b.querySelector('.count')?.remove();
    if (c != null) b.insertAdjacentHTML('beforeend', `<span class="count${b.dataset.tab === 'yara' && c ? ' hot' : ''}">${c.toLocaleString()}</span>`);
  });
  moveLens();
}

// True when the user has scrolled far enough that the tab bar is pinned.
function tabsPinned() {
  const t = $('#tabs');
  // Small tolerance: the report's entry animation briefly offsets the bar.
  return window.scrollY > 0 && t.getBoundingClientRect().top <= parseFloat(getComputedStyle(t).top) + 16;
}

function selectTab(tab, autoDisasm = true) {
  const btn = $(`#tabs [data-tab="${tab}"]`);
  if (!$(`[data-panel="${tab}"]`) || !btn || btn.hidden) tab = 'overview';
  const pinned = tabsPinned();
  state.tab = tab;
  $$('#tabs [data-tab]').forEach((b) => {
    const on = b.dataset.tab === tab;
    b.setAttribute('aria-selected', String(on));
    b.tabIndex = on ? 0 : -1;
  });
  $$('[data-panel]').forEach((p) => { p.hidden = p.dataset.panel !== tab; });
  // Keep the reading position: if the tab bar was pinned, start the new panel
  // right under it instead of letting the page jump.
  if (pinned) alignPanel(tab);
  moveLens();
  if (history.replaceState) history.replaceState(null, '', `#${tab}`);
  if (tab === 'hex') state.hexList?.refresh();
  if (tab === 'strings') state.strList?.refresh();
  if (tab === 'functions') state.fnList?.refresh();
  if (autoDisasm && tab === 'disasm' && state.dis.start == null && state.model && !$('#disList').childElementCount) openDisasm(defaultDisasmVa(), false);
  if (autoDisasm && tab === 'graph' && state.model && !state.cfg.graph && !state.cfg.busy) openGraph(defaultGraphVa());
}

// Place a panel's top edge just below the pinned tab bar.
function alignPanel(name) {
  const p = $(`[data-panel="${name}"]`);
  const tabs = $('#tabs');
  const stickyTop = parseFloat(getComputedStyle(tabs).top) || 0;
  const target = p.getBoundingClientRect().top + window.scrollY - (stickyTop + tabs.offsetHeight + 14);
  window.scrollTo({ top: Math.max(0, target), behavior: 'instant' });
}

// For jumps (string -> hex, branch -> code): only move if the panel is out of view.
function scrollToPanel(name) {
  const p = $(`[data-panel="${name}"]`);
  if (p.hidden || state.tab !== name) return; // the user already moved on
  const top = p.getBoundingClientRect().top;
  const tabsBottom = $('#tabs').getBoundingClientRect().bottom;
  if (top < tabsBottom || top > window.innerHeight * 0.6) alignPanel(name);
}

function moveLens() {
  const active = $(`#tabs [data-tab="${state.tab}"]`);
  const lens = $('#tabLens');
  if (!active || !lens || !active.offsetWidth) return;
  lens.style.width = `${active.offsetWidth}px`;
  lens.style.transform = `translateX(${active.offsetLeft}px)`;
  const tabs = $('#tabs');
  const l = active.offsetLeft, r = l + active.offsetWidth;
  if (l < tabs.scrollLeft || r > tabs.scrollLeft + tabs.clientWidth) tabs.scrollTo({ left: l - 24, behavior: 'smooth' });
}
new ResizeObserver(() => moveLens()).observe($('#tabs'));
document.fonts?.ready.then(moveLens);

// Specular highlight on buttons and a soft spotlight on glass surfaces, following the pointer.
document.addEventListener('pointermove', (e) => {
  const b = e.target.closest?.('.btn');
  if (b) {
    const r = b.getBoundingClientRect();
    b.style.setProperty('--mx', `${e.clientX - r.left}px`);
    b.style.setProperty('--my', `${e.clientY - r.top}px`);
  }
  const s = e.target.closest?.('.card, .stat, .lib, .pitch li');
  if (s) {
    const r = s.getBoundingClientRect();
    s.style.setProperty('--sx', `${e.clientX - r.left}px`);
    s.style.setProperty('--sy', `${e.clientY - r.top}px`);
  }
}, { passive: true });

$('#tabs').addEventListener('click', (e) => {
  const b = e.target.closest('[data-tab]');
  if (b) selectTab(b.dataset.tab);
});
$('#tabs').addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const tabs = $$('#tabs [data-tab]').filter((b) => !b.hidden);
  const i = tabs.findIndex((b) => b.dataset.tab === state.tab);
  const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
  selectTab(next.dataset.tab);
  next.focus();
});

/* ---------- Delegated actions + keyboard ---------- */

document.addEventListener('click', (e) => {
  const xr = e.target.closest('[data-xref]');
  if (xr) { e.stopPropagation(); xrefsForVa(Number(xr.dataset.xref)); return; }
  const api = e.target.closest('[data-api]');
  if (api) { showRefs(`Calls to ${api.dataset.api}`, state.code?.apiRefs.get(api.dataset.api)); return; }
  const sr = e.target.closest('[data-strref]');
  if (sr) {
    const s = state.stringByOff.get(Number(sr.dataset.strref));
    if (s) showRefs(`References to "${s.text.slice(0, 40)}${s.text.length > 40 ? '...' : ''}"`, strRefs(s));
    return;
  }
  const res = e.target.closest('[data-res]');
  if (res) { saveResource(Number(res.dataset.res)); return; }
  const hexEl = e.target.closest('[data-hex]');
  if (hexEl) { gotoHex(Number(hexEl.dataset.hex), Number(hexEl.dataset.len || 1)); return; }
  const disEl = e.target.closest('[data-dis]');
  if (disEl) { openDisasm(Number(disEl.dataset.dis)); return; }
  const tabEl = e.target.closest('[data-tab-link]');
  if (tabEl) { selectTab(tabEl.dataset.tabLink); return; }
  const copyEl = e.target.closest('[data-copy]');
  if (copyEl) {
    navigator.clipboard?.writeText(copyEl.dataset.copy).then(() => {
      copyEl.textContent = 'Copied';
      setTimeout(() => { copyEl.textContent = 'Copy'; }, 1500);
    });
  }
});

const typing = (el) => el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable);

document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (palette.isOpen) palette.close(); else palette.open();
    return;
  }
  if (typing(document.activeElement) || e.ctrlKey || e.metaKey || e.altKey || palette.isOpen || xrefDlg.open) return;
  if (e.key === '/') { e.preventDefault(); palette.open(); return; }
  if (!state.bytes || $('#report').hidden) return;
  if (e.key === 'g') { e.preventDefault(); palette.open('0x'); return; }
  // Space switches between the listing and the graph, like most RE tools.
  if (e.key === ' ' && document.activeElement?.tagName !== 'BUTTON' && (state.tab === 'disasm' || state.tab === 'graph') && state.model.disasm) {
    e.preventDefault();
    if (state.tab === 'disasm') openGraph(defaultGraphVa()); else graphToListing();
    return;
  }
  if (state.tab !== 'disasm' || state.dis.sel == null) return;
  const va = state.dis.sel;
  const row = $(`#disList [data-va="${va}"]`) || $('#disList');
  if (e.key === 'n' || e.key === 'N') {
    e.preventDefault();
    const f = containingFunc(va);
    editName(f ? f.va : va, row);
  } else if (e.key === ';') {
    e.preventDefault();
    editComment(va, row);
  } else if (e.key === 'x' || e.key === 'X') {
    e.preventDefault();
    if (state.code?.xrefs.get(va)) xrefsForVa(va);
    else { const f = containingFunc(va); if (f) xrefsForVa(f.va); else toast(state.code ? 'No references to this line.' : 'Code analysis has not run yet.'); }
  }
});

/* ---------- AI button (coming soon, no action yet) ---------- */

$('#aiBtn').addEventListener('click', () => {
  const b = $('#aiBtn');
  b.classList.remove('pulse');
  void b.offsetWidth;
  b.classList.add('pulse');
});


/* ---------- Boot ---------- */

window.addEventListener('hashchange', () => {
  if (location.hash.startsWith('#r=')) openShared(location.hash.slice(3));
});
if (location.hash.startsWith('#r=')) openShared(location.hash.slice(3));

if ('serviceWorker' in navigator && location.protocol !== 'file:' && !new URLSearchParams(location.search).has('nosw')) {
  navigator.serviceWorker.register('sw.js').catch(() => { /* offline support is optional */ });
}

// Opened through the installed app's "Open with" (File Handling API).
if ('launchQueue' in window) {
  window.launchQueue.setConsumer(async (params) => {
    if (params.files?.length) loadFile(await params.files[0].getFile());
  });
}

// Test hook: window.binkeep.analyze(name, arrayBuffer)
window.binkeep = { analyze, state, compareWith, runCodeAnalysis };
window.binpeek = window.binkeep;
