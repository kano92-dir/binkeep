// Packer and protector detection: section names, byte signatures, then
// generic heuristics (entropy, import count, entry point placement).
import { entropy } from './analysis.js';

const SECTION_NAMES = [
  [/^(UPX[0-9]|\.UPX[0-9]?|UPX!)$/i, 'UPX'],
  [/^\.aspack$|^\.adata$/, 'ASPack'],
  [/^\.MPRESS[12]$/, 'MPRESS'],
  [/^\.themida$/, 'Themida'],
  [/^\.winlice$/, 'WinLicense'],
  [/^\.vmp[0-9]$/, 'VMProtect'],
  [/^\.enigma[12]$/, 'Enigma Protector'],
  [/^\.petite$/, 'Petite'],
  [/^\.nsp[0-2]$/, 'NsPack'],
  [/^(PEC2|PEC2TO|PEC2MO|PECompact2|\.pec[12]?)$/, 'PECompact'],
  [/^\.yP$|^\.y0da$/, 'Y0da Protector'],
  [/^MEW$/, 'MEW'],
  [/^kkrunchy$/, 'kkrunchy'],
  [/^\.perplex$/, 'Perplex'],
  [/^\.spack$/, 'SPack'],
  [/^\.svkp$/, 'SVKP'],
  [/^\.taz$/, 'PESpin'],
  [/^\.ccg$/, 'CCG'],
  [/^\.boom$/, 'The Boomerang'],
  [/^\.packed$|^\.RLPack$/, 'RLPack'],
  [/^pebundle$|^PEBundle$/, 'PEBundle'],
  [/^\.Upack$|^\.ByDwing$/, 'Upack'],
  [/^\.mackt$/, 'ImpRec-rebuilt (dumped)'],
];

// [regex over printable strings, name]
const STRING_SIGS = [
  [/\$Info: This file is packed with the UPX/, 'UPX'],
  [/^UPX!/, 'UPX'],
  [/PECompact2/, 'PECompact'],
  [/aPLib v?\d/, 'aPLib (compression library)'],
  [/VMProtect (begin|end)/, 'VMProtect'],
  [/^(Themida|WinLicense)/, 'Themida / WinLicense'],
  [/Enigma protector/i, 'Enigma Protector'],
  [/ConfusedByAttribute/, 'ConfuserEx (.NET)'],
  [/SmartAssembly\.Attributes/, 'SmartAssembly (.NET)'],
  [/DotfuscatorAttribute/, 'Dotfuscator (.NET)'],
  [/\.NET Reactor|Eziriz/, '.NET Reactor'],
  [/BabelObfuscatorAttribute/, 'Babel (.NET)'],
  [/Obfuscar/, 'Obfuscar (.NET)'],
];

function findBytes(bytes, needle, limit = bytes.length) {
  const end = Math.min(bytes.length, limit) - needle.length;
  outer: for (let i = 0; i <= end; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

export function detectPackers(bytes, model, strings) {
  const found = new Map(); // name -> Set of evidence
  const add = (name, why) => {
    if (!found.has(name)) found.set(name, new Set());
    found.get(name).add(why);
  };

  for (const s of model.sections) {
    const short = s.name.includes(',') ? s.name.split(',')[1] : s.name;
    for (const [re, name] of SECTION_NAMES) if (re.test(short)) add(name, `section ${s.name}`);
  }

  // UPX writes "UPX!" right after the headers on PE, ELF and Mach-O.
  const upx = findBytes(bytes, [0x55, 0x50, 0x58, 0x21], 0x2000);
  if (upx >= 0) add('UPX', `"UPX!" marker at 0x${upx.toString(16)}`);

  const texts = strings.length > 60000 ? strings.slice(0, 60000) : strings;
  for (const [re, name] of STRING_SIGS) {
    const hit = texts.find((s) => re.test(s.text));
    if (hit) add(name, `string "${hit.text.slice(0, 48)}"`);
  }

  // Generic heuristics
  const reasons = [];
  let score = 0;
  const code = model.sections.filter((s) => s.x && s.size > 512 && s.off < bytes.length);
  const codeEntropy = code.length
    ? code.reduce((acc, s) => acc + entropy(bytes, s.off, Math.min(bytes.length, s.off + s.size)) * s.size, 0) / code.reduce((n, s) => n + s.size, 0)
    : null;
  if (codeEntropy != null && codeEntropy > 7.2) { score += 3; reasons.push(`code entropy ${codeEntropy.toFixed(2)} (normal code is 5.5 to 6.8)`); }
  else if (codeEntropy != null && codeEntropy > 6.9) { score += 1; reasons.push(`code entropy ${codeEntropy.toFixed(2)} is on the high side`); }

  const importNames = model.imports.flatMap((l) => l.fns.map((f) => f.name || ''));
  const isPE = model.format.startsWith('PE');
  const dotnet = isPE && model.facts.some(([, v]) => /\.NET/.test(v));
  if (isPE && !dotnet && importNames.length > 0 && importNames.length < 12) {
    score += 2;
    reasons.push(`only ${importNames.length} imports`);
    if (importNames.some((n) => /^LoadLibrary/.test(n)) && importNames.includes('GetProcAddress')) { score += 1; reasons.push('resolves its other APIs at runtime (LoadLibrary + GetProcAddress)'); }
  }
  if (model.entry != null) {
    const es = model.sections.find((s) => model.entry >= s.va && model.entry < s.va + Math.max(s.vsize, s.size));
    const execs = model.sections.filter((s) => s.x);
    if (es && es.w) { score += 2; reasons.push(`entry point is in writable section ${es.name}`); }
    if (es && execs.length > 1 && es === execs[execs.length - 1] && es !== execs[0]) { score += 1; reasons.push(`entry point is in the last code section (${es.name})`); }
  }
  for (const s of model.sections) {
    if (s.x && s.size === 0 && s.vsize > 0x1000) { score += 2; reasons.push(`${s.name || 'a section'} is executable but empty on disk`); break; }
  }

  const packers = [...found].map(([name, why]) => ({ name, evidence: [...why] }));
  let verdict = 'none';
  if (packers.length) verdict = 'signature';
  else if (score >= 4) verdict = 'likely';
  else if (score >= 2) verdict = 'maybe';
  return { packers, verdict, score, reasons, codeEntropy };
}
