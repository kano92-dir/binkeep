// YARA through libyara compiled to WebAssembly (vendor/yara, ISC license).
// Loaded on first use as a classic script that defines a global `Module` factory.

let instance = null;
let loading = null;

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error(`Could not load ${src}`));
    document.head.append(s);
  });
}

export async function getYara() {
  if (instance) return instance;
  if (!loading) {
    loading = (async () => {
      if (typeof window.Module !== 'function') await loadScript(new URL('../vendor/yara/libyara-wasm.js', import.meta.url).href);
      const factory = window.Module;
      instance = await factory();
      return instance;
    })();
    loading.catch(() => { loading = null; });
  }
  return loading;
}

const vec = (v) => {
  const out = [];
  if (!v) return out;
  for (let i = 0; i < v.size(); i++) out.push(v.get(i));
  return out;
};

// Returns { rules: [{ name, meta: [[k, v]], matches: [{ off, len, id, data }] }], errors: [{ line, message, warning }] }
export async function runYara(bytes, rulesText) {
  const yara = await getYara();
  const resp = yara.run(bytes, rulesText);
  const errors = vec(resp.compileErrors).map((e) => ({ line: e.lineNumber, message: e.message, warning: !!e.warning }));
  const rules = vec(resp.matchedRules).map((r) => ({
    name: r.ruleName,
    meta: vec(r.metadata).map((m) => [m.identifier, m.data]),
    matches: vec(r.resolvedMatches).map((m) => ({ off: Number(m.location), len: Number(m.matchLength), id: m.stringIdentifier, data: m.data })),
  }));
  return { rules, errors };
}

export const SAMPLE_RULES = `rule suspicious_process_injection
{
  meta:
    description = "Classic remote thread injection API set"
  strings:
    $a = "VirtualAllocEx"
    $b = "WriteProcessMemory"
    $c = "CreateRemoteThread"
  condition:
    uint16(0) == 0x5A4D and all of them
}

rule embedded_url
{
  strings:
    $url = /https?:\\/\\/[a-z0-9.\\-]{4,}/ nocase
  condition:
    $url
}

rule upx_packed
{
  strings:
    $magic = "UPX!"
  condition:
    $magic in (0..4096)
}
`;
