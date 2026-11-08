// Compare two analyzed files: headers, sections, imports, exports, strings.

const setDiff = (a, b) => [...a].filter((x) => !b.has(x));

export function profileOf(name, bytes, model, strings, hashes) {
  return {
    name,
    size: bytes.length,
    hashes,
    model,
    imports: new Set(model.imports.flatMap((l) => l.fns.map((f) => `${l.lib.toLowerCase()}!${f.name || '#' + f.ordinal}`))),
    exports: new Set(model.exports.map((e) => e.name).filter(Boolean)),
    strings: new Set(strings.map((s) => s.text)),
  };
}

export function diffProfiles(A, B) {
  const facts = [];
  const fa = new Map(A.model.facts), fb = new Map(B.model.facts);
  for (const k of new Set([...fa.keys(), ...fb.keys()])) facts.push({ key: k, a: fa.get(k) ?? '', b: fb.get(k) ?? '', changed: (fa.get(k) ?? '') !== (fb.get(k) ?? '') });

  const mit = [];
  const ma = new Map(A.model.mitigations), mb = new Map(B.model.mitigations);
  for (const k of new Set([...ma.keys(), ...mb.keys()])) {
    const a = ma.get(k), b = mb.get(k);
    if (String(a) !== String(b)) mit.push({ key: k, a, b });
  }

  const sa = new Map(A.model.sections.map((s) => [s.name, s])), sb = new Map(B.model.sections.map((s) => [s.name, s]));
  const sections = [];
  for (const k of new Set([...sa.keys(), ...sb.keys()])) {
    const a = sa.get(k), b = sb.get(k);
    sections.push({
      name: k,
      status: !a ? 'added' : !b ? 'removed' : a.size !== b.size || Math.abs((a.entropy ?? 0) - (b.entropy ?? 0)) > 0.05 ? 'changed' : 'same',
      sizeA: a?.size ?? null, sizeB: b?.size ?? null,
      entA: a?.entropy ?? null, entB: b?.entropy ?? null,
    });
  }

  return {
    identical: !!A.hashes?.['SHA-256'] && A.hashes['SHA-256'] === B.hashes?.['SHA-256'],
    facts, mit, sections,
    importsAdded: setDiff(B.imports, A.imports).sort(),
    importsRemoved: setDiff(A.imports, B.imports).sort(),
    exportsAdded: setDiff(B.exports, A.exports).sort(),
    exportsRemoved: setDiff(A.exports, B.exports).sort(),
    stringsAdded: setDiff(B.strings, A.strings),
    stringsRemoved: setDiff(A.strings, B.strings),
  };
}
