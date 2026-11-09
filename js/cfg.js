// Control flow graph for one function: recursive descent from the function
// start into basic blocks, then a layered (Sugiyama style) layout.
import { classify, isUnconditionalEnd, operandTarget } from './disasm.js';

const MAX_INSNS = 12000;
const MAX_BLOCKS = 800;

function directTarget(fam, ins) {
  const t = operandTarget(fam, ins);
  return t && t.direct && !t.mem ? t.va : null;
}

// end: exclusive upper bound of the function, or null when unknown.
// isFuncStart(va): true when va begins another function (a jump there is a tail call).
export function buildCfg({ engine, model, bytes, start, end = null, isFuncStart = () => false }) {
  const fam = engine.family;
  const insns = new Map();
  const leaders = new Set([start]);
  const work = [start];
  const inRange = (va) => va >= start && (end == null || va < end) && model.vaToOff(va) >= 0;
  const follow = (va) => va != null && inRange(va) && (va === start || !isFuncStart(va));
  let truncated = false;

  const decodeAt = (va) => {
    const off = model.vaToOff(va);
    if (off < 0) return [];
    try { return engine.disasm(bytes.subarray(off, Math.min(bytes.length, off + 0x600)), va, 96); } catch { return []; }
  };

  while (work.length) {
    let va = work.pop();
    if (insns.has(va)) continue;
    if (insns.size >= MAX_INSNS) { truncated = true; break; }
    let buf = decodeAt(va), bi = 0;
    for (;;) {
      if (insns.has(va)) { leaders.add(va); break; }
      if (bi >= buf.length) { buf = decodeAt(va); bi = 0; if (!buf.length) break; }
      const ins = buf[bi++];
      if (ins.address !== va) { buf = []; continue; }
      insns.set(va, ins);
      const kind = classify(fam, ins.mnemonic);
      const next = va + ins.size;
      if (kind === 'ret') break;
      if (kind === 'jump') {
        const t = directTarget(fam, ins);
        if (follow(t)) { leaders.add(t); work.push(t); }
        if (isUnconditionalEnd(fam, ins.mnemonic)) break;
        if (follow(next)) { leaders.add(next); work.push(next); }
        break;
      }
      if (isUnconditionalEnd(fam, ins.mnemonic)) break;
      if (!inRange(next)) break;
      va = next;
    }
  }

  const starts = [...leaders].filter((va) => insns.has(va)).sort((a, b) => a - b);
  if (starts.length > MAX_BLOCKS) { truncated = true; starts.length = MAX_BLOCKS; }
  const index = new Map(starts.map((va, i) => [va, i]));
  const blocks = starts.map((va, id) => {
    const list = [];
    let cur = va, succ = [], exit = null;
    for (;;) {
      const ins = insns.get(cur);
      list.push(ins);
      const kind = classify(fam, ins.mnemonic);
      const next = cur + ins.size;
      if (kind === 'ret') break;
      if (kind === 'jump') {
        const t = directTarget(fam, ins);
        const uncond = isUnconditionalEnd(fam, ins.mnemonic);
        if (t != null && index.has(t)) succ.push({ to: index.get(t), kind: uncond ? 'jmp' : 'true' });
        else if (t != null) exit = t;
        if (!uncond && index.has(next)) succ.push({ to: index.get(next), kind: 'false' });
        break;
      }
      if (isUnconditionalEnd(fam, ins.mnemonic)) break;
      if (!insns.has(next)) break;
      if (index.has(next)) { succ.push({ to: index.get(next), kind: 'jmp' }); break; }
      cur = next;
    }
    // A conditional jump to the very next instruction would draw two edges to one block.
    if (succ.length === 2 && succ[0].to === succ[1].to) succ = [{ to: succ[0].to, kind: 'jmp' }];
    return { id, start: va, insns: list, succ, exit };
  });
  return { start, blocks, truncated, insnCount: insns.size };
}

/* ---------- Layout ---------- */

// sizes[i] = { w, h }. Returns node boxes, edge paths and the total size.
export function layoutCfg(blocks, sizes, opts = {}) {
  const GAP_X = opts.gapX ?? 36, GAP_Y = opts.gapY ?? 64, PAD = opts.pad ?? 40;
  const n = blocks.length;
  if (!n) return { nodes: [], edges: [], width: 0, height: 0 };

  // 1. Back edges via an iterative DFS from the entry block.
  const back = new Set();
  const state = new Uint8Array(n); // 0 new, 1 on stack, 2 done
  const order = [];
  const dfs = (root) => {
    const stack = [[root, 0]];
    state[root] = 1;
    while (stack.length) {
      const top = stack[stack.length - 1];
      const [v, i] = top;
      const s = blocks[v].succ;
      if (i < s.length) {
        top[1]++;
        const w = s[i].to;
        if (state[w] === 1) back.add(`${v}:${i}`);
        else if (state[w] === 0) { state[w] = 1; stack.push([w, 0]); }
      } else {
        state[v] = 2;
        order.push(v);
        stack.pop();
      }
    }
  };
  dfs(0);
  for (let v = 0; v < n; v++) if (!state[v]) dfs(v);
  const topo = order.reverse();

  // 2. Rank = longest path over forward edges.
  const rank = new Int32Array(n);
  for (const v of topo) {
    blocks[v].succ.forEach((e, i) => {
      if (back.has(`${v}:${i}`)) return;
      rank[e.to] = Math.max(rank[e.to], rank[v] + 1);
    });
  }

  // 3. Graph with dummy nodes on long edges. Real nodes keep their ids.
  const W = [], H = [], R = [], isDummy = [];
  for (let v = 0; v < n; v++) { W.push(sizes[v].w); H.push(sizes[v].h); R.push(rank[v]); isDummy.push(false); }
  const preds = Array.from({ length: n }, () => []);
  const succs = Array.from({ length: n }, () => []);
  const chains = []; // forward edges: { from, to, kind, path: [node ids], slot }
  const backEdges = [];
  blocks.forEach((b, v) => b.succ.forEach((e, i) => {
    if (back.has(`${v}:${i}`)) { backEdges.push({ from: v, to: e.to, kind: e.kind }); return; }
    const path = [v];
    for (let r = rank[v] + 1; r < rank[e.to]; r++) {
      const d = W.length;
      W.push(0); H.push(0); R.push(r); isDummy.push(true);
      preds.push([]); succs.push([]);
      path.push(d);
    }
    path.push(e.to);
    for (let k = 0; k + 1 < path.length; k++) { succs[path[k]].push(path[k + 1]); preds[path[k + 1]].push(path[k]); }
    chains.push({ from: v, to: e.to, kind: e.kind, path });
  }));
  const N = W.length;
  const maxRank = Math.max(...R);
  const layers = Array.from({ length: maxRank + 1 }, () => []);
  // Initial order: by first appearance in a BFS from the entry, so the
  // fall-through path tends to stay on the left like in most RE tools.
  const seen = new Uint8Array(N);
  const q = [0];
  seen[0] = 1;
  for (let h = 0; h < q.length; h++) for (const w of succs[q[h]]) if (!seen[w]) { seen[w] = 1; q.push(w); }
  for (let v = 0; v < N; v++) if (!seen[v]) q.push(v);
  for (const v of q) layers[R[v]].push(v);

  // 4. Crossing reduction: barycenter sweeps.
  const pos = new Float64Array(N);
  const setPos = () => layers.forEach((l) => l.forEach((v, i) => { pos[v] = i; }));
  setPos();
  const sweep = (list, nb) => {
    for (const layer of list) {
      const key = new Map(layer.map((v) => {
        const ns = nb[v];
        return [v, ns.length ? ns.reduce((s, w) => s + pos[w], 0) / ns.length : pos[v]];
      }));
      layer.sort((a, b) => key.get(a) - key.get(b) || pos[a] - pos[b]);
      layer.forEach((v, i) => { pos[v] = i; });
    }
  };
  for (let it = 0; it < 6; it++) {
    sweep(layers.slice(1), preds);
    sweep(layers.slice(0, -1).reverse(), succs);
  }
  sweep(layers.slice(1), preds);

  // 5. X placement: pull each node toward its neighbours, then remove
  // overlaps in each layer with the smallest total movement.
  const X = new Float64Array(N); // left edge
  layers.forEach((l) => { let x = 0; for (const v of l) { X[v] = x; x += W[v] + GAP_X; } });
  const center = (v) => X[v] + W[v] / 2;
  const place = (layer, nb) => {
    const desired = layer.map((v) => {
      const ns = nb[v];
      if (!ns.length) return X[v];
      const cs = ns.map(center).sort((a, b) => a - b);
      const mid = cs.length % 2 ? cs[(cs.length - 1) / 2] : (cs[cs.length / 2 - 1] + cs[cs.length / 2]) / 2;
      return mid - W[v] / 2;
    });
    const cl = [];
    layer.forEach((v, i) => {
      let c = { first: i, last: i, w: W[v], sum: desired[i], n: 1 };
      while (cl.length) {
        const p = cl[cl.length - 1];
        if (p.sum / p.n + p.w + GAP_X <= c.sum / c.n) break;
        cl.pop();
        c = { first: p.first, last: c.last, w: p.w + GAP_X + c.w, sum: p.sum + c.sum - c.n * (p.w + GAP_X), n: p.n + c.n };
      }
      cl.push(c);
    });
    for (const c of cl) {
      let x = c.sum / c.n;
      for (let i = c.first; i <= c.last; i++) { X[layer[i]] = x; x += W[layer[i]] + GAP_X; }
    }
  };
  for (let it = 0; it < 8; it++) {
    for (let r = 1; r <= maxRank; r++) place(layers[r], preds);
    for (let r = maxRank - 1; r >= 0; r--) place(layers[r], succs);
  }
  for (let r = 1; r <= maxRank; r++) place(layers[r], preds);

  // 6. Y placement by layer.
  const layerY = [], layerH = [];
  let y = PAD;
  for (let r = 0; r <= maxRank; r++) {
    const h = Math.max(0, ...layers[r].map((v) => H[v]));
    layerY.push(y); layerH.push(h);
    y += h + GAP_Y;
  }
  let minX = Infinity, maxX = -Infinity;
  for (let v = 0; v < N; v++) { minX = Math.min(minX, X[v]); maxX = Math.max(maxX, X[v] + W[v]); }
  const shift = PAD - minX;
  for (let v = 0; v < N; v++) X[v] += shift;
  maxX += shift;

  const nodes = blocks.map((b, v) => ({ x: X[v], y: layerY[R[v]], w: W[v], h: H[v] }));

  // 7. Edge routes. Out ports spread along the bottom, in ports along the top.
  const outCount = new Map(), inCount = new Map();
  const outIdx = new Map(), inIdx = new Map();
  const allEdges = [...chains.map((c) => ({ ...c, back: false })), ...backEdges.map((e) => ({ ...e, back: true }))];
  for (const e of allEdges) {
    outCount.set(e.from, (outCount.get(e.from) || 0) + 1);
    inCount.set(e.to, (inCount.get(e.to) || 0) + 1);
  }
  // Order ports left to right by where the other end sits.
  const otherX = (e, end) => (end === 'out' ? (e.back ? Infinity : center(e.path[1])) : (e.back ? Infinity : center(e.path[e.path.length - 2])));
  for (const [v] of outCount) allEdges.filter((e) => e.from === v).sort((a, b) => otherX(a, 'out') - otherX(b, 'out')).forEach((e, i) => outIdx.set(e, i));
  for (const [v] of inCount) allEdges.filter((e) => e.to === v).sort((a, b) => otherX(a, 'in') - otherX(b, 'in')).forEach((e, i) => inIdx.set(e, i));
  const port = (v, i, k) => {
    const n2 = nodes[v];
    const step = Math.min(18, (n2.w - 24) / Math.max(1, k));
    return n2.x + n2.w / 2 + (i - (k - 1) / 2) * step;
  };

  const edges = [];
  let backSlot = 0;
  for (const e of allEdges) {
    const a = nodes[e.from], b = nodes[e.to];
    const sx = port(e.from, outIdx.get(e), outCount.get(e.from));
    const tx = port(e.to, inIdx.get(e), inCount.get(e.to));
    const sy = a.y + a.h, ty = b.y;
    if (!e.back) {
      let d = `M${sx},${sy}`;
      let px = sx, py = sy;
      for (let k = 1; k < e.path.length - 1; k++) {
        const v = e.path[k];
        const top = layerY[R[v]], bot = top + layerH[R[v]];
        const cx = X[v];
        const m = (top - py) / 2;
        d += ` C${px},${py + m} ${cx},${top - m} ${cx},${top} L${cx},${bot}`;
        px = cx; py = bot;
      }
      const m = Math.max(16, (ty - py) / 2);
      d += ` C${px},${py + m} ${tx},${ty - m} ${tx},${ty}`;
      edges.push({ from: e.from, to: e.to, kind: e.kind, back: false, d });
    } else {
      // Loop back: down out of the source, right past everything in between, up, into the target.
      const r0 = Math.min(R[e.to], R[e.from]), r1 = Math.max(R[e.to], R[e.from]);
      let right = 0;
      for (let r = r0; r <= r1; r++) for (const v of layers[r]) if (!isDummy[v]) right = Math.max(right, X[v] + W[v]);
      const lane = right + 22 + (backSlot++ % 6) * 10;
      maxX = Math.max(maxX, lane);
      const y1 = sy + 14, y2 = ty - 14 - (backSlot % 3) * 4;
      const rr = 8;
      const d = `M${sx},${sy} L${sx},${y1 - rr} Q${sx},${y1} ${sx + rr},${y1} L${lane - rr},${y1} Q${lane},${y1} ${lane},${y1 - rr} L${lane},${y2 + rr} Q${lane},${y2} ${lane - rr},${y2} L${tx + (tx < lane ? rr : -rr)},${y2} Q${tx},${y2} ${tx},${y2 + rr} L${tx},${ty}`;
      edges.push({ from: e.from, to: e.to, kind: e.kind, back: true, d });
    }
  }
  return { nodes, edges, width: maxX + PAD, height: y - GAP_Y + PAD };
}
