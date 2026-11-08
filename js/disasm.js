// Thin wrapper around capstone-wasm 1.0.3 (Capstone compiled to WebAssembly),
// bundled in vendor/capstone so it works offline. Loaded lazily on first use.

const CAPSTONE_URL = new URL('../vendor/capstone/index.mjs', import.meta.url).href;
let modPromise = null;

function loadModule() {
  if (!modPromise) {
    modPromise = import(CAPSTONE_URL).then(async (mod) => {
      await mod.loadCapstone();
      return mod;
    });
    modPromise.catch(() => { modPromise = null; });
  }
  return modPromise;
}

export async function createDisassembler(spec) {
  const { Capstone, Const } = await loadModule();
  const arch = Const[`CS_ARCH_${spec.arch}`];
  const mode = Const[`CS_${spec.mode}`];
  if (arch === undefined || mode === undefined) throw new Error(`Capstone has no support for ${spec.arch}/${spec.mode}`);
  const cs = new Capstone(arch, mode);
  const family = spec.arch === 'X86' ? 'x86' : 'arm';

  return {
    family,
    close: () => cs.close(),
    disasm(bytes, address, count) {
      return cs.disasm(bytes, { address, count }).map((i) => ({
        address: Number(i.address),
        size: i.size,
        bytes: i.bytes,
        mnemonic: i.mnemonic,
        opStr: i.opStr,
      }));
    },
  };
}

// Classify an instruction for coloring and control-flow handling.
export function classify(family, mnem) {
  const m = mnem.toLowerCase();
  if (family === 'x86') {
    if (m === 'call') return 'call';
    if (m.startsWith('ret') || m === 'iret' || m === 'iretq') return 'ret';
    if (m.startsWith('j') || m.startsWith('loop')) return 'jump';
    return '';
  }
  if (m === 'bl' || m === 'blr' || m === 'blx') return 'call';
  if (m === 'ret' || m === 'eret') return 'ret';
  if (m === 'b' || m.startsWith('b.') || m === 'br' || m === 'bx' || /^(cbn?z|tbn?z)$/.test(m) || /^b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)$/.test(m)) return 'jump';
  return '';
}

export function isUnconditionalEnd(family, mnem) {
  const m = mnem.toLowerCase();
  if (family === 'x86') return m === 'jmp' || m.startsWith('ret') || m === 'int3' || m === 'ud2' || m === 'hlt';
  return m === 'b' || m === 'br' || m === 'ret' || m === 'bx';
}

// Resolve the address an operand refers to: a branch target, a RIP-relative
// memory operand, an absolute memory operand, or an ARM64 adr/adrp page.
export function operandTarget(family, insn) {
  const ops = insn.opStr;
  if (family === 'x86') {
    let m = ops.match(/\[rip ([+-]) 0x([0-9a-f]+)\]/i);
    if (m) {
      const d = parseInt(m[2], 16);
      return { va: insn.address + insn.size + (m[1] === '+' ? d : -d), mem: true };
    }
    m = ops.match(/\[0x([0-9a-f]+)\]/i);
    if (m) return { va: parseInt(m[1], 16), mem: true };
    m = ops.match(/^0x([0-9a-f]+)$/i);
    if (m) return { va: parseInt(m[1], 16), mem: false, direct: true };
    m = ops.match(/(?:^|, )0x([0-9a-f]{5,})$/i);
    if (m) return { va: parseInt(m[1], 16), mem: false };
    return null;
  }
  const m = ops.match(/#0x([0-9a-f]+)$/i);
  if (m) return { va: parseInt(m[1], 16), mem: false, direct: true };
  return null;
}
