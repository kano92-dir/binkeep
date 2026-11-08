// Per-file names and comments, kept in this browser and keyed by SHA-256.

const KEY = (sha) => `binkeep.notes.${sha}`;
const empty = () => ({ names: {}, comments: {} });

export function createNotes() {
  let sha = null;
  let data = empty();
  const save = () => {
    if (!sha) return;
    try {
      if (!Object.keys(data.names).length && !Object.keys(data.comments).length) localStorage.removeItem(KEY(sha));
      else localStorage.setItem(KEY(sha), JSON.stringify(data));
    } catch { /* storage blocked: notes live for this session only */ }
  };
  return {
    load(hash) {
      sha = hash;
      try { data = { ...empty(), ...JSON.parse(localStorage.getItem(KEY(hash)) || '{}') }; } catch { data = empty(); }
    },
    reset() { sha = null; data = empty(); },
    import(obj) {
      data = { names: { ...(obj?.names || {}) }, comments: { ...(obj?.comments || {}) } };
      save();
    },
    name: (va) => data.names[va] || '',
    comment: (va) => data.comments[va] || '',
    setName(va, v) { v = v.trim(); if (v) data.names[va] = v; else delete data.names[va]; save(); },
    setComment(va, v) { v = v.trim(); if (v) data.comments[va] = v; else delete data.comments[va]; save(); },
    all: () => data,
    count: () => Object.keys(data.names).length + Object.keys(data.comments).length,
  };
}
