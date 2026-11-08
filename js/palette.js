// Command palette (Ctrl+K / Cmd+K / "/"). The app supplies items for a query;
// each item is { group, label, hint?, run() }.

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Subsequence match score: consecutive and word-start hits score higher.
export function fuzzy(text, q) {
  if (!q) return 1;
  const t = text.toLowerCase();
  const direct = t.indexOf(q);
  if (direct >= 0) return 1000 - direct - (t.length - q.length) * 0.1 + (direct === 0 ? 200 : 0);
  let ti = 0, score = 0, streak = 0;
  for (const ch of q) {
    const i = t.indexOf(ch, ti);
    if (i < 0) return 0;
    streak = i === ti ? streak + 1 : 0;
    score += 1 + streak * 2 + (i === 0 || /[\s_.!:/-]/.test(t[i - 1]) ? 3 : 0);
    ti = i + 1;
  }
  return score;
}

function highlight(label, q) {
  if (!q) return esc(label);
  const i = label.toLowerCase().indexOf(q);
  if (i < 0) return esc(label);
  return `${esc(label.slice(0, i))}<mark>${esc(label.slice(i, i + q.length))}</mark>${esc(label.slice(i + q.length))}`;
}

export function createPalette(getItems) {
  const dlg = document.createElement('dialog');
  dlg.className = 'palette';
  dlg.setAttribute('aria-label', 'Command palette');
  dlg.innerHTML = `
    <div class="pal-search">
      <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input type="text" placeholder="Search functions, imports, strings, or type an address" autocomplete="off" spellcheck="false" aria-label="Command">
      <kbd>esc</kbd>
    </div>
    <div class="pal-list" role="listbox"></div>
    <div class="pal-foot"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>enter</kbd> open</span><span><kbd>0x…</kbd> jump to address</span></div>`;
  document.body.append(dlg);
  const input = dlg.querySelector('input');
  const listEl = dlg.querySelector('.pal-list');
  let items = [];
  let sel = 0;

  const render = () => {
    const q = input.value.trim().toLowerCase();
    items = getItems(q);
    sel = Math.min(sel, Math.max(0, items.length - 1));
    let last = '';
    listEl.innerHTML = items.length
      ? items.map((it, i) => {
          const head = it.group !== last ? `<div class="pal-group">${esc(it.group)}</div>` : '';
          last = it.group;
          return `${head}<button type="button" role="option" class="pal-item${i === sel ? ' sel' : ''}" data-i="${i}" aria-selected="${i === sel}"><span class="pal-label">${highlight(it.label, q)}</span>${it.hint ? `<span class="pal-hint">${esc(it.hint)}</span>` : ''}</button>`;
        }).join('')
      : '<div class="pal-empty">No matches</div>';
    listEl.querySelector('.sel')?.scrollIntoView({ block: 'nearest' });
  };
  const choose = (i) => {
    const it = items[i];
    if (!it) return;
    dlg.close();
    it.run();
  };

  input.addEventListener('input', () => { sel = 0; render(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); render(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); render(); }
    else if (e.key === 'Enter') { e.preventDefault(); choose(sel); }
  });
  listEl.addEventListener('click', (e) => {
    const b = e.target.closest('[data-i]');
    if (b) choose(Number(b.dataset.i));
  });
  listEl.addEventListener('pointermove', (e) => {
    const b = e.target.closest('[data-i]');
    if (b && Number(b.dataset.i) !== sel) { sel = Number(b.dataset.i); listEl.querySelectorAll('.pal-item').forEach((x, i) => { x.classList.toggle('sel', i === sel); x.setAttribute('aria-selected', String(i === sel)); }); }
  });
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); });

  return {
    open(prefill = '') {
      input.value = prefill;
      sel = 0;
      render();
      if (!dlg.open) dlg.showModal();
      input.focus();
      input.select();
    },
    close: () => dlg.close(),
    get isOpen() { return dlg.open; },
  };
}
