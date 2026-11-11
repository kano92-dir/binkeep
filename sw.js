// Offline support. Network first (so updates show up right away), falling
// back to the cache when offline. The app shell is cached on install.
const CACHE = 'binkeep-v6';
const SHARE = 'binkeep-share';
const SHELL = [
  './',
  'index.html',
  'css/style.css',
  'manifest.webmanifest',
  'assets/favicon.svg',
  'assets/icon-192.png',
  'js/app.js',
  'js/analysis.js',
  'js/disasm.js',
  'js/cfg.js',
  'js/findmain.js',
  'js/capabilities.js',
  'js/dotnet.js',
  'js/zip.js',
  'js/android.js',
  'js/extras.js',
  'js/codeanalysis.js',
  'js/packers.js',
  'js/notes.js',
  'js/palette.js',
  'js/report.js',
  'js/diff.js',
  'js/yara.js',
  'js/parsers/pe.js',
  'js/parsers/pe-extra.js',
  'js/parsers/elf.js',
  'js/parsers/macho.js',
  'vendor/capstone/index.mjs',
  'vendor/capstone/capstone.wasm',
  'vendor/yara/libyara-wasm.js',
];

const SHELL_URLS = new Set(SHELL.map((p) => new URL(p, self.registration.scope).href));

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE && k !== SHARE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

// Web Share Target: a file shared to the installed app arrives as a POST.
// Park it in Cache Storage (it never leaves the device) and open the app.
async function receiveShare(req) {
  try {
    const form = await req.formData();
    const file = form.getAll('file').find((f) => f && typeof f !== 'string');
    if (file) {
      const c = await caches.open(SHARE);
      await c.put('shared-file', new Response(file, { headers: { 'x-name': encodeURIComponent(file.name || 'shared-file') } }));
    }
  } catch { /* nothing shared */ }
  return Response.redirect(new URL('./?shared=1', self.registration.scope).href, 303);
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method === 'POST' && new URL(req.url).pathname.endsWith('/share-target')) {
    e.respondWith(receiveShare(req));
    return;
  }
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  const sameOrigin = url.origin === self.location.origin;
  const fonts = url.host === 'fonts.googleapis.com' || url.host === 'fonts.gstatic.com';
  if (!sameOrigin && !fonts) return;
  // Only the app itself and its fonts are cached, never anything else.
  const key = sameOrigin ? url.origin + url.pathname : req.url;
  const cacheable = fonts || SHELL_URLS.has(key) || req.mode === 'navigate';
  if (!cacheable) return;
  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res.ok || res.type === 'opaque') {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return res;
      })
      .catch(() => caches.match(req, { ignoreSearch: true }).then((hit) => hit || (req.mode === 'navigate' ? caches.match('index.html') : Response.error()))),
  );
});
