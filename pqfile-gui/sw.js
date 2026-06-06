// Service worker for pqfile web app.
// Strategy:
//   - Hashed assets (*.wasm, *.js with a content hash in the name): cache-first.
//     These filenames are immutable — once cached they never need revalidation.
//   - Everything else (index.html, sw.js, icon.png): network-first with a
//     cache fallback so new deployments propagate immediately.
//
// Bump CACHE_NAME when you need to force-evict all cached assets
// (e.g. format change incompatible with old entries).
const CACHE_NAME = 'pqfile-v1';

// Trunk content-hashes its output: pqfile-gui-<hash>.js / _bg.wasm
const HASHED_RE = /[.\-][0-9a-f]{8,}\.(js|wasm)$/;

self.addEventListener('install', evt => {
  self.skipWaiting();
  evt.waitUntil(
    caches.open(CACHE_NAME).then(c => c.add('/'))
  );
});

self.addEventListener('activate', evt => {
  evt.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', evt => {
  if (evt.request.method !== 'GET') return;
  const url = new URL(evt.request.url);
  if (url.origin !== self.location.origin) return;

  if (HASHED_RE.test(url.pathname)) {
    // Cache-first: hashed WASM/JS are immutable once built.
    evt.respondWith(
      caches.match(evt.request).then(hit => {
        if (hit) return hit;
        return fetch(evt.request).then(res => {
          if (res.ok) {
            caches.open(CACHE_NAME).then(c => c.put(evt.request, res.clone()));
          }
          return res;
        });
      })
    );
  } else {
    // Network-first: index.html and other non-hashed assets should always
    // reflect the latest deployment; fall back to cache when offline.
    evt.respondWith(
      fetch(evt.request)
        .then(res => {
          if (res.ok) {
            caches.open(CACHE_NAME).then(c => c.put(evt.request, res.clone()));
          }
          return res;
        })
        .catch(() => caches.match(evt.request))
    );
  }
});
