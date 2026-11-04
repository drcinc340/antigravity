const CACHE_NAME = 'antigravity-v2';
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = event.request.url;
  // Never intercept API, SSE stream, or live encrypted tunnel endpoint fetches
  if (
    event.request.method !== 'GET' ||
    url.includes('/api/') ||
    url.includes('/stream') ||
    url.includes('tunnel.json') ||
    url.includes('raw.githubusercontent.com') ||
    url.includes('.trycloudflare.com/api/')
  ) {
    return;
  }

  // Network-first with cache fallback so updates arrive immediately on MacBook & iPhone
  event.respondWith(
    fetch(event.request)
      .then((fetchRes) => {
        if (fetchRes && fetchRes.status === 200) {
          const clone = fetchRes.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone)).catch(() => {});
        }
        return fetchRes;
      })
      .catch(() => {
        return caches.match(event.request).then((cached) => {
          if (cached) return cached;
          if (event.request.mode === 'navigate') {
            return caches.match('./index.html');
          }
        });
      })
  );
});
