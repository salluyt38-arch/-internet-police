const CACHE_NAME = 'internet-police-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/manifest.json'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
  );
});

self.addEventListener('fetch', (e) => {
  if (e.request.url.includes('/api/')) {
    e.respondWith(fetch(e.request));
  } else {
    e.respondWith(
      caches.match(e.request).then((res) => res || fetch(e.request))
    );
  }
});
