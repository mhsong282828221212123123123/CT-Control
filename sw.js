// [v6 완전 네트워크 패스스루 및 캐시 즉시 소각 Service Worker]
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(keys.map((k) => caches.delete(k)));
    }).then(() => {
      return self.registration.unregister();
    }).then(() => {
      return self.clients.claim();
    })
  );
});

self.addEventListener('fetch', (event) => {
  // 브라우저 캐시 무시, 항상 네트워크 직접 요청
  event.respondWith(fetch(event.request));
});
