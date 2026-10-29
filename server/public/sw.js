'use strict';

const CACHE = 'sentinelmdm-v22';
const STATIC_ASSETS = ['/style.css', '/app.js', '/manifest.json', '/icon.svg', '/icon-192.png', '/icon-512.png'];

self.addEventListener('install', e => {
  // .catch() must wrap the WHOLE chain, not just addAll() — caches.open() itself can reject
  // (e.g. the origin's storage quota is full, so it can't even create a new named cache), and an
  // uncaught rejection anywhere in this promise fails SW installation outright. Priming the
  // cache is a nice-to-have; it must never be able to block the worker from installing/activating.
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC_ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── Push Notifications ────────────────────────────────────────────────────────
self.addEventListener('push', e => {
  let data = {};
  try { data = e.data ? e.data.json() : {}; } catch {}
  e.waitUntil(
    self.registration.showNotification(data.title || 'SentinelMDM', {
      body:     data.body || '',
      icon:     '/icon-192.png',
      badge:    '/icon-192.png',
      data:     { url: data.url || '/' },
      tag:      'sentinelmdm',
      renotify: true,
    })
  );
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const target = e.notification.data?.url || '/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if (c.url.startsWith(self.location.origin) && 'focus' in c) return c.focus();
      }
      return clients.openWindow(target);
    })
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Never intercept: API calls, Socket.IO, auth routes, cross-origin
  if (
    url.pathname.startsWith('/api/') ||
    url.pathname.startsWith('/socket.io/') ||
    url.pathname.startsWith('/login') ||
    url.pathname.startsWith('/logout') ||
    url.pathname.startsWith('/setup-2fa') ||
    url.origin !== self.location.origin
  ) return;

  // HTML pages: network-first (ensures auth redirects work)
  if (e.request.destination === 'document') {
    e.respondWith(
      fetch(e.request).catch(() => caches.match(e.request))
    );
    return;
  }

  // Code assets change on every deploy → NETWORK-FIRST (fall back to cache offline).
  // The old cache-first strategy froze these in the cache: because the cache key never
  // changed, the companion-app WebView served a stale app.js forever and never picked
  // up shipped UI fixes (e.g. the Pause→Unpause button flip). Network-first guarantees
  // an online client always runs the latest code, while keeping offline fallback.
  const NETWORK_FIRST = ['/app.js', '/style.css', '/manifest.json'];
  if (NETWORK_FIRST.includes(url.pathname)) {
    // cache:'no-store' bypasses the browser/WebView HTTP cache — without this, fetch()
    // returns the HTTP-cached stale copy and the SW never sees the updated file.
    const req = new Request(e.request, { cache: 'no-store' });
    e.respondWith(
      fetch(req).then(res => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy));
        }
        return res;
      }).catch(() => caches.match(e.request))
    );
    return;
  }

  // Other static assets (icons, images): cache-first — effectively immutable.
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, copy));
        }
        return res;
      });
    })
  );
});
