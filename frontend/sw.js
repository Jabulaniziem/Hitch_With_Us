// Minimal service worker. This app needs a live connection to work (live map,
// real-time driver locations), so we're not caching anything for offline use —
// this file exists only to satisfy the browser's "installable app" requirements.

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Just pass every request straight through to the network
  event.respondWith(fetch(event.request));
});
