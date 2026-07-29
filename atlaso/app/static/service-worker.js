const ATLASO_CACHE = "atlaso-pwa-v198";
const ATLASO_ASSETS = [
  "/manifest.webmanifest",
  "/favicon.ico",
  "/static/offline.html",
  "/static/app.css?v=atlaso-monaco-expand-20260729-4",
  "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-4",
  "/static/app.js?v=atlaso-monaco-kickstarts-20260729-1",
  "/static/terminal.js?v=web-terminal-review-20260716-3",
  "/static/vendor/xterm/xterm.css?v=5.5.0",
  "/static/vendor/xterm/xterm.js?v=5.5.0",
  "/static/pwa.js?v=atlaso-brand-20260725-1",
  "/static/brand/atlaso-icon.svg",
  "/static/brand/atlaso-logo-horizontal-light.svg",
  "/static/brand/atlaso-app-icon-light-180.png",
  "/static/brand/atlaso-app-icon-dark-192.png",
  "/static/brand/atlaso-app-icon-dark-512.png",
  "/static/vendor/tabulator/tabulator.min.css",
  "/static/vendor/tabulator/tabulator.min.js",
  "/static/vendor/monaco/atlaso-monaco.min.css?v=atlaso-monaco-20260729-5",
  "/static/vendor/monaco/atlaso-monaco.min.js?v=atlaso-monaco-20260729-5",
  "/static/vendor/monaco/editor.worker.js?v=atlaso-monaco-20260729-5",
  "/static/vendor/prism/prism-core.min.js",
  "/static/vendor/prism/prism-diff.min.js"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(ATLASO_CACHE).then((cache) =>
      Promise.all(
        ATLASO_ASSETS.map((asset) =>
          fetch(asset, { cache: "reload" })
            .then((response) => {
              if (!response || !response.ok) {
                return undefined;
              }
              return cache.put(asset, response);
            })
            .catch(() => undefined)
        )
      )
    )
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== ATLASO_CACHE).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

function isCacheableAsset(url) {
  return (
    url.pathname === "/manifest.webmanifest" ||
    url.pathname === "/favicon.ico" ||
    url.pathname.startsWith("/static/")
  );
}

function hasDownloadLikePath(url) {
  const lastSegment = url.pathname.split("/").pop() || "";
  return (
    url.pathname.startsWith("/ca/downloads/") ||
    url.pathname.startsWith("/certificate-authority/downloads/") ||
    url.pathname.startsWith("/api/") ||
    /\.[A-Za-z0-9]{1,12}$/.test(lastSegment)
  );
}

function shouldServeOfflineFallback(request, url) {
  const accept = request.headers.get("Accept") || "";
  return accept.includes("text/html") && !hasDownloadLikePath(url);
}

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);

  if (request.method !== "GET" || url.origin !== self.location.origin) {
    return;
  }

  if (request.mode === "navigate") {
    if (!shouldServeOfflineFallback(request, url)) {
      return;
    }
    event.respondWith(
      fetch(request).catch(() => caches.match("/static/offline.html"))
    );
    return;
  }

  if (!isCacheableAsset(url)) {
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      const refresh = fetch(request).then((response) => {
        if (response && response.ok) {
          const copy = response.clone();
          caches.open(ATLASO_CACHE).then((cache) => cache.put(request, copy)).catch(() => undefined);
        }
        return response;
      }).catch(() => undefined);
      if (cached) {
        return cached;
      }
      return refresh.then((response) => response || new Response("", { status: 504, statusText: "Gateway Timeout" }));
    })
  );
});
