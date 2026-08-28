const ATLASO_CACHE_PREFIX = "atlaso-management-pwa-v";
const ATLASO_CACHE = `${ATLASO_CACHE_PREFIX}293`;
const ATLASO_ASSETS = [
  "/manifest.webmanifest",
  "/favicon.ico",
  "/static/offline.html",
  "/static/app.css?v=issues-515-519-9",
  "/static/ui-patterns.js?v=atlaso-ui-foundation-20260726-10",
  "/static/ui-routes.js?v=issue-287-1",
  "/static/appliance-apply-polling.js?v=issue-420-6",
  "/static/app.js?v=issues-515-519-11-513-328-1-595-5",
  "/static/terminal.js?v=issue-287-2",
  "/static/vendor/xterm/xterm.css?v=5.5.0",
  "/static/vendor/xterm/xterm.js?v=5.5.0",
  "/static/pwa.js?v=issue-287-2",
  "/static/brand/atlaso-icon.svg",
  "/static/brand/atlaso-logo-horizontal-light.svg",
  "/static/brand/atlaso-logo-horizontal-transparent-1200x300.png",
  "/static/brand/atlaso-app-icon-light-180.png",
  "/static/brand/atlaso-app-icon-dark-192.png",
  "/static/brand/atlaso-app-icon-dark-512.png",
  "/static/vendor/tabulator/tabulator.min.css",
  "/static/vendor/tabulator/tabulator.min.js",
  "/static/vendor/monaco/atlaso-monaco.min.css?v=atlaso-monaco-20260806-7",
  "/static/vendor/monaco/atlaso-monaco.min.js?v=atlaso-monaco-20260806-7",
  "/static/vendor/monaco/editor.worker.js?v=atlaso-monaco-20260806-7",
  "/static/vendor/prism/prism-core.min.js",
  "/static/vendor/prism/prism-diff.min.js"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(ATLASO_CACHE)
      .then(async (cache) => {
        const results = await Promise.allSettled(ATLASO_ASSETS.map(async (asset) => {
          const response = await fetch(asset, { cache: "reload" });
          if (!response || !response.ok) {
            throw new Error(`Required precache request failed: ${asset}`);
          }
          await cache.put(asset, response);
        }));
        const failure = results.find((result) => result.status === "rejected");
        if (failure) throw failure.reason;
      })
      .then(() => self.skipWaiting())
      .catch(async (error) => {
        // A failed install must not leave a partial cache that a later lifecycle could mistake for complete.
        await caches.delete(ATLASO_CACHE);
        throw error;
      })
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key.startsWith(ATLASO_CACHE_PREFIX) && key !== ATLASO_CACHE)
          .map((key) => caches.delete(key))
      )
    ).then(() => self.clients.claim())
  );
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
  return (
    accept.includes("text/html") &&
    (url.pathname === "/ui/management" || url.pathname.startsWith("/ui/management/")) &&
    !hasDownloadLikePath(url)
  );
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
      fetch(request, { cache: "no-store" }).then((response) => {
        // A controlled update response is authoritative. Never replace a
        // valid 503 status page with the cached offline shell.
        if (response.status === 503 || response.headers.get("X-Atlaso-Update-Mode") === "active") {
          return response;
        }
        return response;
      }).catch(() =>
        caches.open(ATLASO_CACHE).then((cache) => cache.match("/static/offline.html"))
      )
    );
    return;
  }

  if (!isCacheableAsset(url)) {
    return;
  }

  event.respondWith(
    caches.open(ATLASO_CACHE).then((cache) => cache.match(request).then((cached) => {
      const refresh = fetch(request).then((response) => {
        if (response && response.ok) {
          const copy = response.clone();
          cache.put(request, copy).catch(() => undefined);
        }
        return response;
      }).catch(() => undefined);
      if (cached) {
        return cached;
      }
      return refresh.then((response) => response || new Response("", { status: 504, statusText: "Gateway Timeout" }));
    }))
  );
});
